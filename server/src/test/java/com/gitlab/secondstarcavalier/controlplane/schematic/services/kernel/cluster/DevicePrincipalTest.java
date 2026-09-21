// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Device principals end to end: {@code Mint.CreatePersonalPrincipal} registers a
 * key, and {@code Mint.MintUserToken} with {@code AUTH_BROKER_KIND_DEVICE} turns
 * a proof signed by that key into that person's own {@code /people/<pid>} token.
 *
 * <p>Both halves are one test class because they are one loop: registration's
 * only product is a credential row, and the only thing that reads that row is
 * the mint. Testing either against a hand-seeded copy of the other would test
 * the copy.
 *
 * <p>The fake OPA below deliberately answers {@code /tenants/acme} for every
 * evaluation. Every namespace assertion here is therefore also an assertion that
 * the device arm does NOT take its namespace from OPA — if it ever falls back to
 * {@code requireNamespaceFromOpa}, the minted token comes back naming a tenant
 * and these tests say so.
 */
class DevicePrincipalTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String DELEGATE_NAME = "device-broker";
	private static final String IDP_DELEGATE_NAME = "oauth";
	private static final String PLAIN_DELEGATE_NAME = "docmanager";
	private static final String STRANGER_NAME = "not-a-delegate";
	private static final String OPA_NAMESPACE = "/tenants/acme";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private KeyRotator keyRotator;
	private PrincipalMap principalMap;
	private IdentityServiceImpl svc;

	@BeforeEach
	void setUp() {
		keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(DELEGATE_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)
				.build());
		// A real, authenticated S2S delegate that brokers IdP logins only — oauth's
		// shape. Registration must refuse it: being a delegate is not the check.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(IDP_DELEGATE_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		// A delegate with no auth_broker_kinds at all — the default, and every
		// delegate that has not been migrated. Fail-closed means refused.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(PLAIN_DELEGATE_NAME)
				.build());
		principalMap = new PrincipalMap(new InMemoryManager());
		svc = new IdentityServiceImpl(
				3600, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				List::of,
				g -> { },
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				new FakeOpaEvalGrpcClient(),
				null,            // proxyPolicyOpaClient
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // persistState
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // opaConfigWriter
	}

	// ------------------------------------------------------------------
	// Registration
	// ------------------------------------------------------------------

	/**
	 * Registration creates a real row holding the presented credential, and that
	 * row survives a restart — the snapshot path, not just the live map, because
	 * a person who de-registers on the first kernel restart is not registered.
	 * Same round trip {@code KernelPersistencePersonalPrincipalTest} pins, driven
	 * here by the RPC rather than a hand-seeded row.
	 */
	@Test
	void registrationCreatesAPersistedPrincipalHoldingThePresentedKey(@TempDir Path dir) throws Exception {
		DeviceKey key = DeviceKey.generate("cred-iphone");

		String principalId = register(key, "iPhone", true);

		assertNotNull(principalId);
		Kernel.PersonalPrincipal live = principalMap.getPersonalPrincipals(principalId);
		assertEquals(principalId, live.getPrincipalId());
		assertEquals(1, live.getCredentialsCount());
		Kernel.PersonalCredential stored = live.getCredentials(0);
		assertEquals("cred-iphone", stored.getCredentialId());
		assertEquals(key.publicJwk, stored.getPublicKey());
		assertEquals("iPhone", stored.getLabel());
		assertTrue(stored.getPlatformSynced());
		assertEquals(0, stored.getRevokedAtMs());

		// --- snapshot -> restart -> fresh empty map ---
		KernelPersistence persistence = new KernelPersistence(
				dir.toString(), null, null, null, null, null, null,
				() -> {
					try {
						return principalMap.proto();
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				});
		persistence.save();
		PrincipalMap afterRestart = new PrincipalMap(new InMemoryManager());
		ClusterServer.restorePersonalPrincipals(persistence.load(), afterRestart);

		assertEquals(live, afterRestart.getPersonalPrincipals(principalId),
				"the registered person must come back field-identical after a restart");
	}

	/**
	 * A proof that does not verify against the public key in the same request
	 * registers nothing. Without this, the row would record a key whose holder
	 * never demonstrated possession — and every later device login is checked
	 * against that stored key.
	 */
	@Test
	void registrationWithAProofSignedByADifferentKeyIsRefused() throws Exception {
		DeviceKey claimed = DeviceKey.generate("cred-a");
		DeviceKey actual = DeviceKey.generate("cred-a");

		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken(DELEGATE_NAME));
		io.grpc.Context previous = ctx.attach();
		ProtoException ex;
		try {
			ex = assertThrows(ProtoException.class,
					() -> svc.createPersonalPrincipal(CALLER,
							Kernel.CreatePersonalPrincipalRequest.newBuilder()
									.setProofToken(actual.proof())
									.setPublicKey(claimed.publicJwk)
									.build()));
		} finally {
			ctx.detach(previous);
		}

		assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode());
		assertEquals(0, principalMap.proto().getPersonalPrincipalsCount());
	}

	/**
	 * One key, one person. A synced key presented from a second device must not
	 * become a second principal: the credential id is the only handle the device
	 * mint has, so two rows carrying it would make which person a proof resolves
	 * to depend on map iteration order.
	 */
	@Test
	void registeringAnAlreadyRegisteredCredentialIdDoesNotCreateASecondPrincipal() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-synced");
		String first = register(key, "iPhone", true);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> register(key, "iPad", true));

		assertEquals(ProtoException.ALREADY_EXISTS, ex.getCode());
		assertEquals(1, principalMap.proto().getPersonalPrincipalsCount());
		assertEquals(first, principalMap.proto().getPersonalPrincipals(0).getPrincipalId());
	}

	// ------------------------------------------------------------------
	// Registration is broker-only (the closed kernel route)
	// ------------------------------------------------------------------

	/**
	 * No bearer token at all — what a client reaching kernel directly would have,
	 * now that the RPC's NoAuth gateway proxy route is gone. Refused before the
	 * request body is looked at, and nothing is written.
	 *
	 * <p>The proof in this request is perfectly valid, which is the point: the
	 * body proof was never the caller check, and a caller with no S2S identity
	 * fails closed rather than falling through to it.
	 */
	@Test
	void registrationWithNoCallerTokenIsRefusedAndWritesNothing() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-direct");

		ProtoException ex = assertThrows(ProtoException.class,
				() -> svc.createPersonalPrincipal(CALLER,
						Kernel.CreatePersonalPrincipalRequest.newBuilder()
								.setProofToken(key.proof())
								.setPublicKey(key.publicJwk)
								.build()));

		assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode());
		assertEquals(0, principalMap.proto().getPersonalPrincipalsCount());
	}

	/**
	 * An authenticated S2S caller that is a real delegate but brokers IdP logins
	 * only — oauth. Being a delegate is not the check; carrying
	 * AUTH_BROKER_KIND_DEVICE is.
	 */
	@Test
	void registrationByADelegateWithoutTheDeviceBrokerKindIsRefused() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-via-oauth");

		ProtoException ex = assertThrows(ProtoException.class,
				() -> registerAs(IDP_DELEGATE_NAME, key, "iPhone", true));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals(0, principalMap.proto().getPersonalPrincipalsCount());
	}

	/**
	 * Fail-closed on the default. A delegate with no auth_broker_kinds at all —
	 * which is every delegate that has not been migrated — brokers nothing.
	 */
	@Test
	void registrationByADelegateWithNoAuthBrokerKindsIsRefused() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-via-plain");

		ProtoException ex = assertThrows(ProtoException.class,
				() -> registerAs(PLAIN_DELEGATE_NAME, key, "iPhone", true));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals(0, principalMap.proto().getPersonalPrincipalsCount());
	}

	/**
	 * A cluster-signed S2S token that names no delegate at all. The signature
	 * verifies, so this separates "authenticated" from "authorized": passing the
	 * token check is not passing the delegate check.
	 */
	@Test
	void registrationByAnAuthenticatedNonDelegateIsRefused() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-via-stranger");

		ProtoException ex = assertThrows(ProtoException.class,
				() -> registerAs(STRANGER_NAME, key, "iPhone", true));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals(0, principalMap.proto().getPersonalPrincipalsCount());
	}

	/**
	 * The accepted caller: a delegate carrying AUTH_BROKER_KIND_DEVICE — the
	 * personalauth broker's configured shape. Asserted as its own test rather
	 * than left implicit in the registration tests above, so that a change which
	 * denies every caller cannot pass by making all the refusals true.
	 */
	@Test
	void registrationByADeviceBrokerDelegateSucceeds() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-via-personalauth");

		String principalId = registerAs(DELEGATE_NAME, key, "iPhone", true);

		assertNotNull(principalId);
		assertEquals(1, principalMap.proto().getPersonalPrincipalsCount());
		assertEquals("cred-via-personalauth",
				principalMap.getPersonalPrincipals(principalId).getCredentials(0).getCredentialId());
	}

	// ------------------------------------------------------------------
	// AUTH_BROKER_KIND_DEVICE mint
	// ------------------------------------------------------------------

	/**
	 * The whole point: a fresh proof from a registered key mints that person's
	 * own token, and its namespace is exactly {@code /people/<pid>} — not the
	 * tenant OPA named, not the cluster root.
	 */
	@Test
	void deviceProofMintsAPersonalTokenNamespacedToThatPrincipal() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-iphone");
		String principalId = register(key, "iPhone", true);

		Tokenrequest.TokenMintResponse resp = mintWithDeviceProof(key, "");

		String expectedNamespace = "/people/" + principalId;
		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		TokenWrapper access = TokenWrapper.parse(resp.getAccessToken().getBase64());
		assertEquals(expectedNamespace, refresh.getNamespace());
		assertEquals(expectedNamespace, access.getNamespace());
		assertNotEquals(OPA_NAMESPACE, refresh.getNamespace(),
				"the device arm must not take its namespace from OPA");
		assertEquals(Spiffe.userSpiffeId(TRUST_DOMAIN, expectedNamespace, principalId),
				refresh.getSubject());
	}

	/**
	 * The provenance half of the device arm: the minted token records WHICH
	 * broker brokered the login, so a device login stays distinguishable from an
	 * IdP login for the life of the token. That value is the calling Delegate's
	 * bare NAME — not a SPIFFE id, not the issuer — because that is what the
	 * mint stamps, and personalauth.proto documents it in exactly that shape.
	 */
	@Test
	void theMintedTokenRecordsTheBrokeringDelegateAsAzp() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-azp");
		register(key, "iPhone", true);

		Tokenrequest.TokenMintResponse resp = mintWithDeviceProof(key, "");

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(DELEGATE_NAME, refresh.getAzp());
	}

	/**
	 * A revoked credential must not verify. The mutation half is in the same
	 * test on purpose: the identical call succeeds once the revocation mark is
	 * cleared, so the refusal is the revocation check and not some unrelated
	 * precondition of the fixture.
	 */
	@Test
	void aRevokedCredentialCannotMintUntilItIsUnrevoked() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-lost-phone");
		String principalId = register(key, "iPhone", false);
		setRevokedAt(principalId, 1_700_000_000_000L);

		ProtoException ex = assertThrows(ProtoException.class, () -> mintWithDeviceProof(key, ""));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());

		setRevokedAt(principalId, 0);
		assertEquals("/people/" + principalId,
				TokenWrapper.parse(mintWithDeviceProof(key, "").getRefreshToken().getBase64())
						.getNamespace());
	}

	/**
	 * Cross-principal isolation, which is the security property of the whole
	 * arm. The broker relays A's proof but names B in {@code subject} — the one
	 * field it controls. The mint must follow the key, not the field: resolve A,
	 * mint for A. If the resolution ever consults {@code request.subject}, this
	 * comes back as B's namespace and subject.
	 */
	@Test
	void aProofFromOnePrincipalCannotMintForAnother() throws Exception {
		DeviceKey aliceKey = DeviceKey.generate("cred-alice");
		DeviceKey bobKey = DeviceKey.generate("cred-bob");
		String alice = register(aliceKey, "alice phone", true);
		String bob = register(bobKey, "bob phone", true);

		String bobSubject = Spiffe.userSpiffeId(TRUST_DOMAIN, "/people/" + bob, bob);
		Tokenrequest.TokenMintResponse resp = mintWithDeviceProof(aliceKey, bobSubject);

		TokenWrapper minted = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals("/people/" + alice, minted.getNamespace());
		assertEquals(Spiffe.userSpiffeId(TRUST_DOMAIN, "/people/" + alice, alice), minted.getSubject());
		assertNotEquals(bobSubject, minted.getSubject());
	}

	/**
	 * An unregistered key is refused, and refused with the same message a
	 * revoked or badly-signed one gets. The message is asserted verbatim
	 * alongside the revoked case above so the refusals cannot drift apart into
	 * an oracle for which credentials exist.
	 */
	@Test
	void anUnknownCredentialIsRefusedIndistinguishablyFromARevokedOne() throws Exception {
		DeviceKey registered = DeviceKey.generate("cred-known");
		String principalId = register(registered, "iPhone", true);
		DeviceKey stranger = DeviceKey.generate("cred-unknown");

		ProtoException unknown = assertThrows(ProtoException.class,
				() -> mintWithDeviceProof(stranger, ""));

		setRevokedAt(principalId, 1_700_000_000_000L);
		ProtoException revoked = assertThrows(ProtoException.class,
				() -> mintWithDeviceProof(registered, ""));

		assertEquals(ProtoException.PERMISSION_DENIED, unknown.getCode());
		assertEquals(revoked.getCode(), unknown.getCode());
		assertEquals(revoked.getMessage(), unknown.getMessage());
	}

	// ------------------------------------------------------------------
	// Fixture
	// ------------------------------------------------------------------

	/** Registration as the DEVICE broker — the only caller kernel accepts. */
	private String register(DeviceKey key, String label, boolean platformSynced) throws Exception {
		return registerAs(DELEGATE_NAME, key, label, platformSynced);
	}

	/** Registration authenticated as the named delegate's S2S token. */
	private String registerAs(String delegateName, DeviceKey key, String label, boolean platformSynced)
			throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken(delegateName));
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.createPersonalPrincipal(CALLER, Kernel.CreatePersonalPrincipalRequest.newBuilder()
					.setProofToken(key.proof())
					.setPublicKey(key.publicJwk)
					.setLabel(label)
					.setPlatformSynced(platformSynced)
					.build()).getPrincipalId();
		} finally {
			ctx.detach(previous);
		}
	}

	private void setRevokedAt(String principalId, long revokedAtMs) throws Exception {
		Kernel.PersonalPrincipal row = principalMap.getPersonalPrincipals(principalId);
		Kernel.PersonalPrincipal.Builder b = row.toBuilder();
		b.getCredentialsBuilder(0).setRevokedAtMs(revokedAtMs);
		principalMap.putPersonalPrincipals(principalId, b.build());
	}

	/** A MintUserToken call authenticated as the device broker, carrying a fresh device proof. */
	private Tokenrequest.TokenMintResponse mintWithDeviceProof(DeviceKey key, String subject)
			throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken());
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintUserToken(CALLER, Tokenrequest.MintUserTokenRequest.newBuilder()
					.setSubject(subject)
					.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)
					.setProofToken(key.proof())
					.build());
		} finally {
			ctx.detach(previous);
		}
	}

	/** The broker's own S2S token, which is what authenticates a MintUserToken call. */
	private String delegateToken() {
		return delegateToken(DELEGATE_NAME);
	}

	/** A cluster-signed S2S token naming the given service — a delegate or not. */
	private String delegateToken(String serviceName) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", serviceName);
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		return t.getBase64();
	}

	/**
	 * One device key: the Ed25519 pair a phone holds, the public half as the JWK
	 * kernel stores, and a freshly-signed proof JWT whose {@code kid} is the
	 * credential id. Built the same way {@link KeyRotator} builds kernel's own
	 * signing keys, because the proof has to verify through the same
	 * {@code ImmutableJwk} path.
	 */
	private static final class DeviceKey {
		private final String credentialId;
		private final PrivateKey privateKey;
		private final JwkOuterClass.Jwk publicJwk;

		private DeviceKey(String credentialId, PrivateKey privateKey, JwkOuterClass.Jwk publicJwk) {
			this.credentialId = credentialId;
			this.privateKey = privateKey;
			this.publicJwk = publicJwk;
		}

		static DeviceKey generate(String credentialId) throws Exception {
			KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
			// Ed25519 X.509 encoding: the last 32 bytes are the raw public key.
			byte[] x509Encoded = pair.getPublic().getEncoded();
			byte[] rawPub = new byte[32];
			System.arraycopy(x509Encoded, x509Encoded.length - 32, rawPub, 0, 32);
			JwkOuterClass.Jwk jwk = JwkOuterClass.Jwk.newBuilder()
					.setKid(credentialId)
					.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
					.setAlg("EdDSA")
					.setCrv("Ed25519")
					.setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG)
					.setX(B64.encodeToString(rawPub))
					.setCreated(Instant.now().getEpochSecond())
					.build();
			return new DeviceKey(credentialId, pair.getPrivate(), jwk);
		}

		/**
		 * A fresh possession proof: a plain EdDSA JWT whose {@code kid} is the
		 * credential id.
		 *
		 * <p>Assembled by hand rather than through {@code TokenWrapper.create()},
		 * and that is the point twice over. A device is an iOS/Android app, not a
		 * kernel node, so the proof kernel has to accept is whatever a normal JWT
		 * library emits. And kernel's own TokenWrapper cannot produce this token at
		 * all: {@code sign()} refuses a token with no namespace claim, which a
		 * first-launch device does not have and never will — the proof asserts
		 * possession of a key, not membership of a namespace.
		 */
		String proof() throws Exception {
			long now = Instant.now().getEpochSecond();
			String header = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"" + credentialId + "\"}";
			String payload = "{\"iss\":\"" + credentialId + "\",\"sub\":\"" + credentialId
					+ "\",\"aud\":\"kernel\",\"iat\":" + now + ",\"exp\":" + (now + 60)
					+ ",\"jti\":\"" + UUID.randomUUID() + "\"}";
			String signingInput = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8))
					+ "." + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
			Signature signer = Signature.getInstance("Ed25519");
			signer.initSign(privateKey);
			signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
			return signingInput + "." + B64.encodeToString(signer.sign());
		}
	}

	/**
	 * Answers a TENANT namespace for every evaluation, on purpose: the device arm
	 * must ignore it. Entitlements still come from here — OPA remains the sole
	 * entitlement authority; it just does not name the subtree.
	 */
	private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		FakeOpaEvalGrpcClient() {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
		}

		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setNamespace(OPA_NAMESPACE)
					.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder()
							.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
							.build())
					.build();
		}

		private static final Channel UNUSABLE_CHANNEL = new Channel() {
			@Override
			public <ReqT, RespT> ClientCall<ReqT, RespT> newCall(
					MethodDescriptor<ReqT, RespT> methodDescriptor, CallOptions callOptions) {
				throw new UnsupportedOperationException("fake channel must never be used");
			}

			@Override
			public String authority() {
				throw new UnsupportedOperationException("fake channel must never be used");
			}
		};
	}
}
