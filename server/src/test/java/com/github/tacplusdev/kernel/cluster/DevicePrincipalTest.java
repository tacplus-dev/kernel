// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.github.tacplusdev.kernel.model.types.generated.entitlements.Entitlements;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Device tokens on the XID (kernel#18): a device is a credential of a person
 * ({@code Person.devices}), and {@code Mint.MintUserToken} with
 * {@code AUTH_BROKER_KIND_DEVICE} turns a proof signed by that key into the
 * PERSON's token — {@code sub = spiffe://<td>/users/<xid>}, namespace
 * {@code /tenants/people} — with the device named by the {@code device} claim.
 * No {@code /people/<pid>} principal is minted (tacplus#131 retired the root).
 *
 * <p>The devices are enrolled through the identity graph's own write
 * ({@link KernelIdentityGraph#addDevice}); the ceremony that leads to that write
 * — a passkey beside the person's login — is {@code DeviceWebauthnLinkTest}'s.
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
	private static final String OPA_NAMESPACE = "/tenants/acme";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private KeyRotator keyRotator;
	private PrincipalMap principalMap;
	private KernelIdentityGraph graph;
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
		// shape. It may not relay a device proof: being a delegate is not the check.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(IDP_DELEGATE_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		// A delegate with no auth_broker_kinds at all — the default. Fail-closed.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(PLAIN_DELEGATE_NAME)
				.build());
		principalMap = new PrincipalMap(new InMemoryManager());
		graph = new KernelIdentityGraph(principalMap, () -> { }, () -> false);
		svc = new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
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
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
	}

	// ------------------------------------------------------------------
	// AUTH_BROKER_KIND_DEVICE mint
	// ------------------------------------------------------------------

	/**
	 * The whole point: a fresh proof from an enrolled key mints the person's own
	 * token. Its subject is the XID, its namespace is the people tenant — not
	 * the tenant OPA named, not a {@code /people/<pid>} principal — and the
	 * {@code device} claim names the credential, on the refresh token and on the
	 * access token cloned from it.
	 */
	@Test
	void deviceProofMintsThePersonsTokenNamingTheDevice() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-iphone");
		String xid = enrol("google-sub-1", key);

		Tokenrequest.TokenMintResponse resp = mintWithDeviceProof(key, "");

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		TokenWrapper access = TokenWrapper.parse(resp.getAccessToken().getBase64());
		String person = SpiffeIds.userSubject(TRUST_DOMAIN, xid);
		assertEquals("spiffe://" + TRUST_DOMAIN + "/users/" + xid, person);
		for (TokenWrapper token : List.of(refresh, access)) {
			assertEquals(person, token.getSubject());
			assertEquals(PeopleTenant.NAMESPACE, token.getNamespace());
			assertEquals("cred-iphone", token.getCustomField(IdentityServiceImpl.CLAIM_DEVICE));
			assertFalse(token.getNamespace().startsWith("/people/"));
		}
		assertNotEquals(OPA_NAMESPACE, refresh.getNamespace(),
				"the device arm must not take its namespace from OPA");
	}

	/**
	 * Two devices of one person mint the same subject, told apart by the claim
	 * alone: a device is a credential of the XID, not a principal of its own.
	 */
	@Test
	void twoDevicesOfOnePersonAreThatPersonToldApartByTheDeviceClaim() throws Exception {
		DeviceKey phone = DeviceKey.generate("cred-phone");
		DeviceKey laptop = DeviceKey.generate("cred-laptop");
		String xid = enrol("google-sub-1", phone);
		graph.addDevice(xid, credential(laptop, "laptop"));

		TokenWrapper fromPhone = TokenWrapper.parse(mintWithDeviceProof(phone, "").getRefreshToken().getBase64());
		TokenWrapper fromLaptop = TokenWrapper.parse(mintWithDeviceProof(laptop, "").getRefreshToken().getBase64());

		assertEquals(fromPhone.getSubject(), fromLaptop.getSubject());
		assertEquals("cred-phone", fromPhone.getCustomField(IdentityServiceImpl.CLAIM_DEVICE));
		assertEquals("cred-laptop", fromLaptop.getCustomField(IdentityServiceImpl.CLAIM_DEVICE));
	}

	/**
	 * The provenance half of the device arm: the minted token records WHICH
	 * broker brokered the login, so a device login stays distinguishable from an
	 * IdP login for the life of the token. That value is the calling Delegate's
	 * bare NAME — not a SPIFFE id, not the issuer — because that is what the
	 * mint stamps.
	 */
	@Test
	void theMintedTokenRecordsTheBrokeringDelegateAsAzp() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-azp");
		enrol("google-sub-1", key);

		Tokenrequest.TokenMintResponse resp = mintWithDeviceProof(key, "");

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(DELEGATE_NAME, refresh.getAzp());
	}

	/**
	 * Only a device broker may relay a device proof. A real delegate brokering
	 * IdP logins only, and a delegate with no broker kinds at all, are refused
	 * with a proof that is perfectly valid.
	 */
	@Test
	void onlyADeviceBrokerMayRelayADeviceProof() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-via-oauth");
		enrol("google-sub-1", key);

		for (String delegate : List.of(IDP_DELEGATE_NAME, PLAIN_DELEGATE_NAME)) {
			ProtoException ex = assertThrows(ProtoException.class,
					() -> mintWithDeviceProofAs(delegate, key, ""));
			assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode(), delegate);
		}
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
		String xid = enrol("google-sub-1", key);
		graph.revokeDevice(xid, "cred-lost-phone");

		ProtoException ex = assertThrows(ProtoException.class, () -> mintWithDeviceProof(key, ""));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());

		setRevokedAt(xid, 0);
		assertEquals(SpiffeIds.userSubject(TRUST_DOMAIN, xid),
				TokenWrapper.parse(mintWithDeviceProof(key, "").getRefreshToken().getBase64())
						.getSubject());
	}

	/**
	 * Cross-person isolation, which is the security property of the whole arm.
	 * The broker relays A's proof but names B in {@code subject} — the one field
	 * it controls. The mint must follow the key, not the field: resolve A, mint
	 * for A. If the resolution ever consults {@code request.subject}, this comes
	 * back as B's subject.
	 */
	@Test
	void aProofFromOnePersonCannotMintForAnother() throws Exception {
		DeviceKey aliceKey = DeviceKey.generate("cred-alice");
		DeviceKey bobKey = DeviceKey.generate("cred-bob");
		String alice = enrol("google-alice", aliceKey);
		String bob = enrol("google-bob", bobKey);

		String bobSubject = SpiffeIds.userSubject(TRUST_DOMAIN, bob);
		Tokenrequest.TokenMintResponse resp = mintWithDeviceProof(aliceKey, bobSubject);

		TokenWrapper minted = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(SpiffeIds.userSubject(TRUST_DOMAIN, alice), minted.getSubject());
		assertNotEquals(bobSubject, minted.getSubject());
	}

	/**
	 * An unenrolled key is refused, and refused with the same message a revoked
	 * one gets — and so is a device of a person who deleted their account. The
	 * messages are asserted verbatim so the refusals cannot drift apart into an
	 * oracle for which credentials exist.
	 */
	@Test
	void anUnknownCredentialIsRefusedIndistinguishablyFromARevokedOne() throws Exception {
		DeviceKey enrolled = DeviceKey.generate("cred-known");
		String xid = enrol("google-sub-1", enrolled);
		DeviceKey stranger = DeviceKey.generate("cred-unknown");
		DeviceKey deletedPersonsKey = DeviceKey.generate("cred-deleted");
		String deleted = enrol("google-sub-2", deletedPersonsKey);
		graph.deleteAccount(deleted);

		ProtoException unknown = assertThrows(ProtoException.class,
				() -> mintWithDeviceProof(stranger, ""));
		ProtoException gone = assertThrows(ProtoException.class,
				() -> mintWithDeviceProof(deletedPersonsKey, ""));
		graph.revokeDevice(xid, "cred-known");
		ProtoException revoked = assertThrows(ProtoException.class,
				() -> mintWithDeviceProof(enrolled, ""));

		assertEquals(ProtoException.PERMISSION_DENIED, unknown.getCode());
		for (ProtoException other : List.of(gone, revoked)) {
			assertEquals(unknown.getCode(), other.getCode());
			assertEquals(unknown.getMessage(), other.getMessage());
		}
	}

	/**
	 * A device token already out stops at its next exchange when its device
	 * does: the device revoked, the person signed out everywhere, the account
	 * deleted. Until then it exchanges like any refresh token — the control
	 * half, so the refusals are about the device and not the exchange.
	 */
	@Test
	void aDeviceTokenAlreadyOutStopsWhenItsDeviceDoes() throws Exception {
		DeviceKey revokedKey = DeviceKey.generate("cred-revoked");
		DeviceKey signedOutKey = DeviceKey.generate("cred-signed-out");
		DeviceKey deletedKey = DeviceKey.generate("cred-deleted");
		String revoked = enrol("google-revoked", revokedKey);
		String signedOut = enrol("google-signed-out", signedOutKey);
		String deleted = enrol("google-deleted", deletedKey);
		String revokedToken = mintWithDeviceProof(revokedKey, "").getRefreshToken().getBase64();
		String signedOutToken = mintWithDeviceProof(signedOutKey, "").getRefreshToken().getBase64();
		String deletedToken = mintWithDeviceProof(deletedKey, "").getRefreshToken().getBase64();
		for (String token : List.of(revokedToken, signedOutToken, deletedToken)) {
			assertTrue(exchange(token).hasAccessToken());
		}

		graph.revokeDevice(revoked, "cred-revoked");
		graph.bumpGeneration(signedOut);
		graph.deleteAccount(deleted);

		for (String token : List.of(revokedToken, signedOutToken, deletedToken)) {
			ProtoException ex = assertThrows(ProtoException.class, () -> exchange(token));
			assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		}
	}

	/**
	 * A device token is the people tenant's token and nothing more. The retired
	 * {@code /people/<pid>} principal could be exchanged into any tenant its
	 * memberships named; a device token naming a tenant is refused like every
	 * token that is not a session credential — a tenant needs a live proof from
	 * that tenant's IdP.
	 */
	@Test
	void aDeviceTokenCannotBeExchangedIntoATenant() throws Exception {
		DeviceKey key = DeviceKey.generate("cred-iphone");
		enrol("google-sub-1", key);
		Tokenrequest.TokenMintResponse device = mintWithDeviceProof(key, "");

		ProtoException ex = assertThrows(ProtoException.class,
				() -> svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(device.getRefreshToken().getBase64())
						.setTenantNamespace(OPA_NAMESPACE)
						.build()));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
		assertTrue(ex.getMessage().contains("tenant_namespace"), ex.getMessage());
	}

	/**
	 * {@code device} is a claim only kernel sets. An ordinary tenant IdP that
	 * puts one in its id_token has it stripped before OPA and before the token,
	 * so no relayed login can pass for a device token.
	 */
	@Test
	void aRelayedDeviceClaimNeverReachesTheToken() throws Exception {
		Struct claims = Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue("https://idp.acme.example").build())
				.putFields("origin_sub", Value.newBuilder().setStringValue("jody").build())
				.putFields(IdentityServiceImpl.CLAIM_DEVICE, Value.newBuilder().setStringValue("cred-forged").build())
				.build();
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken(IDP_DELEGATE_NAME));
		io.grpc.Context previous = ctx.attach();
		Tokenrequest.TokenMintResponse resp;
		try {
			resp = svc.mintUserToken(CALLER, Tokenrequest.MintUserTokenRequest.newBuilder()
					.setSubject("spiffe://" + TRUST_DOMAIN + "/tenants/acme/users/jody")
					.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
					.setClaims(claims)
					.build());
		} finally {
			ctx.detach(previous);
		}

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(OPA_NAMESPACE, refresh.getNamespace());
		assertNull(refresh.getCustomField(IdentityServiceImpl.CLAIM_DEVICE));
	}

	// ------------------------------------------------------------------
	// Fixture
	// ------------------------------------------------------------------

	/** The ordinary refresh exchange: a token in, an access token out. */
	private Tokenrequest.TokenMintResponse exchange(String refreshToken) throws Exception {
		return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(refreshToken)
				.build());
	}

	/** A person created by a Google login, with {@code key} enrolled as their device; returns the XID. */
	private String enrol(String googleSub, DeviceKey key) throws Exception {
		String xid = graph.resolveOrCreate("google", googleSub).person().getXid();
		graph.addDevice(xid, credential(key, "iPhone"));
		return xid;
	}

	private static Kernel.PersonalCredential credential(DeviceKey key, String label) {
		return Kernel.PersonalCredential.newBuilder()
				.setCredentialId(key.credentialId)
				.setPublicKey(key.publicJwk)
				.setLabel(label)
				.setCreatedAtMs(System.currentTimeMillis())
				.build();
	}

	private void setRevokedAt(String xid, long revokedAtMs) throws Exception {
		Kernel.Person.Builder b = principalMap.getPeople(xid).toBuilder();
		b.getDevicesBuilder(0).setRevokedAtMs(revokedAtMs);
		principalMap.putPeople(xid, b.build());
	}

	/** A MintUserToken call authenticated as the device broker, carrying a fresh device proof. */
	private Tokenrequest.TokenMintResponse mintWithDeviceProof(DeviceKey key, String subject)
			throws Exception {
		return mintWithDeviceProofAs(DELEGATE_NAME, key, subject);
	}

	private Tokenrequest.TokenMintResponse mintWithDeviceProofAs(String delegateName, DeviceKey key,
			String subject) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken(delegateName));
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
		 * device's proof does not have — the proof asserts possession of a key,
		 * not membership of a namespace.
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
