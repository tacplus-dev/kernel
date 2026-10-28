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
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
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
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tenant-user ↔ tenant-user links are retired (kernel#4), and with them the
 * {@code linked} claim they fed.
 *
 * <p>Who the caller is comes from the person (the XID), which tenant a call is
 * for from the request, and whether it is allowed is policy at the target. A
 * token that widens its own namespaces is the thing removed: no token kernel
 * mints carries {@code linked}, whatever an old snapshot still holds, and
 * {@code CreateTenantUserLink} only enrols a device (kernel#18).
 *
 * <p>The fake OPA answers {@code /tenants/drpepper} for drpepper's own IdP,
 * which is how an ordinary tenant login gets its namespace.
 */
class TenantUserLinkTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String BROKER_NAME = "oauth";
	private static final String TENANT_NAMESPACE = "/tenants/drpepper";
	private static final String TENANT_ISSUER = "https://login.drpepper.example/oidc";
	private static final String TENANT_SUBJECT = "jody@drpepper.example";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String APPLE_SUB = "001672.9c4f1a33be7d4e1fb0c2.0913";
	private static final String NONCE = "3f1c9a2e-7b44-4a1d-9f0e-2c6b8d5a1e77";
	private static final Caller CALLER = new Caller("", "test-req");


	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	/** Every claim set the fake OPA was handed, in order. */
	private final List<Struct> opaClaims = new CopyOnWriteArrayList<>();
	private KeyRotator keyRotator;
	private PrincipalMap principalMap;
	private final ConfigMap configMap = new ConfigMap(new InMemoryManager());
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
		// A people-tenant-rooted IdP broker and a /system one. Either may attest a
		// people side: the fleet's one oauth instance brokers every login.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.setTenantNamespace(PeopleTenant.NAMESPACE)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		principalMap = new PrincipalMap(new InMemoryManager());
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
				new FakeOpaEvalGrpcClient(opaClaims),
				null,            // proxyPolicyOpaClient
				configMap,
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
	}

	// ------------------------------------------------------------------
	// Linking two tenant users is retired
	// ------------------------------------------------------------------

	/**
	 * Two IdP logins sharing a nonce used to link a tenant user to a person. A
	 * link is no longer anything kernel records: the request is refused before
	 * either side is resolved, so it does not even create the person.
	 */
	@Test
	void twoLoginsNoLongerLinkAndWriteNothing() {
		ProtoException ex = assertThrows(ProtoException.class, () -> link(NONCE, NONCE));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
		assertTrue(ex.getMessage().contains("device"), ex.getMessage());
		assertEquals(0, peopleCount(), "a refused link resolves neither side");
		assertTrue(opaClaims.isEmpty(), "a refused link reaches no policy");
	}

	// ------------------------------------------------------------------
	// No minted token carries `linked`
	// ------------------------------------------------------------------

	/**
	 * The acceptance case: a person with a device and with tenant links, as a
	 * snapshot written before kernel#4 holds them (both directions of a link to
	 * a drpepper user, and the person's enrolled device). Booting that snapshot
	 * is not a failure, and no token minted afterwards — the drpepper user's
	 * refresh and access tokens, the person's session credential and their
	 * people access token — carries {@code linked}.
	 */
	@Test
	void noMintedTokenCarriesLinkedForAPersonWithDeviceAndTenantLinks() throws Exception {
		peopleMint();
		String personKey = PeopleTenant.NAMESPACE + "|" + personSubject();
		String tenantKey = TENANT_NAMESPACE + "|" + TENANT_SUBJECT;
		Kernel.KernelDiskState old = Kernel.KernelDiskState.newBuilder()
				.addPeople(person().toBuilder().addDevices(device("cred-1")))
				.addAllIdentityLinks(principalMap.proto().getIdentityLinksList())
				.addTenantUserLinks(linkRow(personKey, TENANT_NAMESPACE, TENANT_SUBJECT))
				.addTenantUserLinks(linkRow(tenantKey, PeopleTenant.NAMESPACE, personSubject()))
				.build();

		boot(old);

		assertEquals(1, person().getDevicesCount(), "the person keeps their device");
		Tokenrequest.TokenMintResponse tenant = tenantMint();
		Tokenrequest.TokenMintResponse people = peopleMint();
		for (Tokenrequest.TokenMintResponse resp : List.of(tenant, people)) {
			for (String jwt : List.of(resp.getRefreshToken().getBase64(), resp.getAccessToken().getBase64())) {
				TokenWrapper token = TokenWrapper.parse(jwt);
				assertTrue(token.getLinked().isEmpty(), token.getNamespace() + " token carries linked");
				assertFalse(token.getClaims().containsKey(TokenWrapper.CLAIM_LINKED));
			}
		}
		assertEquals(TENANT_NAMESPACE, TokenWrapper.parse(tenant.getRefreshToken().getBase64()).getNamespace());
		assertEquals(PeopleTenant.NAMESPACE, TokenWrapper.parse(people.getAccessToken().getBase64()).getNamespace());
	}

	/**
	 * Nor can a broker put one there: a relayed claim set carrying
	 * {@code linked} is the IdP's word, and the claim is kernel's name.
	 */
	@Test
	void aRelayedLinkedClaimNeverReachesAToken() throws Exception {
		Struct claims = idpClaims(TENANT_ISSUER, "jody", null).toBuilder()
				.putFields(TokenWrapper.CLAIM_LINKED, Value.newBuilder().setStringValue("/tenants/victim").build())
				.build();
		Tokenrequest.TokenMintResponse resp = mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject(TENANT_SUBJECT)
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(claims)
				.build(), "");

		for (String jwt : List.of(resp.getRefreshToken().getBase64(), resp.getAccessToken().getBase64())) {
			assertTrue(TokenWrapper.parse(jwt).getLinked().isEmpty());
		}
	}

	/**
	 * The rows are ignored, not carried: the next snapshot written holds no
	 * tenant-user links, and booting it is the same person with the same device.
	 */
	@Test
	void theNextSnapshotDropsTheOldLinkRows(@TempDir Path dir) throws Exception {
		peopleMint();
		Kernel.KernelDiskState old = Kernel.KernelDiskState.newBuilder()
				.addPeople(person().toBuilder().addDevices(device("cred-1")))
				.addAllIdentityLinks(principalMap.proto().getIdentityLinksList())
				.addTenantUserLinks(linkRow(PeopleTenant.NAMESPACE + "|" + personSubject(),
						TENANT_NAMESPACE, TENANT_SUBJECT))
				.build();
		boot(old);

		IdentitySnapshot persistence = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, null,
				() -> {
					try {
						return principalMap.proto();
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				});
		persistence.save();
		Kernel.KernelDiskState written = persistence.load();

		assertEquals(0, written.getTenantUserLinksCount());
		assertEquals(List.of(person()), written.getPeopleList());
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	/** The person the Apple login above resolved to, found through the link index. */
	private Kernel.Person person() {
		return principalMap.getPeople(principalMap.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey("apple", APPLE_SUB)).getXid());
	}

	private String personSubject() {
		return SpiffeIds.userSubject(TRUST_DOMAIN, person().getXid());
	}

	private int peopleCount() {
		try {
			return principalMap.proto().getPeopleCount();
		} catch (ProtoException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Boots {@code snapshot} into this test's registry through the real
	 * boot-time restores, in the order the {@code ClusterServer} constructor
	 * calls them.
	 */
	private void boot(Kernel.KernelDiskState snapshot) {
		ClusterServer.restorePeople(snapshot, principalMap);
		ClusterServer.migratePersonalPrincipals(snapshot, principalMap);
	}

	/** One direction of a pre-kernel#4 link, as CreateTenantUserLink wrote it. */
	private static Kernel.TenantUserLinks linkRow(String userKey, String peerNamespace, String peerSubject) {
		return Kernel.TenantUserLinks.newBuilder()
				.setUserKey(userKey)
				.addLinks(Kernel.TenantUserLink.newBuilder()
						.setPeerNamespace(peerNamespace)
						.setPeerSubject(peerSubject)
						.setCreatedAtMs(1_700_000_000_000L))
				.build();
	}

	private static Kernel.PersonalCredential device(String credentialId) {
		return Kernel.PersonalCredential.newBuilder()
				.setCredentialId(credentialId)
				.setPublicKey(JwkOuterClass.Jwk.newBuilder()
						.setKid(credentialId)
						.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
						.setAlg("EdDSA")
						.setCreated(1_770_000_000L))
				.setLabel("iPhone")
				.setCreatedAtMs(1_700_000_000_000L)
				.build();
	}

	/** The claim shape oauth relays: the IdP's own iss/sub/nonce, verified. */
	private static Struct idpClaims(String issuer, String sub, String nonce) {
		Struct.Builder b = Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(sub).build());
		if (nonce != null) {
			b.putFields("origin_nonce", Value.newBuilder().setStringValue(nonce).build());
		}
		return b.build();
	}

	private static Kernel.TenantUserLinkSide side(Struct claims, String subject) {
		return Kernel.TenantUserLinkSide.newBuilder()
				.setClaims(claims)
				.setSubject(subject)
				.build();
	}

	/**
	 * A drpepper login (side a) and an Apple login (side b), each with the nonce
	 * given. Side b's subject is set and deliberately ignored: the people side
	 * derives everything from the verified claims.
	 */
	private static Kernel.CreateTenantUserLinkRequest request(String nonceA, String nonceB) {
		return Kernel.CreateTenantUserLinkRequest.newBuilder()
				.setA(side(idpClaims(TENANT_ISSUER, "jody", nonceA), TENANT_SUBJECT))
				.setB(side(idpClaims(APPLE_ISSUER, APPLE_SUB, nonceB), "whatever-the-broker-says"))
				.build();
	}

	private Kernel.CreateTenantUserLinkResponse link(String nonceA, String nonceB) throws Exception {
		return linkCall(request(nonceA, nonceB), PeopleTenant.NAMESPACE);
	}

	/** Calls the RPC with the named broker's own S2S token in the context. */
	private Kernel.CreateTenantUserLinkResponse linkCall(
			Kernel.CreateTenantUserLinkRequest request, String brokerNamespace) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, brokerToken(brokerNamespace));
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.createTenantUserLink(CALLER, request);
		} finally {
			ctx.detach(previous);
		}
	}

	/** An ordinary drpepper login, minted the ordinary way (namespace from OPA). */
	private Tokenrequest.TokenMintResponse tenantMint() throws Exception {
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject(TENANT_SUBJECT)
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(TENANT_ISSUER, "jody", null))
				.build(), "");
	}

	/** The same person's own login, minted through the people arm. */
	private Tokenrequest.TokenMintResponse peopleMint() throws Exception {
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(APPLE_ISSUER, APPLE_SUB, null))
				.build(), PeopleTenant.NAMESPACE);
	}

	private Tokenrequest.TokenMintResponse mint(
			Tokenrequest.MintUserTokenRequest request, String brokerNamespace) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, brokerToken(brokerNamespace));
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintUserToken(CALLER, request);
		} finally {
			ctx.detach(previous);
		}
	}

	/**
	 * The broker's own S2S token. Its SPIFFE subject carries the namespace the
	 * delegate is rooted at, which is what selects the people arm and what gates
	 * attesting a people link side.
	 */
	private String brokerToken(String brokerNamespace) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = brokerNamespace.isEmpty()
				? Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", BROKER_NAME)
				: TenantServiceSubjects.of(configMap, TRUST_DOMAIN, brokerNamespace, BROKER_NAME);
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

	/** Returns a canned EntitlementEvalResult and records its claims; the channel throws if ever used. */
	private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		private final List<Struct> claims;

		FakeOpaEvalGrpcClient(List<Struct> claims) {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
			this.claims = claims;
		}

		/** Routes drpepper's own IdP into drpepper; a people-provider login routes nowhere. */
		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			claims.add(request.getClaims());
			Value issuer = request.getClaims().getFieldsMap().get("origin_iss");
			boolean tenantLogin = issuer != null && TENANT_ISSUER.equals(issuer.getStringValue());
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setNamespace(tenantLogin ? TENANT_NAMESPACE : "")
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
