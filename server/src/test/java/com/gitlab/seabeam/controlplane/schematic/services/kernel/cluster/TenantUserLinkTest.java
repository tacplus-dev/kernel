// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
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
 * Tenant-user ↔ tenant-user links: proving one, and what a linked user's token
 * then carries.
 *
 * <p>The decision doc's §2 in one class, because the two halves are one fact —
 * a link that is not visible at the next mint has not done anything.
 *
 * <p>The fake OPA answers {@code /tenants/drpepper} for every evaluation, which
 * is how the ordinary-tenant side of a link gets its namespace. The people side
 * never reaches OPA: if it ever did, these tests would see {@code drpepper}
 * where they assert {@code /tenants/people}.
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
				new FakeOpaEvalGrpcClient(),
				null,            // proxyPolicyOpaClient
				new ConfigMap(new InMemoryManager()),
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
	}

	// ------------------------------------------------------------------
	// Proving a link
	// ------------------------------------------------------------------

	/**
	 * The slice in one test: two IdP logins presented together, carrying the one
	 * nonce the client generated for both, link a tenant user to a person.
	 *
	 * <p>Both directions are written, because the mint reads the registry by the
	 * caller's own key — a link recorded on one side only would be invisible to
	 * the other's token.
	 */
	@Test
	void twoLoginsSharingANonceCreateALinkInBothDirections() throws Exception {
		Kernel.CreateTenantUserLinkResponse resp = link(NONCE, NONCE);

		String tenantKey = TENANT_NAMESPACE + "|" + TENANT_SUBJECT;
		String personKey = PeopleTenant.NAMESPACE + "|" + personSubject();
		assertEquals(tenantKey, resp.getAUserKey());
		assertEquals(personKey, resp.getBUserKey());
		assertTrue(resp.getCreatedAtMs() > 0);

		Kernel.TenantUserLinks fromTenant = principalMap.getTenantUserLinks(tenantKey);
		assertEquals(1, fromTenant.getLinksCount());
		assertEquals(PeopleTenant.NAMESPACE, fromTenant.getLinks(0).getPeerNamespace());
		assertEquals(personSubject(), fromTenant.getLinks(0).getPeerSubject());

		Kernel.TenantUserLinks fromPerson = principalMap.getTenantUserLinks(personKey);
		assertEquals(1, fromPerson.getLinksCount());
		assertEquals(TENANT_NAMESPACE, fromPerson.getLinks(0).getPeerNamespace());
		assertEquals(TENANT_SUBJECT, fromPerson.getLinks(0).getPeerSubject());
		assertEquals(resp.getCreatedAtMs(), fromPerson.getLinks(0).getCreatedAtMs(),
				"the two halves of one link must not disagree about when it was made");

		// The people side is a login, so it creates the person if nobody has seen
		// them before — "only an IdP creates a person" holds, this IS an IdP login.
		assertEquals(1, principalMap.proto().getPeopleCount());
		assertEquals(APPLE_SUB, person().getLinks(0).getProviderSubject());
	}

	/**
	 * The nonce IS the proof. Two tokens that do not share one were not obtained
	 * together, so one of them could be a replay of a credential stolen from
	 * somebody else — which is exactly the account takeover a link would grant.
	 */
	@Test
	void aLinkWithMismatchedNoncesIsRefused() {
		ProtoException ex = assertThrows(ProtoException.class,
				() -> link(NONCE, "a-different-nonce"));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertLinkRegistryEmpty();
	}

	/** No nonce at all is the same replay hole, unbound rather than mismatched. */
	@Test
	void aLinkWithNoNonceIsRefused() {
		assertEquals(ProtoException.UNAUTHENTICATED,
				assertThrows(ProtoException.class, () -> link(null, NONCE)).getCode());
		assertEquals(ProtoException.UNAUTHENTICATED,
				assertThrows(ProtoException.class, () -> link(NONCE, null)).getCode());
		assertLinkRegistryEmpty();
	}

	/**
	 * A people side is attested by whichever IdP broker verified the login. The
	 * fleet runs ONE oauth instance, rooted at /system, so a /system broker links
	 * exactly as a people-rooted one does (identity decision record 2026-10-25).
	 */
	@Test
	void aBrokerOutsideThePeopleTenantAttestsAPeopleSideToo() throws Exception {
		Kernel.CreateTenantUserLinkResponse resp = linkCall(request(NONCE, NONCE), "");

		assertEquals(PeopleTenant.NAMESPACE + "|" + personSubject(), resp.getBUserKey());
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/** Re-proving an existing link is the same fact, not a second edge. */
	@Test
	void relinkingTheSameTwoUsersIsIdempotent() throws Exception {
		Kernel.CreateTenantUserLinkResponse first = link(NONCE, NONCE);
		Kernel.CreateTenantUserLinkResponse again = link("a-fresh-nonce", "a-fresh-nonce");

		assertEquals(first.getCreatedAtMs(), again.getCreatedAtMs());
		assertEquals(1, principalMap.getTenantUserLinks(first.getAUserKey()).getLinksCount());
		assertEquals(1, principalMap.getTenantUserLinks(first.getBUserKey()).getLinksCount());
	}

	/**
	 * A link joins two tenants. Both sides landing in one is either a bug in the
	 * caller or an attempt to make a user their own peer, and the `linked` claim
	 * that would result names the namespace the token already carries.
	 */
	@Test
	void bothSidesInOneTenantIsRefused() {
		Kernel.CreateTenantUserLinkRequest request = Kernel.CreateTenantUserLinkRequest.newBuilder()
				.setA(side(idpClaims(TENANT_ISSUER, "jody", NONCE), TENANT_SUBJECT))
				.setB(side(idpClaims(TENANT_ISSUER, "someone-else", NONCE), "other@drpepper.example"))
				.build();

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(request, PeopleTenant.NAMESPACE));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
		assertLinkRegistryEmpty();
	}

	// ------------------------------------------------------------------
	// The `linked` claim at mint
	// ------------------------------------------------------------------

	/**
	 * What the link is FOR: after it, either side's token carries the other's
	 * namespace as a `linked` claim, so the generated namespace backstop accepts
	 * a row in the peer's subtree.
	 *
	 * <p>NAMESPACE-shaped, not a user path: tacplus's backstop compares the claim
	 * against {@code (spec.store_namespace)}, which holds a namespace, so
	 * {@code /users/<xid>} would never compare equal and the linked
	 * caller's read would never be accepted (tacplus, 2026-09-21 13:48 MDT).
	 */
	@Test
	void eitherSidesMintCarriesTheOthersNamespaceAsALinkedClaim() throws Exception {
		link(NONCE, NONCE);

		TokenWrapper tenantToken = TokenWrapper.parse(
				tenantMint().getRefreshToken().getBase64());
		assertEquals(TENANT_NAMESPACE, tenantToken.getNamespace());
		assertEquals(List.of(PeopleTenant.NAMESPACE), tenantToken.getLinked());

		TokenWrapper personToken = TokenWrapper.parse(
				peopleMint().getRefreshToken().getBase64());
		assertEquals(PeopleTenant.NAMESPACE, personToken.getNamespace());
		assertEquals(List.of(TENANT_NAMESPACE), personToken.getLinked());

		// The access token is cloned from the refresh token, so the claim reaches
		// the token services actually present.
		assertEquals(List.of(PeopleTenant.NAMESPACE),
				TokenWrapper.parse(tenantMint().getAccessToken().getBase64()).getLinked());
	}

	/** An unlinked user's token says nothing — the claim is absent, not empty. */
	@Test
	void anUnlinkedUsersMintCarriesNoLinkedClaim() throws Exception {
		TokenWrapper tenantToken = TokenWrapper.parse(
				tenantMint().getRefreshToken().getBase64());

		assertTrue(tenantToken.getLinked().isEmpty());
		assertFalse(tenantToken.getBase64().isEmpty());
		assertTrue(TokenWrapper.parse(peopleMint().getRefreshToken().getBase64())
				.getLinked().isEmpty());
	}

	/**
	 * A link is proved once, by two live logins sharing a nonce, and nothing
	 * kernel holds can re-derive it. A snapshot that dropped it would silently
	 * unlink every user, and the only symptom would be a `linked` claim that
	 * stopped appearing. The real snapshot and the real boot-time restore.
	 */
	@Test
	void aLinkSurvivesARestart(@TempDir Path dir) throws Exception {
		Kernel.CreateTenantUserLinkResponse resp = link(NONCE, NONCE);
		Kernel.TenantUserLinks live = principalMap.getTenantUserLinks(resp.getAUserKey());

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
		PrincipalMap afterRestart = new PrincipalMap(new InMemoryManager());
		ClusterServer.restoreTenantUserLinks(persistence.load(), afterRestart);

		assertEquals(live, afterRestart.getTenantUserLinks(resp.getAUserKey()));
		assertEquals(2, persistence.load().getTenantUserLinksCount(),
				"both directions are persisted, or one side's mint would stop seeing the link");
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

	private void assertLinkRegistryEmpty() {
		try {
			assertEquals(0, principalMap.proto().getTenantUserLinksCount());
		} catch (ProtoException e) {
			throw new RuntimeException(e);
		}
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
				: Spiffe.namespaceSpiffeId(TRUST_DOMAIN, brokerNamespace)
						+ "/" + Spiffe.SERVICES_SEGMENT + "/" + BROKER_NAME;
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

	/** Returns a canned EntitlementEvalResult; the channel throws if ever used. */
	private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		FakeOpaEvalGrpcClient() {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
		}

		/** Routes drpepper's own IdP into drpepper; a people-provider login routes nowhere. */
		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
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
