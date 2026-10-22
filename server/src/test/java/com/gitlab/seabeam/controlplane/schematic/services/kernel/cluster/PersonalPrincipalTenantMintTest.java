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
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The personal-principal arm of {@code Mint.MintToken} (design-session §2.2):
 * one personal principal, N per-tenant tokens, and the {@code TenantMembership}
 * record is the only thing that authorizes the exchange.
 *
 * <p>Every test here is a security test, and the two tenants are the reason.
 * {@link #TENANT_A} is the tenant the fixture person belongs to; {@link #TENANT_B}
 * is a real, populated tenant they do NOT belong to. A mint arm that authorized
 * on "the field parsed" rather than "a live membership matched" passes a
 * single-tenant suite and fails this one.
 *
 * <p>The fake OPA below answers {@link #OPA_NAMESPACE} — a third tenant, named by
 * neither the request nor any membership — for every evaluation. Each namespace
 * assertion is therefore also an assertion that kernel stamps the membership's
 * namespace itself and never asks OPA for it (§0.2: OPA sees no IdP claims at
 * all on this path, so {@code requireNamespaceFromOpa} could only ever refuse).
 */
class PersonalPrincipalTenantMintTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String TENANT_A = "/tenants/acme";
	private static final String TENANT_B = "/tenants/globex";
	private static final String OPA_NAMESPACE = "/tenants/opa-should-not-decide";
	private static final String OPA_GRANT = "KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG";
	private static final String PRINCIPAL_ID = "p-alice";
	private static final String OTHER_PRINCIPAL_ID = "p-bob";
	private static final Caller CALLER = new Caller("", "test-req");

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private final AtomicReference<Userentitlements.EntitlementEvalInput> lastOpaInput =
			new AtomicReference<>();
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
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				"schematic-kernel",
				null);           // webauthnRelyingParty (fail closed)
	}

	@AfterEach
	void tearDown() {
		keyRotator.stop();
	}

	// ------------------------------------------------------------------
	// (a) happy path
	// ------------------------------------------------------------------

	/**
	 * The whole point: a live membership of {@link #TENANT_A} turns the person's
	 * personal token into a {@code /tenants/acme} access token plus one service
	 * token per requested audience — with the person's own {@code sub} and
	 * {@code azp} carried through, so the tenant sees WHICH PERSON is acting.
	 */
	@Test
	void aLiveMembershipMintsATenantTokenStampedWithTheMembershipsNamespace() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false));

		Tokenrequest.TokenMintResponse resp = mint(personToken(PRINCIPAL_ID), TENANT_A, "scotty", "docmanager");

		TokenWrapper access = TokenWrapper.parse(resp.getAccessToken().getBase64());
		assertEquals(TENANT_A, access.getNamespace());
		assertNotEquals(OPA_NAMESPACE, access.getNamespace(),
				"the tenant namespace must come from the membership, never from OPA");
		assertEquals(personSubject(PRINCIPAL_ID), access.getSubject(),
				"sub is the personal principal's, preserved from the presented token");
		assertEquals("personal-runtime", access.getAzp(),
				"azp is preserved from the presented token, as every other MintToken exchange does");
		assertEquals("user", access.getSubType());

		// A personal token is the only long-lived credential; the tenant token is
		// re-minted from it, so no refresh/offline companion comes back.
		assertEquals("", resp.getRefreshToken().getBase64());

		assertEquals(2, resp.getServiceTokensCount());
		for (int i = 0; i < resp.getServiceTokensCount(); i++) {
			TokenWrapper st = TokenWrapper.parse(resp.getServiceTokens(i).getBase64());
			assertEquals(TENANT_A, st.getNamespace());
			assertEquals(personSubject(PRINCIPAL_ID), st.getSubject());
		}
		assertEquals("scotty", TokenWrapper.parse(resp.getServiceTokens(0).getBase64()).getAudience());
		assertEquals("docmanager", TokenWrapper.parse(resp.getServiceTokens(1).getBase64()).getAudience());
	}

	/**
	 * Entitlements come from OPA through the same pair every other mint uses, on
	 * claims kernel SYNTHESIZED from the membership. Both halves are asserted: the
	 * grant OPA returned is on the token, and the claims OPA was asked about are
	 * the membership's — not anything the caller sent.
	 */
	@Test
	void entitlementsComeFromOpaOnClaimsSynthesizedFromTheMembership() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, true));

		Tokenrequest.TokenMintResponse resp = mint(personToken(PRINCIPAL_ID), TENANT_A);


		TokenWrapper access = TokenWrapper.parse(resp.getAccessToken().getBase64());
		assertTrue(access.getCustomField("service_entitlements").contains(OPA_GRANT),
				"the token must carry the entitlements OPA resolved");

		var claims = lastOpaInput.get().getClaims().getFieldsMap();
		assertEquals(PRINCIPAL_ID, claims.get("principal_id").getStringValue());
		assertEquals(TENANT_A, claims.get("tenant_namespace").getStringValue());
		assertEquals("MEMBERSHIP_PROOF_KIND_TENANT_IDP", claims.get("proof_kind").getStringValue());
		assertTrue(claims.get("customer").getBoolValue());
	}

	/**
	 * Step 4, fail closed. The tenant's customer-facing service list comes from
	 * per-tenant login configuration (§6 item 4) and does not exist yet, so the
	 * intersection for a {@code customer} membership is empty: design-session §4
	 * rules that such a membership mints NO service tokens — an empty list, not
	 * an error. The access token still comes back, so the person is inside the
	 * tenant; they just cannot reach a service yet. The paired worker membership
	 * asking for the same audience is what makes this the designation and not a
	 * broken fixture.
	 */
	@Test
	void aCustomerMembershipMintsNoServiceTokensWhileTheListDoesNotExist() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, true));
		Tokenrequest.TokenMintResponse customer = mint(personToken(PRINCIPAL_ID), TENANT_A, "scotty");

		assertEquals(TENANT_A,
				TokenWrapper.parse(customer.getAccessToken().getBase64()).getNamespace());
		assertEquals(0, customer.getServiceTokensCount(),
				"a customer membership must mint no service tokens until the list exists");

		seed(PRINCIPAL_ID, membership(TENANT_A, false));
		assertEquals(1, mint(personToken(PRINCIPAL_ID), TENANT_A, "scotty").getServiceTokensCount());
	}

	/**
	 * This exchange requests services through {@code service_auds} (§2.1). A
	 * single {@code aud} is refused rather than dropped: dropping it would hand
	 * back an access token where the caller asked for a service token. Same
	 * refusal the offline-token arm gives, for the same reason.
	 */
	@Test
	void theTenantExchangeRequestsServicesViaServiceAudsNotAud() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false));

		ProtoException ex = assertThrows(ProtoException.class,
				() -> svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(personToken(PRINCIPAL_ID))
						.setTenantNamespace(TENANT_A)
						.setAud("scotty")
						.build()));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
		assertTrue(ex.getMessage().contains("service_auds"), ex.getMessage());
	}

	// ------------------------------------------------------------------
	// (b) (c) no usable membership
	// ------------------------------------------------------------------

	/**
	 * The two-tenant negative. Alice belongs to {@link #TENANT_A}; Bob belongs to
	 * {@link #TENANT_B}. Alice asking for {@link #TENANT_B} is refused — and
	 * refused identically to asking for a tenant nobody is a member of, so the
	 * mint cannot be used to enumerate which tenants exist or who belongs to them.
	 */
	@Test
	void aTenantThePersonIsNotAMemberOfIsRefusedWithoutRevealingItExists() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false));
		seed(OTHER_PRINCIPAL_ID, membership(TENANT_B, false));

		ProtoException populated = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), TENANT_B));
		ProtoException nonexistent = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), "/tenants/no-such-tenant"));
		ProtoException unknownPerson = assertThrows(ProtoException.class,
				() -> mint(personToken("p-nobody"), TENANT_A));

		assertEquals(ProtoException.PERMISSION_DENIED, populated.getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, nonexistent.getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, unknownPerson.getCode());
		assertEquals(unknownPerson.getCode(), populated.getCode());
		assertEquals("no usable membership of " + TENANT_A + " for this principal",
				unknownPerson.getMessage());
		assertEquals(populated.getMessage().replace(TENANT_B, TENANT_A),
				unknownPerson.getMessage(),
				"a membership miss and an unknown person must be indistinguishable");
	}

	/**
	 * A revoked membership is marked, not deleted (audit trail), so it is still
	 * found by the scan — the mark is what makes it unusable. The mutation half is
	 * in the same test on purpose: the identical call succeeds once the mark is
	 * cleared, so the refusal is the revocation check and not some unrelated
	 * precondition of the fixture.
	 */
	@Test
	void aRevokedMembershipCannotMintUntilTheMarkIsCleared() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false).toBuilder()
				.setRevokedAtMs(1_700_000_000_000L).build());

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), TENANT_A));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());

		seed(PRINCIPAL_ID, membership(TENANT_A, false));
		assertEquals(TENANT_A, TokenWrapper.parse(
				mint(personToken(PRINCIPAL_ID), TENANT_A).getAccessToken().getBase64()).getNamespace());
	}

	/**
	 * An expired membership is refused the same way, and with the same message: a
	 * departure that lapsed and a departure that was revoked are both "no usable
	 * membership", and a future expiry still mints.
	 */
	@Test
	void anExpiredMembershipIsRefusedIndistinguishablyFromARevokedOne() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false).toBuilder()
				.setExpiresAtMs(System.currentTimeMillis() - 1).build());
		ProtoException expired = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), TENANT_A));

		seed(PRINCIPAL_ID, membership(TENANT_A, false).toBuilder()
				.setRevokedAtMs(1_700_000_000_000L).build());
		ProtoException revoked = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), TENANT_A));

		assertEquals(ProtoException.PERMISSION_DENIED, expired.getCode());
		assertEquals(revoked.getCode(), expired.getCode());
		assertEquals(revoked.getMessage(), expired.getMessage());

		seed(PRINCIPAL_ID, membership(TENANT_A, false).toBuilder()
				.setExpiresAtMs(System.currentTimeMillis() + 600_000).build());
		assertEquals(TENANT_A, TokenWrapper.parse(
				mint(personToken(PRINCIPAL_ID), TENANT_A).getAccessToken().getBase64()).getNamespace());
	}

	/**
	 * A disabled person mints nothing, for any tenant, however live the membership
	 * row still looks. The disable mark is on the principal, and the membership
	 * scan is only reached through it.
	 */
	@Test
	void aDisabledPrincipalCannotMintForALiveMembership() throws Exception {
		principalMap.putPersonalPrincipals(PRINCIPAL_ID, Kernel.PersonalPrincipal.newBuilder()
				.setPrincipalId(PRINCIPAL_ID)
				.addMemberships(membership(TENANT_A, false))
				.setDisabledAtMs(1_700_000_000_000L)
				.build());

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), TENANT_A));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	// ------------------------------------------------------------------
	// (d) (e) (f) the selector's own rules
	// ------------------------------------------------------------------

	/**
	 * A personal token may be refreshed into a personal AT without naming a
	 * tenant — that keeps {@code /people/<pid>} — but it may not reach a SERVICE
	 * that way: a service token stamped {@code /people/<pid>} would arrive at a
	 * tenant service as an identity at-or-below no tenant at all.
	 */
	@Test
	void aPersonalTokenCannotMintAServiceTokenWithoutNamingATenant() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false));

		ProtoException viaServiceAuds = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), "", "scotty"));
		ProtoException viaAud = assertThrows(ProtoException.class,
				() -> svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(personToken(PRINCIPAL_ID))
						.setAud("scotty")
						.build()));

		assertEquals(ProtoException.INVALID_ARGUMENT, viaServiceAuds.getCode());
		assertEquals(ProtoException.INVALID_ARGUMENT, viaAud.getCode());

		// The refresh exception the rule is carved around still works, and still
		// keeps the personal namespace.
		TokenWrapper personalAt = TokenWrapper.parse(
				mint(personToken(PRINCIPAL_ID), "").getAccessToken().getBase64());
		assertEquals("/people/" + PRINCIPAL_ID, personalAt.getNamespace());
	}

	/**
	 * The single most important line in the item: a service or workload token may
	 * not name a tenant. Its tenant comes from its SPIFFE subject and from nothing
	 * else (DECISIONS.md item 2), so honouring the selector here — or ignoring it
	 * silently — would be a tenant escape.
	 */
	@Test
	void aServiceTokenMayNotNameATenant() {
		ProtoException ex = assertThrows(ProtoException.class,
				() -> mint(serviceToken(), TENANT_A));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
		assertTrue(ex.getMessage().contains("tenant_namespace"), ex.getMessage());
	}

	/**
	 * {@code /} is at-or-below every namespace in the fleet
	 * ({@code Spiffe.isAtOrBelow}), so a personal token exchanged for one would
	 * satisfy every tenant-targeted level-or-below check there is. Refused even
	 * though no membership could ever match it — the shape is rejected before the
	 * lookup, so this cannot come to depend on a record's contents.
	 */
	@Test
	void theAuthorizationTreeRootIsNotAMintableTenant() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false));

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mint(personToken(PRINCIPAL_ID), "/"));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
	}

	/**
	 * A tenant token is not itself personal, so it cannot be re-exchanged into a
	 * DIFFERENT tenant. Without this, one membership would buy every tenant: the
	 * minted token keeps the person's {@code sub}, and an arm that decided
	 * "personal" from the subject would take this second call.
	 */
	@Test
	void aMintedTenantTokenCannotBeExchangedIntoAnotherTenant() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false), membership(TENANT_B, false));
		String tenantAToken = mint(personToken(PRINCIPAL_ID), TENANT_A).getAccessToken().getBase64();

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mint(tenantAToken, TENANT_B));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
	}

	/**
	 * The tenant token is a user access token, so it lives
	 * {@code access_token_lifetime_seconds} (900 here), not the 1 h
	 * {@code default_token_expiry_seconds}.
	 */
	@Test
	void theTenantTokenLivesForTheAccessLifetimeNotTheDefault() throws Exception {
		seed(PRINCIPAL_ID, membership(TENANT_A, false));
		long now = Instant.now().getEpochSecond();

		long exp = TokenWrapper.parse(mint(personToken(PRINCIPAL_ID), TENANT_A)
				.getAccessToken().getBase64()).getExpiration();

		assertTrue(Math.abs(exp - (now + 900)) <= 5,
				"tenant token exp should be now + 900s, was now + " + (exp - now) + "s");
	}

	// ------------------------------------------------------------------
	// Fixture
	// ------------------------------------------------------------------

	private Tokenrequest.TokenMintResponse mint(String inputToken, String tenantNamespace,
			String... serviceAuds) throws Exception {
		Tokenrequest.TokenMintRequest.Builder req = Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(inputToken)
				.setTenantNamespace(tenantNamespace);
		for (String aud : serviceAuds) {
			req.addServiceAuds(aud);
		}
		return svc.mintToken(CALLER, req.build());
	}

	private static Kernel.TenantMembership membership(String tenantNamespace, boolean customer) {
		return Kernel.TenantMembership.newBuilder()
				.setTenantNamespace(tenantNamespace)
				.setProofKind(Kernel.MembershipProofKind.MEMBERSHIP_PROOF_KIND_TENANT_IDP)
				.setCustomer(customer)
				.setProofReference("idp-subject-" + tenantNamespace)
				.setCreatedAtMs(1_000)
				.build();
	}

	private void seed(String principalId, Kernel.TenantMembership... memberships) throws Exception {
		Kernel.PersonalPrincipal.Builder row = Kernel.PersonalPrincipal.newBuilder()
				.setPrincipalId(principalId)
				.setCreatedAtMs(1_000);
		for (Kernel.TenantMembership m : memberships) {
			row.addMemberships(m);
		}
		principalMap.putPersonalPrincipals(principalId, row.build());
	}

	private static String personSubject(String principalId) {
		return Spiffe.userSpiffeId(TRUST_DOMAIN, "/" + Spiffe.PEOPLE_SEGMENT + "/" + principalId,
				principalId);
	}

	/**
	 * The personal token the device holds: subject
	 * {@code spiffe://<td>/people/<pid>/users/<pid>}, namespace
	 * {@code /people/<pid>}, {@code sub_type=user} — exactly what the
	 * {@code AUTH_BROKER_KIND_DEVICE} mint arm produces.
	 */
	private String personToken(String principalId) {
		String namespace = "/" + Spiffe.PEOPLE_SEGMENT + "/" + principalId;
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(personSubject(principalId))
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("user");
		t.setAzp("personal-runtime");
		t.setNamespace(namespace);
		t.sign(signingKey);
		return t.getBase64();
	}

	/** A kernel-signed SERVICE token — a caller whose tenant is its SPIFFE subject. */
	private String serviceToken() {
		String subject = SpiffeIds.build(TRUST_DOMAIN, TENANT_A, "docmanager");
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setServiceName("docmanager");
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		return t.getBase64();
	}

	/**
	 * Answers a namespace nobody asked for, on purpose: this arm must ignore it.
	 * Entitlements still come from here — OPA remains the sole entitlement
	 * authority; it just does not name the subtree.
	 */
	private class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		FakeOpaEvalGrpcClient() {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
		}

		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			lastOpaInput.set(request);
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setNamespace(OPA_NAMESPACE)
					.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder()
							.addGrants(OPA_GRANT)
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
