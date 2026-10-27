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
import com.github.tacplusdev.kernel.model.types.generated.services.Services;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
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
import org.junit.jupiter.api.function.Executable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DeleteTenant is complete for what kernel owns (kernel#19, decision record
 * tenant-deletion-2026-10-27): after it, no path mints a new token into the
 * tenant, every person's membership of it is gone while the people stay, and
 * nothing of the tenant is left in kernel state but its tombstoned tid.
 *
 * <p>One fleet: a person who signed in through acme's routing (so is a member of
 * acme and people), acme's own {@code docmanager} instance on a Kubernetes
 * service account, a grant held by that instance, and a second tenant, beta,
 * that the deletion must not touch.
 */
class TenantDeletionTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String BROKER_NAME = "oauth";
	private static final String SERVICE_NAME = "docmanager";
	private static final String ACME_NS = "/tenants/acme";
	private static final String BETA_NS = "/tenants/beta";
	private static final String ACME_K8S_NS = "tac-dev-acme0001";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";
	private static final String GOOGLE_SUB = "110169484474386276334";
	/** An issuer no people provider owns: an ordinary tenant login. */
	private static final String TENANT_ISSUER = "https://login.acme.example/oidc";
	private static final String GRANT_ID = "grant-acme";
	private static final String SYSTEM_GRANT_ID = "grant-system";
	private static final Caller CALLER = new Caller("", "test-req");

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private final List<Kernel.Grant> grants = new CopyOnWriteArrayList<>();
	/** What OPA names as the tenant a login (or a grant's replayed claims) routes to. */
	private String opaNamespace = ACME_NS;
	private KeyRotator keyRotator;
	private ConfigMap configMap;
	private PrincipalMap principalMap;
	private WorkloadMap workloadMap;
	private IdentityServiceImpl svc;
	private TenantAdminServiceImpl admin;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(SERVICE_NAME)
				.setTenantNamespace(ACME_NS)
				.addKubernetesServiceAccounts(Kernel.KubernetesServiceAccountMatcher.newBuilder()
						.setKubernetesNamespace(ACME_K8S_NS)
						.setKubernetesServiceAccount(SERVICE_NAME))
				.addAuthorizedServices(Services.ServiceName.SERVICE_NAME_OPA)
				.build());
		grants.add(grant(GRANT_ID, ACME_NS));
		grants.add(grant(SYSTEM_GRANT_ID, ""));
		delegates.add(Kernel.Delegate.newBuilder().setName(SERVICE_NAME).build());

		configMap = new ConfigMap(new InMemoryManager());
		principalMap = new PrincipalMap(new InMemoryManager());
		workloadMap = new WorkloadMap(new InMemoryManager());
		PeopleTenant.seed(configMap, List.of());
		svc = new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				() -> grants,
				updated -> grants.replaceAll(g -> g.getId().equals(updated.getId()) ? updated : g),
				null,            // serviceEntitlements
				null,            // signingCa (X509Mint is refused before it is needed)
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				new FakeOpaEvalGrpcClient(),
				null,            // proxyPolicyOpaClient
				configMap,
				workloadMap,
				principalMap,
				null,            // writeIdentitySnapshot
				FakeKubernetesTokenVerifier.returning(FakeKubernetesTokenVerifier.identity(
						ACME_K8S_NS, SERVICE_NAME, List.of(KERNEL_AUDIENCE))),
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
		admin = new TenantAdminServiceImpl(configMap, () -> TRUST_DOMAIN, () -> { },
				svc::purgeDeletedTenant);
		admin.createTenant(CALLER, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ACME_NS).build());
		admin.createTenant(CALLER, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(BETA_NS).build());
	}

	/**
	 * Every path that minted into acme before the deletion is refused after it:
	 * the session-credential exchange, a new login routed there, a tenant IdP
	 * login, a refresh token from that login, the tenant service's Kubernetes
	 * mint, an access token it already held, both grants, and a certificate. The people tenant
	 * and beta still mint.
	 */
	@Test
	void afterDeleteTenantEveryMintPathIntoItIsRefused() throws Exception {
		Tokenrequest.TokenMintResponse login = personLogin();
		TokenWrapper credential = TokenWrapper.parse(login.getRefreshToken().getBase64());
		assertEquals(ACME_NS, TokenWrapper.parse(login.getAccessToken().getBase64()).getNamespace());
		assertEquals(ACME_NS, accessToken(exchange(credential, ACME_NS)).getNamespace());
		Tokenrequest.TokenMintResponse service = svc.mintServiceToken(CALLER,
				Tokenrequest.MintServiceTokenRequest.newBuilder().setKubernetesToken(fakeJwt()).build());
		TokenWrapper serviceAccess = accessToken(service);
		assertEquals(ACME_NS, serviceAccess.getNamespace());
		assertEquals(ACME_NS, accessToken(serviceTokenFor(serviceAccess)).getNamespace());
		assertEquals(ACME_NS, TokenWrapper.parse(delegated(ACME_NS, GRANT_ID).getToken().getBase64())
				.getNamespace());
		assertEquals(ACME_NS, TokenWrapper.parse(delegated("", SYSTEM_GRANT_ID).getToken().getBase64())
				.getNamespace());
		Tokenrequest.TokenMintResponse tenantLogin = tenantIdpLogin();
		assertEquals(ACME_NS, accessToken(tenantLogin).getNamespace());
		String userRefresh = tenantLogin.getRefreshToken().getBase64();
		assertEquals(ACME_NS, accessToken(mintFrom(userRefresh)).getNamespace());

		deleteAcme();

		// The membership is gone, so the exchange gives its one refusal shape for
		// every miss: it is no oracle for which tenants a person belongs to.
		assertRefused(() -> exchange(credential, ACME_NS));
		assertDeleted(this::personLogin);
		assertDeleted(this::tenantIdpLogin);
		assertDeleted(() -> svc.mintServiceToken(CALLER,
				Tokenrequest.MintServiceTokenRequest.newBuilder().setKubernetesToken(fakeJwt()).build()));
		assertDeleted(() -> mintFrom(userRefresh));
		assertDeleted(() -> serviceTokenFor(serviceAccess));
		assertDeleted(() -> delegated("", SYSTEM_GRANT_ID));
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> delegated(ACME_NS, GRANT_ID)).getCode(), "the tenant's own grant is revoked");
		assertDeleted(() -> withBearer(serviceAccess.getBase64(), () -> svc.mintX509Cert(CALLER,
				Tokenrequest.X509MintRequest.newBuilder().setAud("kernel").build())));

		// Already-issued tokens are left to expire; the person's other tenants mint on.
		assertEquals(PeopleTenant.NAMESPACE, accessToken(exchange(credential, "")).getNamespace());
		opaNamespace = BETA_NS;
		assertEquals(BETA_NS, accessToken(tenantIdpLogin()).getNamespace());
	}

	/**
	 * Memberships go, people stay: the person who belonged to acme is still
	 * there, under the same XID, with their links and their other memberships,
	 * and a login of theirs routed into acme writes no membership back.
	 */
	@Test
	void membershipsAreRemovedAndThePeopleKept() throws Exception {
		personLogin();
		opaNamespace = BETA_NS;
		personLogin();
		Kernel.Person before = googlePerson();
		assertEquals(List.of(PeopleTenant.NAMESPACE, ACME_NS, BETA_NS), membershipsOf(before));

		deleteAcme();

		Kernel.Person after = googlePerson();
		assertEquals(before.getXid(), after.getXid());
		assertEquals(before.getLinksList(), after.getLinksList());
		assertEquals(0, after.getDeletedAtMs());
		assertEquals(List.of(PeopleTenant.NAMESPACE, BETA_NS), membershipsOf(after));

		opaNamespace = ACME_NS;
		assertDeleted(this::personLogin);
		assertEquals(List.of(PeopleTenant.NAMESPACE, BETA_NS), membershipsOf(googlePerson()),
				"a login routed into the deleted tenant writes nothing");
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/**
	 * Nothing tenant-scoped is left: a walk of PrincipalState and ConfigState
	 * finds acme nowhere but in its tombstoned tid, the one row kept so the tid
	 * is never reused. Beta's records are untouched.
	 */
	@Test
	void noTenantScopedStateIsLeft() throws Exception {
		personLogin();
		String acmeService = Spiffe.namespaceSpiffeId(TRUST_DOMAIN, ACME_NS)
				+ "/" + Spiffe.SERVICES_SEGMENT + "/" + SERVICE_NAME;
		workloadMap.putLocalities(acmeService, Kernel.WorkloadLocality.newBuilder()
				.setSpiffeId(acmeService).setLocalityToken("locality").build());
		workloadMap.putRevocations(acmeService + "/pigeon", Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(acmeService + "/pigeon").setRevokedBy(acmeService).build());
		String acmeTid = configMap.getTenants(ACME_NS).getTid();
		Kernel.ConfigState betaBefore = only(configMap.proto(), BETA_NS);

		deleteAcme();

		Kernel.ConfigState config = configMap.proto();
		Kernel.ConfigState.Builder withoutTombstone = config.toBuilder().clearTenantIds();
		for (Kernel.TenantIdRow row : config.getTenantIdsList()) {
			if (row.getTid().equals(acmeTid)) {
				assertEquals(ACME_NS, row.getTenantNamespace());
				assertNotEquals(0, row.getTombstonedAtMs(), "the tid is tombstoned, never freed");
			} else {
				withoutTombstone.addTenantIds(row);
			}
		}
		assertFalse(withoutTombstone.build().toString().contains(ACME_NS),
				"ConfigState still names the deleted tenant: " + withoutTombstone.build());
		assertFalse(principalMap.proto().toString().contains(ACME_NS),
				"PrincipalState still names the deleted tenant: " + principalMap.proto());
		assertEquals(betaBefore, only(configMap.proto(), BETA_NS));

		assertEquals(0, workloadMap.proto().getLocalitiesCount(), "the tenant's localities are deleted");
		assertEquals(1, workloadMap.proto().getRevocationsCount(),
				"a revocation is a deny list entry, and is kept");
		assertNotEquals(0, grant(GRANT_ID).getRevokedAtMs(), "the tenant's grant is revoked");
		assertEquals(0, grant(SYSTEM_GRANT_ID).getRevokedAtMs(), "a /system delegate's grant is not");
	}

	/** A withheld offline token for the tenant is dropped, so no code can redeem it. */
	@Test
	void aWithheldOfflineTokenForTheTenantIsDropped() throws Exception {
		TokenWrapper acme = TokenWrapper.create().setSubject("acme-user");
		acme.setNamespace(ACME_NS);
		TokenWrapper beta = TokenWrapper.create().setSubject("beta-user");
		beta.setNamespace(BETA_NS);
		long expires = Instant.now().toEpochMilli() + 60_000;
		svc.withheldOfflineTokens.put("acme-code", new IdentityServiceImpl.WithheldOfflineToken(acme, "a", expires));
		svc.withheldOfflineTokens.put("beta-code", new IdentityServiceImpl.WithheldOfflineToken(beta, "b", expires));

		deleteAcme();

		assertEquals(java.util.Set.of("beta-code"), svc.withheldOfflineTokens.keySet());
	}

	/**
	 * The refusal is the deleted tenant's, not the name's: a tenant created
	 * again under the same name is a new tenant with a new tid, and mints.
	 */
	@Test
	void aTenantCreatedAgainUnderTheSameNameMints() throws Exception {
		String oldTid = configMap.getTenants(ACME_NS).getTid();
		deleteAcme();
		assertDeleted(this::tenantIdpLogin);

		Kernel.Tenant again = admin.createTenant(CALLER,
				Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ACME_NS).build());

		assertNotEquals(oldTid, again.getTid());
		assertEquals(ACME_NS, accessToken(tenantIdpLogin()).getNamespace());
	}

	/**
	 * A namespace a deployment names in its delegates without a kernel tenant
	 * record is not a deleted tenant: only a tombstone makes one.
	 */
	@Test
	void aTenantKernelHasNoRecordOfStillMints() throws Exception {
		opaNamespace = "/tenants/unrecorded";
		assertEquals("/tenants/unrecorded", accessToken(tenantIdpLogin()).getNamespace());
		opaNamespace = ACME_NS + "/default";
		assertEquals(ACME_NS + "/default", accessToken(tenantIdpLogin()).getNamespace());
		deleteAcme();
		assertDeleted(this::tenantIdpLogin);
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	private void deleteAcme() throws Exception {
		admin.deleteTenant(CALLER, Kernel.DeleteTenantRequest.newBuilder().setTenantNamespace(ACME_NS).build());
		assertTrue(configMap.getTenants(ACME_NS).getName().isEmpty());
	}

	/** Refused because the tenant was deleted, and saying so. */
	private static void assertDeleted(Executable mint) {
		Exception refused = assertRefused(mint);
		assertTrue(refused.getMessage().contains("tenant " + ACME_NS + " was deleted"), refused.getMessage());
	}

	private static Exception assertRefused(Executable mint) {
		Exception refused = assertThrows(Exception.class, mint);
		int code = refused instanceof ProtoException p ? p.getCode()
				: ((IdentityServiceImpl.StatusException) refused).toGrpcStatus().getCode().value();
		assertEquals(ProtoException.PERMISSION_DENIED, code, refused.getMessage());
		return refused;
	}

	/** A Google login; OPA routes it into {@link #opaNamespace}. */
	private Tokenrequest.TokenMintResponse personLogin() throws Exception {
		return userMint(GOOGLE_ISSUER, GOOGLE_SUB);
	}

	/** A login through a tenant's own IdP; OPA names the tenant. */
	private Tokenrequest.TokenMintResponse tenantIdpLogin() throws Exception {
		return userMint(TENANT_ISSUER, "alice");
	}

	private Tokenrequest.TokenMintResponse userMint(String issuer, String subject) throws Exception {
		Tokenrequest.MintUserTokenRequest request = Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject(subject)
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(Struct.newBuilder()
						.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
						.putFields("origin_sub", Value.newBuilder().setStringValue(subject).build())
						.build())
				.build();
		return withBearer(serviceToken("", BROKER_NAME), () -> svc.mintUserToken(CALLER, request));
	}

	private Tokenrequest.TokenMintResponse exchange(TokenWrapper credential, String tenant) throws Exception {
		return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(credential.getBase64())
				.setTenantNamespace(tenant)
				.build());
	}

	private Tokenrequest.TokenMintResponse mintFrom(String inputToken) throws Exception {
		return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder().setInputToken(inputToken).build());
	}

	/** An access token exchanged for a service token to opa. */
	private Tokenrequest.TokenMintResponse serviceTokenFor(TokenWrapper access) throws Exception {
		return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(access.getBase64()).setAud("opa").build());
	}

	private Tokenrequest.MintDelegatedTokenResponse delegated(String delegateNamespace, String grantId)
			throws Exception {
		return withBearer(serviceToken(delegateNamespace, SERVICE_NAME), () -> svc.mintDelegatedToken(CALLER,
				Tokenrequest.MintDelegatedTokenRequest.newBuilder().setGrantId(grantId).build()));
	}

	private Kernel.Person googlePerson() {
		return principalMap.getPeople(principalMap.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey("google", GOOGLE_SUB)).getXid());
	}

	private Kernel.Grant grant(String id) {
		return grants.stream().filter(g -> g.getId().equals(id)).findFirst().orElseThrow();
	}

	private static List<String> membershipsOf(Kernel.Person person) {
		return person.getMembershipsList().stream().map(Kernel.PersonMembership::getTenantNamespace).toList();
	}

	/** The rows of {@code state} that name {@code tenantNamespace}. */
	private static Kernel.ConfigState only(Kernel.ConfigState state, String tenantNamespace) {
		Kernel.ConfigState.Builder b = Kernel.ConfigState.newBuilder();
		state.getTenantsList().stream().filter(t -> tenantNamespace.endsWith("/" + t.getName()))
				.forEach(b::addTenants);
		state.getTenantConfigsList().stream().filter(e -> e.getTenantName().startsWith(tenantNamespace))
				.forEach(b::addTenantConfigs);
		state.getProjectConfigsList().stream().filter(e -> e.getProjectNamespace().startsWith(tenantNamespace))
				.forEach(b::addProjectConfigs);
		state.getTenantIdsList().stream().filter(r -> r.getTenantNamespace().equals(tenantNamespace))
				.forEach(b::addTenantIds);
		return b.build();
	}

	private static Kernel.Grant grant(String id, String delegateNamespace) {
		return Kernel.Grant.newBuilder()
				.setId(id)
				.setDelegateName(SERVICE_NAME)
				.setDelegateNamespace(delegateNamespace)
				.setSubject("alice@acme.example")
				.setClaims(Struct.newBuilder()
						.putFields("sub", Value.newBuilder().setStringValue("alice@acme.example").build()))
				.setAuthorizedScope(Entitlements.TokenEntitlements.newBuilder()
						.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.setCreatedAtMs(Instant.now().toEpochMilli())
				.build();
	}

	private static TokenWrapper accessToken(Tokenrequest.TokenMintResponse resp) {
		return TokenWrapper.parse(resp.getAccessToken().getBase64());
	}

	@FunctionalInterface
	private interface Call<T> {
		T call() throws Exception;
	}

	private static <T> T withBearer(String token, Call<T> call) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current().withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, token);
		io.grpc.Context previous = ctx.attach();
		try {
			return call.call();
		} finally {
			ctx.detach(previous);
		}
	}

	/** A kernel-signed S2S token for the delegate {@code name} rooted at {@code namespace} ("" = /system). */
	private String serviceToken(String namespace, String name) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = namespace.isEmpty()
				? Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", name)
				: Spiffe.namespaceSpiffeId(TRUST_DOMAIN, namespace) + "/" + Spiffe.SERVICES_SEGMENT + "/" + name;
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

	/** A projected service-account token's shape; the fake verifier accepts any. */
	private static String fakeJwt() {
		return "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
	}

	/** Answers {@link #opaNamespace}; the channel throws if ever used. */
	private class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		FakeOpaEvalGrpcClient() {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
		}

		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setNamespace(opaNamespace)
					.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder()
							.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
							.build())
					.build();
		}
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
