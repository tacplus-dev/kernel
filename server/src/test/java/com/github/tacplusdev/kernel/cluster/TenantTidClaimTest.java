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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every token kernel signs into a tenant carries a {@code tid} claim: the tid
 * of the tenant at the top of its namespace, read from kernel's own tenant
 * record at mint (kernel#32; tacplus-dev/tacplus#284 option 1). A token whose
 * namespace is in no tenant carries none. Refresh and exchange re-derive it;
 * nothing a request carries can set it.
 *
 * <p>One fleet: a person who signs in through acme's routing, acme's own
 * {@code docmanager} instance on a Kubernetes service account and a workload
 * under it, a grant held by that instance, a {@code /system} service, and a
 * tenant seeded from the deployment's bootstrap config under a given tid.
 */
class TenantTidClaimTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String BROKER_NAME = "oauth";
	private static final String SERVICE_NAME = "docmanager";
	private static final String SYSTEM_SERVICE_NAME = "fleetwatch";
	private static final String ACME_NS = "/tenants/acme";
	private static final String BETA_NS = "/tenants/beta";
	private static final String GAMMA_NS = "/tenants/gamma";
	private static final String GAMMA_TID = "g4mm4000";
	private static final String ACME_K8S_NS = "tac-dev-acme0001";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";
	private static final String GOOGLE_SUB = "110169484474386276334";
	/** An issuer no people provider owns: an ordinary tenant login. */
	private static final String TENANT_ISSUER = "https://login.acme.example/oidc";
	private static final String GRANT_ID = "grant-acme";
	private static final String FORGED_TID = "zzzzzzzz";
	private static final Caller CALLER = new Caller("", "test-req");

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private final List<Kernel.Grant> grants = new CopyOnWriteArrayList<>();
	/** What OPA names as the tenant a login (or a grant's replayed claims) routes to. */
	private String opaNamespace = ACME_NS;
	private KeyRotator keyRotator;
	private ConfigMap configMap;
	private IdentityServiceImpl svc;
	private TenantAdminServiceImpl admin;
	private String acmeTid;

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
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(SYSTEM_SERVICE_NAME)
				.addAuthorizedServices(Services.ServiceName.SERVICE_NAME_OPA)
				.build());
		grants.add(Kernel.Grant.newBuilder()
				.setId(GRANT_ID)
				.setDelegateName(SERVICE_NAME)
				.setDelegateNamespace(ACME_NS)
				.setSubject("alice@acme.example")
				.setClaims(Struct.newBuilder()
						.putFields("sub", Value.newBuilder().setStringValue("alice@acme.example").build()))
				.setAuthorizedScope(Entitlements.TokenEntitlements.newBuilder()
						.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.setCreatedAtMs(Instant.now().toEpochMilli())
				.build());

		configMap = new ConfigMap(new InMemoryManager());
		PeopleTenant.seed(configMap, List.of());
		svc = new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				() -> grants,
				updated -> grants.replaceAll(g -> g.getId().equals(updated.getId()) ? updated : g),
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				new FakeOpaEvalGrpcClient(),
				null,            // proxyPolicyOpaClient
				configMap,
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				FakeKubernetesTokenVerifier.returning(FakeKubernetesTokenVerifier.identity(
						ACME_K8S_NS, SERVICE_NAME, List.of(KERNEL_AUDIENCE))),
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
		admin = new TenantAdminServiceImpl(configMap, () -> TRUST_DOMAIN, () -> { },
				svc::purgeDeletedTenant);
		admin.createTenant(CALLER, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ACME_NS).build());
		admin.createTenant(CALLER, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(BETA_NS).build());
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				Kernel.BootstrapTenant.newBuilder().setName("gamma").setTid(GAMMA_TID).build()));
		acmeTid = configMap.getTenants(ACME_NS).getTid();
		assertTrue(acmeTid.matches("^[a-z][0-9a-z]{7}$"), acmeTid);
	}

	// ------------------------------------------------------------------
	// Every token kind, for /tenants/<name> and for a namespace below it
	// ------------------------------------------------------------------

	/**
	 * A person's session credential is the people tenant's and carries its
	 * reserved tid; the access tokens exchanged from it carry the tid of the
	 * tenant each one is for.
	 */
	@Test
	void aPersonsCredentialAndAccessTokensCarryTheirTenantsTid() throws Exception {
		Tokenrequest.TokenMintResponse login = personLogin();
		TokenWrapper credential = refreshToken(login);

		assertEquals(PeopleTenant.NAMESPACE, credential.getNamespace());
		assertEquals(TenantIds.PEOPLE, credential.getTid());
		assertTid(acmeTid, accessToken(login), ACME_NS);
		assertTid(acmeTid, accessToken(exchange(credential, ACME_NS)), ACME_NS);
		assertTid(TenantIds.PEOPLE, accessToken(exchange(credential, "")), PeopleTenant.NAMESPACE);
	}

	/** A tenant IdP login's refresh and access tokens, and every refresh after it. */
	@Test
	void aUsersRefreshAndAccessTokensCarryTheTenantsTid() throws Exception {
		Tokenrequest.TokenMintResponse login = tenantIdpLogin();

		assertTid(acmeTid, refreshToken(login), ACME_NS);
		assertTid(acmeTid, accessToken(login), ACME_NS);
		Tokenrequest.TokenMintResponse refreshed = mintFrom(refreshToken(login).getBase64());
		assertTid(acmeTid, accessToken(refreshed), ACME_NS);
	}

	/** A namespace below the tenant (its project) names the tenant at the top. */
	@Test
	void aTokenBelowTheTenantCarriesTheTopTenantsTid() throws Exception {
		opaNamespace = ACME_NS + "/default";
		Tokenrequest.TokenMintResponse login = tenantIdpLogin();

		assertTid(acmeTid, refreshToken(login), ACME_NS + "/default");
		assertTid(acmeTid, accessToken(login), ACME_NS + "/default");
		assertTid(acmeTid, accessToken(mintFrom(refreshToken(login).getBase64())), ACME_NS + "/default");
	}

	/**
	 * A tenant-owned service's tokens: the Kubernetes mint's access token, the
	 * S2S token exchanged from it, and a workload minted under it, bootstrap,
	 * refresh and access alike.
	 */
	@Test
	void aTenantServicesAndItsWorkloadsTokensCarryTheTid() throws Exception {
		TokenWrapper serviceAccess = accessToken(kubernetesMint());
		assertEquals(SpiffeIds.build(TRUST_DOMAIN, SpiffeIds.tenantRoot(acmeTid), SERVICE_NAME),
				serviceAccess.getSubject());
		assertTid(acmeTid, serviceAccess, ACME_NS);
		assertTid(acmeTid, accessToken(serviceTokenFor(serviceAccess)), ACME_NS);

		Tokenrequest.WorkloadMintResponse minted = withBearer(serviceAccess.getBase64(),
				() -> svc.mintWorkload(CALLER,
						Tokenrequest.WorkloadMintRequest.newBuilder().setWorkloadName("pigeon").build()));
		TokenWrapper bootstrap = TokenWrapper.from(minted.getBootstrapToken());
		assertTid(acmeTid, bootstrap, ACME_NS);
		Tokenrequest.TokenMintResponse workload = mintFrom(bootstrap.getBase64());
		assertTid(acmeTid, refreshToken(workload), ACME_NS);
		assertTid(acmeTid, accessToken(workload), ACME_NS);
		assertTid(acmeTid, accessToken(mintFrom(refreshToken(workload).getBase64())), ACME_NS);
	}

	/** A token a tenant's service mints from a grant is the consenting user's, in the user's tenant. */
	@Test
	void aGrantMintedTokenCarriesTheUsersTenantsTid() throws Exception {
		TokenWrapper token = TokenWrapper.parse(delegated(ACME_NS, GRANT_ID).getToken().getBase64());

		assertTid(acmeTid, token, ACME_NS);
	}

	/** Two tenants, two tids: a token in beta never carries acme's. */
	@Test
	void eachTenantsTokensCarryItsOwnTid() throws Exception {
		String betaTid = configMap.getTenants(BETA_NS).getTid();
		assertNotEquals(acmeTid, betaTid);

		opaNamespace = BETA_NS;
		assertTid(betaTid, accessToken(tenantIdpLogin()), BETA_NS);
		opaNamespace = ACME_NS;
		assertTid(acmeTid, accessToken(tenantIdpLogin()), ACME_NS);
	}

	/** A tenant the deployment seeds under a given tid stamps that tid. */
	@Test
	void aBootstrapTenantsTokensCarryItsSeededTid() throws Exception {
		opaNamespace = GAMMA_NS;

		assertTid(GAMMA_TID, accessToken(tenantIdpLogin()), GAMMA_NS);
	}

	// ------------------------------------------------------------------
	// Root and /system
	// ------------------------------------------------------------------

	/** A {@code /system} service's S2S token carries no tid claim at all. */
	@Test
	void aSystemServicesTokenCarriesNoTid() throws Exception {
		TokenWrapper input = TokenWrapper.parse(serviceToken("", SYSTEM_SERVICE_NAME));
		assertNull(TenantIds.topTenantOf(input.getNamespace()), input.getNamespace());

		TokenWrapper s2s = accessToken(serviceTokenFor(input));

		assertEquals(input.getNamespace(), s2s.getNamespace());
		assertNoTid(s2s);
	}

	/** A workload a {@code /system} service mints is {@code /system}'s too: no tid on any of its tokens. */
	@Test
	void aSystemWorkloadsTokensCarryNoTid() throws Exception {
		Tokenrequest.WorkloadMintResponse minted = withBearer(serviceToken("", SYSTEM_SERVICE_NAME),
				() -> svc.mintWorkload(CALLER,
						Tokenrequest.WorkloadMintRequest.newBuilder().setWorkloadName("pigeon").build()));
		TokenWrapper bootstrap = TokenWrapper.from(minted.getBootstrapToken());
		assertNull(TenantIds.topTenantOf(bootstrap.getNamespace()), bootstrap.getNamespace());
		assertNoTid(bootstrap);

		Tokenrequest.TokenMintResponse workload = mintFrom(bootstrap.getBase64());
		assertNoTid(refreshToken(workload));
		assertNoTid(accessToken(workload));
	}

	// ------------------------------------------------------------------
	// Never from a request
	// ------------------------------------------------------------------

	/**
	 * A relayed IdP claim named {@code tid} (Microsoft relays one) reaches the
	 * token only {@code origin_}-prefixed; the {@code tid} claim is kernel's.
	 */
	@Test
	void aForgedTidInTheRelayedClaimsIsIgnored() throws Exception {
		Tokenrequest.TokenMintResponse login = userMint(TENANT_ISSUER, "alice", Struct.newBuilder()
				.putFields("tid", Value.newBuilder().setStringValue(FORGED_TID).build()));

		for (TokenWrapper token : List.of(refreshToken(login), accessToken(login),
				accessToken(mintFrom(refreshToken(login).getBase64())))) {
			assertTid(acmeTid, token, ACME_NS);
			assertEquals(FORGED_TID, token.getCustomField("origin_tid"), "relayed under its origin_ name");
		}
	}

	/** A delegate's custom claims cannot name the tid either: the platform's claim names are skipped. */
	@Test
	void aForgedTidInADelegatesCustomClaimsIsIgnored() throws Exception {
		delegates.replaceAll(d -> d.getName().equals(BROKER_NAME)
				? d.toBuilder().putCustomClaims("tid", FORGED_TID).putCustomClaims("team", "payments").build()
				: d);

		Tokenrequest.TokenMintResponse login = tenantIdpLogin();

		assertTid(acmeTid, refreshToken(login), ACME_NS);
		assertTid(acmeTid, accessToken(login), ACME_NS);
		assertEquals("payments", accessToken(login).getCustomField("team"), "other custom claims still land");
	}

	/**
	 * The claim follows kernel's record, never the presented token: a tenant
	 * created again under the same name has a new tid, and a refresh of a token
	 * minted under the old one carries the new tid, not the one it presented.
	 */
	@Test
	void aRefreshReDerivesTheTidFromTheRecord() throws Exception {
		TokenWrapper oldRefresh = refreshToken(tenantIdpLogin());
		assertTid(acmeTid, oldRefresh, ACME_NS);

		admin.deleteTenant(CALLER, Kernel.DeleteTenantRequest.newBuilder().setTenantNamespace(ACME_NS).build());
		String newTid = admin.createTenant(CALLER,
				Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ACME_NS).build()).getTid();
		assertNotEquals(acmeTid, newTid);

		TokenWrapper refreshed = accessToken(mintFrom(oldRefresh.getBase64()));
		assertTid(newTid, refreshed, ACME_NS);
		assertEquals(acmeTid, oldRefresh.getTid(), "the token minted before keeps the tid it was minted with");
		assertTid(newTid, accessToken(tenantIdpLogin()), ACME_NS);
	}

	/**
	 * A namespace a deployment names without a kernel tenant record still mints
	 * (kernel#19), with no tid to stamp: the token carries no claim, and the
	 * generated readers refuse a tenant-scoped call without one.
	 */
	@Test
	void aTenantKernelHasNoRecordOfMintsWithoutATid() throws Exception {
		opaNamespace = "/tenants/unrecorded";
		TokenWrapper token = accessToken(tenantIdpLogin());

		assertEquals("/tenants/unrecorded", token.getNamespace());
		assertNoTid(token);
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	private static void assertTid(String tid, TokenWrapper token, String namespace) {
		assertEquals(namespace, token.getNamespace());
		assertEquals(tid, token.getTid(), "tid of " + token.getSubject() + " in " + namespace);
		assertEquals(tid, token.getProto().getPayloadMap().get(IdentityServiceImpl.TID), "the claim as signed");
	}

	private static void assertNoTid(TokenWrapper token) {
		assertFalse(token.getProto().getPayloadMap().containsKey(IdentityServiceImpl.TID),
				token.getSubject() + " in " + token.getNamespace() + " carries a tid: " + token.getTid());
		assertEquals("", token.getTid());
	}

	/** A Google login; OPA routes it into {@link #opaNamespace}. */
	private Tokenrequest.TokenMintResponse personLogin() throws Exception {
		return userMint(GOOGLE_ISSUER, GOOGLE_SUB, Struct.newBuilder());
	}

	/** A login through a tenant's own IdP; OPA names the tenant. */
	private Tokenrequest.TokenMintResponse tenantIdpLogin() throws Exception {
		return userMint(TENANT_ISSUER, "alice", Struct.newBuilder());
	}

	private Tokenrequest.TokenMintResponse userMint(String issuer, String subject, Struct.Builder claims)
			throws Exception {
		Tokenrequest.MintUserTokenRequest request = Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject(subject)
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(claims
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

	/** Acme's docmanager on its Kubernetes service account. */
	private Tokenrequest.TokenMintResponse kubernetesMint() throws Exception {
		return svc.mintServiceToken(CALLER,
				Tokenrequest.MintServiceTokenRequest.newBuilder().setKubernetesToken(fakeJwt()).build());
	}

	/** A token exchanged for a service token to opa. */
	private Tokenrequest.TokenMintResponse serviceTokenFor(TokenWrapper token) throws Exception {
		return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(token.getBase64()).setAud("opa").build());
	}

	private Tokenrequest.MintDelegatedTokenResponse delegated(String delegateNamespace, String grantId)
			throws Exception {
		return withBearer(serviceToken(delegateNamespace, SERVICE_NAME), () -> svc.mintDelegatedToken(CALLER,
				Tokenrequest.MintDelegatedTokenRequest.newBuilder().setGrantId(grantId).build()));
	}

	private static TokenWrapper accessToken(Tokenrequest.TokenMintResponse resp) {
		return TokenWrapper.parse(resp.getAccessToken().getBase64());
	}

	private static TokenWrapper refreshToken(Tokenrequest.TokenMintResponse resp) {
		return TokenWrapper.parse(resp.getRefreshToken().getBase64());
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

	/**
	 * A kernel-signed S2S token for the delegate {@code name} of the tenant {@code namespace}
	 * ("" = /system), its subject rooted at the tenant's tid, as a running instance holds one.
	 */
	private String serviceToken(String namespace, String name) throws Exception {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = namespace.isEmpty()
				? Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", name)
				: SpiffeIds.build(TRUST_DOMAIN, SpiffeIds.tenantRoot(configMap.getTenants(namespace).getTid()), name);
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(namespace.isEmpty() ? Spiffe.namespaceFromSpiffe(subject) : namespace);
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
