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
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The reserved {@code people} tenant end to end: bootstrap, and person creation
 * on first IdP login.
 *
 * <p>The two halves are one test class because they are one loop — the tenant
 * the bootstrap creates is the namespace the mint stamps, and a person row is
 * the only product of either.
 *
 * <p>The fake OPA below deliberately answers {@code /tenants/acme} for every
 * evaluation. Every namespace assertion on the people arm is therefore also an
 * assertion that it does NOT take its namespace from OPA: if it ever fell back
 * to {@code requireNamespaceFromOpa}, the minted token would come back naming
 * acme and these tests would say so. The last test mints through a plain
 * {@code /system} broker to show that arm is untouched and still OPA's.
 */
class PeopleTenantMintTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	/** The broker's service path. One delegate per tenant may carry it. */
	private static final String BROKER_NAME = "oauth";
	private static final String OPA_NAMESPACE = "/tenants/acme";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";
	/** An Apple `sub`: dotted hex, and a legal path segment as it stands. */
	private static final String APPLE_SUB = "001672.9c4f1a33be7d4e1fb0c2.0913";
	private static final String GOOGLE_SUB = "110169484474386276334";
	private static final Caller CALLER = new Caller("", "test-req");

	/**
	 * Why every test that has to reach the people arm is disabled: the generated
	 * {@code Spiffe} grammar reserves {@code people} as a structural tag, so
	 * {@code /tenants/people} is not a constructible namespace at all —
	 * {@code Spiffe.namespaceSpiffeId} and {@code Spiffe.userSpiffeId} both refuse
	 * it with "reserved tag \"people\" cannot be a tenant name". That blocks the
	 * people-tenant broker's OWN delegate identity as well as its users, so these
	 * tests cannot even build a caller token. It is tacplus's work-split item
	 * ("`people` as a reserved tenant name in the grammar validators"), and
	 * hand-building the SPIFFE strings here instead is exactly the duplication of
	 * generated code this fleet forbids. Delete these annotations when tacplus
	 * lands it; nothing else here should need to change.
	 */
	private static final String PEOPLE_NAMESPACE_BLOCKED =
			"blocked: the tacplus Spiffe grammar reserves `people`, so /tenants/people is not yet "
					+ "a constructible namespace — see the slice's decision doc";

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private KeyRotator keyRotator;
	private PrincipalMap principalMap;
	private ConfigMap configMap;
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
		// The people tenant's own IdP broker: same service path as every other
		// oauth instance, distinguished only by the namespace it is rooted at.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.setTenantNamespace(PeopleTenant.NAMESPACE)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		// A /system oauth broker — an ordinary tenant login, the arm that must not
		// change.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		principalMap = new PrincipalMap(new InMemoryManager());
		configMap = new ConfigMap(new InMemoryManager());
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
				configMap,
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // persistState
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // opaConfigWriter
	}

	// ------------------------------------------------------------------
	// Person creation on first IdP login
	// ------------------------------------------------------------------

	/**
	 * The create half: a login for a (provider, sub) pair nobody has seen makes
	 * exactly one person, under the id derived from that pair.
	 *
	 * <p>Driven through {@code findOrCreatePerson} rather than the whole mint
	 * because the mint cannot complete yet — see
	 * {@link #aFirstApplePeopleLoginMintsThatPersonsToken}, which is the same
	 * assertion end to end and is blocked on tacplus.
	 */
	@Test
	void aFirstAppleLoginCreatesExactlyOnePerson() throws Exception {
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB);

		String userId = "apple." + APPLE_SUB;
		assertEquals(1, principalMap.proto().getPeopleCount());
		Kernel.Person person = principalMap.getPeople(userId);
		assertEquals(userId, person.getUserId());
		assertEquals(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, person.getProvider());
		assertEquals(APPLE_SUB, person.getProviderSubject());
		assertTrue(person.getCreatedAtMs() > 0, "the row records when the person was created");
	}

	/**
	 * The find half, and the point of the whole slice: the same human signing in
	 * again — from another device, another browser, any number of times — lands
	 * on the SAME row. A second row here would be a second person with the same
	 * Apple account.
	 */
	@Test
	void aRepeatLoginFindsTheSamePersonAndCreatesNoDuplicate() throws Exception {
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB);
		Kernel.Person first = principalMap.getPeople("apple." + APPLE_SUB);

		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB);
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB);

		assertEquals(1, principalMap.proto().getPeopleCount(),
				"a repeat login must find the existing person, not create another");
		assertEquals(first, principalMap.getPeople("apple." + APPLE_SUB),
				"the existing row is left exactly as it was — created_at included");
	}

	/**
	 * One provider identity is one person. The same subject STRING from a
	 * different provider is a different human until an explicit, both-sides-proven
	 * merge exists; guessing otherwise is how accounts get hijacked.
	 */
	@Test
	void theSameSubjectUnderTwoProvidersIsTwoPeople() throws Exception {
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, GOOGLE_SUB);
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_GOOGLE, GOOGLE_SUB);

		assertEquals(2, principalMap.proto().getPeopleCount());
		assertEquals(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE,
				principalMap.getPeople("apple." + GOOGLE_SUB).getProvider());
		assertEquals(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_GOOGLE,
				principalMap.getPeople("google." + GOOGLE_SUB).getProvider());
	}

	/** A disabled person cannot simply sign back in; the mark is what stops them. */
	@Test
	void aDisabledPersonIsRefused() throws Exception {
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB);
		String userId = "apple." + APPLE_SUB;
		principalMap.putPeople(userId, principalMap.getPeople(userId).toBuilder()
				.setDisabledAtMs(System.currentTimeMillis())
				.build());

		assertThrows(IdentityServiceImpl.StatusException.class,
				() -> createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB));
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/**
	 * A person is created once and found thereafter, so losing the row on a
	 * restart would not merely forget them — it would re-create them with a fresh
	 * {@code created_at_ms} on their next login. The round trip through the real
	 * snapshot and the real boot-time restore, not a copy of either.
	 */
	@Test
	void aCreatedPersonSurvivesARestart(@TempDir Path dir) throws Exception {
		createPerson(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, APPLE_SUB);
		Kernel.Person live = principalMap.getPeople("apple." + APPLE_SUB);

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
		ClusterServer.restorePeople(persistence.load(), afterRestart);

		assertEquals(live, afterRestart.getPeople("apple." + APPLE_SUB),
				"the person must come back field-identical after a restart");
	}

	/**
	 * The IdP set is FIXED. A broker that somehow presents a third issuer mints
	 * nothing and creates nobody — the tenant's providers are the enum's, not a
	 * configuration's. Refused before any identity is derived, so it runs today.
	 */
	@Test
	@Disabled(PEOPLE_NAMESPACE_BLOCKED)
	void anIssuerOutsideTheFixedSetMintsNothing() {
		ProtoException ex = assertThrows(ProtoException.class,
				() -> peopleLogin("https://login.microsoftonline.com/common/v2.0", "abc"));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertPeopleRegistryEmpty();
	}

	/**
	 * A login carrying no verified IdP claims. The people arm takes NOTHING from
	 * {@code request.subject} — the field is set below and is deliberately
	 * ignored — so with no claims there is no identity to mint for, and the
	 * request cannot fall back to naming a person itself.
	 */
	@Test
	@Disabled(PEOPLE_NAMESPACE_BLOCKED)
	void aLoginWithNoVerifiedIdpClaimsMintsNothing() {
		ProtoException ex = assertThrows(ProtoException.class, () -> mint(
				Tokenrequest.MintUserTokenRequest.newBuilder()
						.setSubject("apple." + APPLE_SUB)
						.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
						.build(),
				PeopleTenant.NAMESPACE));

		assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode());
		assertPeopleRegistryEmpty();
	}

	/**
	 * The whole slice end to end: a first Apple login creates the person AND
	 * mints that person's own token — subject {@code
	 * spiffe://<td>/tenants/people/users/apple.<sub>}, namespace
	 * {@code /tenants/people} (not the {@code /tenants/acme} the fake OPA keeps
	 * answering).
	 *
	 * <p>DISABLED, and the one thing in this slice that does not work: the
	 * generated {@code Spiffe} grammar reserves {@code people} as a structural
	 * tag, so {@code Spiffe.userSpiffeId(td, "/tenants/people", ...)} refuses with
	 * "reserved tag \"people\" cannot be a tenant name". That is tacplus's own
	 * work-split item ("`people` as a reserved tenant name in the grammar
	 * validators"), and hand-building the SPIFFE string here instead is exactly
	 * the duplication of generated code this fleet forbids. Delete the
	 * {@code @Disabled} when tacplus lands it; nothing else here should need to
	 * change.
	 */
	@Test
	@Disabled(PEOPLE_NAMESPACE_BLOCKED)
	void aFirstApplePeopleLoginMintsThatPersonsToken() throws Exception {
		Tokenrequest.TokenMintResponse resp = peopleLogin(APPLE_ISSUER, APPLE_SUB);

		String userId = "apple." + APPLE_SUB;
		assertEquals(1, principalMap.proto().getPeopleCount());
		assertEquals(APPLE_SUB, principalMap.getPeople(userId).getProviderSubject());

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(PeopleTenant.NAMESPACE, refresh.getNamespace());
		assertEquals(Spiffe.userSpiffeId(TRUST_DOMAIN, PeopleTenant.NAMESPACE, userId),
				refresh.getSubject());
		assertEquals(PeopleTenant.NAMESPACE,
				TokenWrapper.parse(resp.getAccessToken().getBase64()).getNamespace());

		// And again: the repeat login finds the same row rather than a second one.
		Tokenrequest.TokenMintResponse again = peopleLogin(APPLE_ISSUER, APPLE_SUB);
		assertEquals(1, principalMap.proto().getPeopleCount());
		assertEquals(refresh.getSubject(),
				TokenWrapper.parse(again.getRefreshToken().getBase64()).getSubject());
	}

	/**
	 * The ordinary tenant arm is untouched: a {@code /system}-rooted oauth broker
	 * still mints the subject it was handed, into the namespace OPA names. Without
	 * this, "the people arm is selected by the delegate's own namespace" would be
	 * an assertion about one branch and not about the fork.
	 */
	@Test
	void aBrokerOutsideThePeopleTenantStillMintsTheOrdinaryWay() throws Exception {
		Tokenrequest.TokenMintResponse resp = mint(
				Tokenrequest.MintUserTokenRequest.newBuilder()
						.setSubject("alice@example.com")
						.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
						.setClaims(idpClaims(APPLE_ISSUER, APPLE_SUB))
						.build(),
				"");

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(OPA_NAMESPACE, refresh.getNamespace());
		assertEquals("alice@example.com", refresh.getSubject());
		assertPeopleRegistryEmpty();
	}

	// ------------------------------------------------------------------
	// Bootstrap
	// ------------------------------------------------------------------

	/**
	 * The bootstrap: kernel creates the tenant and writes the two fixed providers
	 * into its oauth slice, which is how oauth learns the people tenant's IdPs —
	 * through the same per-tenant config slice every other tenant uses.
	 */
	@Test
	void seedCreatesTheTenantWithBothFixedProviders() throws Exception {
		PeopleTenant.seed(configMap, List.of(
				credential(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, "apple-client"),
				credential(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_GOOGLE, "google-client")));

		assertEquals(PeopleTenant.NAME, configMap.getTenants(PeopleTenant.NAMESPACE).getName());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE,
				configMap.getTenants(PeopleTenant.NAMESPACE).getStatus());
		var oauth = configMap.getTenantConfigs(PeopleTenant.NAMESPACE).getConfig().getOauth();
		assertEquals(2, oauth.getProvidersCount());
		assertEquals(APPLE_ISSUER, oauth.getProviders(0).getIssuerUrl());
		assertEquals("apple-client", oauth.getProviders(0).getClientId());
		assertEquals(GOOGLE_ISSUER, oauth.getProviders(1).getIssuerUrl());
		// No admin: nothing seeds a cred_pair, so no token is ever entitled here.
		assertEquals(0, configMap.getTenantConfigs(PeopleTenant.NAMESPACE)
				.getConfig().getKernel().getCredPairsCount());
	}

	/**
	 * Kernel re-seeds at every boot. The client credentials the bundle declares
	 * are authoritative, but the tenant's own record must not be reborn each
	 * restart — a tenant whose created_at moves has no history.
	 */
	@Test
	void reSeedingKeepsTheTenantsCreatedAt() throws Exception {
		PeopleTenant.seed(configMap, List.of(
				credential(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, "apple-client")));
		var created = configMap.getTenants(PeopleTenant.NAMESPACE).getCreatedAt();

		PeopleTenant.seed(configMap, List.of(
				credential(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, "rotated-client"),
				credential(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_GOOGLE, "google-client")));

		assertEquals(created, configMap.getTenants(PeopleTenant.NAMESPACE).getCreatedAt());
		var oauth = configMap.getTenantConfigs(PeopleTenant.NAMESPACE).getConfig().getOauth();
		assertEquals(2, oauth.getProvidersCount());
		assertEquals("rotated-client", oauth.getProviders(0).getClientId());
	}

	/**
	 * The reserved half of "reserved tenant": even a root-entitled caller — which
	 * passes the generated level-or-below check for every namespace — cannot
	 * create, reconfigure or delete it. That refusal is what makes "no admin"
	 * true rather than merely intended.
	 */
	@Test
	void tenantAdminRefusesTheReservedNamespace() throws Exception {
		PeopleTenant.seed(configMap, List.of(
				credential(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, "apple-client")));
		TenantAdminServiceImpl admin = new TenantAdminServiceImpl(
				configMap, () -> TRUST_DOMAIN, () -> { });

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> admin.createTenant(CALLER, Kernel.CreateTenantRequest.newBuilder()
						.setTenantNamespace(PeopleTenant.NAMESPACE).build())).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> admin.deleteTenant(CALLER, Kernel.DeleteTenantRequest.newBuilder()
						.setTenantNamespace(PeopleTenant.NAMESPACE).build())).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> admin.updateTenantConfig(CALLER, Kernel.SetTenantConfigRequest.newBuilder()
						.setTenantNamespace(PeopleTenant.NAMESPACE)
						.setConfig(configMap.getTenantConfigs(PeopleTenant.NAMESPACE).getConfig())
						.build())).getCode());

		assertEquals(PeopleTenant.NAME, configMap.getTenants(PeopleTenant.NAMESPACE).getName(),
				"the reserved tenant is still standing after all three refusals");
	}

	// ------------------------------------------------------------------
	// User id derivation
	// ------------------------------------------------------------------

	/**
	 * A subject that cannot be a path segment goes through the generated
	 * {@code opaqueSegment}, deterministically and domain-separated by provider.
	 * Neither provider emits such a subject today; the branch exists so that one
	 * that did would still resolve to one stable person rather than refusing the
	 * login.
	 */
	@Test
	void aSubjectThatBreaksTheSegmentGrammarIsCarriedOpaquely() {
		String hostile = "sub/with slashes";

		String id = PeopleTenant.userId(
				Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE, hostile);

		assertEquals(Spiffe.opaqueSegment("apple", hostile), id);
		assertSame(id, Spiffe.normalizeSegment(id), "the derived id must be a legal segment");
		assertNotEquals(id, PeopleTenant.userId(
				Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_GOOGLE, hostile),
				"the provider domain-separates, so two providers never collide");
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	/** The mint's own find-or-create step, reached directly. */
	private void createPerson(Kernel.PeopleIdpProvider provider, String providerSubject)
			throws Exception {
		svc.findOrCreatePerson(PeopleTenant.userId(provider, providerSubject),
				provider, providerSubject);
	}

	private void assertPeopleRegistryEmpty() {
		try {
			assertEquals(0, principalMap.proto().getPeopleCount());
		} catch (ProtoException e) {
			throw new RuntimeException(e);
		}
	}

	private static Kernel.PeopleIdpCredential credential(
			Kernel.PeopleIdpProvider provider, String clientId) {
		return Kernel.PeopleIdpCredential.newBuilder()
				.setProvider(provider)
				.setClientId(clientId)
				.setClientSecret("secret-" + clientId)
				.build();
	}

	/** The claim shape oauth relays: the IdP's own iss/sub, verified, under origin_*. */
	private static Struct idpClaims(String issuer, String providerSubject) {
		return Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(providerSubject).build())
				.putFields("azp", Value.newBuilder().setStringValue(BROKER_NAME).build())
				.build();
	}

	private Tokenrequest.TokenMintResponse peopleLogin(String issuer, String providerSubject)
			throws Exception {
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				// Set, and deliberately ignored by the people arm: everything
				// identifying comes out of the verified claims.
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(issuer, providerSubject))
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
	 * delegate is rooted at, which is the only thing that selects the people arm.
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
