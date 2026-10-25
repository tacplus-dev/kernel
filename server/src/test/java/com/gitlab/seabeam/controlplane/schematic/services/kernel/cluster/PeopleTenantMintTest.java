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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * People, end to end (identity decision record 2026-10-25, step 1): the
 * reserved {@code people} tenant's bootstrap, and the XID-keyed person created
 * on first IdP login — its first link and its {@code people} membership — found
 * through the link on every login after.
 *
 * <p>The fake OPA below answers whatever {@link #opaNamespace} says. It starts
 * EMPTY — the login no tenant routes, which is exactly what a Google sign-in on
 * a fleet with no claim matchers looks like — and the org tests set it to
 * {@code /tenants/acme}. Every namespace assertion on the people arm is
 * therefore also an assertion about which half of "org + people" the token
 * landed in.
 */
class PeopleTenantMintTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	/** The broker's service path. One delegate per tenant may carry it. */
	private static final String BROKER_NAME = "oauth";
	private static final String ORG_NAMESPACE = "/tenants/acme";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";
	private static final String MICROSOFT_ISSUER = "https://login.microsoftonline.com/common/v2.0";
	/** An Apple `sub`: dotted hex, and a legal path segment as it stands. */
	private static final String APPLE_SUB = "001672.9c4f1a33be7d4e1fb0c2.0913";
	private static final String GOOGLE_SUB = "110169484474386276334";
	private static final Caller CALLER = new Caller("", "test-req");

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	/** What OPA names as the tenant this login routes to; empty is "no tenant". */
	private String opaNamespace = "";
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
		// The fleet's oauth: ONE instance, rooted at /system, brokering every
		// login. And a people-tenant-rooted one, to show the root does not matter.
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.setTenantNamespace(PeopleTenant.NAMESPACE)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.build());
		principalMap = new PrincipalMap(new InMemoryManager());
		configMap = new ConfigMap(new InMemoryManager());
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
				configMap,
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
	}

	// ------------------------------------------------------------------
	// The XID, its first link, and the `people` membership
	// ------------------------------------------------------------------

	/**
	 * The create half: a login for a (idp_id, sub) nobody has seen mints exactly
	 * one XID, one Person keyed by it carrying that link and the {@code people}
	 * membership, and the index row that finds it next time.
	 */
	@Test
	void aFirstGoogleLoginCreatesExactlyOnePerson() throws Exception {
		Kernel.Person person = resolve("google", GOOGLE_SUB);

		assertEquals(1, principalMap.proto().getPeopleCount());
		assertEquals(1, principalMap.proto().getIdentityLinksCount());
		assertFalse(person.getXid().isEmpty(), "the XID is minted");
		assertEquals(person.getXid(), Spiffe.normalizeSegment(person.getXid()),
				"the XID is a legal SPIFFE path segment as minted");
		assertEquals(person, principalMap.getPeople(person.getXid()));
		assertEquals(person.getXid(), principalMap.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey("google", GOOGLE_SUB)).getXid());
		assertEquals(1, person.getLinksCount());
		assertEquals("google", person.getLinks(0).getIdpId());
		assertEquals(GOOGLE_SUB, person.getLinks(0).getProviderSubject());
		assertEquals(1, person.getMembershipsCount());
		assertEquals(PeopleTenant.NAMESPACE, person.getMemberships(0).getTenantNamespace());
		assertTrue(person.getCreatedAtMs() > 0, "the row records when the person was created");
	}

	/**
	 * The find half, and the point of the XID: the same human signing in again —
	 * from another device, another browser, any number of times — resolves to the
	 * SAME XID. A second XID here would be a second person with the same account.
	 */
	@Test
	void aRepeatLoginResolvesTheSameXidAndCreatesNoDuplicate() throws Exception {
		Kernel.Person first = resolve("google", GOOGLE_SUB);

		assertEquals(first, resolve("google", GOOGLE_SUB));
		assertEquals(first, resolve("google", GOOGLE_SUB));
		assertEquals(1, principalMap.proto().getPeopleCount(),
				"a repeat login must find the existing person, not create another");
		assertEquals(1, principalMap.proto().getIdentityLinksCount());
	}

	/**
	 * One provider identity is one person. The same subject STRING from a
	 * different provider is a different human until an explicit, both-sides-proven
	 * Link exists (the record's step 4); guessing otherwise is how accounts get
	 * hijacked. And two people are two XIDs, never one.
	 */
	@Test
	void distinctLinksAreDistinctPeople() throws Exception {
		Kernel.Person apple = resolve("apple", GOOGLE_SUB);
		Kernel.Person google = resolve("google", GOOGLE_SUB);
		Kernel.Person other = resolve("google", "9" + GOOGLE_SUB);

		assertEquals(3, principalMap.proto().getPeopleCount());
		assertNotEquals(apple.getXid(), google.getXid());
		assertNotEquals(google.getXid(), other.getXid());
	}

	/**
	 * The sign-ups kill switch refuses the create half: a link nobody has seen
	 * gets no person while it is on, and gets one as soon as it is off again.
	 */
	@Test
	void whileSignupsArePausedAFirstLoginCreatesNoPerson() throws Exception {
		svc.setPeopleSignupsPaused(() -> true);

		IdentityServiceImpl.StatusException refused = assertThrows(IdentityServiceImpl.StatusException.class,
				() -> resolve("apple", APPLE_SUB));
		assertEquals(io.grpc.Status.Code.PERMISSION_DENIED, refused.toGrpcStatus().getCode());
		assertPeopleRegistryEmpty();

		svc.setPeopleSignupsPaused(() -> false);
		resolve("apple", APPLE_SUB);
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/** ...and only the create half: someone who already has a person signs in as before. */
	@Test
	void whileSignupsArePausedAReturningPersonStillSignsIn() throws Exception {
		Kernel.Person before = resolve("google", GOOGLE_SUB);
		svc.setPeopleSignupsPaused(() -> true);

		assertEquals(before, resolve("google", GOOGLE_SUB));
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/** A disabled person cannot simply sign back in; the mark is what stops them. */
	@Test
	void aDisabledPersonIsRefused() throws Exception {
		Kernel.Person person = resolve("apple", APPLE_SUB);
		principalMap.putPeople(person.getXid(), person.toBuilder()
				.setDisabledAtMs(System.currentTimeMillis())
				.build());

		assertThrows(IdentityServiceImpl.StatusException.class, () -> resolve("apple", APPLE_SUB));
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/**
	 * The XID is immutable, so losing the person or the link on a restart would
	 * not merely forget them — it would mint them a NEW XID on their next login.
	 * The round trip through the real snapshot and the real boot-time restore.
	 */
	@Test
	void aCreatedPersonAndItsLinkSurviveARestart(@TempDir Path dir) throws Exception {
		Kernel.Person live = resolve("apple", APPLE_SUB);

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
		ClusterServer.restorePeople(persistence.load(), afterRestart);

		assertEquals(live, afterRestart.getPeople(live.getXid()),
				"the person must come back field-identical after a restart");
		assertEquals(live.getXid(), afterRestart.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey("apple", APPLE_SUB)).getXid(),
				"the link must come back, or the next login mints a second XID");
	}

	// ------------------------------------------------------------------
	// The mint
	// ------------------------------------------------------------------

	/**
	 * The seatrials case, and the whole of step 1 end to end: ONE oauth instance
	 * rooted at /system brokers a Google login that no tenant routes. It creates
	 * the person and mints that person's own token — subject
	 * {@code spiffe://<td>/users/<xid>}, namespace {@code /tenants/people} — and
	 * a second login resolves to the same subject.
	 */
	@Test
	void aGoogleLoginNoTenantRoutesMintsThatPersonsPeopleToken() throws Exception {
		Tokenrequest.TokenMintResponse resp = login(GOOGLE_ISSUER, GOOGLE_SUB, "");

		assertEquals(1, principalMap.proto().getPeopleCount());
		Kernel.Person person = person("google", GOOGLE_SUB);
		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(SpiffeIds.userSubject(TRUST_DOMAIN, person.getXid()), refresh.getSubject());
		assertEquals("spiffe://" + TRUST_DOMAIN + "/users/" + person.getXid(), refresh.getSubject());
		assertEquals(PeopleTenant.NAMESPACE, refresh.getNamespace());
		assertEquals(PeopleTenant.NAMESPACE,
				TokenWrapper.parse(resp.getAccessToken().getBase64()).getNamespace());

		// And again: the repeat login finds the same person rather than a second one.
		Tokenrequest.TokenMintResponse again = login(GOOGLE_ISSUER, GOOGLE_SUB, "");
		assertEquals(1, principalMap.proto().getPeopleCount());
		assertEquals(refresh.getSubject(),
				TokenWrapper.parse(again.getRefreshToken().getBase64()).getSubject());
	}

	/**
	 * The issuer selects the people arm, not the broker's root: a people-rooted
	 * broker and the /system broker resolve the same login to the same XID.
	 */
	@Test
	void theBrokersRootDoesNotChangeWhoThePersonIs() throws Exception {
		TokenWrapper viaSystem = TokenWrapper.parse(
				login(GOOGLE_ISSUER, GOOGLE_SUB, "").getRefreshToken().getBase64());
		TokenWrapper viaPeople = TokenWrapper.parse(
				login(GOOGLE_ISSUER, GOOGLE_SUB, PeopleTenant.NAMESPACE).getRefreshToken().getBase64());

		assertEquals(viaSystem.getSubject(), viaPeople.getSubject());
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/**
	 * An org login activates the org AND people. When the claim matchers route a
	 * Google login into acme, the token minted is acme's — same XID subject,
	 * namespace {@code /tenants/acme} — and the org membership is recorded once,
	 * at that first org login; a later login writes nothing.
	 */
	@Test
	void aGoogleLoginAnOrgRoutesMintsTheOrgTokenAndRecordsTheMembership() throws Exception {
		opaNamespace = ORG_NAMESPACE;

		Tokenrequest.TokenMintResponse resp = login(GOOGLE_ISSUER, GOOGLE_SUB, "");

		Kernel.Person person = person("google", GOOGLE_SUB);
		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(SpiffeIds.userSubject(TRUST_DOMAIN, person.getXid()), refresh.getSubject());
		assertEquals(ORG_NAMESPACE, refresh.getNamespace());
		assertEquals(2, person.getMembershipsCount());
		assertEquals(PeopleTenant.NAMESPACE, person.getMemberships(0).getTenantNamespace());
		assertEquals(ORG_NAMESPACE, person.getMemberships(1).getTenantNamespace());

		login(GOOGLE_ISSUER, GOOGLE_SUB, "");
		assertEquals(person, person("google", GOOGLE_SUB), "a repeat org login writes nothing");

		// The same person signing in where no tenant routes them gets `people`.
		opaNamespace = "";
		TokenWrapper personal = TokenWrapper.parse(
				login(GOOGLE_ISSUER, GOOGLE_SUB, "").getRefreshToken().getBase64());
		assertEquals(refresh.getSubject(), personal.getSubject());
		assertEquals(PeopleTenant.NAMESPACE, personal.getNamespace());
	}

	/** An org that removed a member: a revoked membership mints no org token. */
	@Test
	void aRevokedOrgMembershipMintsNoOrgToken() throws Exception {
		opaNamespace = ORG_NAMESPACE;
		login(GOOGLE_ISSUER, GOOGLE_SUB, "");
		Kernel.Person person = person("google", GOOGLE_SUB);
		principalMap.putPeople(person.getXid(), person.toBuilder()
				.setMemberships(1, person.getMemberships(1).toBuilder()
						.setRevokedAtMs(System.currentTimeMillis()))
				.build());

		ProtoException ex = assertThrows(ProtoException.class,
				() -> login(GOOGLE_ISSUER, GOOGLE_SUB, ""));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	/**
	 * A people-provider login carrying no verified subject. The people arm takes
	 * NOTHING from {@code request.subject} — the field is set below and is
	 * deliberately ignored — so with no {@code origin_sub} there is no link to
	 * resolve, and the request cannot fall back to naming a person itself.
	 */
	@Test
	void aPeopleLoginWithNoVerifiedSubjectMintsNothing() {
		ProtoException ex = assertThrows(ProtoException.class, () -> mint(
				Tokenrequest.MintUserTokenRequest.newBuilder()
						.setSubject(GOOGLE_SUB)
						.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
						.setClaims(Struct.newBuilder()
								.putFields("origin_iss", Value.newBuilder().setStringValue(GOOGLE_ISSUER).build())
								.build())
						.build(),
				""));

		assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode());
		assertPeopleRegistryEmpty();
	}

	/**
	 * The people providers are FIXED. An issuer outside the set is an ordinary
	 * tenant login on the untouched path — the subject the broker supplies, the
	 * namespace OPA names — and it creates nobody. (Which idp_id a tenant IdP
	 * carries, and so when its users become XIDs, is open; see IDENTITY.md.)
	 */
	@Test
	void anIssuerOutsideTheFixedSetIsAnOrdinaryTenantLogin() throws Exception {
		opaNamespace = ORG_NAMESPACE;

		Tokenrequest.TokenMintResponse resp = mint(
				Tokenrequest.MintUserTokenRequest.newBuilder()
						.setSubject("alice@example.com")
						.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
						.setClaims(idpClaims(MICROSOFT_ISSUER, "abc"))
						.build(),
				"");

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertEquals(ORG_NAMESPACE, refresh.getNamespace());
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
	// Harness
	// ------------------------------------------------------------------

	/** The mint's own resolve-or-create step, reached directly. */
	private Kernel.Person resolve(String idpId, String providerSubject) throws Exception {
		return svc.resolveOrCreatePerson(idpId, providerSubject);
	}

	/** The person a link resolves to, through the index. */
	private Kernel.Person person(String idpId, String providerSubject) {
		return principalMap.getPeople(principalMap.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey(idpId, providerSubject)).getXid());
	}

	private void assertPeopleRegistryEmpty() {
		try {
			assertEquals(0, principalMap.proto().getPeopleCount());
			assertEquals(0, principalMap.proto().getIdentityLinksCount());
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

	/** A people-provider login brokered by the delegate rooted at {@code brokerNamespace}. */
	private Tokenrequest.TokenMintResponse login(String issuer, String providerSubject,
			String brokerNamespace) throws Exception {
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				// Set, and deliberately ignored by the people arm: everything
				// identifying comes out of the verified claims.
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(issuer, providerSubject))
				.build(), brokerNamespace);
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

	/** The broker's own S2S token; its SPIFFE subject carries the namespace it is rooted at. */
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

	/** Answers {@link #opaNamespace} as the routed tenant; the channel throws if ever used. */
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
