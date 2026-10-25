// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The session credential (identity decision record 2026-10-25, step 2): the
 * trust rule, proof by proof. A session is a set of proofs; each IdP assertion
 * activates exactly the tenants it routes to; proofs accumulate (Merge) and are
 * dropped (Unmerge) without a write; an access token is minted only against a
 * live proof for that tenant, else PERMISSION_DENIED with a step-up.
 *
 * <p>The fake OPA answers {@link #opaNamespace}: empty is a personal login (no
 * tenant routes it), {@code /tenants/acme} is acme's claim matchers routing it.
 */
class SessionCredentialTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String BROKER_NAME = "oauth";
	private static final String ACME = "/tenants/acme";
	private static final String BETA = "/tenants/beta";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String MICROSOFT_ISSUER = "https://login.microsoftonline.com/common/v2.0";
	private static final String GOOGLE_SUB = "110169484474386276334";
	private static final String APPLE_SUB = "001672.9c4f1a33be7d4e1fb0c2.0913";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final String STEP_UP = "sign in with that tenant's identity provider";

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private String opaNamespace = "";
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
				null, null, name -> null, (name, chain) -> { },
				() -> TRUST_DOMAIN,
				ISSUER,
				new FakeOpaEvalGrpcClient(),
				null,
				new ConfigMap(new InMemoryManager()),
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null, null,
				KERNEL_AUDIENCE,
				null);
	}

	// ------------------------------------------------------------------
	// What a proof vouches for
	// ------------------------------------------------------------------

	/** A personal login activates {@code people} only; any other tenant is a step-up. */
	@Test
	void aPersonalProofYieldsPeopleOnly() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));

		List<SessionCredential.Proof> proofs = SessionCredential.proofsOf(credential);
		assertEquals(1, proofs.size());
		assertEquals("google", proofs.get(0).idpId());
		assertEquals(GOOGLE_SUB, proofs.get(0).providerSubject());
		assertEquals(List.of(PeopleTenant.NAMESPACE), proofs.get(0).tenants());

		TokenWrapper people = accessToken(exchange(credential, PeopleTenant.NAMESPACE));
		assertEquals(PeopleTenant.NAMESPACE, people.getNamespace());
		assertEquals(credential.getSubject(), people.getSubject());
		assertEquals(credential.getJTI(), people.getCustomField("parent_jti"));

		ProtoException ex = assertThrows(ProtoException.class, () -> exchange(credential, ACME));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains(STEP_UP), ex.getMessage());
	}

	/** An org login activates the org AND people — and not a second org. */
	@Test
	void anOrgProofYieldsTheOrgAndPeople() throws Exception {
		opaNamespace = ACME;
		Tokenrequest.TokenMintResponse resp = login(GOOGLE_ISSUER, GOOGLE_SUB);
		TokenWrapper credential = credential(resp);

		assertEquals(List.of(ACME, PeopleTenant.NAMESPACE),
				SessionCredential.proofsOf(credential).get(0).tenants());
		assertEquals(ACME, accessToken(resp).getNamespace(), "the first AT is the org's");
		assertEquals(ACME, accessToken(exchange(credential, ACME)).getNamespace());
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(credential, PeopleTenant.NAMESPACE)).getNamespace());
		assertEquals(PeopleTenant.NAMESPACE, accessToken(exchange(credential, "")).getNamespace(),
				"no tenant named means people");

		ProtoException ex = assertThrows(ProtoException.class, () -> exchange(credential, BETA));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains(STEP_UP), ex.getMessage());
	}

	/**
	 * What a proof vouches for is fixed at login. A claim matcher added later
	 * routes the NEXT login into acme; it does not widen the session already out.
	 */
	@Test
	void aProofsTenantsAreFixedAtLoginNotReDerivedAtExchange() throws Exception {
		TokenWrapper personal = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		opaNamespace = ACME;

		assertEquals(ProtoException.PERMISSION_DENIED,
				assertThrows(ProtoException.class, () -> exchange(personal, ACME)).getCode());
		assertEquals(ACME, accessToken(login(GOOGLE_ISSUER, GOOGLE_SUB)).getNamespace(),
				"a fresh login through the new matcher is what activates acme");
	}

	// ------------------------------------------------------------------
	// Merge and Unmerge
	// ------------------------------------------------------------------

	/** Proofs accumulate: the org login merged into the personal session activates the org. */
	@Test
	void mergeUnionsProofsAndTheMergedCredentialMintsBoth() throws Exception {
		TokenWrapper personal = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		opaNamespace = ACME;
		// The same human, a second Google identity routed into acme.
		TokenWrapper org = credential(login(GOOGLE_ISSUER, "9" + GOOGLE_SUB, personal));

		TokenWrapper merged = TokenWrapper.parse(svc.mergeCredentials(callerOf(personal),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(personal.getBase64())
						.addCredentials(org.getBase64())
						.build()).getCredential().getBase64());

		assertEquals(personal.getSubject(), merged.getSubject());
		assertEquals(2, SessionCredential.proofsOf(merged).size());
		assertEquals(ACME, accessToken(exchange(merged, ACME)).getNamespace());
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(merged, PeopleTenant.NAMESPACE)).getNamespace());
	}

	/** The same identity presented twice is one proof — the fresher one. */
	@Test
	void mergeDedupesByIdentityKeepingTheFresherProof() throws Exception {
		TokenWrapper older = credential(login(GOOGLE_ISSUER, GOOGLE_SUB, 1_000L));
		TokenWrapper fresher = credential(login(GOOGLE_ISSUER, GOOGLE_SUB, 2_000L));

		TokenWrapper merged = TokenWrapper.parse(svc.mergeCredentials(callerOf(older),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(fresher.getBase64())
						.addCredentials(older.getBase64())
						.build()).getCredential().getBase64());

		List<SessionCredential.Proof> proofs = SessionCredential.proofsOf(merged);
		assertEquals(1, proofs.size());
		assertEquals(2_000L, proofs.get(0).authTime());
	}

	/** Two people are never merged: that is Link, a write with its own warning path. */
	@Test
	void mergeRefusesCredentialsOfDifferentPeople() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper apple = credential(login(APPLE_ISSUER, APPLE_SUB));
		assertFalse(google.getSubject().equals(apple.getSubject()));

		ProtoException ex = assertThrows(ProtoException.class, () -> svc.mergeCredentials(
				callerOf(google),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(google.getBase64())
						.addCredentials(apple.getBase64())
						.build()));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	/** Unmerge drops a proof and what it vouched for; dropping the last one is a sign-out. */
	@Test
	void unmergeDropsAProofAndTheLastOneSignsOut() throws Exception {
		TokenWrapper personal = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		opaNamespace = ACME;
		TokenWrapper org = credential(login(GOOGLE_ISSUER, "9" + GOOGLE_SUB, personal));
		TokenWrapper merged = TokenWrapper.parse(svc.mergeCredentials(callerOf(personal),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(personal.getBase64()).addCredentials(org.getBase64())
						.build()).getCredential().getBase64());

		Kernel.RevokeCredentialProofResponse one = svc.revokeCredentialProof(callerOf(personal),
				Kernel.RevokeCredentialProofRequest.newBuilder()
						.setCredential(merged.getBase64())
						.setIdpId("google").setProviderSubject("9" + GOOGLE_SUB)
						.build());
		TokenWrapper remaining = TokenWrapper.parse(one.getCredential().getBase64());
		assertEquals(1, SessionCredential.proofsOf(remaining).size());
		assertEquals(ProtoException.PERMISSION_DENIED,
				assertThrows(ProtoException.class, () -> exchange(remaining, ACME)).getCode(),
				"the dropped proof no longer vouches acme");
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(remaining, PeopleTenant.NAMESPACE)).getNamespace());
		// Unmerge changes only what the credential can mint: the link remains.
		assertEquals(2, principalMap.proto().getIdentityLinksCount());

		Kernel.RevokeCredentialProofResponse last = svc.revokeCredentialProof(callerOf(personal),
				Kernel.RevokeCredentialProofRequest.newBuilder()
						.setCredential(remaining.getBase64())
						.setIdpId("google").setProviderSubject(GOOGLE_SUB)
						.build());
		assertFalse(last.hasCredential(), "dropping the last proof returns nothing");

		assertEquals(ProtoException.NOT_FOUND, assertThrows(ProtoException.class,
				() -> svc.revokeCredentialProof(callerOf(personal),
						Kernel.RevokeCredentialProofRequest.newBuilder()
								.setCredential(remaining.getBase64())
								.setIdpId("apple").setProviderSubject("nobody")
								.build())).getCode());
	}

	/** A credential is the caller's own: another person's bearer cannot merge or unmerge it. */
	@Test
	void anotherPersonCannotMergeOrUnmergeYourCredential() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper apple = credential(login(APPLE_ISSUER, APPLE_SUB));

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> svc.mergeCredentials(callerOf(apple), Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(google.getBase64()).build())).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> svc.revokeCredentialProof(callerOf(apple),
						Kernel.RevokeCredentialProofRequest.newBuilder()
								.setCredential(google.getBase64())
								.setIdpId("google").setProviderSubject(GOOGLE_SUB).build())).getCode());
	}

	// ------------------------------------------------------------------
	// What stops a mint
	// ------------------------------------------------------------------

	/** An expired proof no longer mints, while a live one beside it still does. */
	@Test
	void anExpiredProofNoLongerMints() throws Exception {
		TokenWrapper personal = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		opaNamespace = ACME;
		long shortExp = Instant.now().getEpochSecond() + 2;
		TokenWrapper org = credential(login(GOOGLE_ISSUER, "9" + GOOGLE_SUB, personal, shortExp));
		TokenWrapper merged = TokenWrapper.parse(svc.mergeCredentials(callerOf(personal),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(personal.getBase64()).addCredentials(org.getBase64())
						.build()).getCredential().getBase64());
		assertEquals(ACME, accessToken(exchange(merged, ACME)).getNamespace());

		Thread.sleep(3_000);

		ProtoException ex = assertThrows(ProtoException.class, () -> exchange(merged, ACME));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains(STEP_UP), ex.getMessage());
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(merged, PeopleTenant.NAMESPACE)).getNamespace(),
				"the personal proof is the long-lived one");
	}

	/** The first mint-time read: an unlinked identity's proof no longer mints. */
	@Test
	void aProofWhoseLinkIsGoneNoLongerMints() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		principalMap.deleteIdentityLinks(IdentityServiceImpl.identityLinkKey("google", GOOGLE_SUB));

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> exchange(credential, PeopleTenant.NAMESPACE)).getCode());
	}

	/** The second mint-time read: an org that removed the member stops the org token at the next mint. */
	@Test
	void aRevokedMembershipNoLongerMintsThatTenant() throws Exception {
		opaNamespace = ACME;
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		Kernel.Person person = person();
		principalMap.putPeople(person.getXid(), person.toBuilder()
				.setMemberships(1, person.getMemberships(1).toBuilder()
						.setRevokedAtMs(System.currentTimeMillis()))
				.build());

		assertEquals(ProtoException.PERMISSION_DENIED,
				assertThrows(ProtoException.class, () -> exchange(credential, ACME)).getCode());
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(credential, PeopleTenant.NAMESPACE)).getNamespace(),
				"people is not the org's to take");
	}

	/** Sign out everywhere is one write: the generation bump fails every outstanding credential. */
	@Test
	void aGenerationBumpFailsEveryOutstandingCredential() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		Kernel.Person person = person();
		principalMap.putPeople(person.getXid(), person.toBuilder().setGeneration(1).build());

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> exchange(credential, PeopleTenant.NAMESPACE)).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> svc.mergeCredentials(callerOf(credential), Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(credential.getBase64()).build())).getCode());

		TokenWrapper fresh = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		assertEquals("1", fresh.getCustomField(SessionCredential.CLAIM_GENERATION));
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(fresh, PeopleTenant.NAMESPACE)).getNamespace());
	}

	/** A disabled person's credential mints nothing. */
	@Test
	void aDisabledPersonsCredentialMintsNothing() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		Kernel.Person person = person();
		principalMap.putPeople(person.getXid(), person.toBuilder()
				.setDisabledAtMs(System.currentTimeMillis()).build());

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> exchange(credential, PeopleTenant.NAMESPACE)).getCode());
	}

	// ------------------------------------------------------------------
	// Credential and legacy refresh token are distinguished by shape
	// ------------------------------------------------------------------

	/**
	 * A legacy single-namespace refresh token is never read as a proof set: with
	 * a tenant named it is refused the way it always was (INVALID_ARGUMENT, not
	 * the credential arm's step-up), and without one it exchanges the legacy way.
	 */
	@Test
	void aLegacyRefreshTokenIsNeverAProofSet() throws Exception {
		opaNamespace = ACME;
		Tokenrequest.TokenMintResponse resp = mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("alice@example.com")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(MICROSOFT_ISSUER, "abc", 0, 0))
				.build());
		TokenWrapper legacy = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertFalse(SessionCredential.isCredential(legacy));
		assertNull(legacy.getCustomField(SessionCredential.CLAIM_PROOFS));

		ProtoException ex = assertThrows(ProtoException.class,
				() -> exchange(legacy, PeopleTenant.NAMESPACE));
		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
		assertFalse(ex.getMessage().contains(STEP_UP), "the credential arm never saw it");

		assertEquals(ACME, accessToken(exchange(legacy, "")).getNamespace(),
				"the legacy exchange is untouched");
	}

	/**
	 * A credential never takes the legacy clone path: its access token carries
	 * none of the credential's own claims, and the checks the legacy path does
	 * not make (here, the generation) are made.
	 */
	@Test
	void aCredentialNeverTakesTheLegacyRefreshPath() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));

		TokenWrapper access = accessToken(exchange(credential, ""));
		assertNull(access.getCustomField(SessionCredential.CLAIM_PROOFS),
				"a clone would have copied the proofs into the access token");
		assertNull(access.getCustomField(SessionCredential.CLAIM_GENERATION));
		assertEquals(PeopleTenant.NAMESPACE, access.getNamespace());

		// offline_access hands the same credential back, not a renewed one.
		Tokenrequest.TokenMintResponse withCredential = svc.mintToken(CALLER,
				Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(credential.getBase64()).setOfflineAccess(true).build());
		assertEquals(credential.getBase64(), withCredential.getRefreshToken().getBase64());
	}

	/** A token kernel did not sign, or signed as something else, is no credential to Merge. */
	@Test
	void mergeRefusesWhatIsNotASessionCredential() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper access = accessToken(exchange(credential, ""));

		assertEquals(ProtoException.INVALID_ARGUMENT, assertThrows(ProtoException.class,
				() -> svc.mergeCredentials(callerOf(credential), Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(access.getBase64()).build())).getCode());
		assertEquals(ProtoException.INVALID_ARGUMENT, assertThrows(ProtoException.class,
				() -> svc.mergeCredentials(callerOf(credential), Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials("not.a.token").build())).getCode());
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	private Tokenrequest.TokenMintResponse login(String issuer, String sub) throws Exception {
		return login(issuer, sub, null, 0);
	}

	private Tokenrequest.TokenMintResponse login(String issuer, String sub, long authTime) throws Exception {
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(issuer, sub, authTime, 0))
				.build());
	}

	/**
	 * A login of a second identity that belongs to the SAME person as
	 * {@code sameAs}: the link is written first, as Link (step 4) will write it,
	 * so the two logins resolve to one XID.
	 */
	private Tokenrequest.TokenMintResponse login(String issuer, String sub,
			TokenWrapper sameAs) throws Exception {
		return login(issuer, sub, sameAs, 0);
	}

	private Tokenrequest.TokenMintResponse login(String issuer, String sub,
			TokenWrapper sameAs, long exp) throws Exception {
		if (sameAs != null) {
			String xid = SessionCredential.xidOf(sameAs);
			String idpId = PeopleTenant.idpId(PeopleTenant.providerForIssuer(issuer));
			String key = IdentityServiceImpl.identityLinkKey(idpId, sub);
			principalMap.putIdentityLinks(key, Kernel.IdentityLinkRow.newBuilder()
					.setLinkKey(key).setXid(xid).build());
			Kernel.Person person = principalMap.getPeople(xid);
			principalMap.putPeople(xid, person.toBuilder()
					.addLinks(Kernel.IdentityLink.newBuilder().setIdpId(idpId).setProviderSubject(sub))
					.build());
		}
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(issuer, sub, 0, 0))
				.setExp(exp)
				.build());
	}

	private Tokenrequest.TokenMintResponse exchange(TokenWrapper credential, String tenant) throws Exception {
		return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(credential.getBase64())
				.setTenantNamespace(tenant)
				.build());
	}

	private static TokenWrapper credential(Tokenrequest.TokenMintResponse resp) {
		TokenWrapper credential = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		assertTrue(SessionCredential.isCredential(credential), "the long-lived token is the credential");
		return credential;
	}

	private static TokenWrapper accessToken(Tokenrequest.TokenMintResponse resp) {
		return TokenWrapper.parse(resp.getAccessToken().getBase64());
	}

	/** The one person these tests create through Google. */
	private Kernel.Person person() {
		return principalMap.getPeople(principalMap.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey("google", GOOGLE_SUB)).getXid());
	}

	/** The C2S caller: a verified bearer of the person a credential names. */
	private static Caller callerOf(TokenWrapper credential) {
		return new Caller("{\"sub\":\"" + credential.getSubject() + "\",\"namespace\":\""
				+ PeopleTenant.NAMESPACE + "\"}", "test-req");
	}

	private static Struct idpClaims(String issuer, String sub, long authTime, long unused) {
		Struct.Builder claims = Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(sub).build())
				.putFields("email", Value.newBuilder().setStringValue("jody@example.com").build())
				.putFields("azp", Value.newBuilder().setStringValue(BROKER_NAME).build());
		if (authTime > 0) {
			claims.putFields("origin_auth_time", Value.newBuilder().setNumberValue(authTime).build());
		}
		return claims.build();
	}

	private Tokenrequest.TokenMintResponse mint(Tokenrequest.MintUserTokenRequest request) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, brokerToken());
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintUserToken(CALLER, request);
		} finally {
			ctx.detach(previous);
		}
	}

	private String brokerToken() {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", BROKER_NAME);
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
