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
	/** An issuer no people provider owns: an ordinary tenant login. */
	private static final String TENANT_ISSUER = "https://login.drpepper.example/oidc";
	/** Microsoft's consumer directory (personal accounts) and a work directory. */
	private static final String MSA_TID = "9188040d-6c67-4c5b-b112-36a304b66dad";
	private static final String WORK_TID = "72f988bf-86f1-41af-91ab-2d7cd011db47";
	private static final String OID = "00000000-0000-0000-66f3-3332eca7ea81";
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

	/**
	 * Sign out of one provider: naming only the provider drops its proof, the
	 * credential keeps the other, and the response carries the re-signed
	 * credential and an access token in a tenant the remaining proofs vouch —
	 * the bearer's own when one still does, else {@code people}.
	 */
	@Test
	void signingOutOfOneProviderKeepsTheOtherProof() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		opaNamespace = ACME;
		TokenWrapper apple = credential(login(APPLE_ISSUER, APPLE_SUB, google));
		TokenWrapper merged = TokenWrapper.parse(svc.mergeCredentials(callerOf(google),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(google.getBase64()).addCredentials(apple.getBase64())
						.build()).getCredential().getBase64());

		// Out of Apple, the org proof, while working in acme: acme goes with it.
		Kernel.RevokeCredentialProofResponse outOfApple = svc.revokeCredentialProof(callerOf(merged, ACME),
				Kernel.RevokeCredentialProofRequest.newBuilder()
						.setCredential(merged.getBase64()).setIdpId("apple").build());
		TokenWrapper googleOnly = TokenWrapper.parse(outOfApple.getCredential().getBase64());
		List<SessionCredential.Proof> left = SessionCredential.proofsOf(googleOnly);
		assertEquals(1, left.size());
		assertEquals("google", left.get(0).idpId());
		TokenWrapper at = TokenWrapper.parse(outOfApple.getAccessToken().getBase64());
		assertEquals(googleOnly.getSubject(), at.getSubject());
		assertEquals(PeopleTenant.NAMESPACE, at.getNamespace(), "acme is no longer vouched: the AT is people's");
		ProtoException stepUp = assertThrows(ProtoException.class, () -> exchange(googleOnly, ACME));
		assertEquals(ProtoException.PERMISSION_DENIED, stepUp.getCode());
		assertTrue(stepUp.getMessage().contains(STEP_UP), "the removed proof is a step-up away again");

		// Out of Google instead: the Apple proof still vouches acme, so the AT stays there.
		Kernel.RevokeCredentialProofResponse outOfGoogle = svc.revokeCredentialProof(callerOf(merged, ACME),
				Kernel.RevokeCredentialProofRequest.newBuilder()
						.setCredential(merged.getBase64()).setIdpId("google").build());
		TokenWrapper appleOnly = TokenWrapper.parse(outOfGoogle.getCredential().getBase64());
		assertEquals("apple", SessionCredential.proofsOf(appleOnly).get(0).idpId());
		assertEquals(ACME, TokenWrapper.parse(outOfGoogle.getAccessToken().getBase64()).getNamespace());
	}

	/** Signing out of the last provider ends the session: no credential, no access token. */
	@Test
	void signingOutOfTheLastProviderEndsTheSession() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		Kernel.RevokeCredentialProofResponse out = svc.revokeCredentialProof(callerOf(google),
				Kernel.RevokeCredentialProofRequest.newBuilder()
						.setCredential(google.getBase64()).setIdpId("google").build());
		assertFalse(out.hasCredential());
		assertFalse(out.hasAccessToken());
	}

	/** A provider the credential carries no proof of — unknown or simply not signed in — is refused. */
	@Test
	void signingOutOfAProviderTheSessionDoesNotCarryIsRefused() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		for (String idpId : List.of("facebook", "apple")) {
			assertEquals(ProtoException.NOT_FOUND, assertThrows(ProtoException.class,
					() -> svc.revokeCredentialProof(callerOf(google),
							Kernel.RevokeCredentialProofRequest.newBuilder()
									.setCredential(google.getBase64()).setIdpId(idpId).build())).getCode(),
					idpId);
		}
	}

	/** Naming only the provider signs out of every sign-in of it the session carries. */
	@Test
	void signingOutOfAProviderDropsEachOfItsProofs() throws Exception {
		TokenWrapper personal = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper second = credential(login(GOOGLE_ISSUER, "9" + GOOGLE_SUB, personal));
		TokenWrapper apple = credential(login(APPLE_ISSUER, APPLE_SUB, personal));
		TokenWrapper merged = TokenWrapper.parse(svc.mergeCredentials(callerOf(personal),
				Kernel.MergeCredentialsRequest.newBuilder()
						.addCredentials(personal.getBase64()).addCredentials(second.getBase64())
						.addCredentials(apple.getBase64())
						.build()).getCredential().getBase64());

		TokenWrapper left = TokenWrapper.parse(svc.revokeCredentialProof(callerOf(merged),
				Kernel.RevokeCredentialProofRequest.newBuilder()
						.setCredential(merged.getBase64()).setIdpId("google").build())
				.getCredential().getBase64());
		List<SessionCredential.Proof> proofs = SessionCredential.proofsOf(left);
		assertEquals(1, proofs.size());
		assertEquals("apple", proofs.get(0).idpId());
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
				.setClaims(idpClaims(TENANT_ISSUER, "abc", 0, 0))
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
	// Microsoft is a people provider, keyed by (tid, oid)
	// ------------------------------------------------------------------

	/** A Microsoft login no tenant routes is a person, linked as microsoft|<tid>:<oid>. */
	@Test
	void aMicrosoftLoginIsAPersonKeyedByTidAndOid() throws Exception {
		TokenWrapper credential = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "pairwise-sub-1"));

		SessionCredential.Proof proof = SessionCredential.proofsOf(credential).get(0);
		assertEquals("microsoft", proof.idpId());
		assertEquals(MSA_TID + ":" + OID, proof.providerSubject());
		assertEquals(List.of(PeopleTenant.NAMESPACE), proof.tenants());
		assertEquals(SessionCredential.xidOf(credential), principalMap.getIdentityLinks(
				IdentityServiceImpl.identityLinkKey("microsoft", MSA_TID + ":" + OID)).getXid());

		// The pairwise `sub` is not the key: the same account through another
		// app registration (another sub) is the same person.
		TokenWrapper again = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "pairwise-sub-2"));
		assertEquals(credential.getSubject(), again.getSubject());
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/** The same oid in another directory is another account, so another person. */
	@Test
	void theSameOidInAnotherDirectoryIsAnotherPerson() throws Exception {
		TokenWrapper personal = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		TokenWrapper work = credential(microsoftLogin(WORK_TID, WORK_TID, OID, "s"));

		assertFalse(personal.getSubject().equals(work.getSubject()));
	}

	/** No oid, or a tid the issuer does not name, is no Microsoft identity at all. */
	@Test
	void aMicrosoftLoginWithoutAMatchingTidAndOidMintsNothing() {
		assertEquals(ProtoException.UNAUTHENTICATED, assertThrows(ProtoException.class,
				() -> microsoftLogin(MSA_TID, WORK_TID, OID, "s")).getCode());
		assertEquals(ProtoException.UNAUTHENTICATED, assertThrows(ProtoException.class,
				() -> microsoftLogin(MSA_TID, MSA_TID, null, "s")).getCode());
		try {
			assertEquals(0, principalMap.proto().getPeopleCount());
		} catch (ProtoException e) {
			throw new RuntimeException(e);
		}
	}

	// ------------------------------------------------------------------
	// MergePeople: the record's Link
	// ------------------------------------------------------------------

	/**
	 * Multi-login: signed in with Google, the person adds a Microsoft sign-in
	 * nobody has seen. That login made a throwaway XID; MergePeople folds it
	 * into the older Google person without a warning, and the merged credential
	 * carries both proofs. A fresh Microsoft login later resolves to the Google
	 * person.
	 */
	@Test
	void addingAFreshSecondSignInFoldsItIntoThePersonWithoutAWarning() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper microsoft = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		String loserXid = SessionCredential.xidOf(microsoft);

		TokenWrapper merged = mergePeople(google, google, microsoft, false);

		assertEquals(google.getSubject(), merged.getSubject(), "the older person survives");
		assertEquals(2, SessionCredential.proofsOf(merged).size());
		assertEquals(PeopleTenant.NAMESPACE,
				accessToken(exchange(merged, PeopleTenant.NAMESPACE)).getNamespace());
		Kernel.Person survivor = person();
		assertEquals(2, survivor.getLinksCount());
		assertEquals(survivor.getXid(), principalMap.getPeople(loserXid).getMergedIntoXid(),
				"the absorbed XID is tombstoned with a redirect");
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> exchange(microsoft, PeopleTenant.NAMESPACE)).getCode(),
				"the absorbed person's own credential mints nothing");

		TokenWrapper later = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		assertEquals(google.getSubject(), later.getSubject(),
				"the Microsoft account now signs in as the Google person");
	}

	/** Either order: the survivor is the older XID, whoever's bearer asked. */
	@Test
	void theOlderPersonSurvivesWhicheverSideAsks() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper microsoft = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));

		TokenWrapper merged = mergePeople(microsoft, microsoft, google, true);

		assertEquals(google.getSubject(), merged.getSubject());
	}

	/** Absorbing somebody's existing account is the warning path: confirm or nothing moves. */
	@Test
	void absorbingAnExistingAccountTakesConfirm() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		// The Microsoft person signs in again: no longer the login that made it.
		TokenWrapper returning = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		assertFalse(SessionCredential.proofsOf(returning).get(0).first());

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mergePeople(google, google, returning, false));
		assertEquals(ProtoException.FAILED_PRECONDITION, ex.getCode());
		assertEquals(2, principalMap.proto().getPeopleList().stream()
				.filter(p -> p.getMergedIntoXid().isEmpty()).count(), "nothing moved");

		TokenWrapper merged = mergePeople(google, google, returning, true);
		assertEquals(google.getSubject(), merged.getSubject());
	}

	/** The org memberships of the absorbed person move with it. */
	@Test
	void membershipsMoveToTheSurvivor() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		opaNamespace = ACME;
		TokenWrapper work = credential(microsoftLogin(WORK_TID, WORK_TID, OID, "s"));

		TokenWrapper merged = mergePeople(google, google, work, true);

		assertEquals(ACME, accessToken(exchange(merged, ACME)).getNamespace(),
				"the work proof still vouches acme, and the membership moved");
	}

	/** Two credentials of one person are a Merge: nothing is written. */
	@Test
	void mergePeopleOfOnePersonIsAMerge() throws Exception {
		TokenWrapper one = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper two = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));

		TokenWrapper merged = mergePeople(one, one, two, false);

		assertEquals(one.getSubject(), merged.getSubject());
		assertEquals(1, SessionCredential.proofsOf(merged).size());
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	/** A third person's bearer cannot join two others. */
	@Test
	void mergePeopleNeedsTheCallerToBeOneOfThem() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper microsoft = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		TokenWrapper apple = credential(login(APPLE_ISSUER, APPLE_SUB));

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> mergePeople(apple, google, microsoft, true)).getCode());
	}

	// ------------------------------------------------------------------
	// Step 4: linked accounts, Unlink, delete account, sign out everywhere
	// ------------------------------------------------------------------

	/** The linked-accounts screen: the caller's own links and memberships, nobody else's. */
	@Test
	void getLinkedAccountsListsTheCallersLinksAndMemberships() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper microsoft = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		mergePeople(google, google, microsoft, false);

		Kernel.GetLinkedAccountsResponse resp = svc.getLinkedAccounts(callerOf(google),
				Kernel.GetLinkedAccountsRequest.getDefaultInstance());

		assertEquals(SessionCredential.xidOf(google), resp.getXid());
		assertEquals(2, resp.getLinksCount());
		assertEquals(PeopleTenant.NAMESPACE, resp.getMemberships(0).getTenantNamespace());
	}

	/**
	 * Unlink removes a sign-in the session is not using; the next login with it
	 * is a new person. The sign-in the session uses is refused.
	 */
	@Test
	void unlinkRemovesAnotherSignInButNotTheOneInUse() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper microsoft = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		mergePeople(google, google, microsoft, false);

		assertEquals(ProtoException.FAILED_PRECONDITION, assertThrows(ProtoException.class,
				() -> unlink(google, "google", GOOGLE_SUB)).getCode(), "not the one you are signed in with");

		unlink(google, "microsoft", MSA_TID + ":" + OID);

		assertEquals(1, person().getLinksCount());
		TokenWrapper again = credential(microsoftLogin(MSA_TID, MSA_TID, OID, "s"));
		assertFalse(google.getSubject().equals(again.getSubject()), "an unlinked sign-in starts a new person");
		assertEquals(ProtoException.NOT_FOUND, assertThrows(ProtoException.class,
				() -> unlink(google, "apple", "never-linked")).getCode());
	}

	/** Delete account warns first; confirmed, the person is gone and the sign-in starts over. */
	@Test
	void deleteAccountIsWarnedThenTombstonesThePerson() throws Exception {
		TokenWrapper credential = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		String xid = SessionCredential.xidOf(credential);

		ProtoException warned = assertThrows(ProtoException.class, () -> deleteAccount(credential, false));
		assertEquals(ProtoException.FAILED_PRECONDITION, warned.getCode());
		assertTrue(warned.getMessage().contains("cannot be undone"), warned.getMessage());
		assertEquals(PeopleTenant.NAMESPACE, accessToken(exchange(credential, "")).getNamespace(),
				"the warning changes nothing");

		deleteAccount(credential, true);

		assertTrue(principalMap.getPeople(xid).getDeletedAtMs() > 0, "the person is tombstoned, not removed");
		assertEquals(0, principalMap.getPeople(xid).getLinksCount());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> exchange(credential, "")).getCode(), "every credential is dead");
		TokenWrapper fresh = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		assertFalse(credential.getSubject().equals(fresh.getSubject()), "the XID is never reused");
	}

	/** Sign out everywhere: the caller's own credential dies too; a new login works. */
	@Test
	void signOutEverywhereKillsEveryOutstandingCredential() throws Exception {
		TokenWrapper one = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper two = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));

		svc.revokeSessions(callerOf(one), Kernel.RevokeSessionsRequest.newBuilder()
				.setCredential(one.getBase64()).build());

		for (TokenWrapper dead : List.of(one, two)) {
			assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
					() -> exchange(dead, "")).getCode());
		}
		TokenWrapper fresh = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		assertEquals(one.getSubject(), fresh.getSubject(), "the same person signs back in");
		assertEquals(PeopleTenant.NAMESPACE, accessToken(exchange(fresh, "")).getNamespace());
	}

	/** Another person's bearer can unlink, delete or sign out nothing of yours. */
	@Test
	void step4WritesNeedTheCredentialsOwnBearer() throws Exception {
		TokenWrapper google = credential(login(GOOGLE_ISSUER, GOOGLE_SUB));
		TokenWrapper apple = credential(login(APPLE_ISSUER, APPLE_SUB));

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> svc.deleteAccount(callerOf(apple), Kernel.DeleteAccountRequest.newBuilder()
						.setCredential(google.getBase64()).setConfirm(true).build())).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> svc.revokeSessions(callerOf(apple), Kernel.RevokeSessionsRequest.newBuilder()
						.setCredential(google.getBase64()).build())).getCode());
		assertEquals(0, person().getDeletedAtMs());
	}

	private void unlink(TokenWrapper credential, String idpId, String subject) throws Exception {
		svc.deleteIdentityLink(callerOf(credential), Kernel.DeleteIdentityLinkRequest.newBuilder()
				.setCredential(credential.getBase64()).setIdpId(idpId).setProviderSubject(subject).build());
	}

	private void deleteAccount(TokenWrapper credential, boolean confirm) throws Exception {
		svc.deleteAccount(callerOf(credential), Kernel.DeleteAccountRequest.newBuilder()
				.setCredential(credential.getBase64()).setConfirm(confirm).build());
	}

	private TokenWrapper mergePeople(TokenWrapper bearer, TokenWrapper a, TokenWrapper b,
			boolean confirm) throws Exception {
		return TokenWrapper.parse(svc.mergePeople(callerOf(bearer), Kernel.MergePeopleRequest.newBuilder()
				.setCredentialA(a.getBase64()).setCredentialB(b.getBase64()).setConfirm(confirm)
				.build()).getCredential().getBase64());
	}

	/** A Microsoft login as oauth relays one: origin_iss names the directory; tid, oid verbatim. */
	private Tokenrequest.TokenMintResponse microsoftLogin(String issuerTid, String tid, String oid,
			String sub) throws Exception {
		Struct.Builder claims = Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder()
						.setStringValue("https://login.microsoftonline.com/" + issuerTid + "/v2.0").build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(sub).build())
				.putFields("tid", Value.newBuilder().setStringValue(tid).build());
		if (oid != null) {
			claims.putFields("oid", Value.newBuilder().setStringValue(oid).build());
		}
		return mint(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(claims.build())
				.build());
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
		return callerOf(credential, PeopleTenant.NAMESPACE);
	}

	/** The C2S caller with a bearer minted in {@code tenant}. */
	private static Caller callerOf(TokenWrapper credential, String tenant) {
		return new Caller("{\"sub\":\"" + credential.getSubject() + "\",\"namespace\":\""
				+ tenant + "\"}", "test-req");
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
