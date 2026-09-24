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
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.ByteString;
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
import java.security.MessageDigest;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * §3 of the identity decision doc, WebAuthn/passkey arm: linking a device to a
 * person, and unlinking it again.
 *
 * <p>The thing under test is a PAIR OF BINDINGS, so nearly every test here is a
 * refusal. One request carries a WebAuthn assertion and one Apple login; the
 * id_token's {@code nonce} is the device key's RFC 7638 thumbprint, and the
 * assertion's challenge names that exact login. Either half on its own, or two
 * halves from different ceremonies, must link nothing — that is the whole
 * security claim, and "the happy path works" proves none of it.
 *
 * <p>The fake OPA answers {@code /tenants/drpepper} for every evaluation, on
 * purpose: neither side of a device link may reach it. A device side resolves
 * from the credential the assertion is signed by and a people side from the
 * verified issuer/subject, so a {@code drpepper} namespace appearing anywhere in
 * these assertions means a side fell through to {@code requireNamespaceFromOpa}.
 *
 * <p><b>On the mint tests.</b> What a link is FOR is the {@code linked} claim on
 * the device's own token, and the login that produces that token today is the
 * existing {@code AUTH_BROKER_KIND_DEVICE} JWT-proof path — the credential row
 * is the same row however it was registered, and {@code verifyDeviceProof}
 * finds it by {@code kid}. A real desktop passkey cannot sign a JWT, so a
 * WebAuthn LOGIN is a named follow-on (it needs a fresh server-issued challenge,
 * which the link ceremony does not: see the slice's decision doc). These two
 * tests therefore prove exactly what they say — that a linked device principal's
 * token carries the person's namespace, and that unlinking stops it — using the
 * login path that exists.
 */
class DeviceWebauthnLinkTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String BROKER_NAME = "personalauth";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String APPLE_SUB = "001672.9c4f1a33be7d4e1fb0c2.0913";
	private static final String TENANT_NAMESPACE = "/tenants/drpepper";
	private static final String TENANT_ISSUER = "https://login.drpepper.example/oidc";
	private static final Caller CALLER = new Caller("", "test-req");

	/** The people user the Apple login above resolves to. */
	private static final String PERSON_USER_ID = "apple." + APPLE_SUB;

	/** The relying party this deployment serves, and the one the passkey signs for. */
	private static final String RP_ID = "example.test";
	private static final String ORIGIN = "https://example.test";
	private static final WebauthnProof.RelyingParty RELYING_PARTY =
			WebauthnProof.RelyingParty.of(RP_ID, java.util.Set.of(ORIGIN));

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private KeyRotator keyRotator;
	private PrincipalMap principalMap;
	private IdentityServiceImpl svc;
	private PersonalIdentityServiceImpl personalIdentity;
	private Passkey passkey;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		// Three delegates, one per gate a device link has to pass: the people
		// tenant's own device broker (the only one that may do this), a device
		// broker rooted at /system, and a people-tenant broker that is an IdP
		// broker only. Which of the three calls is what the refusal tests vary.
		delegates.add(delegate(PeopleTenant.NAMESPACE,
				Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));
		delegates.add(delegate("", Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));
		delegates.add(delegate(TENANT_NAMESPACE,
				Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP));
		principalMap = new PrincipalMap(new InMemoryManager());
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
				new ConfigMap(new InMemoryManager()),
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // persistState
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				RELYING_PARTY);
		personalIdentity = new PersonalIdentityServiceImpl(principalMap, null);
		passkey = Passkey.generate();
	}

	// ------------------------------------------------------------------
	// Proving a device link
	// ------------------------------------------------------------------

	/**
	 * The slice in one test. A passkey nobody has seen before and one Apple login
	 * whose nonce is that key's thumbprint: the credential is registered, the
	 * person is created, and the two are linked in both directions.
	 *
	 * <p>Registration happens HERE and not in an RPC of its own, deliberately: a
	 * passkey nobody has linked belongs to nobody, so there is no moment before
	 * this one at which the row has an owner to attribute it to.
	 */
	@Test
	void aPasskeyAndAnAppleLoginRegisterTheDeviceAndLinkItToThatPerson() throws Exception {
		Kernel.CreateTenantUserLinkResponse resp = link();

		// The device side registered a personal principal holding this passkey.
		assertEquals(1, principalMap.proto().getPersonalPrincipalsCount());
		Kernel.PersonalPrincipal principal = principalMap.proto().getPersonalPrincipals(0);
		assertEquals(1, principal.getCredentialsCount());
		assertEquals(passkey.credentialId, principal.getCredentials(0).getCredentialId());
		assertEquals(passkey.publicJwk, principal.getCredentials(0).getPublicKey());
		assertEquals("Jody's ThinkPad", principal.getCredentials(0).getLabel());
		assertEquals(0, principal.getCredentials(0).getRevokedAtMs());

		// The people side created the person, the same way an ordinary IdP login
		// would: this IS an IdP login, and only an IdP creates a person.
		assertEquals(1, principalMap.proto().getPeopleCount());
		assertEquals(APPLE_SUB, principalMap.getPeople(PERSON_USER_ID).getProviderSubject());

		String deviceKey = deviceNamespace(principal) + "|" + deviceSubject(principal);
		String personKey = PeopleTenant.NAMESPACE + "|" + personSubject();
		assertEquals(deviceKey, resp.getAUserKey());
		assertEquals(personKey, resp.getBUserKey());

		Kernel.TenantUserLinks fromDevice = principalMap.getTenantUserLinks(deviceKey);
		assertEquals(1, fromDevice.getLinksCount());
		assertEquals(PeopleTenant.NAMESPACE, fromDevice.getLinks(0).getPeerNamespace());
		assertEquals(personSubject(), fromDevice.getLinks(0).getPeerSubject());

		Kernel.TenantUserLinks fromPerson = principalMap.getTenantUserLinks(personKey);
		assertEquals(1, fromPerson.getLinksCount());
		assertEquals(deviceNamespace(principal), fromPerson.getLinks(0).getPeerNamespace());
		assertEquals(resp.getCreatedAtMs(), fromPerson.getLinks(0).getCreatedAtMs());
	}

	/**
	 * BINDING ONE, the half that stops a stolen id_token.
	 *
	 * <p>A device key whose thumbprint no login ever named links nothing. Without
	 * this, any Apple id_token an attacker could obtain — including one for their
	 * OWN account, replayed at a victim's device, or one lifted from an unrelated
	 * sign-in — would attach whatever key the attacker chose to present.
	 */
	@Test
	void aDeviceKeyThatNoLoginsNonceNamesCannotLink() {
		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(request(passkey, "a-nonce-from-some-other-ceremony",
						APPLE_ISSUER, APPLE_SUB), PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertNothingWritten();
	}

	/**
	 * BINDING TWO, the half that stops a stolen assertion.
	 *
	 * <p>The assertion is real, signed by the real key, and the login's nonce IS
	 * this key's thumbprint — but the assertion was produced against a different
	 * login (a different Apple subject), so its challenge names a ceremony that is
	 * not the one presented. This is the replay the design has to refuse: an
	 * attacker who captures an assertion must not be able to pair it with an
	 * id_token they can obtain themselves.
	 */
	@Test
	void anAssertionFromAnotherCeremonyCannotBeReplayedOntoThisLogin() throws Exception {
		Kernel.WebauthnAssertion stale = passkey.assertFor(
				WebauthnProof.loginBinding(APPLE_ISSUER, "some.other.apple.subject",
						WebauthnProof.thumbprint(passkey.publicJwk)));

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(requestWith(stale, passkey.publicJwk,
						WebauthnProof.thumbprint(passkey.publicJwk), APPLE_ISSUER, APPLE_SUB),
						PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertNothingWritten();
	}

	/**
	 * BINDING THREE, the relying party: the authenticator's own statement of
	 * which domain it unlocked the key for.
	 *
	 * <p>Everything else about this request holds — the key is real, the
	 * signature verifies, the nonce is the thumbprint, the challenge names this
	 * exact login. Only the {@code rpIdHash} names another domain, which is what
	 * an assertion collected by a hostile relying party looks like.
	 */
	@Test
	void anAssertionProducedForAnotherRelyingPartyLinksNothing() throws Exception {
		Kernel.WebauthnAssertion elsewhere = passkey.assertFor(
				WebauthnProof.loginBinding(APPLE_ISSUER, APPLE_SUB,
						WebauthnProof.thumbprint(passkey.publicJwk)),
				"attacker.test", ORIGIN);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(requestWith(elsewhere, passkey.publicJwk,
						WebauthnProof.thumbprint(passkey.publicJwk), APPLE_ISSUER, APPLE_SUB),
						PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("different relying party"), ex.getMessage());
		assertNothingWritten();
	}

	/**
	 * The other half of the pair: the BROWSER's statement of which page asked.
	 * The RP ID is this deployment's, so the authenticator is satisfied — a
	 * look-alike page served under the same RP ID is exactly the case the origin
	 * is there to catch.
	 */
	@Test
	void anAssertionCollectedFromAnotherOriginLinksNothing() throws Exception {
		Kernel.WebauthnAssertion elsewhere = passkey.assertFor(
				WebauthnProof.loginBinding(APPLE_ISSUER, APPLE_SUB,
						WebauthnProof.thumbprint(passkey.publicJwk)),
				RP_ID, "https://phish.example.test");

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(requestWith(elsewhere, passkey.publicJwk,
						WebauthnProof.thumbprint(passkey.publicJwk), APPLE_ISSUER, APPLE_SUB),
						PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("origin this deployment does not serve"),
				ex.getMessage());
		assertNothingWritten();
	}

	/**
	 * A deployment that configured no relying party refuses every assertion
	 * rather than accepting an unchecked one. There is no constant that would be
	 * right for two deployments, so the absent configuration must fail closed —
	 * and this is the test that says so, because nothing else would notice the
	 * difference between "no relying party" and "no check".
	 */
	@Test
	void anUnconfiguredRelyingPartyRefusesAPerfectlyGoodAssertion() throws Exception {
		String challenge = WebauthnProof.loginBinding(APPLE_ISSUER, APPLE_SUB,
				WebauthnProof.thumbprint(passkey.publicJwk));
		Kernel.WebauthnAssertion good = passkey.assertFor(challenge);

		WebauthnProof.verify(good, passkey.publicJwk, challenge, RELYING_PARTY);

		WebauthnProof.Invalid ex = assertThrows(WebauthnProof.Invalid.class,
				() -> WebauthnProof.verify(good, passkey.publicJwk, challenge,
						WebauthnProof.RelyingParty.NONE));
		assertEquals("no WebAuthn relying party is configured to check against",
				ex.getMessage());
	}

	/**
	 * The environment is the deployment's configuration surface, and half of it
	 * is not configuration: an RP ID with no origins would check one half of
	 * WebAuthn's anti-phishing pair and silently skip the other.
	 */
	@Test
	void halfAnEnvironmentConfiguresNoRelyingParty() {
		assertTrue(WebauthnProof.RelyingParty.fromEnvironment(java.util.Map.of(
				WebauthnProof.RelyingParty.RP_ID_ENV, RP_ID,
				WebauthnProof.RelyingParty.ORIGINS_ENV, ORIGIN)).isConfigured());
		assertFalse(WebauthnProof.RelyingParty.fromEnvironment(java.util.Map.of(
				WebauthnProof.RelyingParty.RP_ID_ENV, RP_ID)).isConfigured());
		assertFalse(WebauthnProof.RelyingParty.fromEnvironment(java.util.Map.of(
				WebauthnProof.RelyingParty.ORIGINS_ENV, ORIGIN)).isConfigured());
		assertFalse(WebauthnProof.RelyingParty.fromEnvironment(java.util.Map.of(
				WebauthnProof.RelyingParty.RP_ID_ENV, "  ",
				WebauthnProof.RelyingParty.ORIGINS_ENV, ORIGIN)).isConfigured());
		assertFalse(WebauthnProof.RelyingParty.fromEnvironment(java.util.Map.of()).isConfigured());
	}

	/**
	 * The signature is checked by kernel, against the key, over bytes kernel
	 * recomputes. A broker that rewrote any of the four assertion fields — or an
	 * attacker who never held the private half — produces this.
	 */
	@Test
	void anAssertionWhoseSignatureDoesNotVerifyLinksNothing() throws Exception {
		Kernel.WebauthnAssertion good = passkey.assertFor(
				WebauthnProof.loginBinding(APPLE_ISSUER, APPLE_SUB,
						WebauthnProof.thumbprint(passkey.publicJwk)));
		byte[] tampered = good.getSignature().toByteArray();
		tampered[0] ^= 0x01;

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(requestWith(
						good.toBuilder().setSignature(ByteString.copyFrom(tampered)).build(),
						passkey.publicJwk, WebauthnProof.thumbprint(passkey.publicJwk),
						APPLE_ISSUER, APPLE_SUB),
						PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertNothingWritten();
	}

	/**
	 * Once a credential is registered, the STORED key is what the assertion is
	 * checked against — the request's copy is consulted exactly once, on the
	 * first link, when there is no row to consult instead.
	 *
	 * <p>Without that, a broker (or anyone reaching this RPC) could re-present a
	 * registered credential id under a key of its own and link somebody else's
	 * device id to its own person. Here the second key's thumbprint is what the
	 * login names, so the request is internally consistent and still refused.
	 */
	@Test
	void aRegisteredCredentialIdCannotBeReclaimedUnderADifferentKey() throws Exception {
		link();
		Passkey impostor = Passkey.generate(passkey.credentialId);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(request(impostor, WebauthnProof.thumbprint(impostor.publicJwk),
						APPLE_ISSUER, APPLE_SUB), PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals(passkey.publicJwk,
				principalMap.proto().getPersonalPrincipals(0).getCredentials(0).getPublicKey());
	}

	/**
	 * A device links to a PERSON. The other side being an ordinary tenant login
	 * would make the device a credential for an account kernel did not create and
	 * cannot re-derive — and would put a tenant namespace in the device's
	 * {@code linked} claim on a proof the tenant's own IdP never saw.
	 */
	@Test
	void aDeviceCannotLinkToAnOrdinaryTenantLogin() throws Exception {
		String thumbprint = WebauthnProof.thumbprint(passkey.publicJwk);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> linkCall(request(passkey, thumbprint, TENANT_ISSUER, "jody"),
						PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertNothingWritten();
	}

	/**
	 * Two gates, both required, neither implied by the other: the caller must be
	 * a delegate trusted to broker a DEVICE proof, and it must be rooted at the
	 * people tenant (§2's people-side gate, unchanged). A device broker parked in
	 * /system could otherwise name an Apple subject it never authenticated.
	 */
	@Test
	void aDeviceLinkNeedsADeviceBrokerRootedAtThePeopleTenant() throws Exception {
		String thumbprint = WebauthnProof.thumbprint(passkey.publicJwk);
		Kernel.CreateTenantUserLinkRequest request =
				request(passkey, thumbprint, APPLE_ISSUER, APPLE_SUB);

		// A device broker, but in /system: it passes the broker-kind gate and
		// fails the people-side one.
		assertEquals(ProtoException.PERMISSION_DENIED,
				assertThrows(ProtoException.class, () -> linkCall(request, "",
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)).getCode());
		// A people-tenant broker, but an IdP broker only: it fails the first gate.
		assertEquals(ProtoException.PERMISSION_DENIED,
				assertThrows(ProtoException.class, () -> linkCall(request, TENANT_NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)).getCode());
		assertNothingWritten();
	}

	/** A link joins a device to a person. Two assertions prove no login at all. */
	@Test
	void twoDeviceSidesAreRefused() throws Exception {
		String thumbprint = WebauthnProof.thumbprint(passkey.publicJwk);
		Kernel.CreateTenantUserLinkRequest request = Kernel.CreateTenantUserLinkRequest.newBuilder()
				.setA(deviceSide(passkey, thumbprint))
				.setB(deviceSide(Passkey.generate(), thumbprint))
				.build();

		assertEquals(ProtoException.INVALID_ARGUMENT,
				assertThrows(ProtoException.class, () -> linkCall(request, PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)).getCode());
		assertNothingWritten();
	}

	/**
	 * A device kernel has never seen has no stored key, so it must present one.
	 * Refusing rather than defaulting is what keeps "the request's copy is used
	 * once, and only when there is nothing else" a property rather than a habit.
	 */
	@Test
	void anUnregisteredDeviceMustPresentItsPublicKey() throws Exception {
		Kernel.TenantUserLinkSide keyless = deviceSide(passkey,
				WebauthnProof.thumbprint(passkey.publicJwk)).toBuilder()
				.clearDevicePublicKey()
				.build();
		Kernel.CreateTenantUserLinkRequest request = Kernel.CreateTenantUserLinkRequest.newBuilder()
				.setA(keyless)
				.setB(loginSide(APPLE_ISSUER, APPLE_SUB,
						WebauthnProof.thumbprint(passkey.publicJwk)))
				.build();

		assertEquals(ProtoException.INVALID_ARGUMENT,
				assertThrows(ProtoException.class, () -> linkCall(request, PeopleTenant.NAMESPACE,
						Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)).getCode());
		assertNothingWritten();
	}

	/**
	 * Presenting the same device and the same person again is the same fact: one
	 * principal, one credential, one edge each way. Replaying the whole request
	 * is therefore harmless, which is what lets the assertion carry no freshness
	 * of its own — the same position §2 took on replaying both id_tokens.
	 */
	@Test
	void relinkingTheSameDeviceIsIdempotent() throws Exception {
		Kernel.CreateTenantUserLinkResponse first = link();
		Kernel.CreateTenantUserLinkResponse again = link();

		assertEquals(first.getAUserKey(), again.getAUserKey());
		assertEquals(first.getCreatedAtMs(), again.getCreatedAtMs());
		assertEquals(1, principalMap.proto().getPersonalPrincipalsCount());
		assertEquals(1, principalMap.getTenantUserLinks(first.getAUserKey()).getLinksCount());
		assertEquals(1, principalMap.getTenantUserLinks(first.getBUserKey()).getLinksCount());
	}

	// ------------------------------------------------------------------
	// What the link is for, and taking it away
	// ------------------------------------------------------------------

	/**
	 * The point of the whole slice: after linking, the DEVICE's own token carries
	 * {@code /tenants/people} as a {@code linked} claim, so the generated
	 * namespace backstop accepts a row in the person's subtree. Before the link,
	 * the same device's token carries nothing.
	 *
	 * <p>See the class javadoc on why the login here is the JWT-proof device arm.
	 */
	@Test
	void aLinkedDevicesTokenCarriesThePeopleNamespace() throws Exception {
		link();

		TokenWrapper refresh = TokenWrapper.parse(deviceMint().getRefreshToken().getBase64());
		assertEquals(List.of(PeopleTenant.NAMESPACE), refresh.getLinked());
		assertNotEquals(TENANT_NAMESPACE, refresh.getNamespace(),
				"a device side must never take its namespace from OPA");
		// The access token is cloned from the refresh token, so the claim reaches
		// the token services actually present.
		assertEquals(List.of(PeopleTenant.NAMESPACE),
				TokenWrapper.parse(deviceMint().getAccessToken().getBase64()).getLinked());
	}

	/**
	 * Unlink, end to end, from the device's own token: the mark is written on both
	 * directions and the {@code linked} claim stops appearing at the very next
	 * mint. A device that can no longer read the person's rows is the observable
	 * meaning of "the person unlinked it".
	 *
	 * <p>The credential itself is NOT revoked — the device is still a principal
	 * and can still log in as itself. Unlinking withdraws reach into the person's
	 * namespace, which is exactly what the link granted.
	 */
	@Test
	void unlinkingStopsTheLinkedClaimAtTheNextMint() throws Exception {
		Kernel.CreateTenantUserLinkResponse linked = link();
		Kernel.PersonalPrincipal principal = principalMap.proto().getPersonalPrincipals(0);
		assertEquals(List.of(PeopleTenant.NAMESPACE),
				TokenWrapper.parse(deviceMint().getRefreshToken().getBase64()).getLinked());

		Kernel.RevokeTenantUserLinkResponse revoked = personalIdentity.revokeTenantUserLink(
				linkOwner(deviceNamespace(principal), deviceSubject(principal)),
				Kernel.RevokeTenantUserLinkRequest.newBuilder()
						.setPeerNamespace(PeopleTenant.NAMESPACE)
						.setPeerSubject(personSubject())
						.build());

		assertTrue(revoked.getRevokedAtMs() > 0);
		assertTrue(TokenWrapper.parse(deviceMint().getRefreshToken().getBase64())
				.getLinked().isEmpty(), "an unlinked device must carry no linked claim");
		// Both directions are marked, or the person's own token would still name
		// the device's namespace.
		assertEquals(revoked.getRevokedAtMs(), principalMap
				.getTenantUserLinks(linked.getAUserKey()).getLinks(0).getRevokedAtMs());
		assertEquals(revoked.getRevokedAtMs(), principalMap
				.getTenantUserLinks(linked.getBUserKey()).getLinks(0).getRevokedAtMs());
		// Marked, never deleted: the edge is still there to be audited.
		assertEquals(1, principalMap.getTenantUserLinks(linked.getAUserKey()).getLinksCount());
		// And the device is still a principal with a live credential.
		assertEquals(0, principalMap.proto().getPersonalPrincipals(0)
				.getCredentials(0).getRevokedAtMs());
	}

	/**
	 * Either side may unlink — "from any linked device or via the people tenant
	 * flow" (§3). The person's own token revokes the same edge, and the owner
	 * half still comes from the caller's {@code sub}, never the request.
	 */
	@Test
	void thePersonCanUnlinkTheDeviceFromTheirOwnSide() throws Exception {
		Kernel.CreateTenantUserLinkResponse linked = link();
		Kernel.PersonalPrincipal principal = principalMap.proto().getPersonalPrincipals(0);

		personalIdentity.revokeTenantUserLink(
				linkOwner(PeopleTenant.NAMESPACE, personSubject()),
				Kernel.RevokeTenantUserLinkRequest.newBuilder()
						.setPeerNamespace(deviceNamespace(principal))
						.setPeerSubject(deviceSubject(principal))
						.build());

		assertTrue(TokenWrapper.parse(deviceMint().getRefreshToken().getBase64())
				.getLinked().isEmpty());
		assertNotEquals(0, principalMap.getTenantUserLinks(linked.getAUserKey())
				.getLinks(0).getRevokedAtMs());
	}

	/**
	 * Re-proving a link after an unlink restores it, and does not leave a second
	 * edge behind: a row carrying one live and one revoked edge for one peer
	 * would make "is this link live?" depend on which the reader saw first.
	 */
	@Test
	void relinkingAfterAnUnlinkClearsTheMarkRatherThanAddingAnEdge() throws Exception {
		Kernel.CreateTenantUserLinkResponse linked = link();
		Kernel.PersonalPrincipal principal = principalMap.proto().getPersonalPrincipals(0);
		personalIdentity.revokeTenantUserLink(
				linkOwner(deviceNamespace(principal), deviceSubject(principal)),
				Kernel.RevokeTenantUserLinkRequest.newBuilder()
						.setPeerNamespace(PeopleTenant.NAMESPACE)
						.setPeerSubject(personSubject())
						.build());

		link();

		assertEquals(1, principalMap.getTenantUserLinks(linked.getAUserKey()).getLinksCount());
		assertEquals(0, principalMap.getTenantUserLinks(linked.getAUserKey())
				.getLinks(0).getRevokedAtMs());
		assertEquals(List.of(PeopleTenant.NAMESPACE),
				TokenWrapper.parse(deviceMint().getRefreshToken().getBase64()).getLinked());
	}

	/**
	 * The owner half of the edge is the caller's own key, so "no such link" and
	 * "that link is not yours" are necessarily the same answer. Nothing here can
	 * be used to discover whether somebody else's link exists.
	 */
	@Test
	void unlinkingSomethingThatIsNotLinkedIsNotFound() throws Exception {
		link();
		Kernel.PersonalPrincipal principal = principalMap.proto().getPersonalPrincipals(0);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> personalIdentity.revokeTenantUserLink(
						linkOwner(deviceNamespace(principal), deviceSubject(principal)),
						Kernel.RevokeTenantUserLinkRequest.newBuilder()
								.setPeerNamespace(TENANT_NAMESPACE)
								.setPeerSubject("jody@drpepper.example")
								.build()));

		assertEquals(ProtoException.NOT_FOUND, ex.getCode());
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	/**
	 * A verified caller standing in one namespace as one subject. {@code Caller}
	 * wraps the VERIFIED TOKEN PAYLOAD, not a subject string, and the unlink
	 * handler reads the minted `namespace` and `sub` claims straight out of it —
	 * the same pair the link registry is keyed on.
	 */
	private static Caller linkOwner(String namespace, String subject) {
		return new Caller("{\"sub\":\"" + subject + "\",\"namespace\":\"" + namespace + "\"}",
				"test-req");
	}

	private static Kernel.Delegate delegate(String namespace, Tokenrequest.AuthBrokerKind kind) {
		return Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.setTenantNamespace(namespace)
				.addAuthBrokerKinds(kind)
				.build();
	}

	private String personSubject() {
		return Spiffe.userSpiffeId(TRUST_DOMAIN, PeopleTenant.NAMESPACE, PERSON_USER_ID);
	}

	private static String deviceNamespace(Kernel.PersonalPrincipal principal) {
		return "/" + Spiffe.PEOPLE_SEGMENT + "/" + principal.getPrincipalId();
	}

	private String deviceSubject(Kernel.PersonalPrincipal principal) {
		return Spiffe.userSpiffeId(TRUST_DOMAIN, deviceNamespace(principal),
				principal.getPrincipalId());
	}

	private void assertNothingWritten() {
		try {
			assertEquals(0, principalMap.proto().getTenantUserLinksCount(),
					"an unbound proof must link nothing");
			assertEquals(0, principalMap.proto().getPersonalPrincipalsCount(),
					"an unbound proof must register nothing");
			assertEquals(0, principalMap.proto().getPeopleCount(),
					"an unbound proof must create nobody");
		} catch (ProtoException e) {
			throw new RuntimeException(e);
		}
	}

	/** The claim shape the broker relays: the IdP's own iss/sub/nonce, verified. */
	private static Struct idpClaims(String issuer, String sub, String nonce) {
		return Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(sub).build())
				.putFields("origin_nonce", Value.newBuilder().setStringValue(nonce).build())
				.build();
	}

	private static Kernel.TenantUserLinkSide loginSide(String issuer, String sub, String nonce) {
		return Kernel.TenantUserLinkSide.newBuilder()
				.setClaims(idpClaims(issuer, sub, nonce))
				.setSubject("whatever-the-broker-says")
				.build();
	}

	/** A device side whose assertion is bound to the login the arguments name. */
	private static Kernel.TenantUserLinkSide deviceSide(Passkey key, String nonce)
			throws Exception {
		return sideWith(key.assertFor(WebauthnProof.loginBinding(APPLE_ISSUER, APPLE_SUB, nonce)),
				key.publicJwk);
	}

	private static Kernel.TenantUserLinkSide sideWith(Kernel.WebauthnAssertion assertion,
			JwkOuterClass.Jwk publicKey) {
		return Kernel.TenantUserLinkSide.newBuilder()
				.setDeviceAssertion(assertion)
				.setDevicePublicKey(publicKey)
				.setDeviceLabel("Jody's ThinkPad")
				.build();
	}

	/**
	 * One device link: the passkey's assertion bound to an Apple login carrying
	 * {@code nonce}. The caller chooses the nonce and the login, which is how the
	 * refusal tests take the two bindings apart one at a time.
	 */
	private static Kernel.CreateTenantUserLinkRequest request(
			Passkey key, String nonce, String issuer, String sub) throws Exception {
		return requestWith(
				key.assertFor(WebauthnProof.loginBinding(issuer, sub, nonce)),
				key.publicJwk, nonce, issuer, sub);
	}

	private static Kernel.CreateTenantUserLinkRequest requestWith(
			Kernel.WebauthnAssertion assertion, JwkOuterClass.Jwk publicKey,
			String nonce, String issuer, String sub) {
		return Kernel.CreateTenantUserLinkRequest.newBuilder()
				.setA(sideWith(assertion, publicKey))
				.setB(loginSide(issuer, sub, nonce))
				.build();
	}

	/** The well-formed link this class's happy paths use. */
	private Kernel.CreateTenantUserLinkResponse link() throws Exception {
		return linkCall(
				request(passkey, WebauthnProof.thumbprint(passkey.publicJwk), APPLE_ISSUER, APPLE_SUB),
				PeopleTenant.NAMESPACE, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE);
	}

	private Kernel.CreateTenantUserLinkResponse linkCall(
			Kernel.CreateTenantUserLinkRequest request, String brokerNamespace,
			Tokenrequest.AuthBrokerKind brokerKind) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current().withValue(
				ClusterServer.RAW_AUTH_TOKEN_KEY, brokerToken(brokerNamespace, brokerKind));
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.createTenantUserLink(CALLER, request);
		} finally {
			ctx.detach(previous);
		}
	}

	/** The device's own login, through the existing AUTH_BROKER_KIND_DEVICE arm. */
	private Tokenrequest.TokenMintResponse deviceMint() throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current().withValue(
				ClusterServer.RAW_AUTH_TOKEN_KEY,
				brokerToken("", Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintUserToken(CALLER, Tokenrequest.MintUserTokenRequest.newBuilder()
					.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)
					.setProofToken(passkey.jwtProof())
					.build());
		} finally {
			ctx.detach(previous);
		}
	}

	/**
	 * The broker's own S2S token. Its SPIFFE subject carries the namespace the
	 * delegate is rooted at, which is what selects the delegate and gates whether
	 * a people side may be attested at all.
	 */
	private String brokerToken(String brokerNamespace, Tokenrequest.AuthBrokerKind kind) {
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

	/**
	 * One passkey: the Ed25519 pair a desktop authenticator holds, the public
	 * half as the JWK kernel stores, and a real WebAuthn assertion over
	 * {@code authenticatorData || SHA-256(clientDataJSON)}.
	 *
	 * <p>Ed25519 rather than P-256 only because the JDK's raw-Ed25519 signature
	 * needs no DER handling in a test fixture; kernel accepts all three WebAuthn
	 * key types and picks the algorithm from the key's own shape.
	 */
	private static final class Passkey {
		private final String credentialId;
		private final PrivateKey privateKey;
		private final JwkOuterClass.Jwk publicJwk;

		private Passkey(String credentialId, PrivateKey privateKey, JwkOuterClass.Jwk publicJwk) {
			this.credentialId = credentialId;
			this.privateKey = privateKey;
			this.publicJwk = publicJwk;
		}

		static Passkey generate() throws Exception {
			return generate(B64.encodeToString(UUID.randomUUID().toString()
					.getBytes(StandardCharsets.UTF_8)));
		}

		static Passkey generate(String credentialId) throws Exception {
			KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
			// Ed25519 X.509 encoding: the last 32 bytes are the raw public key.
			byte[] x509Encoded = pair.getPublic().getEncoded();
			byte[] rawPub = new byte[32];
			System.arraycopy(x509Encoded, x509Encoded.length - 32, rawPub, 0, 32);
			return new Passkey(credentialId, pair.getPrivate(), JwkOuterClass.Jwk.newBuilder()
					.setKid(credentialId)
					.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
					.setAlg("EdDSA")
					.setCrv("Ed25519")
					.setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG)
					.setX(B64.encodeToString(rawPub))
					.setCreated(Instant.now().getEpochSecond())
					.build());
		}

		/** A real assertion over the challenge given, as a browser would produce. */
		Kernel.WebauthnAssertion assertFor(String challenge) throws Exception {
			return assertFor(challenge, RP_ID, ORIGIN);
		}

		/**
		 * The same assertion, but produced for the relying party named — the
		 * fixture a phished ceremony needs. Everything else is identical and the
		 * signature is real, so a test using it fails on the relying party or on
		 * nothing.
		 */
		Kernel.WebauthnAssertion assertFor(String challenge, String rpId, String origin)
				throws Exception {
			// rpIdHash(32) || flags(1) || signCount(4). Flags 0x05 = user present +
			// user verified, which is what a passkey unlock sets.
			byte[] authenticatorData = new byte[37];
			System.arraycopy(sha256(rpId.getBytes(StandardCharsets.UTF_8)), 0,
					authenticatorData, 0, 32);
			authenticatorData[32] = 0x05;
			authenticatorData[36] = 0x01;

			byte[] clientDataJson = ("{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge
					+ "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}")
					.getBytes(StandardCharsets.UTF_8);

			byte[] signed = new byte[authenticatorData.length + 32];
			System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
			System.arraycopy(sha256(clientDataJson), 0, signed, authenticatorData.length, 32);

			Signature signer = Signature.getInstance("Ed25519");
			signer.initSign(privateKey);
			signer.update(signed);

			return Kernel.WebauthnAssertion.newBuilder()
					.setCredentialId(credentialId)
					.setAuthenticatorData(ByteString.copyFrom(authenticatorData))
					.setClientDataJson(ByteString.copyFrom(clientDataJson))
					.setSignature(ByteString.copyFrom(signer.sign()))
					.build();
		}

		/**
		 * A possession proof for the EXISTING device login arm — see the class
		 * javadoc. A real passkey cannot produce this; this key can, which is what
		 * lets the mint half of the slice be proven against the credential row the
		 * link actually wrote rather than a hand-seeded copy of it.
		 */
		String jwtProof() throws Exception {
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

		private static byte[] sha256(byte[] input) throws Exception {
			return MessageDigest.getInstance("SHA-256").digest(input);
		}
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
					.setNamespace(TENANT_NAMESPACE)
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
