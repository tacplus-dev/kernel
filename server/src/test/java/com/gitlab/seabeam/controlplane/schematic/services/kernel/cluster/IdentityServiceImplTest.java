// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCert;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.grants.Grants;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityServiceImplTest {
	/**
	 * The wildcard under test is taken from the generated catalog rather than
	 * named literally: this test used to assert on {@code ANTHROPIC_ANY} and
	 * broke when the anthropic proxy left the platform (platform/proto
	 * {@code operator.proto} now reserves "anthropic"), so no such grant is
	 * generated any more. The behaviour being pinned is the expansion itself,
	 * which does not depend on which service happens to ship today.
	 */
	@Test
	void serviceEntitlementsNormalizeConvenienceWildcardsToExactRpcGrants() {
		String wildcard = Grants.tokens().stream()
				.filter(Grants::isWildcard)
				.filter(token -> !Grants.expand(token).isEmpty())
				.findFirst()
				.orElseThrow(() -> new AssertionError(
						"generated grant catalog has no expanding wildcard grant"));
		List<String> expected = Grants.expand(wildcard);

		Entitlements.TokenEntitlements entitlements = Entitlements.TokenEntitlements.newBuilder()
				.addGrants(wildcard)
				.addAzp("oauth")
				.build();

		Entitlements.TokenEntitlements normalized =
				IdentityServiceImpl.normalizeServiceEntitlements(entitlements);

		assertTrue(normalized.getGrantsList().containsAll(expected));
		assertFalse(normalized.getGrantsList().contains(wildcard));
		assertFalse(normalized.getGrantsList().stream().anyMatch(grant -> grant.endsWith("_ANY")));
		assertTrue(normalized.getAzpList().contains("oauth"));
	}

	/**
	 * principal_scope is how wide the caller's authority over PRINCIPALS is, and
	 * the generated (spec.owner_default) guard reads it off the
	 * service_entitlements claim. Normalisation rebuilds TokenEntitlements from
	 * its parts, so a field it forgets to carry is a field that reaches no
	 * service — the scope would cross opa -> kernel typed and then vanish one
	 * method before the claim is written.
	 */
	@Test
	void serviceEntitlementsNormalizationCarriesPrincipalScope() {
		Entitlements.TokenEntitlements entitlements = Entitlements.TokenEntitlements.newBuilder()
				.addAzp("oauth")
				.setPrincipalScope("PRINCIPAL_SCOPE_ANY")
				.build();

		assertEquals("PRINCIPAL_SCOPE_ANY",
				IdentityServiceImpl.normalizeServiceEntitlements(entitlements).getPrincipalScope());

		// A caller the policy stamped nothing for stays unstamped: absent is what
		// the guard fails closed on, and an empty string must not become a value.
		assertEquals("", IdentityServiceImpl.normalizeServiceEntitlements(
				Entitlements.TokenEntitlements.newBuilder().addAzp("oauth").build())
				.getPrincipalScope());
	}

	/**
	 * Every RPC in this system is made with a token scoped to one service
	 * audience, so a scope that does not survive scopeToService is a scope no
	 * handler ever sees.
	 */
	/**
	 * data_grants (BIG GOAL 3 item 7/9): a MAY_REDACT field unlock, distinct from
	 * "grants" (RPC authorization). Normalisation rebuilds TokenEntitlements from
	 * its parts the same way it does for principal_scope above, and had the same
	 * bug: the field crossed opa's EvalEntitlement result typed, and then this
	 * method dropped it silently, so no token ever carried a data_grants claim.
	 */
	@Test
	void serviceEntitlementsNormalizationCarriesDataGrants() {
		Entitlements.TokenEntitlements entitlements = Entitlements.TokenEntitlements.newBuilder()
				.addAzp("oauth")
				.addDataGrants("ACCOUNTINGRECORD_ACCOUNTING_RECORD_PRINCIPAL_SUB")
				.build();

		assertEquals(List.of("ACCOUNTINGRECORD_ACCOUNTING_RECORD_PRINCIPAL_SUB"),
				IdentityServiceImpl.normalizeServiceEntitlements(entitlements).getDataGrantsList());

		// A caller the policy stamped no data grant for stays unstamped.
		assertTrue(IdentityServiceImpl.normalizeServiceEntitlements(
				Entitlements.TokenEntitlements.newBuilder().addAzp("oauth").build())
				.getDataGrantsList().isEmpty());
	}

	/**
	 * data_grants must survive an access→service (aud-scoped) exchange
	 * unconditionally, the same way principal_scope does above — a data grant
	 * names a (record type, field) egress unlock, not an RPC, so it has no entry
	 * in the per-service Grants catalog "grants" is filtered against and would be
	 * silently dropped by a naive port of the grants-scoping logic. This is the
	 * bug that left a query-audience token (e.g. the one pull-accounting/Query
	 * calls use) without the data_grants claim a kernel-audience/login token was
	 * correctly stamped with, which is what accounting.correlates-to-row caught.
	 */
	@Test
	void serviceScopedTokenKeepsDataGrants() {
		String wildcard = Grants.tokens().stream()
				.filter(Grants::isWildcard)
				.filter(token -> !Grants.expand(token).isEmpty())
				.findFirst()
				.orElseThrow(() -> new AssertionError(
						"generated grant catalog has no expanding wildcard grant"));
		String pkg = Grants.lookup(Grants.expand(wildcard).get(0)).orElseThrow().pkg;

		Entitlements.TokenEntitlements scoped = TokenExchangeServiceImpl.scopeToService(
				Entitlements.TokenEntitlements.newBuilder()
						.addGrants(wildcard)
						.addDataGrants("ACCOUNTINGRECORD_ACCOUNTING_RECORD_PRINCIPAL_SUB")
						.build(),
				pkg);

		assertEquals(List.of("ACCOUNTINGRECORD_ACCOUNTING_RECORD_PRINCIPAL_SUB"),
				scoped.getDataGrantsList());
	}

	/**
	 * BIG GOAL 3 item 6 Piece C live proof: a DelegationProbe C2S EventBus
	 * publish route is declared in the "tasks" contract package but physically
	 * dialed through "eventbus". Policy stamps the contract-scoped wildcard
	 * (TASKS_ANY / TASKS_WRITE_ANY), so the caller's token normalizes to the
	 * TASKS_DELEGATION_PROBE_BUS_STATE_SERVICE_PUBLISH_TO_STREAM grant. Before
	 * this fix, scopeToService compared that grant's package ("tasks") directly
	 * against the physical dial audience ("eventbus") and dropped it, so a
	 * kernel-minted eventbus-audience token never carried the grant the
	 * delegated publish RPC needed — the live e2e failure this test pins.
	 */
	@Test
	void serviceScopedEventBusAudienceTokenKeepsRoutingAliasedContractGrant() {
		String contractToken = "TASKS_DELEGATION_PROBE_BUS_STATE_SERVICE_PUBLISH_TO_STREAM";
		assertTrue(Grants.tokens().contains(contractToken),
				"generated grant catalog is missing " + contractToken
						+ "; testapp/services/tasks proto must declare DelegationProbeBusStateService.PublishToStream");
		Grants.Grant contract = Grants.lookup(contractToken).orElseThrow();
		assertEquals("tasks", contract.pkg);
		assertTrue(contract.routingAliasPackages.contains("eventbus"),
				contractToken + " must carry \"eventbus\" as a generated routing-alias package");

		Entitlements.TokenEntitlements scoped = TokenExchangeServiceImpl.scopeToService(
				Entitlements.TokenEntitlements.newBuilder()
						.addGrants(contractToken)
						.build(),
				"eventbus");

		assertTrue(scoped.getGrantsList().contains(contractToken),
				"scopeToService(targetAud=eventbus) dropped the routing-aliased tasks-package grant; got "
						+ scoped.getGrantsList());
	}

	@Test
	void serviceScopedTokenKeepsPrincipalScope() {
		String wildcard = Grants.tokens().stream()
				.filter(Grants::isWildcard)
				.filter(token -> !Grants.expand(token).isEmpty())
				.findFirst()
				.orElseThrow(() -> new AssertionError(
						"generated grant catalog has no expanding wildcard grant"));
		String pkg = Grants.lookup(Grants.expand(wildcard).get(0)).orElseThrow().pkg;

		Entitlements.TokenEntitlements scoped = TokenExchangeServiceImpl.scopeToService(
				Entitlements.TokenEntitlements.newBuilder()
						.addGrants(wildcard)
						.setPrincipalScope("PRINCIPAL_SCOPE_ANY")
						.build(),
				pkg);

		assertFalse(scoped.getGrantsList().isEmpty());
		assertEquals("PRINCIPAL_SCOPE_ANY", scoped.getPrincipalScope());
	}

	/**
	 * Regression: a requested project that arrives with a leading slash was
	 * concatenated onto the tenant namespace verbatim. Minted live against the
	 * cluster, the root tenant ("/") plus a CLI-supplied "/drpepper/prod"
	 * produced {@code namespace: //drpepper/prod} — an empty path segment that
	 * {@code Spiffe.normalizeNamespace} rejects, so every level-or-below check
	 * on that token failed.
	 */
	@Test
	void projectScopedNamespaceDoesNotDoubleTheLeadingSlash() throws Exception {
		// The observed live case: the session sits at the root tenant, OPA
		// returned no authorized_projects list, and the CLI sent its profile
		// namespace ("/drpepper/prod") in TokenMintRequest.project. Before the
		// fix this minted "//drpepper/prod".
		assertEquals("/drpepper/prod", IdentityServiceImpl.projectScopedNamespace(
				sessionToken("/", "/drpepper/prod", null), ""));

		// A leading slash on an otherwise ordinary leaf.
		assertEquals("/drpepper/prod", IdentityServiceImpl.projectScopedNamespace(
				sessionToken("/drpepper", "/prod", null), ""));

		// The documented leaf form is unchanged.
		assertEquals("/drpepper/prod", IdentityServiceImpl.projectScopedNamespace(
				sessionToken("/drpepper", "prod", AUTHORIZED), ""));

		// Normalizing before the authorization check means a slash-prefixed
		// request matches the bare leaf names OPA reports.
		assertEquals("/drpepper/prod", IdentityServiceImpl.projectScopedNamespace(
				sessionToken("/drpepper", "default", AUTHORIZED), "/prod"));

		// And a whole path is now refused outright rather than silently minting
		// a malformed namespace, because the check sees the value that is
		// actually appended.
		assertThrows(IdentityServiceImpl.StatusException.class,
				() -> IdentityServiceImpl.projectScopedNamespace(
						sessionToken("/", "/drpepper/prod", AUTHORIZED), ""));
	}

	private static final String AUTHORIZED = "[\"default\",\"prod\"]";

	/**
	 * A session token carrying the v3 project claims stamped at login.
	 * {@code authorizedProjects} is null when the policy returned no list —
	 * the shape the deployed policy produced when this defect was observed.
	 */
	private static TokenWrapper sessionToken(
			String namespace, String defaultProject, String authorizedProjects) {
		TokenWrapper token = TokenWrapper.create();
		token.setNamespace(namespace);
		token.setCustomField("default_project", defaultProject);
		if (authorizedProjects != null) {
			token.setCustomField("authorized_projects", authorizedProjects);
		}
		return token;
	}

	@Test
	void serviceIntermediateCaIsRotatedWhenSigningCaChanges() throws Exception {
		ImmutableCertChain oldSigningCa = signingCa("old-signing-ca");
		ImmutableCertChain newSigningCa = signingCa("new-signing-ca");
		X509.X509CertChain serviceCa = serviceCa("oauth", oldSigningCa);

		assertNotNull(ServiceIntermediateCa.reusable(
				"oauth", serviceCa, oldSigningCa, LoggerFactory.getLogger(getClass())));
		assertNull(ServiceIntermediateCa.reusable(
				"oauth", serviceCa, newSigningCa, LoggerFactory.getLogger(getClass())));
	}

	/**
	 * Regression: origin_iss must survive the claim copy. It is an already
	 * origin_-prefixed IdP claim AND a declared JwtPayloadType, so it is a member of
	 * STANDARD_JWT_CLAIMS; when the skip check ran first the kernel dropped it on
	 * every re-mint of an access token from a stored offline/refresh token, and the
	 * entitlements policy — which derives the tenant from input.claims.origin_iss —
	 * then resolved zero grants on a token that still parsed and authenticated.
	 */
	@Test
	void alreadyOriginPrefixedClaimsSurviveTheClaimCopy() {
		String idpIssuer = "https://keycloak.example.test/realms/schematic";
		Struct claims = Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(idpIssuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue("idp-subject").build())
				.putFields("email", Value.newBuilder().setStringValue("joeuser@example.test").build())
				.putFields("token_use", Value.newBuilder().setStringValue("forged").build())
				.build();

		TokenWrapper token = TokenWrapper.create();
		token.setClaimsFromStruct(claims,
				IdentityServiceImpl.STANDARD_JWT_CLAIMS, IdentityServiceImpl.WELL_KNOWN_JWT_CLAIMS);

		// The collision that caused the bug is real: origin_iss is a declared payload type.
		assertTrue(IdentityServiceImpl.STANDARD_JWT_CLAIMS.contains("origin_iss"));

		assertEquals(idpIssuer, token.getCustomField("origin_iss"));
		assertEquals("idp-subject", token.getCustomField("origin_sub"));
		assertEquals("joeuser@example.test", token.getCustomField("email"));
		// A Schematic-internal claim supplied by the IdP is still dropped.
		assertNull(token.getCustomField("token_use"));
	}

	private static final String CALLER_SPIFFE_ID = "spiffe://local.dev/system/services/oauth";
	private static final String VICTIM_SPIFFE_ID = "spiffe://local.dev/system/services/kernel";
	private static final long MAX_TOKEN_LIFETIME_SECONDS = 2_592_000; // bootstrap default, 30 days
	private static final long DEFAULT_TOKEN_EXPIRY_SECONDS = 3_600;

	/**
	 * X509Mint used to sign {@code request.cert_request.toBuilder().addUriSans(sub)}
	 * — the caller's whole CSR with the one verified identity appended — so any
	 * service holding a valid token of its own could have a cert signed carrying
	 * another service's SPIFFE id, another service's DNS name, a spoofed subject
	 * CN, or CA:TRUE with a path length. The signed cert must assert only what
	 * kernel derived from the token it verified.
	 */
	@Test
	void x509MintSignsOnlyTheCallersVerifiedIdentityAndNoCallerConstraints() throws Exception {
		String serviceName = SpiffeIds.serviceName(CALLER_SPIFFE_ID);
		assertEquals("oauth", serviceName);

		long now = Instant.now().getEpochSecond();
		KeyPair callerKey = generateEcKeyPair();
		X509.X509CertRequest hostile = X509.X509CertRequest.newBuilder()
				.setKey(publicKeyProto("oauth-tls", callerKey))
				.setExp(now + 86_400)
				// Spoofed subject CN, identity, peer DNS name and CA rights.
				.setIssuer("kernel")
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN)
				.addUriSans(VICTIM_SPIFFE_ID)
				.addDnsNames("oauth")
				.addDnsNames("oauth-0")
				.addDnsNames("oauth0")
				.addDnsNames("kernel")
				.addDnsNames("gateway.default.svc")
				.setIsCa(true)
				.setPathLenConstraint(5)
				.build();

		X509.X509CertRequest signed = IdentityServiceImpl.kernelCertRequest(
				hostile, CALLER_SPIFFE_ID, serviceName, now,
				MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_EXPIRY_SECONDS);

		assertEquals(List.of(CALLER_SPIFFE_ID), signed.getUriSansList());
		assertEquals(serviceName, signed.getIssuer());
		assertEquals(X509.X509KeyUsage.X509_KEY_USAGE_DIGITAL_SIGNATURE, signed.getKeyUsage());
		assertFalse(signed.getIsCa());
		assertEquals(0, signed.getPathLenConstraint());
		// Names the caller owns survive (its own service name, wildcard, pod
		// hostname); another service's name does not.
		assertEquals(List.of("oauth", "*.oauth", "oauth-0", "oauth0"), signed.getDnsNamesList());

		// And the same holds of the certificate that comes out of the signer.
		ImmutableCertChain intermediateCa = ImmutableCertChain.from(
				serviceCa(serviceName, signingCa("signing-ca")));
		X509Certificate leaf = ImmutableCert.from(intermediateCa.sign(signed)).getX509Certificate();

		assertEquals("CN=oauth", leaf.getSubjectX500Principal().getName());
		assertEquals(-1, leaf.getBasicConstraints(), "leaf cert must not be a CA");
		List<String> sans = leaf.getSubjectAlternativeNames().stream()
				.map(entry -> String.valueOf(entry.get(1)))
				.toList();
		assertTrue(sans.contains(CALLER_SPIFFE_ID));
		assertFalse(sans.contains(VICTIM_SPIFFE_ID));
		assertFalse(sans.contains("kernel"));
		assertFalse(sans.contains("gateway.default.svc"));
	}

	/**
	 * The cert path dropped the max-token-lifetime ceiling every other mint path
	 * in IdentityServiceImpl applies, so a caller's requested exp was signed
	 * as-is — a decade-long service cert for the asking. Same ceiling, same
	 * INVALID_ARGUMENT, same wording as the token paths.
	 */
	@Test
	void x509MintRefusesAnExpBeyondTheMaxTokenLifetimeCeiling() throws Exception {
		long now = Instant.now().getEpochSecond();
		KeyPair callerKey = generateEcKeyPair();
		X509.X509CertRequest.Builder base = X509.X509CertRequest.newBuilder()
				.setKey(publicKeyProto("oauth-tls", callerKey))
				.setIssuer("oauth")
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_DIGITAL_SIGNATURE);

		long tenYears = now + 10L * 365 * 24 * 3600;
		IdentityServiceImpl.StatusException tooLong = assertThrows(
				IdentityServiceImpl.StatusException.class,
				() -> IdentityServiceImpl.kernelCertRequest(
						base.setExp(tenYears).build(), CALLER_SPIFFE_ID, "oauth", now,
						MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_EXPIRY_SECONDS));
		assertTrue(tooLong.getMessage().contains("exceeds max token lifetime ceiling"), tooLong.getMessage());

		// An exp in the past is refused the same way the token paths refuse it.
		assertThrows(IdentityServiceImpl.StatusException.class,
				() -> IdentityServiceImpl.kernelCertRequest(
						base.setExp(now - 1).build(), CALLER_SPIFFE_ID, "oauth", now,
						MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_EXPIRY_SECONDS));

		// A request at the ceiling, and the ordinary 24h request the generated
		// service managers send, are both honored unchanged.
		assertEquals(now + MAX_TOKEN_LIFETIME_SECONDS,
				IdentityServiceImpl.kernelCertRequest(
						base.setExp(now + MAX_TOKEN_LIFETIME_SECONDS).build(), CALLER_SPIFFE_ID, "oauth", now,
						MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_EXPIRY_SECONDS).getExp());
		assertEquals(now + 86_400,
				IdentityServiceImpl.kernelCertRequest(
						base.setExp(now + 86_400).build(), CALLER_SPIFFE_ID, "oauth", now,
						MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_EXPIRY_SECONDS).getExp());

		// No exp requested falls back to the default token expiry, as the token
		// paths do.
		assertEquals(now + DEFAULT_TOKEN_EXPIRY_SECONDS,
				IdentityServiceImpl.kernelCertRequest(
						base.clearExp().build(), CALLER_SPIFFE_ID, "oauth", now,
						MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_EXPIRY_SECONDS).getExp());
	}

	private static KeyOuterClass.PublicKey publicKeyProto(String id, KeyPair keyPair) {
		return KeyOuterClass.PublicKey.newBuilder()
				.setId(id)
				.setBase64(Base64.getUrlEncoder().withoutPadding()
						.encodeToString(keyPair.getPublic().getEncoded()))
				.build();
	}

	private static ImmutableCertChain signingCa(String name) throws Exception {
		ImmutableKey key = ImmutableKey.from(keyProto(name, generateEcKeyPair()));
		X509.X509Cert cert = ImmutableCertChain.forSelfSigning(key).selfSign(
				name,
				Instant.now().plusSeconds(86_400).getEpochSecond(),
				X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN,
				List.of());
		return ImmutableCertChain.from(X509.X509CertChain.newBuilder()
				.setId(name)
				.setKey(key.getProto())
				.addChain(cert)
				.build());
	}

	private static X509.X509CertChain serviceCa(String serviceName, ImmutableCertChain signingCa)
			throws Exception {
		KeyPair keyPair = generateEcKeyPair();
		KeyOuterClass.PublicKey publicKey = KeyOuterClass.PublicKey.newBuilder()
				.setId(serviceName + "-intermediate-ca")
				.setBase64(Base64.getUrlEncoder().withoutPadding().encodeToString(keyPair.getPublic().getEncoded()))
				.build();
		X509.X509Cert cert = signingCa.sign(X509.X509CertRequest.newBuilder()
				.setKey(publicKey)
				.setExp(Instant.now().plusSeconds(86_400).getEpochSecond())
				.setIssuer(serviceName + " Intermediate CA")
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN)
				.setIsCa(true)
				.setPathLenConstraint(0)
				.build());
		return X509.X509CertChain.newBuilder()
				.setId(serviceName)
				.setKey(keyProto(serviceName + "-intermediate-ca", keyPair))
				.addChain(cert)
				.build();
	}

	private static KeyPair generateEcKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		return generator.generateKeyPair();
	}

	private static KeyOuterClass.Key keyProto(String id, KeyPair keyPair) {
		String pem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
				+ "\n-----END PRIVATE KEY-----\n";
		return KeyOuterClass.Key.newBuilder()
				.setId(id)
				.setBase64(Base64.getUrlEncoder().withoutPadding().encodeToString(pem.getBytes()))
				.build();
	}
}
