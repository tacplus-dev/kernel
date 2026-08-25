// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.grants.Grants;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
