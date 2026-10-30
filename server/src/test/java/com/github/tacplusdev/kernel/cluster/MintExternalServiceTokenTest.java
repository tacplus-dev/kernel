// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code Mint.MintExternalServiceToken}: a service's OWN identity, minted fresh
 * on every call as an ES256 token for an off-cluster audience the caller's
 * Delegate allowlists in {@code external_audiences}.
 */
class MintExternalServiceTokenTest {

	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String SERVICE_SUB = "spiffe://test.schematic.io/system/services/llmproxy";
	private static final String ANTHROPIC_AUD = "https://api.anthropic.com";
	private static final long DEFAULT_EXPIRY_SECONDS = 3600;
	private static final long MAX_LIFETIME_SECONDS = 86_400;
	/** Tolerance for the second boundary between the test's `now` and the impl's. */
	private static final long SKEW_SECONDS = 5;

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	private IdentityServiceImpl identityService;

	@BeforeEach
	void setUp() {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		delegates.add(Kernel.Delegate.newBuilder()
				.setName("llmproxy")
				.addExternalAudiences(ANTHROPIC_AUD)
				.build());

		identityService = new IdentityServiceImpl(
				DEFAULT_EXPIRY_SECONDS, 900, 86_400, MAX_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				List::of,        // grants
				null,            // grantsWriter
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> "test.schematic.io",
				ISSUER,
				null,            // opaEvalClient — this path never calls OPA
				null,            // proxyPolicyOpaClient — nor proxy policy
				null,            // tenantConfigs
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty
	}

	@AfterEach
	void tearDown() {
		keyRotator.stop();
	}

	@Test
	void mintsAnEs256ExternalTokenForAnAllowlistedAudience() {
		long now = Instant.now().getEpochSecond();
		String es256Kid = keyRotator.getActiveJwk(KeyRotator.SigAlg.ES256).getKid();

		TokenWrapper token = mint(request(serviceToken(SERVICE_SUB, now + 3600), ANTHROPIC_AUD, now + 600));

		assertEquals("ES256", token.getAlg());
		assertEquals(es256Kid, token.getKid());
		assertEquals(ISSUER, token.getIssuer());
		assertEquals(SERVICE_SUB, token.getSubject());
		assertEquals(ANTHROPIC_AUD, token.getAudience());
		assertEquals("external", token.getTokenUse());
		assertEquals("/system", token.getNamespace());
		assertWithinSkew(now, token.getIssuedAt());
		assertEquals(now + 600, token.getExpiration());
	}

	@Test
	void rejectsAnAudienceNotInTheDelegatesAllowlist() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(serviceToken(SERVICE_SUB, now + 3600), "https://evil.example.com", 0)));

		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
	}

	@Test
	void rejectsAnAllowlistEntryThatIsOnlyAPrefixMatch() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(serviceToken(SERVICE_SUB, now + 3600), ANTHROPIC_AUD + "/", 0)));

		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
	}

	/** A member-port audience (kernel#30) is MintToken's alone, even when allowlisted here. */
	@Test
	void rejectsAMemberPortAudienceEvenWhenAllowlisted() {
		long now = Instant.now().getEpochSecond();
		delegates.replaceAll(d -> d.toBuilder().addExternalAudiences("member:llmproxy").build());

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(serviceToken(SERVICE_SUB, now + 3600), "member:llmproxy", 0)));

		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
	}

	@Test
	void rejectsACallerWithNoDelegate() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(serviceToken("spiffe://test.schematic.io/system/services/stranger", now + 3600),
						ANTHROPIC_AUD, 0)));

		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
	}

	@Test
	void rejectsAUserToken() {
		long now = Instant.now().getEpochSecond();
		TokenWrapper user = baseToken(SERVICE_SUB, now + 3600);
		user.setSubType("user");
		user.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(user.getBase64(), ANTHROPIC_AUD, 0)));

		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
	}

	@Test
	void rejectsATokenNotSignedByKernel() throws Exception {
		long now = Instant.now().getEpochSecond();
		KeyRotator foreign = new KeyRotator(3600, 86_400, j -> { }, kid -> { }, List::of, null);
		foreign.start();
		try {
			TokenWrapper forged = baseToken(SERVICE_SUB, now + 3600);
			forged.setSubType("service");
			forged.sign(foreign.getActiveSigningKey(KeyRotator.SigAlg.ED25519));

			ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
					request(forged.getBase64(), ANTHROPIC_AUD, 0)));

			assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		} finally {
			foreign.stop();
		}
	}

	@Test
	void subjectComesFromTheInputTokenNeverTheRequest() {
		long now = Instant.now().getEpochSecond();
		// The request carries no subject field at all; the only identity in play is
		// the verified token's. A second allowlisted delegate proves sub tracks it.
		String other = "spiffe://test.schematic.io/system/services/argus";
		delegates.add(Kernel.Delegate.newBuilder().setName("argus").addExternalAudiences(ANTHROPIC_AUD).build());

		assertEquals(SERVICE_SUB, mint(request(serviceToken(SERVICE_SUB, now + 3600), ANTHROPIC_AUD, 0)).getSubject());
		assertEquals(other, mint(request(serviceToken(other, now + 3600), ANTHROPIC_AUD, 0)).getSubject());
	}

	@Test
	void everyCallMintsANewTokenWithAFreshJti() {
		long now = Instant.now().getEpochSecond();
		String input = serviceToken(SERVICE_SUB, now + 3600);
		Tokenrequest.MintExternalServiceTokenRequest req = request(input, ANTHROPIC_AUD, now + 600);

		TokenWrapper first = mint(req);
		TokenWrapper second = mint(req);

		assertNotEquals(first.getJTI(), second.getJTI());
		assertNotEquals(first.getBase64(), second.getBase64());
	}

	@Test
	void rejectsARequestedExpBeyondNowPlus600() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(serviceToken(SERVICE_SUB, now + 3600), ANTHROPIC_AUD, now + 601 + SKEW_SECONDS)));

		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
	}

	@Test
	void rejectsARequestedExpInThePast() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class, () -> identityService.mintExternalServiceToken(null,
				request(serviceToken(SERVICE_SUB, now + 3600), ANTHROPIC_AUD, now - 1)));

		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
	}

	@Test
	void zeroExpDefaultsToNowPlus600() {
		long now = Instant.now().getEpochSecond();

		TokenWrapper token = mint(request(serviceToken(SERVICE_SUB, now + 3600), ANTHROPIC_AUD, 0));

		assertWithinSkew(now + 600, token.getExpiration());
	}

	@Test
	void neverOutlivesTheInputToken() {
		long now = Instant.now().getEpochSecond();
		long inputExp = now + 120;

		TokenWrapper token = mint(request(serviceToken(SERVICE_SUB, inputExp), ANTHROPIC_AUD, now + 600));

		assertEquals(inputExp, token.getExpiration());
	}

	// ---- fixture -----------------------------------------------------------

	private TokenWrapper mint(Tokenrequest.MintExternalServiceTokenRequest request) {
		return TokenWrapper.from(identityService.mintExternalServiceToken(null, request).getAccessToken());
	}

	private static Tokenrequest.MintExternalServiceTokenRequest request(String inputToken, String aud, long exp) {
		return Tokenrequest.MintExternalServiceTokenRequest.newBuilder()
				.setInputToken(inputToken)
				.setAud(aud)
				.setExp(exp)
				.build();
	}

	/** A kernel-signed service token for kernel's own audience — what the generated client sends. */
	private String serviceToken(String subject, long exp) {
		TokenWrapper token = baseToken(subject, exp);
		token.setSubType("service");
		token.setTokenUse("access");
		token.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));
		return token.getBase64();
	}

	private static TokenWrapper baseToken(String subject, long exp) {
		return TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(Instant.now().getEpochSecond())
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString())
				.setNamespace("/system");
	}

	private static void assertWithinSkew(long expected, long actual) {
		assertTrue(Math.abs(actual - expected) <= SKEW_SECONDS,
				"expected near " + expected + ", got " + actual);
	}
}
