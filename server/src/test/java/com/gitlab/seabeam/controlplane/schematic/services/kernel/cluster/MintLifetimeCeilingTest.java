// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.google.protobuf.Timestamp;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lifetime ceilings on the two mint paths that had none.
 *
 * <p>{@code MintClientToken} signed whatever {@code exp} the cred_pair holder
 * asked for — every other short-lived mint path in {@link IdentityServiceImpl}
 * caps against max_token_lifetime, this one only checked {@code exp > now}.
 *
 * <p>{@code MintToken}'s exchange arm capped the new token against
 * max_token_lifetime but never against the presented token's OWN remaining
 * expiry, so an exchange could hand back a token outliving the credential
 * bought it — a caller could renew its way past what its original credential
 * had left.
 */
class MintLifetimeCeilingTest {

	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String TENANT_NS = "/tenants/acme";
	private static final long DEFAULT_EXPIRY_SECONDS = 3600;
	private static final long MAX_LIFETIME_SECONDS = 86_400;
	/** MintClientToken's own default C2S lifetime (DEFAULT_TOKEN_TTL_SECONDS). */
	private static final long CLIENT_TOKEN_DEFAULT_SECONDS = 3600;
	/** Tolerance for the second boundary between the test's `now` and the impl's. */
	private static final long SKEW_SECONDS = 5;
	/** Remaining life on the cred_pair used by the expires_at ceiling tests. */
	private static final long CRED_PAIR_REMAINING_SECONDS = 600;

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	private ConfigMap configMap;
	private IdentityServiceImpl identityService;
	private String credPairId;
	private JwkOuterClass.Jwk credPairJwk;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		// The cred_pair's keypair is the kernel's own active Ed25519 key: this test
		// is about lifetimes, not about key provenance, and reusing it keeps the
		// proof signable without a second key fixture.
		credPairJwk = keyRotator.getActiveJwk(KeyRotator.SigAlg.ED25519);
		credPairId = credPairJwk.getKid();

		configMap = new ConfigMap(new InMemoryManager());
		configMap.putTenantConfigs(TENANT_NS, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(TENANT_NS)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setKernel(Credentials.KernelTenantConfig.newBuilder()
								.addCredPairs(Credentials.CredPair.newBuilder()
										.setId(credPairId)
										.setTenantName(TENANT_NS)
										.setPublicKey(credPairJwk)
										.addNamespaces("*")))
						.build())
				.build());

		identityService = identityServiceOver(configMap);
	}

	private IdentityServiceImpl identityServiceOver(ConfigMap tenantConfigs) {
		return new IdentityServiceImpl(
				DEFAULT_EXPIRY_SECONDS, 900, 86_400, MAX_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS,
				keyRotator,
				() -> verifyingKeys,
				List::of,        // delegates
				List::of,        // grants
				null,            // grantsWriter
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> "test.schematic.io",
				ISSUER,
				null,            // opaEvalClient (no refresh->access resolve on these paths)
				null,            // proxyPolicyOpaClient
				tenantConfigs,
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty (fail closed)
	}

	/**
	 * The same tenant and the same cred_pair id, but the credential now carries an
	 * {@code expires_at}. A fresh ConfigMap rather than a second cred_pair because
	 * {@code TokenWrapper.sign} stamps the kid from the signing key, so every proof
	 * this fixture can produce names the one id.
	 */
	private IdentityServiceImpl identityServiceWithCredPairExpiring(long expiresAt) throws Exception {
		ConfigMap expiring = new ConfigMap(new InMemoryManager());
		expiring.putTenantConfigs(TENANT_NS, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(TENANT_NS)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setKernel(Credentials.KernelTenantConfig.newBuilder()
								.addCredPairs(Credentials.CredPair.newBuilder()
										.setId(credPairId)
										.setTenantName(TENANT_NS)
										.setPublicKey(credPairJwk)
										.setExpiresAt(Timestamp.newBuilder().setSeconds(expiresAt))
										.addNamespaces("*")))
						.build())
				.build());
		return identityServiceOver(expiring);
	}

	@AfterEach
	void tearDown() {
		keyRotator.stop();
	}

	// ---- MintClientToken ---------------------------------------------------

	@Test
	void mintClientTokenRejectsARequestedExpBeyondTheMaxLifetimeCeiling() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class,
				() -> identityService.mintClientToken(null, clientRequest(now + (90L * 86_400))));

		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
		assertTrue(e.getMessage().contains("exceeds max token lifetime ceiling"),
				"should name the ceiling it breached, got: " + e.getMessage());
	}

	@Test
	void mintClientTokenHonoursARequestedExpInsideTheCeiling() {
		long now = Instant.now().getEpochSecond();
		long requested = now + MAX_LIFETIME_SECONDS - 60;

		Tokenrequest.TokenMintResponse resp = identityService.mintClientToken(null, clientRequest(requested));

		assertEquals(requested, TokenWrapper.from(resp.getAccessToken()).getExpiration());
	}

	@Test
	void mintClientTokenDefaultLifetimeIsUnchanged() {
		long now = Instant.now().getEpochSecond();

		Tokenrequest.TokenMintResponse resp = identityService.mintClientToken(null, clientRequest(0));

		assertWithinSkew(now + CLIENT_TOKEN_DEFAULT_SECONDS,
				TokenWrapper.from(resp.getAccessToken()).getExpiration());
	}

	/**
	 * L1: the cred_pair's own {@code expires_at} gated the credential at mint time
	 * but was never a ceiling on the token's {@code exp}. A holder minting one
	 * second before the credential expired still got a token good for the full
	 * max_token_lifetime, so expiring or revoking the credential left up to that
	 * whole window of live access behind it.
	 */
	@Test
	void mintClientTokenRejectsARequestedExpBeyondTheCredPairsOwnExpiry() throws Exception {
		long now = Instant.now().getEpochSecond();
		long credPairExpiresAt = now + CRED_PAIR_REMAINING_SECONDS;
		IdentityServiceImpl service = identityServiceWithCredPairExpiring(credPairExpiresAt);
		// Comfortably inside the max-lifetime ceiling, so only the credential's own
		// remaining life can hold this down.
		long requested = now + MAX_LIFETIME_SECONDS - 60;

		ProtoException e = assertThrows(ProtoException.class,
				() -> service.mintClientToken(null, clientRequest(requested)));

		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
		assertTrue(e.getMessage().contains("ceiling " + credPairExpiresAt),
				"the ceiling named must be the cred_pair's own expiry, got: " + e.getMessage());
	}

	/**
	 * L1, the half a caller never sees fail: with no requested exp, the default 1h
	 * TTL sailed straight past a credential with 10 minutes left on it.
	 */
	@Test
	void mintClientTokenDefaultLifetimeIsCappedByTheCredPairsOwnExpiry() throws Exception {
		assertTrue(CRED_PAIR_REMAINING_SECONDS < CLIENT_TOKEN_DEFAULT_SECONDS,
				"fixture proves nothing unless the credential expires before the default TTL");
		long credPairExpiresAt = Instant.now().getEpochSecond() + CRED_PAIR_REMAINING_SECONDS;
		IdentityServiceImpl service = identityServiceWithCredPairExpiring(credPairExpiresAt);

		Tokenrequest.TokenMintResponse resp = service.mintClientToken(null, clientRequest(0));

		assertEquals(credPairExpiresAt, TokenWrapper.from(resp.getAccessToken()).getExpiration());
	}

	/** And a request inside the credential's remaining life is still honoured. */
	@Test
	void mintClientTokenHonoursARequestedExpInsideTheCredPairsOwnExpiry() throws Exception {
		long credPairExpiresAt = Instant.now().getEpochSecond() + CRED_PAIR_REMAINING_SECONDS;
		IdentityServiceImpl service = identityServiceWithCredPairExpiring(credPairExpiresAt);
		long requested = credPairExpiresAt - 60;

		Tokenrequest.TokenMintResponse resp = service.mintClientToken(null, clientRequest(requested));

		assertEquals(requested, TokenWrapper.from(resp.getAccessToken()).getExpiration());
	}

	// ---- MintToken (exchange arm) ------------------------------------------

	@Test
	void mintTokenExchangeCannotOutliveTheInputToken() {
		long now = Instant.now().getEpochSecond();
		long inputExp = now + 600; // 10 minutes left on the presented credential
		// Well inside the max-lifetime ceiling, so only the input token's own
		// expiry can hold this down.
		long requested = now + MAX_LIFETIME_SECONDS - 60;

		Tokenrequest.TokenMintResponse resp = identityService.mintToken(null,
				Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(accessToken(inputExp))
						.setExp(requested)
						.build());

		assertEquals(inputExp, TokenWrapper.from(resp.getAccessToken()).getExpiration());
	}

	@Test
	void mintTokenExchangeDefaultLifetimeIsUnchangedWhenTheInputOutlivesIt() {
		long now = Instant.now().getEpochSecond();

		Tokenrequest.TokenMintResponse resp = identityService.mintToken(null,
				Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(accessToken(now + (2 * DEFAULT_EXPIRY_SECONDS)))
						.build());

		assertWithinSkew(now + DEFAULT_EXPIRY_SECONDS,
				TokenWrapper.from(resp.getAccessToken()).getExpiration());
	}

	// ---- fixture -----------------------------------------------------------

	private Tokenrequest.MintClientTokenRequest clientRequest(long exp) {
		return Tokenrequest.MintClientTokenRequest.newBuilder()
				.setInputToken(credPairProof())
				.setExp(exp)
				.build();
	}

	/**
	 * A cred_pair proof JWT: kid = cred_pair id, signed by the cred_pair's key.
	 *
	 * <p>Short-lived on purpose: kernel now caps the proof lifetime it accepts
	 * independently of what the client asked for, so a proof good for five minutes
	 * is refused (see {@code ClientProofHardeningTest}).
	 */
	private String credPairProof() {
		long now = Instant.now().getEpochSecond();
		TokenWrapper proof = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject("cred-pair:" + credPairId)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 60)
				.setJTI(UUID.randomUUID().toString());
		proof.setNamespace(TENANT_NS);
		proof.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));
		return proof.getBase64();
	}

	/** A kernel-signed user access token — the exchange arm's input. */
	private String accessToken(long exp) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper token = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject("user@example.com")
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		token.setSubType("user");
		token.setTokenUse("access");
		token.setNamespace(TENANT_NS);
		token.sign(signingKey);
		return token.getBase64();
	}

	private static void assertWithinSkew(long expected, long actual) {
		assertTrue(Math.abs(actual - expected) <= SKEW_SECONDS,
				"expected exp near " + expected + ", got " + actual);
	}
}
