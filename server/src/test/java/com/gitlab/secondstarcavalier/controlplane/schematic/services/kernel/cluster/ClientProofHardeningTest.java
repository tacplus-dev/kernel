// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The hardening a client-minted proof JWT was missing on {@code MintClientToken}.
 *
 * <p>A cred_pair proof is the one credential class where the CLIENT chooses the
 * whole payload, and the path used to be nothing but {@code parse} then
 * {@code verify}. {@code verify} does enforce {@code exp}, so replay was bounded
 * by the proof's own expiry — but the client set that expiry with nothing
 * constraining how far out, nothing tied the proof to kernel, and nothing
 * noticed the same proof arriving twice. Anyone who captured one could replay it
 * verbatim for fresh tokens until it expired (L2).
 *
 * <p>Also covers the two smaller refusals on the same RPC: the minted audience
 * is the proto package constant rather than a string literal (L3), and a
 * cred_pair id configured under more than one tenant is refused rather than
 * resolved by {@code tenant_configs} iteration order (L7).
 */
class ClientProofHardeningTest {

	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String TENANT_NS = "/tenants/acme";
	private static final String OTHER_TENANT_NS = "/tenants/globex";
	private static final long MAX_LIFETIME_SECONDS = 86_400;
	/** MAX_PROOF_LIFETIME_SECONDS + PROOF_CLOCK_SKEW_SECONDS in the impl. */
	private static final long PROOF_EXP_CEILING_SECONDS = 120;

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
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

		// The cred_pair's keypair is kernel's own active Ed25519 key: TokenWrapper
		// stamps the kid from the signing key, so reusing it is what makes a proof
		// whose kid names the cred_pair signable without a second key fixture.
		credPairJwk = keyRotator.getActiveJwk(KeyRotator.SigAlg.ED25519);
		credPairId = credPairJwk.getKid();

		identityService = identityServiceOver(tenantConfigs(TENANT_NS));
	}

	@AfterEach
	void tearDown() {
		keyRotator.stop();
	}

	// ---- L2: anti-replay binding -------------------------------------------

	/**
	 * The replay itself: one captured proof, presented twice. It used to mint
	 * twice, because nothing recorded that the {@code jti} had been spent.
	 */
	@Test
	void aProofCannotBeReplayedForASecondToken() {
		String proof = proof(p -> { });

		assertNotNull(identityService.mintClientToken(null, request(proof)),
				"first presentation is the legitimate one");

		ProtoException e = assertThrows(ProtoException.class,
				() -> identityService.mintClientToken(null, request(proof)));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("already been used"),
				"should refuse as a spent jti, got: " + e.getMessage());
	}

	/** A proof with no {@code jti} at all cannot be replay-checked, so it is refused. */
	@Test
	void aProofWithNoJtiIsRefused() {
		long now = Instant.now().getEpochSecond();
		TokenWrapper unsigned = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject("cred-pair:" + credPairId)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(now + 60);
		unsigned.setNamespace(TENANT_NS);
		unsigned.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));

		ProtoException e = assertThrows(ProtoException.class,
				() -> identityService.mintClientToken(null, request(unsigned.getBase64())));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("no jti"), "got: " + e.getMessage());
	}

	/**
	 * The client used to choose the replay window. A proof valid for a year
	 * verified fine, and every second of that year was a window a captured copy
	 * could be replayed in.
	 */
	@Test
	void aProofLifetimeBeyondTheCapIsRefusedHoweverLongTheClientAskedFor() {
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class,
				() -> identityService.mintClientToken(null,
						request(proof(p -> p.setExpiration(now + (365L * 86_400))))));

		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("lifetime exceeds"), "got: " + e.getMessage());
	}

	/**
	 * The cap carries the same 60s skew allowance {@code TokenWrapper.verify}
	 * applies, so a client whose clock runs fast is not refused for it.
	 */
	@Test
	void aProofInsideTheCapPlusClockSkewIsAccepted() {
		long now = Instant.now().getEpochSecond();

		assertNotNull(identityService.mintClientToken(null,
				request(proof(p -> p.setExpiration(now + PROOF_EXP_CEILING_SECONDS - 5)))));
	}

	/** A proof minted for some other relying party is not a proof to kernel. */
	@Test
	void aProofAudiencedElsewhereIsRefused() {
		ProtoException e = assertThrows(ProtoException.class,
				() -> identityService.mintClientToken(null,
						request(proof(p -> p.setAudience("https://someone-elses-api.example")))));

		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("audience"), "got: " + e.getMessage());
	}

	// ---- L3: the minted audience -------------------------------------------

	/**
	 * The C2S token's audience was the literal {@code "kernel"} while every
	 * sibling mint path in the file used the proto package constant. Identical
	 * today; the point is that a package rename moves both together instead of
	 * silently minting an audience no authenticator accepts.
	 */
	@Test
	void theMintedTokenIsAudiencedToTheProtoPackageConstant() {
		Tokenrequest.TokenMintResponse resp =
				identityService.mintClientToken(null, request(proof(p -> { })));

		assertEquals(Kernel.getDescriptor().getPackage(),
				TokenWrapper.from(resp.getAccessToken()).getAudience());
	}

	// ---- L7: an id that resolves ambiguously -------------------------------

	/**
	 * Nothing enforces that cred_pair ids are unique across tenants. The lookup
	 * used to break on the first id match, so {@code tenant_configs} iteration
	 * order decided whose namespace the token was scoped to and the loser's
	 * credential minted into somebody else's namespace. There is no right answer
	 * to pick; refuse.
	 */
	@Test
	void aCredPairIdConfiguredUnderTwoTenantsIsRefusedRatherThanResolvedByIterationOrder()
			throws Exception {
		ConfigMap shared = tenantConfigs(TENANT_NS);
		shared.putTenantConfigs(OTHER_TENANT_NS, tenantEntry(OTHER_TENANT_NS));
		IdentityServiceImpl service = identityServiceOver(shared);

		ProtoException e = assertThrows(ProtoException.class,
				() -> service.mintClientToken(null, request(proof(p -> { }))));

		assertEquals(ProtoException.FAILED_PRECONDITION, e.getCode());
		assertTrue(e.getMessage().contains("more than one tenant"), "got: " + e.getMessage());
	}

	/** One owner is still the ordinary case, and still mints into that namespace. */
	@Test
	void aCredPairIdOwnedByOneTenantMintsIntoThatNamespace() {
		Tokenrequest.TokenMintResponse resp =
				identityService.mintClientToken(null, request(proof(p -> { })));

		assertEquals(TENANT_NS, TokenWrapper.from(resp.getAccessToken()).getNamespace());
	}

	// ---- fixture -----------------------------------------------------------

	private Tokenrequest.MintClientTokenRequest request(String inputToken) {
		return Tokenrequest.MintClientTokenRequest.newBuilder()
				.setInputToken(inputToken)
				.build();
	}

	/**
	 * A well-formed cred_pair proof — fresh jti, kernel audience, 60s life — with
	 * {@code tweak} applied before signing so a test can spoil exactly one field.
	 */
	private String proof(java.util.function.Consumer<TokenWrapper> tweak) {
		long now = Instant.now().getEpochSecond();
		TokenWrapper p = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject("cred-pair:" + credPairId)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(now + 60)
				.setJTI(UUID.randomUUID().toString());
		p.setNamespace(TENANT_NS);
		tweak.accept(p);
		p.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));
		return p.getBase64();
	}

	private ConfigMap tenantConfigs(String tenantName) throws Exception {
		ConfigMap configMap = new ConfigMap(new InMemoryManager());
		configMap.putTenantConfigs(tenantName, tenantEntry(tenantName));
		return configMap;
	}

	/** The same cred_pair id under whichever tenant is asked for. */
	private Kernel.TenantConfigEntry tenantEntry(String tenantName) {
		return Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(tenantName)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setKernel(Credentials.KernelTenantConfig.newBuilder()
								.addCredPairs(Credentials.CredPair.newBuilder()
										.setId(credPairId)
										.setTenantName(tenantName)
										.setPublicKey(credPairJwk)
										.addNamespaces("*")))
						.build())
				.build();
	}

	private IdentityServiceImpl identityServiceOver(ConfigMap tenantConfigs) {
		return new IdentityServiceImpl(
				3600, MAX_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS,
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
				null,            // opaEvalClient
				null,            // proxyPolicyOpaClient
				tenantConfigs,
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // persistState
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null,            // opaConfigWriter
				null);           // webauthnRelyingParty (fail closed)
	}
}
