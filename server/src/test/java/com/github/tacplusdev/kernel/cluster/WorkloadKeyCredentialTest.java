// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.common.credentials.Credentials;
import com.github.tacplusdev.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Timestamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Workload keys (kernel#28): a tenant registers the public half of a key pair
 * for one of its own workloads that cannot federate, and the workload trades an
 * assertion signed with the private half ({@code MintClientToken}) for an
 * ordinary short-lived token for exactly the key's subject, which it exchanges
 * ({@code MintToken}) for service tokens to the key's audiences only.
 *
 * <p>Drives the real {@link TenantAdminServiceImpl} and
 * {@link IdentityServiceImpl} over one in-memory {@code ConfigState}. The
 * workload's key pairs come from a second {@link KeyRotator}, never kernel's.
 */
class WorkloadKeyCredentialTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String ACME = "/tenants/acme";
	private static final String GLOBEX = "/tenants/globex";
	private static final String AUD = "docstore";
	private static final long DAY = 86_400;

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<JwkOuterClass.Jwk> workloadPublicKeys = new CopyOnWriteArrayList<>();

	private KeyRotator kernelKeys;
	private KeyRotator workloadKeyPairs;
	private ConfigMap configMap;
	private TenantAdminServiceImpl admin;
	private IdentityServiceImpl identity;
	private String acmeSubject;

	@BeforeEach
	void setUp() throws Exception {
		kernelKeys = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		kernelKeys.start();
		workloadKeyPairs = new KeyRotator(3600, 86_400,
				workloadPublicKeys::add,
				kid -> workloadPublicKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> workloadPublicKeys,
				null);
		workloadKeyPairs.start();

		configMap = new ConfigMap(new InMemoryManager());
		admin = new TenantAdminServiceImpl(configMap, () -> TRUST_DOMAIN, null);
		for (String ns : List.of(ACME, GLOBEX)) {
			admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
					.setTenantNamespace(ns)
					.setConstraints(Kernel.Constraints.newBuilder()
							.setEntitlementsCeiling(TenantAdminServiceImpl.buildFullEntitlements()))
					.build());
		}
		acmeSubject = TenantServiceSubjects.of(configMap, TRUST_DOMAIN, ACME, "ingest");
		identity = identityServiceOver(configMap);
	}

	@AfterEach
	void tearDown() {
		kernelKeys.stop();
		workloadKeyPairs.stop();
	}

	// ---- a valid assertion --------------------------------------------------

	@Test
	void aValidAssertionMintsATokenForExactlyTheScopedSubject() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);

		TokenWrapper at = TokenWrapper.from(
				identity.mintClientToken(null, request(assertion(key, KeyRotator.SigAlg.ED25519, a -> { })))
						.getAccessToken());

		assertEquals(acmeSubject, at.getSubject());
		assertEquals(acmeSubject, at.getPrincipal());
		assertEquals(IdentityServiceImpl.SUB_TYPE_SERVICE, at.getSubType());
		assertEquals(ACME, at.getNamespace(), "acts in its tenant's name");
		assertEquals(Kernel.getDescriptor().getPackage(), at.getAudience(), "the access token is kernel's");
		assertTrue(at.getExpiration() <= Instant.now().getEpochSecond() + 900, "short-lived");

		TokenWrapper st = TokenWrapper.from(identity.mintToken(null, exchange(at, AUD)).getAccessToken());
		assertEquals(acmeSubject, st.getSubject());
		assertEquals(AUD, st.getAudience());
		assertEquals(ACME, st.getNamespace());
		assertTrue(st.getExpiration() <= at.getExpiration(), "never outlives the token it came from");
	}

	/**
	 * The assertion as docs/workload-keys.md builds it, with no kernel library:
	 * a raw Ed25519 key pair, its JWK by hand, and a JWT of plain JSON.
	 */
	@Test
	void anAssertionBuiltAsTheDocsShowMints() throws Exception {
		java.security.KeyPair pair = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
		byte[] spki = pair.getPublic().getEncoded();
		byte[] raw = java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length);
		java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
		Credentials.WorkloadKey key = admin.createWorkloadKey(null, Kernel.CreateWorkloadKeyRequest.newBuilder()
				.setTenantNamespace(ACME)
				.setPublicKey(JwkOuterClass.Jwk.newBuilder()
						.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP).setCrv("Ed25519").setX(b64.encodeToString(raw)))
				.setSubject(acmeSubject)
				.addAudiences(AUD)
				.build());

		long now = Instant.now().getEpochSecond();
		String header = "{\"alg\":\"EdDSA\",\"kid\":\"" + key.getId() + "\",\"typ\":\"JWT\"}";
		String payload = "{\"iss\":\"" + acmeSubject + "\",\"sub\":\"" + acmeSubject + "\",\"aud\":\"kernel\","
				+ "\"iat\":" + now + ",\"exp\":" + (now + 60) + ",\"jti\":\"" + UUID.randomUUID() + "\"}";
		String input = b64.encodeToString(header.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + "."
				+ b64.encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		java.security.Signature signer = java.security.Signature.getInstance("Ed25519");
		signer.initSign(pair.getPrivate());
		signer.update(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		String assertion = input + "." + b64.encodeToString(signer.sign());

		TokenWrapper at = TokenWrapper.from(identity.mintClientToken(null, request(assertion)).getAccessToken());
		assertEquals(acmeSubject, at.getSubject());
	}

	@Test
	void anEs256KeyMintsToo() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ES256);

		assertNotNull(identity.mintClientToken(null, request(assertion(key, KeyRotator.SigAlg.ES256, a -> { }))));
	}

	@Test
	void severalActiveKeysPerIdentityEachMintAndUseIsRecorded() throws Exception {
		Credentials.WorkloadKey first = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		Credentials.WorkloadKey second = register(ACME, acmeSubject, KeyRotator.SigAlg.ES256);
		assertFalse(storedKey(ACME, first.getId()).hasLastUsedAt());

		identity.mintClientToken(null, request(assertion(first, KeyRotator.SigAlg.ED25519, a -> { })));
		identity.mintClientToken(null, request(assertion(second, KeyRotator.SigAlg.ES256, a -> { })));

		assertTrue(storedKey(ACME, first.getId()).hasLastUsedAt());
		assertTrue(storedKey(ACME, second.getId()).hasLastUsedAt());
	}

	// ---- refusals -----------------------------------------------------------

	@Test
	void anotherTenantsSubjectIsRefusedAtRegistration() {
		String globexSubject = TenantServiceSubjects.of(configMap, TRUST_DOMAIN, GLOBEX, "ingest");

		ProtoException e = assertThrows(ProtoException.class,
				() -> register(ACME, globexSubject, KeyRotator.SigAlg.ED25519));
		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());

		ProtoException system = assertThrows(ProtoException.class,
				() -> register(ACME, SpiffeIds.build(TRUST_DOMAIN, "ingest"), KeyRotator.SigAlg.ED25519));
		assertEquals(ProtoException.PERMISSION_DENIED, system.getCode(), "a /system service is no tenant's");
	}

	@Test
	void aWrongAudienceIsRefused() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> a.setAudience("https://elsewhere.example")))));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("audience"), "got: " + e.getMessage());
	}

	@Test
	void anAssertionLivingOverFiveMinutesIsRefused() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> a.setExpiration(now + 301)))));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("lifetime exceeds"), "got: " + e.getMessage());

		assertNotNull(identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> a.setExpiration(now + 300)))),
				"five minutes is allowed");
	}

	@Test
	void aReplayedJtiIsRefused() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		String once = assertion(key, KeyRotator.SigAlg.ED25519, a -> { });
		identity.mintClientToken(null, request(once));

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null, request(once)));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("already been used"), "got: " + e.getMessage());
	}

	@Test
	void aRevokedKeyIsRefusedAndItsTokensBuyNothingMore() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		TokenWrapper at = TokenWrapper.from(identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> { }))).getAccessToken());

		admin.revokeWorkloadKey(null, Kernel.RevokeWorkloadKeyRequest.newBuilder()
				.setTenantNamespace(ACME).setId(key.getId()).build());

		ProtoException mint = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> { }))));
		assertEquals(ProtoException.UNAUTHENTICATED, mint.getCode());
		assertTrue(mint.getMessage().contains("revoked"), "got: " + mint.getMessage());

		ProtoException exchange = assertThrows(ProtoException.class,
				() -> identity.mintToken(null, exchange(at, AUD)));
		assertEquals(ProtoException.PERMISSION_DENIED, exchange.getCode());
	}

	@Test
	void anAudienceTheKeyDoesNotListIsRefusedOnExchange() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		TokenWrapper at = TokenWrapper.from(identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> { }))).getAccessToken());

		ProtoException e = assertThrows(ProtoException.class,
				() -> identity.mintToken(null, exchange(at, "billing")));
		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
	}

	@Test
	void aKeyOfADeletedTenantMintsNothing() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);

		admin.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder().setTenantNamespace(ACME).build());

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> { }))));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
	}

	@Test
	void onlyEd25519OrEs256KeysRegister() {
		JwkOuterClass.Jwk rsa = JwkOuterClass.Jwk.newBuilder()
				.setKty(KeyOuterClass.KeyType.KEY_TYPE_RSA).setN("AQAB").setE("AQAB").build();

		ProtoException e = assertThrows(ProtoException.class, () -> admin.createWorkloadKey(null,
				Kernel.CreateWorkloadKeyRequest.newBuilder()
						.setTenantNamespace(ACME).setSubject(acmeSubject).setPublicKey(rsa).build()));
		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
	}

	// ---- inactivity and per-tenant settings -------------------------------

	@Test
	void aKeyUnusedPastTheDefaultWindowIsRefused() throws Exception {
		Credentials.WorkloadKey stale = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		Credentials.WorkloadKey recent = register(ACME, acmeSubject, KeyRotator.SigAlg.ES256);
		long now = Instant.now().getEpochSecond();
		rewriteKey(ACME, stale.getId(), k -> k.setCreatedAt(ts(now - 91 * DAY)));
		rewriteKey(ACME, recent.getId(), k -> k.setCreatedAt(ts(now - 120 * DAY)).setLastUsedAt(ts(now - 89 * DAY)));

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(stale, KeyRotator.SigAlg.ED25519, a -> { }))));
		assertEquals(ProtoException.UNAUTHENTICATED, e.getCode());
		assertTrue(e.getMessage().contains("disabled"), "got: " + e.getMessage());

		assertNotNull(identity.mintClientToken(null, request(assertion(recent, KeyRotator.SigAlg.ES256, a -> { }))),
				"used 89 days ago is inside the 90-day window, however old the key");
		assertEquals(Kernel.WorkloadKeyState.WORKLOAD_KEY_STATE_DISABLED, listedState(stale.getId()));
		assertEquals(Kernel.WorkloadKeyState.WORKLOAD_KEY_STATE_ACTIVE, listedState(recent.getId()));
	}

	@Test
	void aTenantsOwnInactivityWindowTakesEffect() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		Credentials.WorkloadKey globexKey = register(GLOBEX,
				TenantServiceSubjects.of(configMap, TRUST_DOMAIN, GLOBEX, "ingest"), KeyRotator.SigAlg.ES256);
		long now = Instant.now().getEpochSecond();
		rewriteKey(ACME, key.getId(), k -> k.setCreatedAt(ts(now - 2 * 3600)));
		rewriteKey(GLOBEX, globexKey.getId(), k -> k.setCreatedAt(ts(now - 2 * 3600)));
		setPolicy(ACME, Credentials.WorkloadKeyPolicy.newBuilder().setInactiveAfterSeconds(3600).build());

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(key, KeyRotator.SigAlg.ED25519, a -> { }))));
		assertTrue(e.getMessage().contains("disabled"), "got: " + e.getMessage());
		assertNotNull(identity.mintClientToken(null,
				request(assertion(globexKey, KeyRotator.SigAlg.ES256, a -> { }))), "globex keeps the default");
	}

	@Test
	void aTenantsMaximumLifetimeTakesEffectAndBoundsTheToken() throws Exception {
		Credentials.WorkloadKey old = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		Credentials.WorkloadKey young = register(ACME, acmeSubject, KeyRotator.SigAlg.ES256);
		long now = Instant.now().getEpochSecond();
		rewriteKey(ACME, old.getId(), k -> k.setCreatedAt(ts(now - 2 * DAY)).setLastUsedAt(ts(now - 60)));
		rewriteKey(ACME, young.getId(), k -> k.setCreatedAt(ts(now - DAY + 120)));
		setPolicy(ACME, Credentials.WorkloadKeyPolicy.newBuilder().setMaxLifetimeSeconds(DAY).build());

		ProtoException e = assertThrows(ProtoException.class, () -> identity.mintClientToken(null,
				request(assertion(old, KeyRotator.SigAlg.ED25519, a -> { }))));
		assertTrue(e.getMessage().contains("maximum key lifetime"), "got: " + e.getMessage());

		TokenWrapper at = TokenWrapper.from(identity.mintClientToken(null,
				request(assertion(young, KeyRotator.SigAlg.ES256, a -> { }))).getAccessToken());
		assertTrue(at.getExpiration() <= now + 120, "the token ends when the key does");
	}

	@Test
	void updateTenantConfigKeepsTheStoredKeys() throws Exception {
		Credentials.WorkloadKey key = register(ACME, acmeSubject, KeyRotator.SigAlg.ED25519);
		admin.updateTenantConfig(null, Kernel.SetTenantConfigRequest.newBuilder()
				.setTenantNamespace(ACME)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setKernel(Credentials.KernelTenantConfig.newBuilder()
								.addCredPairs(adminCredPair())
								.addWorkloadKeys(Credentials.WorkloadKey.newBuilder().setId("wk-forged"))))
				.build());

		List<Credentials.WorkloadKey> stored =
				configMap.getTenantConfigs(ACME).getConfig().getKernel().getWorkloadKeysList();
		assertEquals(1, stored.size());
		assertEquals(key.getId(), stored.get(0).getId());
	}

	// ---- root bootstrap ----------------------------------------------------

	@Test
	void rootBootstrapKeepsWorkingAsRootsOwnKeys() throws Exception {
		register(ACME, acmeSubject, KeyRotator.SigAlg.ES256);
		JwkOuterClass.Jwk rootJwk = workloadKeyPairs.getActiveJwk(KeyRotator.SigAlg.ED25519);
		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(Credentials.CredPair.newBuilder()
				.setId(rootJwk.getKid())
				.setTenantName("/")
				.setPublicKey(rootJwk)
				.addNamespaces("*")
				.build()), "/");
		long now = Instant.now().getEpochSecond();
		TokenWrapper proof = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject("cred-pair:" + rootJwk.getKid())
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(now + 60)
				.setJTI(UUID.randomUUID().toString());
		proof.setNamespace("/");
		proof.sign(workloadKeyPairs.getActiveSigningKey(KeyRotator.SigAlg.ED25519));

		TokenWrapper token = TokenWrapper.from(
				identity.mintClientToken(null, request(proof.getBase64())).getAccessToken());
		assertEquals("cred-pair:" + rootJwk.getKid(), token.getSubject());
		assertEquals("/", token.getNamespace());
	}

	// ---- fixture -----------------------------------------------------------

	private Credentials.WorkloadKey register(String ns, String subject, KeyRotator.SigAlg alg) throws ProtoException {
		return admin.createWorkloadKey(null, Kernel.CreateWorkloadKeyRequest.newBuilder()
				.setTenantNamespace(ns)
				.setPublicKey(workloadKeyPairs.getActiveJwk(alg))
				.setSubject(subject)
				.addAudiences(AUD)
				.build());
	}

	/**
	 * A well-formed assertion — kid the key's id, kernel audience, iat now, 60s
	 * life, fresh jti — signed by the workload's private key, with {@code tweak}
	 * applied before signing.
	 */
	private String assertion(Credentials.WorkloadKey key, KeyRotator.SigAlg alg, Consumer<TokenWrapper> tweak) {
		long now = Instant.now().getEpochSecond();
		TokenWrapper a = TokenWrapper.create()
				.setIssuer(key.getSubject())
				.setSubject(key.getSubject())
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(now + 60)
				.setJTI(UUID.randomUUID().toString());
		a.setNamespace(ACME);
		tweak.accept(a);
		ImmutableKey signing = workloadKeyPairs.getActiveSigningKey(alg);
		a.sign(ImmutableKey.from(signing.getProto().toBuilder().setId(key.getId()).build()));
		return a.getBase64();
	}

	private static Tokenrequest.MintClientTokenRequest request(String assertion) {
		return Tokenrequest.MintClientTokenRequest.newBuilder().setInputToken(assertion).build();
	}

	private static Tokenrequest.TokenMintRequest exchange(TokenWrapper accessToken, String aud) {
		return Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(accessToken.getProto().getBase64())
				.setAud(aud)
				.build();
	}

	private Credentials.WorkloadKey storedKey(String ns, String id) throws ProtoException {
		for (Credentials.WorkloadKey k : configMap.getTenantConfigs(ns).getConfig().getKernel().getWorkloadKeysList()) {
			if (k.getId().equals(id)) {
				return k;
			}
		}
		throw new AssertionError("no key " + id + " in " + ns);
	}

	/** Moves a stored key in time, as the passing days would. */
	private void rewriteKey(String ns, String id, Consumer<Credentials.WorkloadKey.Builder> change)
			throws ProtoException {
		Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
		Credentials.KernelTenantConfig.Builder kernel = entry.getConfig().getKernel().toBuilder();
		for (Credentials.WorkloadKey.Builder k : kernel.getWorkloadKeysBuilderList()) {
			if (k.getId().equals(id)) {
				change.accept(k);
			}
		}
		WorkloadKeys.putKernelConfig(configMap, entry, kernel.build());
	}

	private void setPolicy(String ns, Credentials.WorkloadKeyPolicy policy) throws ProtoException {
		admin.updateTenantConfig(null, Kernel.SetTenantConfigRequest.newBuilder()
				.setTenantNamespace(ns)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setKernel(Credentials.KernelTenantConfig.newBuilder()
								.addCredPairs(adminCredPair())
								.setWorkloadKeyPolicy(policy)))
				.build());
	}

	private Kernel.WorkloadKeyState listedState(String id) throws ProtoException {
		for (Kernel.WorkloadKeyListing l : admin.listWorkloadKeys(null,
				Kernel.ListWorkloadKeysRequest.newBuilder().setTenantNamespace(ACME).build(), null).items) {
			if (l.getId().equals(id)) {
				return l.getState();
			}
		}
		throw new AssertionError("no listing for " + id);
	}

	/** A tenant admin cred_pair, which UpdateTenantConfig's min-admin invariant asks for. */
	private Credentials.CredPair adminCredPair() {
		return Credentials.CredPair.newBuilder()
				.setId("cp-admin")
				.setTenantName(ACME)
				.setPublicKey(kernelKeys.getActiveJwk(KeyRotator.SigAlg.ED25519))
				.setEntitlements(TenantAdminServiceImpl.buildFullEntitlements())
				.addNamespaces("*")
				.build();
	}

	private static Timestamp ts(long seconds) {
		return Timestamp.newBuilder().setSeconds(seconds).build();
	}

	private IdentityServiceImpl identityServiceOver(ConfigMap tenantConfigs) {
		return new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
				kernelKeys,
				() -> verifyingKeys,
				List::of,        // delegates
				List::of,        // grants
				null,            // grantsWriter
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				null,            // opaEvalClient
				null,            // proxyPolicyOpaClient
				tenantConfigs,
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty (fail closed)
	}
}
