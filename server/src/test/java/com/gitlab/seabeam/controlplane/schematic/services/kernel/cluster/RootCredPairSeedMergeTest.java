// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.google.protobuf.Timestamp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code ClusterServer} calls {@link TenantAdminServiceImpl#seedRootCredPairs}
 * on every kernel start, AFTER the disk snapshot has been rehydrated into the
 * {@link ConfigMap}. When that seed was a whole-entry replace, every restart
 * silently discarded whatever the running cluster held for the root namespace
 * and left only the bootstrap bundle's cred_pairs behind.
 *
 * <p>{@code installConfigHolder}'s bundle-wins seeding (see
 * {@code ConfigStateSeedBundleWinsTest}) covers the per-service ConfigHolder
 * roots; it never touched this path, which writes the kernel's own
 * {@code ConfigState.tenant_configs}.
 *
 * <p>The seed now merges: bootstrap ids are upserted (so rotating a root key in
 * the bundle still takes effect), everything else in the root config survives.
 */
class RootCredPairSeedMergeTest {

	private static final String ROOT_NS = "/";

	private ConfigMap configMap;

	@BeforeEach
	void setUp() {
		configMap = new ConfigMap(new InMemoryManager());
	}

	/** Cold start: an empty root entry is seeded from the bundle. */
	@Test
	void coldStartSeedsTheBundleCredPairs() throws Exception {
		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(bundleCredPair("cp-root", "k1")), ROOT_NS);

		assertEquals(List.of("cp-root"), storedIds());
		assertEquals(ROOT_NS, configMap.getTenantConfigs(ROOT_NS).getTenantName());
		Credentials.CredPair stored = storedCredPair("cp-root");
		assertEquals(ROOT_NS, stored.getTenantName());
		assertEquals(List.of("*"), stored.getNamespacesList());
		assertTrue(stored.getEntitlements().getGrantsCount() > 0, "seeded cred_pair should hold full entitlements");
	}

	/**
	 * The bug: a cred_pair written to the root namespace at runtime (here,
	 * placed in the map exactly as {@code UpdateTenantConfig} or the snapshot
	 * rehydrate would) must survive the next boot's reseed.
	 */
	@Test
	void runtimeRootCredPairSurvivesReseed() throws Exception {
		// Boot 1 seeds the bundle.
		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(bundleCredPair("cp-root", "k1")), ROOT_NS);
		// An operator adds a second root admin while the cluster runs.
		putRootConfig(configMap.getTenantConfigs(ROOT_NS).getConfig().toBuilder()
				.setKernel(configMap.getTenantConfigs(ROOT_NS).getConfig().getKernel().toBuilder()
						.addCredPairs(Credentials.CredPair.newBuilder()
								.setId("cp-runtime")
								.setTenantName(ROOT_NS)
								.setPublicKey(jwk("k-runtime"))
								.addNamespaces("*")
								.build()))
				.build());

		// Boot 2: same bundle, snapshot already rehydrated.
		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(bundleCredPair("cp-root", "k1")), ROOT_NS);

		assertTrue(storedIds().contains("cp-runtime"),
				"runtime root cred_pair must survive the reseed, stored ids: " + storedIds());
		assertTrue(storedIds().contains("cp-root"));
	}

	/**
	 * The merge is per cred_pair id: the bundle stays authoritative for the ids
	 * it declares, so rotating a root key there takes effect on the next boot —
	 * and an id that was already seeded keeps its original created_at rather
	 * than being re-stamped every start.
	 */
	@Test
	void bundleRotationOfASeededIdTakesEffectAndKeepsCreatedAt() throws Exception {
		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(bundleCredPair("cp-root", "k1")), ROOT_NS);
		Timestamp createdAt = storedCredPair("cp-root").getCreatedAt();

		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(bundleCredPair("cp-root", "k2")), ROOT_NS);

		assertEquals(1, storedIds().size(), "rotation must not duplicate the id, stored ids: " + storedIds());
		assertEquals("k2", storedCredPair("cp-root").getPublicKey().getKid());
		assertEquals(createdAt, storedCredPair("cp-root").getCreatedAt());
	}

	/** An empty bundle list is a no-op — it must not blank the root entry. */
	@Test
	void emptyBundleLeavesTheRootEntryAlone() throws Exception {
		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(bundleCredPair("cp-root", "k1")), ROOT_NS);

		TenantAdminServiceImpl.seedRootCredPairs(configMap, List.of(), ROOT_NS);

		assertEquals(List.of("cp-root"), storedIds());
	}

	// ------------------------------------------------------------------
	// fixture
	// ------------------------------------------------------------------

	private void putRootConfig(TenantConfigOuterClass.TenantConfig cfg) {
		configMap.putTenantConfigs(ROOT_NS, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(ROOT_NS)
				.setConfig(cfg)
				.build());
	}

	private static Credentials.CredPair bundleCredPair(String id, String kid) {
		return Credentials.CredPair.newBuilder()
				.setId(id)
				.setPublicKey(jwk(kid))
				.build();
	}

	private static JwkOuterClass.Jwk jwk(String kid) {
		return JwkOuterClass.Jwk.newBuilder()
				.setKid(kid)
				.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
				.setAlg("EdDSA")
				.setCreated(1_770_000_000L)
				.build();
	}

	private List<String> storedIds() {
		return configMap.getTenantConfigs(ROOT_NS).getConfig().getKernel().getCredPairsList()
				.stream().map(Credentials.CredPair::getId).toList();
	}

	private Credentials.CredPair storedCredPair(String id) {
		return configMap.getTenantConfigs(ROOT_NS).getConfig().getKernel().getCredPairsList()
				.stream().filter(cp -> cp.getId().equals(id)).findFirst().orElseThrow();
	}
}
