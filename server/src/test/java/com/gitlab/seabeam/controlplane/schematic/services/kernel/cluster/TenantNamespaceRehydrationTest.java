// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.CaMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.IdentityMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two tenants that share a leaf name under different parents must survive a
 * restart as themselves.
 *
 * <p>{@code Tenant.name} holds the leaf segment only, and {@code
 * ConfigMap.proto()} projects the tenants boundary to its values and drops the
 * map keys, so the snapshot used to be indexed by leaf: {@code
 * /tenants/acme/prod} and {@code /tenants/beta/prod} overwrote each other and
 * the restore handed both namespaces whichever record happened to win. After a
 * restart one namespace silently carried the other tenant's status and
 * entitlements ceiling — a ceiling widening or a wrongly-active tenant.
 */
class TenantNamespaceRehydrationTest {

	private static final String ACME_PROD = "/tenants/acme/prod";
	private static final String BETA_PROD = "/tenants/beta/prod";

	private static Kernel.Tenant tenant(String leaf, Kernel.TenantStatus status, String... ceiling) {
		return Kernel.Tenant.newBuilder()
				.setName(leaf)
				.setStatus(status)
				.setConstraints(Kernel.Constraints.newBuilder()
						.setEntitlementsCeiling(Entitlements.TokenEntitlements.newBuilder()
								.addAllGrants(List.of(ceiling))
								.build())
						.build())
				.build();
	}

	private static void seed(ConfigMap configMap, String namespace, Kernel.Tenant t) throws Exception {
		configMap.putTenants(namespace, t);
		configMap.putTenantConfigs(namespace, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(namespace)
				.build());
	}

	/** The real boot path: snapshot the live maps, then restore into fresh ones. */
	private static ConfigMap restart(ConfigMap before, Path dir) throws Exception {
		IdentitySnapshot persistence = new IdentitySnapshot(
				dir.toString(), null, null, null,
				() -> {
					try {
						return ClusterServer.snapshotConfigState(before);
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				},
				null, null, null);
		persistence.save();

		Kernel.KernelDiskState snapshot = persistence.load();
		assertNotNull(snapshot, "snapshot should load back");
		return rehydrate(snapshot);
	}

	private static ConfigMap rehydrate(Kernel.KernelDiskState snapshot) {
		InMemoryManager manager = new InMemoryManager();
		ConfigMap after = new ConfigMap(manager);
		ClusterServer.rehydrateFromSnapshot(
				snapshot,
				new IdentityMap(manager),
				new CaMap(manager),
				new WorkloadMap(manager),
				after);
		return after;
	}

	/** The regression: same-leaf tenants must not swap status or ceiling. */
	@Test
	void sameNamedTenantsUnderDifferentParentsDoNotCollide(@TempDir Path dir) throws Exception {
		ConfigMap before = new ConfigMap(new InMemoryManager());
		seed(before, ACME_PROD, tenant("prod", Kernel.TenantStatus.TENANT_STATUS_ACTIVE, "ACME_READ"));
		seed(before, BETA_PROD, tenant("prod", Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, "BETA_READ"));

		ConfigMap after = restart(before, dir);

		Kernel.Tenant acme = after.getTenants(ACME_PROD);
		Kernel.Tenant beta = after.getTenants(BETA_PROD);
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE, acme.getStatus());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, beta.getStatus(),
				"a suspended tenant must not come back active wearing its namesake's status");
		assertEquals(List.of("ACME_READ"), acme.getConstraints().getEntitlementsCeiling().getGrantsList());
		assertEquals(List.of("BETA_READ"), beta.getConstraints().getEntitlementsCeiling().getGrantsList(),
				"a tenant must not inherit its namesake's entitlements ceiling");
	}

	/** The restored row must be field-identical to what TenantAdmin wrote. */
	@Test
	void restoredTenantsKeepTheLeafNameTheLiveBoundaryUses(@TempDir Path dir) throws Exception {
		ConfigMap before = new ConfigMap(new InMemoryManager());
		Kernel.Tenant acme = tenant("prod", Kernel.TenantStatus.TENANT_STATUS_ACTIVE, "ACME_READ");
		seed(before, ACME_PROD, acme);

		ConfigMap after = restart(before, dir);

		assertEquals(acme, after.getTenants(ACME_PROD),
				"the restored tenant must match the live row exactly, leaf name included");
		assertEquals(before.proto().getTenantConfigsList(), after.proto().getTenantConfigsList());
	}

	/** A tenant known only through one of its projects is still restored. */
	@Test
	void aTenantReachedOnlyThroughItsProjectKeyIsRestored(@TempDir Path dir) throws Exception {
		ConfigMap before = new ConfigMap(new InMemoryManager());
		before.putTenants(ACME_PROD, tenant("prod", Kernel.TenantStatus.TENANT_STATUS_ACTIVE, "ACME_READ"));
		before.putProjectConfigs(ACME_PROD + "/app", Kernel.ProjectConfigEntry.newBuilder()
				.setProjectNamespace(ACME_PROD + "/app")
				.build());

		ConfigMap after = restart(before, dir);

		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE, after.getTenants(ACME_PROD).getStatus());
	}

	/**
	 * A snapshot written by the old code carries leaf names only. It still
	 * restores — one unambiguous tenant is all such a snapshot can promise — so a
	 * node can be upgraded without discarding its state.
	 */
	@Test
	void aPreNamespaceSnapshotStillRestoresAnUnambiguousTenant() {
		Kernel.KernelDiskState legacy = Kernel.KernelDiskState.newBuilder()
				.addTenants(tenant("prod", Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, "ACME_READ"))
				.addTenantConfigs(Kernel.TenantConfigEntry.newBuilder().setTenantName(ACME_PROD).build())
				.build();

		ConfigMap after = rehydrate(legacy);

		Kernel.Tenant restored = after.getTenants(ACME_PROD);
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, restored.getStatus());
		assertEquals("prod", restored.getName());
	}

	/** A tenant_config key with no matching tenant record is skipped, not faked. */
	@Test
	void aConfigKeyWithNoTenantRecordRestoresNoTenant() {
		Kernel.KernelDiskState snapshot = Kernel.KernelDiskState.newBuilder()
				.addTenantConfigs(Kernel.TenantConfigEntry.newBuilder().setTenantName(BETA_PROD).build())
				.build();

		ConfigMap after = rehydrate(snapshot);

		assertTrue(after.getTenants(BETA_PROD).getName().isEmpty());
	}
}
