// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.graphs.hazelcast.HazelcastManager;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.SerializerRegistry;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ClusterMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A tenant's name may not have the shape of a tid, 8 of {@code [0-9a-z]}
 * (kernel#31). Generated MCP-session and c2s record-reader code takes a
 * caller's tid from the namespace claim, which holds the tenant's name
 * (tacplus-dev/tacplus#284), so a tenant named like a tid is routed as that
 * tid: another tenant's, or {@code people}'s or {@code restore}'s.
 *
 * <p>A tenant's name is the leaf of its namespace, set at creation or by the
 * bootstrap seed and never again: kernel has no path that renames a tenant, so
 * create and seed are every path that sets one.
 */
class TenantNameShapeTest {

	private static final String REFUSAL = "a tenant name must not have the shape of a tid (8 of [0-9a-z])";

	private ConfigMap configMap;
	private TenantAdminServiceImpl admin;

	@BeforeEach
	void setUp() {
		configMap = new ConfigMap(new InMemoryManager());
		admin = new TenantAdminServiceImpl(configMap, () -> "test.schematic.io", () -> { });
	}

	private Kernel.Tenant create(String ns) throws ProtoException {
		return admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ns).build());
	}

	private void seed(String name) throws ProtoException {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(Kernel.BootstrapTenant.newBuilder().setName(name).build()));
	}

	// ---- Create ------------------------------------------------------------

	@ParameterizedTest
	@ValueSource(strings = {"acmecorp", "contoso1", "00000001", "abcdefgh"})
	void createRefusesATidShapedName(String name) {
		ProtoException e = assertThrows(ProtoException.class, () -> create("/tenants/" + name));
		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
		assertEquals(REFUSAL, e.getMessage());
		assertTrue(configMap.getTenants("/tenants/" + name).getName().isEmpty(), "no record was written");
		assertTrue(configMap.proto().getTenantIdsList().isEmpty(), "no tid was minted");
	}

	/** The name is the leaf, so a sub-tenant's leaf is checked as a top-level one is. */
	@ParameterizedTest
	@ValueSource(strings = {"acmecorp", "contoso1", "00000001", "abcdefgh"})
	void createRefusesATidShapedSubTenantName(String name) throws Exception {
		create("/tenants/acme");

		ProtoException e = assertThrows(ProtoException.class, () -> create("/tenants/acme/" + name));
		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
		assertEquals(REFUSAL, e.getMessage());
	}

	@ParameterizedTest
	@ValueSource(strings = {"acme", "acme-corp", "acmecorp9", "Acmecorp"})
	void createAcceptsANameThatIsNotTidShaped(String name) throws Exception {
		assertEquals(name, create("/tenants/" + name).getName());
		assertEquals(name, create("/tenants/" + name + "/" + name).getName());
	}

	// ---- Bootstrap seed ----------------------------------------------------

	@ParameterizedTest
	@ValueSource(strings = {"acmecorp", "contoso1", "00000001", "abcdefgh"})
	void seedRefusesATidShapedName(String name) {
		ProtoException e = assertThrows(ProtoException.class, () -> seed(name));
		assertTrue(e.getMessage().contains("/tenants/" + name + ": " + REFUSAL), e.getMessage());
		assertTrue(configMap.getTenants("/tenants/" + name).getName().isEmpty(), "no record was written");
		assertTrue(configMap.proto().getTenantIdsList().isEmpty(), "no tid was minted");
	}

	@ParameterizedTest
	@ValueSource(strings = {"acme", "acme-corp", "acmecorp9", "Acmecorp"})
	void seedAcceptsANameThatIsNotTidShaped(String name) throws Exception {
		seed(name);
		assertEquals(name, configMap.getTenants("/tenants/" + name).getName());
	}

	/** One refused entry does not stop the others, as with any refused seed. */
	@Test
	void aRefusedSeedLeavesTheOthersSeeded() {
		assertThrows(ProtoException.class, () -> TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				Kernel.BootstrapTenant.newBuilder().setName("acmecorp").build(),
				Kernel.BootstrapTenant.newBuilder().setName("acme").build())));
		assertEquals("acme", configMap.getTenants("/tenants/acme").getName());
	}

	// ---- Boot backstop -----------------------------------------------------

	/**
	 * A record written before the guard (here put straight into the map, as a
	 * restored snapshot does) is found at boot; the reserved tenants are not.
	 */
	@Test
	void bootFindsEveryExistingTenantWithATidShapedName() throws Exception {
		PeopleTenant.seed(configMap, List.of());
		RestoreTenant.seed(configMap);
		create("/tenants/acme");
		putLegacy("/tenants/acmecorp");
		putLegacy("/tenants/acme/00000001");

		assertEquals(List.of("/tenants/acme/00000001", "/tenants/acmecorp"),
				TenantIds.tidShapedTenants(configMap));
	}

	@Test
	void bootFindsNoneWhenEveryNameIsFine() throws Exception {
		create("/tenants/acme");
		create("/tenants/acmecorp9");

		assertEquals(List.of(), TenantIds.tidShapedTenants(configMap));
	}

	/** The cluster status carries what boot found. */
	@Test
	void clusterStatusNamesTheTidShapedTenants() {
		HazelcastInstance hazelcast = Hazelcast.newHazelcastInstance(hazelcastConfig());
		try {
			ClusterMap clusterMap = new ClusterMap(new HazelcastManager(hazelcast));
			ClusterStatePublisher publisher = new ClusterStatePublisher(
					hazelcast, clusterMap, null, Kernel.Config.getDefaultInstance(), 0, null, null, null);

			publisher.publishTidShapedTenants(List.of());
			assertEquals(List.of(), clusterMap.getTenantNameHealth().getTidShapedTenantsList());

			publisher.publishTidShapedTenants(List.of("/tenants/acme/00000001", "/tenants/acmecorp"));
			assertEquals(List.of("/tenants/acme/00000001", "/tenants/acmecorp"),
					clusterMap.getTenantNameHealth().getTidShapedTenantsList());
		} finally {
			hazelcast.shutdown();
		}
	}

	private void putLegacy(String ns) throws ProtoException {
		configMap.putTenants(ns, Kernel.Tenant.newBuilder()
				.setName(ns.substring(ns.lastIndexOf('/') + 1))
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.build());
		configMap.putProjectConfigs(ns + "/default", Kernel.ProjectConfigEntry.newBuilder()
				.setProjectNamespace(ns + "/default")
				.setConfig(Kernel.ProjectConfig.getDefaultInstance())
				.build());
	}

	private static Config hazelcastConfig() {
		Config config = new Config();
		config.setClusterName("tenant-name-shape-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		SerializerRegistry.register(config);
		return config;
	}
}
