// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.services_config.ServicesConfig;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.gateway.Gateway;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.Opa;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.opalib.Opalib;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.BackendServers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Kernel installs the bundle's per-service configs into the ConfigHolder
 * boundary maps on every start ({@code ClusterServer.installConfigHolder}).
 *
 * <p>The bundle wins, per root and unconditionally: config is code, so the
 * git-committed bundle is the single source of truth and a changed bundle value
 * must become live on the next kernel restart, for every service. The bundle is
 * the only writer; anything written into a root out of band is transient by
 * definition and is reverted by the next install. Both directions are asserted
 * here, against the generated {@code BackendServers.installServices} that does
 * the work.
 */
class ConfigStateSeedBundleWinsTest {

	/** A policy written into the root out of band, after the cluster was up. */
	private static final Opa.Config LIVE_OPA_CONFIG = Opa.Config.newBuilder()
			.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
					.setEntryPoint("schematic/authz/live")
					.setCreated(1_770_000_000L))
			.build();

	/** The policy the bundle carries — what every restart reverts to. */
	private static final Opa.Config BUNDLE_OPA_CONFIG = Opa.Config.newBuilder()
			.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
					.setEntryPoint("schematic/authz/bundle")
					.setCreated(1_740_000_000L))
			.build();

	private static final Gateway.Config BUNDLE_GATEWAY_CONFIG =
			Gateway.Config.newBuilder().addExternalHostnames("bundle.schematic.test").build();

	private static final ServicesConfig.Services BUNDLE = ServicesConfig.Services.newBuilder()
			.setOpaConfig(BUNDLE_OPA_CONFIG)
			.setGatewayConfig(BUNDLE_GATEWAY_CONFIG)
			.build();

	private BackendServers servers;

	@BeforeEach
	void setUp() {
		servers = new BackendServers(new InMemoryManager(), new SecurityAuthenticator());
	}

	@AfterEach
	void tearDown() {
		if (servers != null) {
			servers.close();
		}
	}

	/** Bootstrap: a cold cluster with empty roots gets seeded. */
	@Test
	void emptyRootsAreSeededFromTheBundle() throws Exception {
		assertEquals(2, servers.installServices(BUNDLE));

		assertEquals(BUNDLE_OPA_CONFIG, servers.getOpaConfigStateMap().getConfig());
		assertEquals(BUNDLE_GATEWAY_CONFIG, servers.getGatewayConfigStateMap().getConfig());
	}

	/** Restart: a config written out of band is reverted to the bundle's. */
	@Test
	void populatedRootIsOverwrittenByTheBundleOnReinstall() throws Exception {
		servers.installServices(BUNDLE);
		// A policy lands over the seeded default while the cluster runs.
		servers.getOpaConfigStateMap().putConfig(LIVE_OPA_CONFIG);

		// The restarting member re-runs the install with the same bundle.
		assertEquals(2, servers.installServices(BUNDLE));

		assertEquals(BUNDLE_OPA_CONFIG, servers.getOpaConfigStateMap().getConfig());
	}

	/**
	 * The incident this rule exists for: a bundle value changed between boots
	 * reaches the running cluster even though the root is already populated.
	 */
	@Test
	void aChangedBundleValueTakesEffectOnTheNextInstall() throws Exception {
		servers.installServices(BUNDLE);

		ServicesConfig.Services changed = BUNDLE.toBuilder()
				.setGatewayConfig(Gateway.Config.newBuilder()
						.addExternalHostnames("changed.schematic.test"))
				.build();

		assertEquals(2, servers.installServices(changed));

		assertEquals(changed.getGatewayConfig(), servers.getGatewayConfigStateMap().getConfig());
	}

	/** A root the bundle does not carry is left as it is. */
	@Test
	void rootsAbsentFromTheBundleAreLeftAlone() throws Exception {
		servers.getOpaConfigStateMap().putConfig(LIVE_OPA_CONFIG);

		ServicesConfig.Services gatewayOnly = ServicesConfig.Services.newBuilder()
				.setGatewayConfig(BUNDLE_GATEWAY_CONFIG)
				.build();

		assertEquals(1, servers.installServices(gatewayOnly));

		assertEquals(LIVE_OPA_CONFIG, servers.getOpaConfigStateMap().getConfig());
		assertEquals(BUNDLE_GATEWAY_CONFIG, servers.getGatewayConfigStateMap().getConfig());
	}
}
