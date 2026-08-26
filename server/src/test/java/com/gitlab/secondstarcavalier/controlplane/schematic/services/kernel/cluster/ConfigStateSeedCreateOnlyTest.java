// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.services_config.ServicesConfig;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.echo.EchoOuterClass;
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
 * When that install was an unconditional put, a plain rolling restart reverted
 * live-pushed config — an OPA policy, the gateway cert, the OAuth providers —
 * to whatever the bundle carried, with nothing in the cluster surfacing the
 * loss.
 *
 * <p>Seeding is therefore create-only, decided per root: seed what is absent,
 * never overwrite what is populated. Both directions are asserted here, against
 * the generated {@code BackendServers.installServices} that does the work.
 */
class ConfigStateSeedCreateOnlyTest {

	/** The policy an operator pushed live, after the cluster was already up. */
	private static final Opa.Config LIVE_OPA_CONFIG = Opa.Config.newBuilder()
			.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
					.setEntryPoint("schematic/authz/live")
					.setCreated(1_770_000_000L))
			.build();

	/** The policy the bundle carries — what a restart used to revert to. */
	private static final Opa.Config BUNDLE_OPA_CONFIG = Opa.Config.newBuilder()
			.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
					.setEntryPoint("schematic/authz/bundle")
					.setCreated(1_740_000_000L))
			.build();

	private static final EchoOuterClass.Config BUNDLE_ECHO_CONFIG =
			EchoOuterClass.Config.newBuilder().setGreeting("bundle-hello").build();

	private static final ServicesConfig.Services BUNDLE = ServicesConfig.Services.newBuilder()
			.setOpaConfig(BUNDLE_OPA_CONFIG)
			.setEchoConfig(BUNDLE_ECHO_CONFIG)
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

	/** Bootstrap: a cold cluster with empty roots still gets seeded. */
	@Test
	void emptyRootsAreSeededFromTheBundle() throws Exception {
		assertEquals(2, servers.installServices(BUNDLE));

		assertEquals(BUNDLE_OPA_CONFIG, servers.getOpaConfigStateMap().getConfig());
		assertEquals(BUNDLE_ECHO_CONFIG, servers.getEchoConfigStateMap().getConfig());
	}

	/** Restart: the second install must not revert a populated root. */
	@Test
	void populatedRootSurvivesReinstall() throws Exception {
		servers.installServices(BUNDLE);
		// Operator pushes a policy over the seeded default while the cluster runs.
		servers.getOpaConfigStateMap().putConfig(LIVE_OPA_CONFIG);

		// The restarting member re-runs the install with the same bundle.
		assertEquals(0, servers.installServices(BUNDLE));

		assertEquals(LIVE_OPA_CONFIG, servers.getOpaConfigStateMap().getConfig());
	}

	/**
	 * The decision is per root, not per cluster: a cluster holding one populated
	 * root still gets its remaining empty roots filled in.
	 */
	@Test
	void partiallyPopulatedClusterGetsItsMissingRootsSeeded() throws Exception {
		servers.getOpaConfigStateMap().putConfig(LIVE_OPA_CONFIG);

		assertEquals(1, servers.installServices(BUNDLE));

		assertEquals(LIVE_OPA_CONFIG, servers.getOpaConfigStateMap().getConfig());
		assertEquals(BUNDLE_ECHO_CONFIG, servers.getEchoConfigStateMap().getConfig());
	}
}
