// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.services_config.ServicesConfig;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.Opa;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.opalib.Opalib;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.BackendServers;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Mint.UpdateOpaConfig's single write path: an unconditional put into opa's
 * config-state root, the one triggered way around {@code installConfigHolder}'s
 * create-only seeding (see {@link ConfigStateSeedCreateOnlyTest}) so an
 * authorized operator can push a live config change into an already-seeded
 * cluster on demand.
 */
class UpdateOpaConfigTest {

	private static final Opa.Config SEEDED_CONFIG = Opa.Config.newBuilder()
			.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
					.setEntryPoint("schematic/authz/bundle")
					.setCreated(1_740_000_000L))
			.build();

	private static final Opa.Config PUSHED_CONFIG = Opa.Config.newBuilder()
			.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
					.setEntryPoint("schematic/authz/live")
					.setCreated(1_770_000_000L))
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

	/** The RPC overwrites an already-populated root, unlike installConfigHolder's seeding. */
	@Test
	void overwritesAnAlreadyPopulatedRoot() throws Exception {
		servers.installServices(ServicesConfig.Services.newBuilder().setOpaConfig(SEEDED_CONFIG).build());
		assertEquals(SEEDED_CONFIG, servers.getOpaConfigStateMap().getConfig());

		IdentityServiceImpl identityService = newIdentityService(
				config -> servers.getOpaConfigStateMap().putConfig(config));

		identityService.updateOpaConfig(null, Kernel.UpdateOpaConfigRequest.newBuilder()
				.setConfig(ServicesConfig.Services.newBuilder().setOpaConfig(PUSHED_CONFIG))
				.build());

		assertEquals(PUSHED_CONFIG, servers.getOpaConfigStateMap().getConfig());
	}

	/** The existing create-only seed behavior is unaffected by this RPC's existence. */
	@Test
	void seedCreateOnlyBehaviorIsUnchanged() throws Exception {
		servers.getOpaConfigStateMap().putConfig(SEEDED_CONFIG);

		assertEquals(0, servers.installServices(
				ServicesConfig.Services.newBuilder().setOpaConfig(PUSHED_CONFIG).build()));

		assertEquals(SEEDED_CONFIG, servers.getOpaConfigStateMap().getConfig());
	}

	/** A kernel with no writable opa config state (e.g. not yet wired) fails closed. */
	@Test
	void unimplementedWhenNoOpaConfigWriter() {
		IdentityServiceImpl identityService = newIdentityService(null);

		assertThrows(ProtoException.class, () -> identityService.updateOpaConfig(null,
				Kernel.UpdateOpaConfigRequest.newBuilder()
						.setConfig(ServicesConfig.Services.newBuilder().setOpaConfig(PUSHED_CONFIG))
						.build()));
	}

	private static IdentityServiceImpl newIdentityService(
			java.util.function.Consumer<Opa.Config> opaConfigWriter) {
		return new IdentityServiceImpl(
				3600, 86_400, 86_400,
				null,            // keyRotator
				java.util.List::of, // verifyingKeys
				java.util.List::of, // delegates
				java.util.List::of, // grants
				null,            // grantsWriter
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> "test.schematic.io",
				"https://kernel.test/oidc",
				null,            // opaClient
				null,            // proxyPolicyOpaClient
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // persistState
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				opaConfigWriter);
	}
}
