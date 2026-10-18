// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Helpers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Regression test for kernel-8444: kernel's hand-written bootstrap uses
 * Kernel.Config (not Grpcconfig.Config), so health_probe_port must exist
 * on Kernel.Config and be defaulted by its configDefaults.
 *
 * The existing cross-language parity test in tacplus only covers
 * Grpcconfig.Config.configDefaults — it passed while kernel was broken
 * because kernel never reads Grpcconfig.Config.
 */
class KernelHealthProbePortTest {

	@Test
	void configDefaultsSetsHealthProbePort() {
		Kernel.Config empty = Kernel.Config.getDefaultInstance();
		assertEquals(0, empty.getHealthProbePort(),
				"proto default instance should have health_probe_port=0");

		Kernel.Config defaulted = Helpers.configDefaults(empty).build();
		assertEquals(8444, defaulted.getHealthProbePort(),
				"Kernel.Config.configDefaults must set health_probe_port to 8444");
	}

	@Test
	void configDefaultsPreservesExplicitHealthProbePort() {
		Kernel.Config explicit = Kernel.Config.newBuilder()
				.setHealthProbePort(9999)
				.build();

		Kernel.Config defaulted = Helpers.configDefaults(explicit).build();
		assertEquals(9999, defaulted.getHealthProbePort(),
				"configDefaults must not overwrite an explicitly set health_probe_port");
	}
}
