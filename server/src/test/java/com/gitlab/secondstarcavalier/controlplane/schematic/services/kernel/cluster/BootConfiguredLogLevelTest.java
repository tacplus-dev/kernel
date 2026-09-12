// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.logger.LogbackConfigurator;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.logger.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Regression test: the operator's configured boot log level must actually be
 * applied. Bootstrap called {@code LogbackConfigurator.install(null)} after
 * resolving Kernel.Config, which discarded the {@code logger} block and left
 * every node on the default INFO — even though {@code logger} is a required
 * field on Kernel.Config, so every valid config carries one.
 *
 * <p>Kernel is the only service that resolves its own Kernel.Config instead of
 * going through the generated GrpcConfigLoader, which does the equivalent
 * {@code install(cfg.getLogger())}, so nothing else covers this path.
 */
class BootConfiguredLogLevelTest {

	/** The Kernel.Config a boot-time YAML file produces, parsed the way Bootstrap parses it. */
	private static Kernel.Config configWithLoggerLevel(String level) throws Exception {
		return Helpers.configFromYaml("logger:\n  level: " + level + "\n");
	}

	private static Level rootLevel() {
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		return context.getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME).getLevel();
	}

	@AfterEach
	void restoreDefaultLogging() {
		// install() resets the LoggerContext, so leave the fork on the same
		// defaults kernel's pre-config install establishes at boot.
		LogbackConfigurator.install(null);
	}

	@Test
	void yamlLoggerBlockReachesKernelConfig() throws Exception {
		Kernel.Config config = configWithLoggerLevel("debug");

		assertEquals(Logger.Level.LEVEL_DEBUG, config.getLogger().getLevel(),
				"a config file's logger.level must survive into Kernel.Config");
	}

	@Test
	void bootInstallAppliesConfiguredLevel() throws Exception {
		Kernel.Config config = configWithLoggerLevel("debug");

		LogbackConfigurator.install(config.getLogger());

		assertEquals(Level.DEBUG, rootLevel(),
				"boot install must apply the configured level to the root logger");
	}

	@Test
	void discardingTheConfigLeavesTheDefaultLevel() throws Exception {
		Kernel.Config config = configWithLoggerLevel("debug");
		assertEquals(Logger.Level.LEVEL_DEBUG, config.getLogger().getLevel());

		// What Bootstrap used to do with a resolved config in hand.
		LogbackConfigurator.install(null);

		assertEquals(Level.INFO, rootLevel(),
				"install(null) ignores the configured level — this is the bug being fixed");
	}
}
