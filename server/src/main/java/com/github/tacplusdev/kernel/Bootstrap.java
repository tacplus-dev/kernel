// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.tacplusdev.kernel.cluster.ClusterServer;
import com.github.tacplusdev.kernel.model.chassis.logger.LogbackConfigurator;
import com.github.tacplusdev.kernel.model.types.services.kernel.Helpers;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;

/**
 * Shared bootstrap logic for kernel nodes. Resolves a
 * {@link Kernel.Config} from a config file, environment variables, or
 * both, then starts the server.
 */
public class Bootstrap {

	private static final Logger logger = LoggerFactory.getLogger(Bootstrap.class);
	private static final String DEFAULT_CONFIG_NAME = "config";

	/**
	 * Resolves configuration from args and environment, then starts the server.
	 */
	public static void run(String[] args) throws Exception {
		System.setProperty("hazelcast.internal.override.enterprise", "true");

		// Install credential redaction and transport-logger pins as the FIRST action,
		// before any gRPC channel exists. kernel does not reach the generated
		// GrpcConfigLoader (it resolves its own Kernel.Config below), so the install
		// that tacplus 6ed3608d added there never runs here. Without this, kernel logs
		// raw "authorization: Bearer ey..." headers if any transport logger is at DEBUG
		// -- the same leak that put 44 live JWTs in stratum's pod logs.
		com.github.tacplusdev.kernel.model.chassis.logger.LogbackConfigurator
				.install(null);

		Kernel.Config config = resolveConfig(args);
		if (config == null)
			return;

		// Re-install now that Kernel.Config is resolved, so the operator's
		// configured logger block (level, format, appenders) actually takes
		// effect. The pre-config install above runs with defaults because it
		// has to happen before any gRPC channel exists; this is the generated
		// GrpcConfigLoader's install(cfg.getLogger()) call, which kernel never
		// reaches because it resolves its own Kernel.Config.
		LogbackConfigurator.install(config.getLogger());
		logger.info(
				"Starting kernel node: listener={}, cluster={}",
				config.getListener(),
				config.getClusterName());

		// Kernel does no durability for service state: Hazelcast is in-memory
		// coordination, every boundary is config-seeded, rebuildable from peers,
		// or ephemeral, and durable data belongs in stratum records. The
		// `data` volume holds only kernel's OWN identity snapshot
		// (KernelDiskState) and the Ratis fenced-lock tree.
		ClusterServer server;
		try {
			server = new ClusterServer(config);
		} catch (Exception e) {
			logger.error("Failed to initialize ClusterServer — shutting down", e);
			System.exit(1);
			return;
		}

		try {
			server.start();
		} catch (IOException e) {
			logger.error("Failed to start gRPC server — shutting down", e);
			server.shutdown();
			System.exit(1);
			return;
		}

		logger.info("Kernel node ready — gRPC {}", config.getListener());

		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			logger.info("Shutting down...");
			server.shutdown();
			logger.info("Shut down");
		}));

		server.awaitTermination();
	}

	/**
	 * Resolves the config from args/env.
	 */
	public static Kernel.Config resolveConfig(String[] args) throws Exception {
		String configPath = parseConfigArg(args);
		Kernel.Config fileConfig = loadConfigFile(configPath);
		var envConfig = Helpers.configFromEnvVar(System.getenv()).build();

		Kernel.Config config;
		if (fileConfig != null && hasAnyField(envConfig)) {
			config = Helpers.mergeConfig(envConfig, fileConfig).build();
		} else if (fileConfig != null) {
			config = fileConfig;
		} else if (hasAnyField(envConfig)) {
			config = envConfig;
		} else {
			System.err.println(
					"No config found. Provide --config <path>, place config.yaml in working dir, or set env vars.");
			System.exit(1);
			return null;
		}

		config = Helpers.configDefaults(config).build();
		Helpers.validateConfig(config);

		return config;
	}

	// ── helpers ──────────────────────────────────────────────────────────
	private static String parseConfigArg(String[] args) {
		for (int i = 0; i < args.length - 1; i++) {
			if ("--config".equals(args[i]) || "-c".equals(args[i])) {
				return args[i + 1];
			}
		}
		String env = System.getenv("BOOTSTRAP_CONFIG");
		if (env != null && !env.isEmpty()) {
			return env;
		}
		return null;
	}

	private static Kernel.Config loadConfigFile(String configPath) throws IOException {
		if (configPath != null) {
			Path path = Path.of(configPath);
			if (!Files.exists(path)) {
				throw new IOException("Config file not found: " + path.toAbsolutePath());
			}
			logger.info("Loading config from {}", path.toAbsolutePath());
			return parseConfig(path);
		}

		for (String ext : new String[] { "yaml", "json", "toml" }) {
			Path path = Path.of(DEFAULT_CONFIG_NAME + "." + ext);
			if (Files.exists(path)) {
				logger.info("Loading config from {}", path.toAbsolutePath());
				return parseConfig(path);
			}
		}

		return null;
	}

	private static Kernel.Config parseConfig(Path path) throws IOException {
		String content = Files.readString(path);
		String name = path.getFileName().toString();
		if (name.endsWith(".yaml") || name.endsWith(".yml")) {
			return Helpers.configFromYaml(content);
		} else if (name.endsWith(".json")) {
			return Helpers.configFromJson(content);
		} else if (name.endsWith(".toml")) {
			return Helpers.configFromToml(content);
		}
		return Helpers.configFromYaml(content);
	}

	private static boolean hasAnyField(Kernel.Config config) {
		return !config.getClusterName().isEmpty()
				|| config.hasListener()
				|| !config.getMembersList().isEmpty()
				|| config.getNodeCount() != 0
				|| config.hasTls()
				|| config.getPartitionCount() != 0
				// Config.disk_dir is kernel's one on-disk directory (identity
				// snapshot + FencedLock Raft log); kernel does no other durability.
				|| !config.getDiskDir().isEmpty();
	}
}
