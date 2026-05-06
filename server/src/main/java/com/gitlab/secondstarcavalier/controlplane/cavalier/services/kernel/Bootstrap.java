// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster.ClusterServer;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.persistence.PersistenceManager;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.logger.LogbackConfigurator;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;

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

		Kernel.Config config = resolveConfig(args);
		if (config == null)
			return;

		LogbackConfigurator.install(null);
		logger.info(
				"Starting kernel node: listener={}, cluster={}",
				config.getListener(),
				config.getClusterName());

		// Create persistence
		int grpcPort = config.getListener().getPort();

		String hostname = System.getenv("HOSTNAME");
		if (hostname == null || hostname.isEmpty()) {
			hostname = config.getListener().getHost();
		}
		String instanceName = (hostname != null && !hostname.isEmpty() && !hostname.equals("0.0.0.0"))
				? "node-" + hostname
				: "node-" + grpcPort;

		PersistenceManager.PersistenceConfig persistenceConfig = PersistenceManager.PersistenceConfig.fromEnv();
		PersistenceManager persistence = new PersistenceManager(Path.of(config.getPersistenceDir()), instanceName,
				persistenceConfig);

		ClusterServer server;
		try {
			server = new ClusterServer(config, persistence);
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
				|| !config.getPersistenceDir().isEmpty()
				|| config.getPersistenceFormatValue() != 0;
	}
}
