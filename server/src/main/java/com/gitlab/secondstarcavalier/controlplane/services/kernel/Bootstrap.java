// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster.ClusterServer;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.PersistenceProvider;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence.PersistenceManager;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.logger.LogbackConfigurator;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared bootstrap logic for kernel nodes. Resolves a
 * {@link Kernel.BootstrapConfig} from a config file, environment variables, or
 * both, then starts the server.
 */
public class Bootstrap {

    private static final Logger logger = LoggerFactory.getLogger(Bootstrap.class);
    private static final String DEFAULT_CONFIG_NAME = "bootstrap-config";

    /**
     * Resolved configuration: both bootstrap and frontend configs.
     */
    public record ResolvedConfig(Kernel.BootstrapConfig bootstrap, Kernel.Config frontend) {}

    /**
     * Resolves configuration from args and environment, then starts the server.
     */
    public static void run(String[] args) throws Exception {
        System.setProperty("hazelcast.internal.override.enterprise", "true");

        ResolvedConfig resolved = resolveConfigs(args);
        if (resolved == null) return;

        LogbackConfigurator.install(null);
        logger.info(
                "Starting kernel node: listener={}, cluster={}",
                resolved.bootstrap().getListener(),
                resolved.bootstrap().getClusterName());

        // Create persistence
        Kernel.BootstrapConfig cfg = resolved.bootstrap();
        var members = cfg.getMembersList();
        int grpcPort = cfg.getListener().getPort();

        String hostname = System.getenv("HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = cfg.getListener().getHost();
        }
        String instanceName = (hostname != null && !hostname.isEmpty() && !hostname.equals("0.0.0.0"))
                ? "node-" + hostname
                : "node-" + (grpcPort + 1);

        PersistenceManager.PersistenceConfig persistenceConfig = PersistenceManager.PersistenceConfig.fromEnv();
        PersistenceManager persistence =
                new PersistenceManager(Path.of(cfg.getPersistenceDir()), instanceName, persistenceConfig);

        ClusterServer server;
        try {
            server = new ClusterServer(
                    resolved.bootstrap(),
                    resolved.frontend(),
                    persistence);
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

        logger.info("Kernel node ready — gRPC {}", resolved.bootstrap().getListener());

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutting down...");
            server.shutdown();
            logger.info("Shut down");
        }));

        server.awaitTermination();
    }

    /**
     * Resolves the bootstrap and frontend config from args/env.
     */
    public static ResolvedConfig resolveConfigs(String[] args) throws Exception {
        String configPath = parseConfigArg(args);
        Kernel.BootstrapConfig fileConfig = loadConfigFile(configPath);
        var envConfig = Helpers.bootstrapConfigFromEnvVar(System.getenv()).build();

        Kernel.BootstrapConfig bootstrapConfig;
        if (fileConfig != null && hasAnyField(envConfig)) {
            var merged = Helpers.mergeBootstrapConfig(envConfig, fileConfig);
            if (envConfig.getConfigCase() == Kernel.BootstrapConfig.ConfigCase.CONFIG_NOT_SET) {
                switch (fileConfig.getConfigCase()) {
                    case URL_LOADER:
                        merged.setUrlLoader(fileConfig.getUrlLoader());
                        break;
                    case FILE_LOADER:
                        merged.setFileLoader(fileConfig.getFileLoader());
                        break;
                    default:
                        break;
                }
            }
            bootstrapConfig = merged.build();
        } else if (fileConfig != null) {
            bootstrapConfig = fileConfig;
        } else if (hasAnyField(envConfig)) {
            bootstrapConfig = envConfig;
        } else {
            System.err.println(
                    "No config found. Provide --config <path>, place bootstrap-config.yaml in working dir, or set PROTO_SERVICES_BACKENDDB_BOOTSTRAP_CONFIG_* env vars.");
            System.exit(1);
            return null;
        }

        bootstrapConfig = Helpers.bootstrapConfigDefaults(bootstrapConfig).build();
        Helpers.validateBootstrapConfig(bootstrapConfig);

        Kernel.Config frontendConfig = resolveConfig(bootstrapConfig);
        if (frontendConfig != null) {
            Helpers.validateConfig(frontendConfig);
        }

        return new ResolvedConfig(bootstrapConfig, frontendConfig);
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

    private static Kernel.BootstrapConfig loadConfigFile(String configPath) throws IOException {
        if (configPath != null) {
            Path path = Path.of(configPath);
            if (!Files.exists(path)) {
                throw new IOException("Config file not found: " + path.toAbsolutePath());
            }
            logger.info("Loading bootstrap config from {}", path.toAbsolutePath());
            return parseBootstrapConfig(path);
        }

        for (String ext : new String[] {"yaml", "json", "toml"}) {
            Path path = Path.of(DEFAULT_CONFIG_NAME + "." + ext);
            if (Files.exists(path)) {
                logger.info("Loading bootstrap config from {}", path.toAbsolutePath());
                return parseBootstrapConfig(path);
            }
        }

        return null;
    }

    private static Kernel.BootstrapConfig parseBootstrapConfig(Path path) throws IOException {
        String content = Files.readString(path);
        String name = path.getFileName().toString();
        if (name.endsWith(".yaml") || name.endsWith(".yml")) {
            return Helpers.bootstrapConfigFromYaml(content);
        } else if (name.endsWith(".json")) {
            return Helpers.bootstrapConfigFromJson(content);
        } else if (name.endsWith(".toml")) {
            return Helpers.bootstrapConfigFromToml(content);
        }
        return Helpers.bootstrapConfigFromBytes(content.getBytes());
    }

    private static Kernel.Config resolveConfig(Kernel.BootstrapConfig config) throws Exception {
        switch (config.getConfigCase()) {
            case FILE_LOADER: {
                String filePath = config.getFileLoader().getPath();
                Path path = Path.of(filePath);
                if (!Files.exists(path)) {
                    throw new IOException("Config file_loader path not found: " + path.toAbsolutePath());
                }
                logger.info("Resolving file_loader config from {}", path.toAbsolutePath());
                return parseConfig(path);
            }
            case URL_LOADER: {
                var loader = config.getUrlLoader();
                logger.info("Fetching config from URL: {}", loader.getUrl());
                return fetchConfigFromUrl(loader.getUrl(), loader.getToken(), config.getLoaderCaList());
            }
            default:
                logger.info("No config loader specified — starting without frontend config");
                return null;
        }
    }

    private static Kernel.Config fetchConfigFromUrl(
            String url,
            String token,
            List<com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509.X509Cert>
                    trustedCas)
            throws Exception {

        HttpClient.Builder clientBuilder = HttpClient.newBuilder();

        if (!trustedCas.isEmpty()) {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            int i = 0;
            for (var ca : trustedCas) {
                byte[] pemBytes = java.util.Base64.getUrlDecoder().decode(ca.getBase64());
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(pemBytes));
                trustStore.setCertificateEntry("trusted-ca-" + i++, cert);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            clientBuilder.sslContext(sslContext);
        }

        HttpClient client = clientBuilder.build();

        HttpRequest.Builder reqBuilder =
                HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (token != null && !token.isEmpty()) {
            reqBuilder.header("Authorization", "Bearer " + token);
        }

        HttpResponse<String> response = client.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to fetch config from " + url + ": HTTP " + response.statusCode());
        }

        String body = response.body();
        String contentType = response.headers().firstValue("Content-Type").orElse("");

        if (contentType.contains("json") || url.endsWith(".json")) {
            return Helpers.configFromJson(body);
        }
        return Helpers.configFromYaml(body);
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

    private static boolean hasAnyField(Kernel.BootstrapConfig config) {
        return !config.getClusterName().isEmpty()
                || config.hasListener()
                || !config.getMembersList().isEmpty()
                || config.getNodeCount() != 0
                || config.hasTls()
                || config.getPartitionCount() != 0
                || !config.getPersistenceDir().isEmpty()
                || config.getPersistenceFormatValue() != 0
                || config.getConfigCase() != Kernel.BootstrapConfig.ConfigCase.CONFIG_NOT_SET;
    }
}
