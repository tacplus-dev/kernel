// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster.ClusterServer;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.KeyHelpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.logger.LogbackConfigurator;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.serviceconfig.Serviceconfig;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.host.HostOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Entry point for a single cluster node.
 *
 * <p>
 * Resolves a {@link Kernel.BootstrapConfig} from a config file, environment
 * variables, or both, then starts the server. "Mock" vs "production" is just a
 * matter of what config you provide — there is no separate code path.
 *
 * <p>
 * The {@code mock} subcommand generates bootstrap configs for a local cluster.
 */
public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static final String DEFAULT_CONFIG_NAME = "bootstrap-config";
    private static final int DEFAULT_MOCK_NODES = 3;
    private static final int GRPC_BASE_PORT = 5000;
    private static final int HAZELCAST_BASE_PORT = 6000;
    private static final int RAFT_BASE_PORT = 7000;
    private static final String MOCK_CLUSTER_NAME = "mock-cluster";

    public static void main(String[] args) throws Exception {
        // Enable Hazelcast SSL support (open-source build gate bypass).
        // The SSL wiring code ships in the open-source jar but is gated behind
        // an isEnterprise() check. This override enables mTLS for cluster
        // member-to-member communication without requiring an Enterprise license.
        System.setProperty("hazelcast.internal.override.enterprise", "true");

        if (args.length > 0 && "mock".equals(args[0])) {
            generateMockConfigs(args);
            return;
        }

        startServer(args);
    }

    // ── mock config generation ───────────────────────────────────────────
    private static void generateMockConfigs(String[] args) throws Exception {
        int nodeCount = DEFAULT_MOCK_NODES;
        Path outputDir = Path.of("mock");

        // Parse mock subcommand args: mock [--nodes N] [--output-dir DIR]
        for (int i = 1; i < args.length - 1; i++) {
            if ("--nodes".equals(args[i]) || "-n".equals(args[i])) {
                nodeCount = Integer.parseInt(args[i + 1]);
                i++;
            } else if ("--output-dir".equals(args[i]) || "-o".equals(args[i])) {
                outputDir = Path.of(args[i + 1]);
                i++;
            }
        }

        if (nodeCount < 1) {
            System.err.println("Node count must be at least 1");
            System.exit(1);
            return;
        }

        // Build the shared member list (hazelcast discovery endpoints)
        List<HostOuterClass.Host> members = new ArrayList<>();
        for (int i = 0; i < nodeCount; i++) {
            members.add(HostOuterClass.Host.newBuilder()
                    .setHost("127.0.0.1")
                    .setPort(HAZELCAST_BASE_PORT + i)
                    .build());
        }

        // Generate a self-signed CA for the mock cluster
        KeyOuterClass.Key caKey = KeyHelpers.newEC256Key();
        ImmutableKey caImmKey = ImmutableKey.from(caKey);
        long expEpoch = Instant.now().plus(365, ChronoUnit.DAYS).getEpochSecond();

        ImmutableCertPair caSigner = ImmutableCertPair.forSelfSigning(caImmKey);
        X509.X509Cert caCert = caSigner.selfSign("mock-ca", expEpoch,
                X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN, List.of());

        // Rebuild CA signer with the actual cert so sign() works
        X509.X509CertPair caPair = X509.X509CertPair.newBuilder()
                .setKey(caKey).setCert(caCert).build();
        caSigner = ImmutableCertPair.from(caPair);

        // Generate per-node bootstrap configs
        for (int i = 0; i < nodeCount; i++) {
            // Generate node key and CA-sign its cert
            KeyOuterClass.Key nodeKey = KeyHelpers.newEC256Key();
            ImmutableKey nodeImmKey = ImmutableKey.from(nodeKey);
            KeyOuterClass.PublicKey nodePubKey = KeyHelpers.newPublicKey(nodeImmKey.getPublicKey());

            X509.X509CertRequest certReq = X509.X509CertRequest.newBuilder()
                    .setIssuer("mock-node-" + i)
                    .setKey(nodePubKey)
                    .setExp(expEpoch)
                    .setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_DIGITAL_SIGNATURE)
                    .addExtKeyUsage(X509.X509ExtKeyUsage.X509_EXT_KEY_USAGE_SERVER_AUTH)
                    .addExtKeyUsage(X509.X509ExtKeyUsage.X509_EXT_KEY_USAGE_CLIENT_AUTH)
                    .build();
            X509.X509Cert nodeCert = caSigner.sign(certReq);

            X509.X509CertPair nodeTls = X509.X509CertPair.newBuilder()
                    .setKey(nodeKey).setCert(nodeCert).build();

            var config = Kernel.BootstrapConfig.newBuilder()
                    .setClusterName(MOCK_CLUSTER_NAME)
                    .setListener(HostOuterClass.Host.newBuilder()
                            .setHost("0.0.0.0")
                            .setPort(GRPC_BASE_PORT + i))
                    .setRaftPort(RAFT_BASE_PORT + i)
                    .setNodeCount(nodeCount)
                    .setTls(nodeTls)
                    .addLoaderCa(caCert)
                    .addAllMembers(members)
                    .build();

            // Apply defaults (partition_count etc.)
            config = Helpers.bootstrapConfigDefaults(config).build();

            Path nodeDir = outputDir.resolve("node-" + i);
            Files.createDirectories(nodeDir);
            Path configFile = nodeDir.resolve("bootstrap-config.yaml");
            Files.writeString(configFile, Helpers.bootstrapConfigToYaml(config));
            System.out.println("Wrote " + configFile);
        }

        // Generate bootstrap config with all gRPC endpoints for clients
        var clientConfigBuilder = Serviceconfig.BootstrapConfig.newBuilder();
        for (int i = 0; i < nodeCount; i++) {
            clientConfigBuilder.addEndpoints("127.0.0.1:" + (GRPC_BASE_PORT + i));
        }
        var clientConfig = clientConfigBuilder.build();

        String clientYaml = com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.serviceconfig.Helpers.bootstrapConfigToYaml(clientConfig);

        Files.createDirectories(outputDir);
        Path clientFile = outputDir.resolve("backendclient.yaml");
        Files.writeString(clientFile, clientYaml);
        System.out.println("Wrote " + clientFile);

        System.out.println("\nGenerated " + nodeCount + "-node mock cluster config in " + outputDir);
        System.out.println("Start each node with:");
        for (int i = 0; i < nodeCount; i++) {
            System.out.println("  java -jar kernel.jar --config " + outputDir.resolve("node-" + i).resolve("bootstrap-config.yaml"));
        }
        System.out.println("\nClient config: " + clientFile);
    }

    // ── server startup ───────────────────────────────────────────────────
    private static void startServer(String[] args) throws Exception {
        // 1. Parse --config/-c from args
        String configPath = parseConfigArg(args);

        // 2. Load BootstrapConfig from file (if available)
        Kernel.BootstrapConfig fileConfig = loadConfigFile(configPath);

        // 3. Load BootstrapConfig from env vars
        var envConfig = Helpers.bootstrapConfigFromEnvVar(System.getenv()).build();

        // 4. Merge: env overrides file, or use whichever is available
        //
        // Note: hasAnyField uses a stricter check than equals(defaultInstance)
        // because bootstrapConfigFromEnvVar unconditionally sets sub-messages
        // (network, logger) even when no env vars are present. The naive
        // equals() check would always trigger the merge path, and the
        // generated mergeBootstrapConfig does not handle the config oneof,
        // which would drop the inline config (keys, configs, etc.).
        Kernel.BootstrapConfig bootstrapConfig;
        if (fileConfig != null && hasAnyField(envConfig)) {
            var merged = Helpers.mergeBootstrapConfig(envConfig, fileConfig);
            // mergeBootstrapConfig doesn't handle the config oneof — preserve
            // the file config's oneof if env didn't set one.
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
            System.err.println("No config found. Provide --config <path>, place bootstrap-config.yaml in working dir, or set PROTO_SERVICES_BACKENDDB_BOOTSTRAP_CONFIG_* env vars.");
            System.exit(1);
            return;
        }

        // 5. Apply defaults
        bootstrapConfig = Helpers.bootstrapConfigDefaults(bootstrapConfig).build();

        // 6. Validate BootstrapConfig
        Helpers.validateBootstrapConfig(bootstrapConfig);

        // 7. Resolve config oneof — fetch Config from url_loader or file_loader
        Kernel.Config frontendConfig = resolveConfig(bootstrapConfig);

        // 8. Validate frontend Config
        if (frontendConfig != null) {
            Helpers.validateConfig(frontendConfig);
        }

        // 9. Start
        LogbackConfigurator.install(null);
        logger.info("Starting with config: listener={}:{}, cluster={}",
                bootstrapConfig.getListener().getHost(),
                bootstrapConfig.getListener().getPort(),
                bootstrapConfig.getClusterName());

        ClusterServer server;
        try {
            server = new ClusterServer(bootstrapConfig, frontendConfig);
        } catch (Exception e) {
            logger.error("Failed to initialize ClusterServer — shutting down", e);
            // Hazelcast non-daemon threads keep the JVM alive even after constructor failure.
            // Force halt to avoid gray failure (process alive but not serving).
            System.exit(1);
            return;
        }

        try {
            server.start();
        } catch (Exception e) {
            logger.error("Failed to start gRPC server — shutting down", e);
            server.shutdown();
            System.exit(1);
            return;
        }

        logger.info("Node ready — gRPC {}:{}", bootstrapConfig.getListener().getHost(),
                bootstrapConfig.getListener().getPort());

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutting down...");
            server.shutdown();
            logger.info("Shut down");
        }));

        server.awaitTermination();
    }

    // ── helpers ──────────────────────────────────────────────────────────
    private static String parseConfigArg(String[] args) {
        for (int i = 0; i < args.length - 1; i++) {
            if ("--config".equals(args[i]) || "-c".equals(args[i])) {
                return args[i + 1];
            }
        }
        // Fall back to BOOTSTRAP_CONFIG env var (consistent with fleetwood, ironmaiden, etc.)
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

        // Probe for bootstrap-config.{yaml,json,toml} in working directory
        for (String ext : new String[]{"yaml", "json", "toml"}) {
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
        // Fall back to auto-detect
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
            String url, String token,
            List<com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509.X509Cert> trustedCas)
            throws Exception {

        HttpClient.Builder clientBuilder = HttpClient.newBuilder();

        // Build SSLContext from trusted CAs if provided
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

        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET();
        if (token != null && !token.isEmpty()) {
            reqBuilder.header("Authorization", "Bearer " + token);
        }

        HttpResponse<String> response = client.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to fetch config from " + url + ": HTTP " + response.statusCode());
        }

        String body = response.body();
        String contentType = response.headers().firstValue("Content-Type").orElse("");

        // Parse based on content type or URL extension
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
        // Don't use equals(defaultInstance) — bootstrapConfigFromEnvVar
        // unconditionally sets sub-messages (network, logger) which makes the
        // config always differ from the default. Instead check if any
        // user-visible fields are actually set.
        return !config.getClusterName().isEmpty()
                || config.hasListener()
                || !config.getMembersList().isEmpty()
                || config.getNodeCount() != 0
                || config.hasTls()
                || config.getPartitionCount() != 0
                || config.getEnableMetrics()
                || config.getEnableTracing()
                || !config.getPersistenceDir().isEmpty()
                || config.getPersistenceFormatValue() != 0
                || config.getRaftPort() != 0
                || config.getConfigCase() != Kernel.BootstrapConfig.ConfigCase.CONFIG_NOT_SET;
    }
}
