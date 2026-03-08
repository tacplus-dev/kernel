// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import static com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster.PeerContext.PEER_KEY;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.HazelcastManager;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.PersistenceProvider;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.backendclient.BackendServer;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.sentinel.Sentinel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.wrappers.views.JwkVerifyingKeysViewServer;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.BackendServers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Lock;
import com.hazelcast.cluster.MembershipEvent;
import com.hazelcast.cluster.MembershipListener;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.Attributes;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerServiceDefinition;
import io.grpc.ServerTransportFilter;
import io.grpc.health.v1.HealthCheckResponse.ServingStatus;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.protobuf.services.HealthStatusManager;
import java.io.IOException;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A single cluster node: one Hazelcast instance paired with one gRPC server.
 * The constructor wires everything together; call {@link #start()} to begin
 * serving and {@link #shutdown()} to tear down.
 *
 * <p>
 * Dependencies that differ between core and edge (persistence, distributed
 * locks) are injected via {@link PersistenceProvider} and a lock provider
 * function. Core nodes pass real implementations; edge nodes pass
 * {@link PersistenceProvider#disabled()} and null.
 */
public class ClusterServer {

    private static final Logger logger = LoggerFactory.getLogger(ClusterServer.class);

    private final int grpcPort;
    private final HazelcastInstance hazelcast;
    private final PersistenceProvider persistence;
    private final BackendServers backendServers;
    private final JwkVerifyingKeysViewServer jwkViewServer;
    private final ClusterStatePublisher clusterPublisher;
    private final ClusterSetLogLevelHandler clusterSetLogLevelHandler;
    private final HealthStatusManager healthManager;
    private final Server grpcServer;
    private final KeyRotator keyRotator;
    private final ExternalJwkResolver externalJwkResolver;
    private final CaKeyHolder caKeyHolder;
    private final AutoCloseable raftCloseable;

    /**
     * @param protoConfig    the bootstrap configuration
     * @param frontendConfig the frontend configuration (nullable)
     * @param persistence    persistence provider (use
     *                       {@link PersistenceProvider#disabled()} for edge)
     * @param lockProvider   distributed lock provider (nullable — null for edge)
     * @param raftCloseable  closeable for the Raft subsystem (nullable — null for
     *                       edge)
     */
    public ClusterServer(
            Kernel.BootstrapConfig protoConfig,
            Kernel.Config frontendConfig,
            PersistenceProvider persistence,
            Function<String, Lock> lockProvider,
            AutoCloseable raftCloseable) {

        // Apply all defaults (including sub-message defaults) in one shot
        Kernel.BootstrapConfig cfg =
                Helpers.bootstrapConfigDefaults(protoConfig).build();
        boolean isCore = cfg.getMode() != Kernel.NodeMode.NODE_MODE_EDGE;
        boolean isEdge = cfg.getMode() != Kernel.NodeMode.NODE_MODE_CORE;

        this.persistence = persistence;
        this.raftCloseable = raftCloseable;

        // Extract values from proto config with defaults
        this.grpcPort = cfg.getListener().getPort();
        int hzPort = grpcPort + 1;
        var members = cfg.getMembersList();
        if (frontendConfig == null) {
            frontendConfig = Kernel.Config.getDefaultInstance();
        }

        // Determine hostname for self-identification.
        String hostname = System.getenv("HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = cfg.getListener().getHost();
        }
        String instanceName = (hostname != null && !hostname.isEmpty() && !hostname.equals("0.0.0.0"))
                ? "node-" + hostname
                : "node-" + hzPort;

        // 1. Create Hazelcast instance
        var hzConfig = new com.hazelcast.config.Config();
        hzConfig.setClusterName(cfg.getClusterName());
        hzConfig.setInstanceName(instanceName);
        hzConfig.setProperty("hazelcast.partition.count", String.valueOf(cfg.getPartitionCount()));
        hzConfig.setProperty("hazelcast.logging.type", "slf4j");
        hzConfig.setProperty("hazelcast.phone.home.enabled", "false");

        // Non-core nodes join as lite members — no data partitions, no partition
        // ownership.
        if (!isCore) {
            hzConfig.setLiteMember(true);
        }

        // Network configuration
        var networkConfig = hzConfig.getNetworkConfig();
        networkConfig.setPort(hzPort);
        networkConfig.setPortAutoIncrement(false);

        var joinConfig = networkConfig.getJoin();
        joinConfig.getMulticastConfig().setEnabled(false);
        TcpIpConfig tcp = joinConfig.getTcpIpConfig();
        tcp.setEnabled(true);
        for (var member : members) {
            tcp.addMember(member.getHost() + ":" + (member.getPort() + 1));
        }

        hzConfig.getRestConfig().setEnabled(false);

        SerializerRegistry.register(hzConfig);
        this.hazelcast = Hazelcast.newHazelcastInstance(hzConfig);

        String modeName = isCore && isEdge ? "core-edge" : isCore ? "core" : "edge";
        logger.info(
                "Hazelcast {} started (mode={}, lite={}, cluster size={})",
                instanceName,
                modeName,
                hazelcast.getCluster().getLocalMember().isLiteMember(),
                hazelcast.getCluster().getMembers().size());

        // 2. Health management (start as NOT_SERVING until restore completes)
        this.healthManager = new HealthStatusManager();
        healthManager.setStatus("", ServingStatus.NOT_SERVING);

        // 3. Initialize persistence (core only)
        int nodeCount = cfg.getNodeCount() > 0 ? cfg.getNodeCount() : members.size();
        if (isCore && persistence.isEnabled()) {
            int initialQuorumForPersistence = nodeCount / 2 + 1;
            try {
                persistence.initialize(hazelcast, initialQuorumForPersistence);
            } catch (IOException e) {
                logger.warn(
                        "Persistence initialization failed — starting without "
                                + "restored state. Data will converge from peers.",
                        e);
            }
        }

        // 4. Create backend servers
        HazelcastManager manager =
                isCore ? new HazelcastManager(hazelcast, persistence, lockProvider) : new HazelcastManager(hazelcast);
        this.backendServers = new BackendServers(manager);

        // Set initial quorum state
        long initialCoreCount = hazelcast.getCluster().getMembers().stream()
                .filter(m -> !m.isLiteMember())
                .count();
        int quorumSize = nodeCount / 2 + 1;
        backendServers.services().setQuorumAvailable(!isCore || initialCoreCount >= quorumSize);

        // Create JWK verifying keys view server
        this.jwkViewServer = new JwkVerifyingKeysViewServer(
                backendServers.getAuthenticator(),
                () -> {
                    java.util.Map<String, JwkOuterClass.Jwk> result = new java.util.LinkedHashMap<>();
                    try {
                        for (JwkOuterClass.Jwk jwk : backendServers
                                .services()
                                .getIdentityStateMap()
                                .proto()
                                .getVerifyingKeysList()) {
                            result.put(jwk.getKid(), jwk);
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to read IdentityState verifying keys: {}", e.getMessage());
                    }
                    return result;
                },
                () -> {
                    java.util.Map<String, JwkOuterClass.Jwk> result = new java.util.LinkedHashMap<>();
                    try {
                        for (JwkOuterClass.Jwk jwk : backendServers
                                .services()
                                .getTokenExchangerStateMap()
                                .proto()
                                .getVerifyingKeysList()) {
                            result.put(jwk.getKid(), jwk);
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to read TokenExchangerInternal verifying keys: {}", e.getMessage());
                    }
                    return result;
                });

        // Capture delegate CredPair public keys from Config
        final var delegatePublicKeys = new java.util.ArrayList<JwkOuterClass.Jwk>();
        for (Kernel.Delegate delegate : frontendConfig.getDelegatesList()) {
            for (JwkOuterClass.CredPair cp : delegate.getCredPairsList()) {
                if (cp.hasPublicKey()) {
                    delegatePublicKeys.add(cp.getPublicKey());
                }
            }
        }

        // Combined key supplier
        Supplier<List<JwkOuterClass.Jwk>> allKeysSupplier = () -> {
            var keys = new java.util.ArrayList<>(delegatePublicKeys);
            try {
                keys.addAll(backendServers
                        .services()
                        .getTokenExchangerStateMap()
                        .proto()
                        .getVerifyingKeysList());
            } catch (Exception e) {
                logger.warn("Failed to read verifying keys: {}", e.getMessage());
            }
            return keys;
        };

        // Wire JWT key provider for SecurityAuthenticator
        backendServers.getAuthenticator().setKeyProvider(() -> {
            return JwkOuterClass.Jwks.newBuilder()
                    .addAllKeys(allKeysSupplier.get())
                    .build();
        });

        // Install trusted CAs from Config into TrustedCaState
        installTrustedCas(frontendConfig.getTrustedCasList());

        // Install Config.configs into ConfigHolder boundary maps
        installConfigHolder(frontendConfig);

        // ClusterState SetLogLevel handler
        this.clusterSetLogLevelHandler = new ClusterSetLogLevelHandler();

        // 5. Dynamic quorum monitoring
        final int quorumThreshold = quorumSize;
        final boolean coreMode = isCore;
        hazelcast.getCluster().addMembershipListener(new MembershipListener() {
            private volatile boolean hadQuorum = true;

            @Override
            public void memberAdded(MembershipEvent e) {
                long coreCount = hazelcast.getCluster().getMembers().stream()
                        .filter(m -> !m.isLiteMember())
                        .count();
                int totalSize = hazelcast.getCluster().getMembers().size();
                boolean hasQuorum = !coreMode || coreCount >= quorumThreshold;
                logger.info(
                        "[node:{}] Member joined: {} (lite={}) — cluster size={}, core count={}",
                        grpcPort,
                        e.getMember().getAddress(),
                        e.getMember().isLiteMember(),
                        totalSize,
                        coreCount);
                if (hasQuorum && !hadQuorum) {
                    logger.info(
                            "[node:{}] QUORUM RESTORED ({} core members, need {}) — atomic operations re-enabled",
                            grpcPort,
                            coreCount,
                            quorumThreshold);
                }
                hadQuorum = hasQuorum;
                backendServers.services().setQuorumAvailable(hasQuorum);
                clusterPublisher.onMembershipChange();
            }

            @Override
            public void memberRemoved(MembershipEvent e) {
                long coreCount = hazelcast.getCluster().getMembers().stream()
                        .filter(m -> !m.isLiteMember())
                        .count();
                int totalSize = hazelcast.getCluster().getMembers().size();
                boolean hasQuorum = !coreMode || coreCount >= quorumThreshold;
                logger.warn(
                        "[node:{}] Member left: {} (lite={}) — cluster size={}, core count={}",
                        grpcPort,
                        e.getMember().getAddress(),
                        e.getMember().isLiteMember(),
                        totalSize,
                        coreCount);
                if (!hasQuorum && hadQuorum) {
                    logger.warn(
                            "[node:{}] QUORUM LOST ({} core members, need {}) — atomic writes blocked, cluster remains online",
                            grpcPort,
                            coreCount,
                            quorumThreshold);
                }
                hadQuorum = hasQuorum;
                backendServers.services().setQuorumAvailable(hasQuorum);
                clusterPublisher.onMembershipChange();
            }
        });

        // Cluster is always SERVING once construction completes.
        healthManager.setStatus("", ServingStatus.SERVING);

        // 6. Build gRPC server
        BackendServer backendServer = new BackendServer();

        Kernel.RateLimitConfig rateLimit = frontendConfig.getRateLimit();
        var rateLimiter = new RateLimitInterceptor(
                rateLimit.getPollingRate(),
                rateLimit.getUnaryRate(),
                backendServers.services().getGrpcServices(),
                backendServer);

        ServerTransportFilter transportFilter = new ServerTransportFilter() {
            @Override
            public Attributes transportReady(Attributes transportAttrs) {
                var remote = transportAttrs.get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
                logger.info("Node {} — client connected: {}", grpcPort, remote);
                rateLimiter.connectionOpened();
                return transportAttrs;
            }

            @Override
            public void transportTerminated(Attributes transportAttrs) {
                if (transportAttrs == null) {
                    return;
                }
                var remote = transportAttrs.get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
                logger.info("Node {} — client disconnected: {}", grpcPort, remote);
                rateLimiter.connectionClosed();
            }
        };

        @SuppressWarnings("Convert2Lambda")
        ServerInterceptor rpcInterceptor = new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
                    ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
                String method = call.getMethodDescriptor().getFullMethodName();
                var remote = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
                String peer = remote != null ? remote.toString() : "unknown";
                logger.info("Node {} — {} from {}", grpcPort, method, peer);
                Context ctx = Context.current().withValue(PEER_KEY, peer);
                return Contexts.interceptCall(ctx, call, headers, next);
            }
        };

        // Build gRPC server with TLS
        ImmutableCertPair grpcTlsPair = ImmutableCertPair.from(cfg.getTls());
        SslContext grpcSslContext;
        try {
            SslContextBuilder sslBuilder = SslContextBuilder.forServer(
                            grpcTlsPair.getKey().getPrivateKey(),
                            grpcTlsPair.getCert().getX509Certificate())
                    .clientAuth(ClientAuth.NONE);
            grpcSslContext = GrpcSslContexts.configure(sslBuilder).build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure gRPC TLS", e);
        }

        NettyServerBuilder serverBuilder = NettyServerBuilder.forPort(grpcPort)
                .sslContext(grpcSslContext)
                .addTransportFilter(transportFilter)
                .intercept(rpcInterceptor)
                .intercept(backendServers.getAuthenticator().callerInterceptor());

        serverBuilder.intercept(rateLimiter);

        // Create cluster state publisher
        String nodeId = hazelcast.getCluster().getLocalMember().getUuid().toString();
        this.clusterPublisher = new ClusterStatePublisher(
                hazelcast,
                backendServers.services().getClusterStateMap(),
                persistence,
                cfg,
                frontendConfig,
                grpcPort,
                rateLimiter,
                () -> Sentinel.AdminTokenCacheStats.newBuilder()
                        .setNodeId(nodeId)
                        .setTimestampMs(System.currentTimeMillis())
                        .build());

        if (isEdge) {
            // --- Edge mode: register ALL gRPC services for microservice clients ---
            String clusterStateSvcName = "kernel.ClusterStateBackendService";
            for (ServerServiceDefinition svc : backendServers.services().getGrpcServices()) {
                if (svc.getServiceDescriptor().getName().equals(clusterStateSvcName)) {
                    serverBuilder.addService(clusterSetLogLevelHandler.wrapWithSetLogLevel(svc));
                } else {
                    serverBuilder.addService(svc);
                }
            }
            // Register libs gRPC services (ServiceConfigStateBackendService, etc.)
            for (ServerServiceDefinition svc : backendServers.libs().getGrpcServices()) {
                serverBuilder.addService(svc);
            }
            serverBuilder.addService(new BackendServiceImpl(backendServer, grpcPort, hazelcast, cfg.getClusterName()));
            serverBuilder.addService(io.grpc.ServerInterceptors.interceptForward(
                    jwkViewServer.bindService(),
                    backendServers.getAuthenticator().callerInterceptor()));
        }
        // Health service is always registered
        serverBuilder.addService(healthManager.getHealthService());

        // Create and register the token exchanger on all nodes (CORE and EDGE).
        // EDGE nodes serve microservice clients directly; CORE nodes must also
        // run the exchanger so that EDGE nodes can obtain tokens via the cluster.
        if (frontendConfig.getDelegatesCount() > 0) {
            var exchangerState = backendServers.services().getTokenExchangerStateMap();

            this.keyRotator = new KeyRotator(
                    frontendConfig.getKeyRotationIntervalSeconds() > 0
                            ? frontendConfig.getKeyRotationIntervalSeconds()
                            : 86400,
                    jwk -> {
                        try {
                            exchangerState.putVerifyingKeys(jwk.getKid(), jwk);
                        } catch (Exception e) {
                            throw new RuntimeException("putVerifyingKeys failed", e);
                        }
                    },
                    kid -> exchangerState.deleteVerifyingKeys(kid),
                    () -> {
                        try {
                            return new java.util.ArrayList<>(
                                    exchangerState.proto().getVerifyingKeysList());
                        } catch (Exception e) {
                            logger.warn("Failed to read verifying keys: {}", e.getMessage());
                            return List.of();
                        }
                    });

            this.externalJwkResolver = new ExternalJwkResolver(allKeysSupplier);

            final var delegates = frontendConfig.getDelegatesList();
            var exchangerService = new TokenExchangerService(
                    frontendConfig.getDefaultTokenExpirySeconds(),
                    externalJwkResolver,
                    keyRotator,
                    allKeysSupplier,
                    () -> delegates);

            backendServers.services().registerTokenExchangerService(exchangerService);
            serverBuilder.addService(exchangerService);
            logger.info("TokenExchangerService registered on gRPC server ({} delegates)", delegates.size());
        } else {
            this.keyRotator = null;
            this.externalJwkResolver = null;
        }

        // Create and register the X509 cert exchanger on all nodes (CORE and EDGE).
        // Every node generates its own CA keypair so it can sign certs locally.
        {
            var caState = backendServers.services().getCaStateMap();

            this.caKeyHolder = new CaKeyHolder(
                    frontendConfig.getCaCertLifetimeSeconds() > 0
                            ? frontendConfig.getCaCertLifetimeSeconds()
                            : 31536000,
                    cert -> caState.putCaCerts(cert.getId(), cert));

            var certExchangerService = new X509CertExchangerService(caKeyHolder);
            backendServers.services().registerX509CertExchangerService(certExchangerService);
            serverBuilder.addService(certExchangerService);
            logger.info("X509CertExchangerService registered on gRPC server");
        }

        this.grpcServer = serverBuilder.build();
        logger.info("Kernel node configured as {} (grpcPort={})", modeName.toUpperCase(), grpcPort);
    }

    private void installTrustedCas(List<X509.X509Cert> configCas) {
        var map = backendServers.services().getTrustedCaStateMap();
        int installed = 0;
        for (var ca : configCas) {
            if (ca.getId().isEmpty()) {
                logger.warn("Skipping trusted CA without id");
                continue;
            }
            map.putTrustedCas(ca.getId(), ca);
            installed++;
        }
        if (installed > 0) {
            logger.info("Installed {} trusted CA(s) into TrustedCaState", installed);
        }
    }

    private void installConfigHolder(Kernel.Config config) {
        if (!config.hasConfigs()) {
            logger.info("No configs in Config — config state maps unchanged");
            return;
        }
        int installed = backendServers.services().installServices(config.getConfigs());
        logger.info("Installed {} config(s) into per-service config state maps", installed);
    }

    public void start() throws IOException {
        grpcServer.start();
        clusterPublisher.start();
        if (keyRotator != null) {
            keyRotator.start();
        }
        if (externalJwkResolver != null) {
            externalJwkResolver.start();
        }
        if (caKeyHolder != null) {
            caKeyHolder.start();
        }
        logger.info("gRPC server started on port {}", grpcPort);
    }

    public void shutdown() {
        if (caKeyHolder != null) {
            caKeyHolder.stop();
        }
        if (keyRotator != null) {
            keyRotator.stop();
        }
        if (externalJwkResolver != null) {
            externalJwkResolver.stop();
        }
        clusterPublisher.stop();
        healthManager.enterTerminalState();
        grpcServer.shutdown();
        jwkViewServer.close();
        backendServers.services().close();
        persistence.close();
        if (raftCloseable != null) {
            try {
                raftCloseable.close();
            } catch (Exception e) {
                logger.warn("Failed to close Raft subsystem", e);
            }
        }
        hazelcast.shutdown();
        logger.info("Node {} shut down", grpcPort);
    }

    public void awaitTermination() throws InterruptedException {
        grpcServer.awaitTermination();
    }

    public int getGrpcPort() {
        return grpcPort;
    }
}
