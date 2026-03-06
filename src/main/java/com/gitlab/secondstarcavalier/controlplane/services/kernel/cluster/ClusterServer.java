// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.HazelcastManager;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence.PersistenceManager;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.raft.RatisLockManager;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence.PersistenceManager.PersistenceConfig;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.backendclient.BackendServer;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.utils.Validation;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.sentinel.Sentinel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.BackendServers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.wrappers.views.JwkVerifyingKeysViewServer;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster.PeerContext.PEER_KEY;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Supplier;

/**
 * A single cluster node: one Hazelcast instance paired with one gRPC server.
 * The constructor wires everything together; call {@link #start()} to begin
 * serving and {@link #shutdown()} to tear down.
 */
public class ClusterServer {

    private static final Logger logger = LoggerFactory.getLogger(ClusterServer.class);

    private final int grpcPort;
    private final HazelcastInstance hazelcast;
    private final PersistenceManager persistence;
    private final BackendServers backendServers;
    private final JwkVerifyingKeysViewServer jwkViewServer;
    private final ClusterStatePublisher clusterPublisher;
    private final ClusterSetLogLevelHandler clusterSetLogLevelHandler;
    private final HealthStatusManager healthManager;
    private final Server grpcServer;
    private final KeyRotator keyRotator;
    private final ExternalJwkResolver externalJwkResolver;
    private final RatisLockManager ratisLockManager;

    public ClusterServer(Kernel.BootstrapConfig protoConfig, Kernel.Config frontendConfig) {

        // Apply all defaults (including sub-message defaults) in one shot
        Kernel.BootstrapConfig cfg = Helpers.bootstrapConfigDefaults(protoConfig).build();

        // Extract values from proto config with defaults
        this.grpcPort = Validation.parsePort(cfg.getListener());
        int hzPort = grpcPort + 1;
        List<String> members = cfg.getMembersList();
        if (frontendConfig == null) {
            frontendConfig = Kernel.Config.getDefaultInstance();
        }

        // Determine hostname for self-identification.
        // Docker sets HOSTNAME to the container hostname (e.g., kernel-0).
        // For local/mock usage, fall back to matching listener host against members.
        String hostname = System.getenv("HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = Validation.parseHost(cfg.getListener());
        }
        String instanceName = (hostname != null && !hostname.isEmpty() && !hostname.equals("0.0.0.0"))
                ? "node-" + hostname
                : "node-" + hzPort;

        // 1. Create and start Ratis lock manager FIRST.
        // Raft consensus must form before the Hazelcast cluster starts so that
        // distributed locks are available when backend maps are initialized.
        String raftHost = hostname;
        // If hostname is a bind address (0.0.0.0), find our hostname in the members list
        // by matching the listener port.
        if ("0.0.0.0".equals(raftHost) || raftHost == null || raftHost.isEmpty()) {
            // Fall back: for local/mock mode, match by port offset
            if (members.size() > 0) {
                int idx = grpcPort - Validation.parsePort(members.get(0)) + 1;
                if (idx >= 0 && idx < members.size()) {
                    raftHost = Validation.parseHost(members.get(idx));
                } else {
                    raftHost = Validation.parseHost(members.get(0));
                }
            }
        }
        int raftPort = cfg.getRaftPort();
        try {
            this.ratisLockManager = new RatisLockManager(
                    raftHost,
                    raftPort,
                    members,
                    new java.io.File(cfg.getPersistenceDir(), "raft"),
                    cfg.getTls(),
                    cfg.getLoaderCaList());
            ratisLockManager.start();
            ratisLockManager.waitForLeader();
        } catch (Exception e) {
            throw new RuntimeException("Failed to start RatisLockManager", e);
        }

        // 2. Create Hazelcast instance (after Raft consensus is established)
        var hzConfig = new com.hazelcast.config.Config();
        hzConfig.setClusterName(cfg.getClusterName());
        hzConfig.setInstanceName(instanceName);
        hzConfig.setProperty("hazelcast.partition.count", String.valueOf(cfg.getPartitionCount()));
        hzConfig.setProperty("hazelcast.logging.type", "slf4j");
        hzConfig.setProperty("hazelcast.phone.home.enabled", "false");

        // Network configuration
        var networkConfig = hzConfig.getNetworkConfig();
        networkConfig.setPort(hzPort);
        networkConfig.setPortAutoIncrement(false);

        var joinConfig = networkConfig.getJoin();
        joinConfig.getMulticastConfig().setEnabled(false);
        TcpIpConfig tcp = joinConfig.getTcpIpConfig();
        tcp.setEnabled(true);
        for (String member : members) {
            tcp.addMember(member);
        }

        // Explicitly disable client protocol and REST.
        // No Hazelcast clients can connect — only cluster members.
        hzConfig.getRestConfig().setEnabled(false);

        SerializerRegistry.register(hzConfig);
        this.hazelcast = Hazelcast.newHazelcastInstance(hzConfig);

        logger.info("Hazelcast {} started (cluster size={})",
                instanceName, hazelcast.getCluster().getMembers().size());

        // 3. Create persistence manager
        PersistenceConfig persistenceConfig = PersistenceConfig.fromEnv();
        this.persistence = new PersistenceManager(
                Path.of(cfg.getPersistenceDir()), instanceName, persistenceConfig);

        // 4. Health management (start as NOT_SERVING until restore completes)
        this.healthManager = new HealthStatusManager();
        healthManager.setStatus("", ServingStatus.NOT_SERVING);

        // 5. Initialize persistence (restore from dump/redo, negotiate winner)
        //    Compute initial quorum from node_count (falling back to members size)
        int nodeCount = cfg.getNodeCount() > 0 ? cfg.getNodeCount() : members.size();
        int initialQuorumForPersistence = nodeCount / 2 + 1;
        if (persistenceConfig.enabled()) {
            try {
                persistence.initialize(hazelcast, initialQuorumForPersistence);
            } catch (IOException e) {
                logger.error("Persistence initialization failed", e);
                throw new RuntimeException("Failed to initialize persistence", e);
            }
        }

        // 6. Create backend servers (persistence listeners attached to maps)
        HazelcastManager manager = new HazelcastManager(hazelcast, persistence, ratisLockManager);
        this.backendServers = new BackendServers(manager);

        // Create JWK verifying keys view server — aggregates all view_member collections
        this.jwkViewServer = new JwkVerifyingKeysViewServer(
                backendServers.getAuthenticator(),
                // IdentityState.verifying_keys
                () -> {
                    java.util.Map<String, JwkOuterClass.Jwk> result = new java.util.LinkedHashMap<>();
                    try {
                        for (JwkOuterClass.Jwk jwk : backendServers.services().getIdentityStateMap()
                                .proto().getVerifyingKeysList()) {
                            result.put(jwk.getKid(), jwk);
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to read IdentityState verifying keys: {}", e.getMessage());
                    }
                    return result;
                },
                // TokenExchangerInternal.verifying_keys
                () -> {
                    java.util.Map<String, JwkOuterClass.Jwk> result = new java.util.LinkedHashMap<>();
                    try {
                        for (JwkOuterClass.Jwk jwk : backendServers.services().getTokenExchangerStateMap()
                                .proto().getVerifyingKeysList()) {
                            result.put(jwk.getKid(), jwk);
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to read TokenExchangerInternal verifying keys: {}", e.getMessage());
                    }
                    return result;
                });

        // Capture CredPair public keys from Config (immutable after cluster init).
        final var credPairPublicKeys = frontendConfig.getCredPairsList().stream()
                .map(JwkOuterClass.CredPair::getPublicKey)
                .collect(java.util.stream.Collectors.toList());

        // Combined key supplier: TokenExchangerInternal.verifying_keys + CredPair public keys.
        // verifying_keys are rotated by KeyRotator; CredPair keys come from Config.
        Supplier<List<JwkOuterClass.Jwk>> allKeysSupplier = () -> {
            var keys = new java.util.ArrayList<>(credPairPublicKeys);
            try {
                keys.addAll(backendServers.services().getTokenExchangerStateMap()
                        .proto().getVerifyingKeysList());
            } catch (Exception e) {
                logger.warn("Failed to read verifying keys: {}", e.getMessage());
            }
            return keys;
        };

        // Wire JWT key provider for SecurityAuthenticator (used by per-service interceptors).
        backendServers.getAuthenticator().setKeyProvider(() -> {
            return JwkOuterClass.Jwks.newBuilder()
                    .addAllKeys(allKeysSupplier.get())
                    .build();
        });

        // 5a. Install trusted CAs from Config into TrustedCaState
        installTrustedCas(frontendConfig.getTrustedCasList());

        // 5d. Install Config.configs into ConfigHolder boundary maps
        installConfigHolder(frontendConfig);

        // 5e. ClusterState SetLogLevel handler — implements SetLogLevel command
        this.clusterSetLogLevelHandler = new ClusterSetLogLevelHandler();

        // 6. Dynamic quorum monitoring — quorum = currentSize / 2 + 1
        int memberCount = members.size();
        hazelcast.getCluster().addMembershipListener(new MembershipListener() {
            private volatile boolean hadQuorum = true;

            @Override
            public void memberAdded(MembershipEvent e) {
                int size = hazelcast.getCluster().getMembers().size();
                int quorum = size / 2 + 1;
                boolean hasQuorum = size >= quorum;
                logger.info("[node:{}] Member joined: {} — cluster size={}/{}",
                        grpcPort, e.getMember().getAddress(), size, memberCount);
                if (hasQuorum && !hadQuorum) {
                    logger.info("[node:{}] QUORUM ACHIEVED ({}/{} members)",
                            grpcPort, size, memberCount);
                }
                hadQuorum = hasQuorum;
                backendServers.services().setQuorumAvailable(hasQuorum);
                healthManager.setStatus("", hasQuorum ? ServingStatus.SERVING : ServingStatus.NOT_SERVING);
                clusterPublisher.onMembershipChange();
            }

            @Override
            public void memberRemoved(MembershipEvent e) {
                int size = hazelcast.getCluster().getMembers().size();
                int quorum = size / 2 + 1;
                boolean hasQuorum = size >= quorum;
                logger.warn("[node:{}] Member left: {} — cluster size={}/{}",
                        grpcPort, e.getMember().getAddress(), size, memberCount);
                if (!hasQuorum && hadQuorum) {
                    logger.error("[node:{}] QUORUM LOST ({}/{} members, need {})",
                            grpcPort, size, memberCount, quorum);
                }
                hadQuorum = hasQuorum;
                backendServers.services().setQuorumAvailable(hasQuorum);
                healthManager.setStatus("", hasQuorum ? ServingStatus.SERVING : ServingStatus.NOT_SERVING);
                clusterPublisher.onMembershipChange();
            }
        });

        // Set initial health based on current cluster size
        int initialSize = hazelcast.getCluster().getMembers().size();
        int initialQuorum = initialSize / 2 + 1;
        boolean initialHasQuorum = initialSize >= initialQuorum;
        healthManager.setStatus("", initialHasQuorum ? ServingStatus.SERVING : ServingStatus.NOT_SERVING);

        // 7. Build gRPC server
        BackendServer backendServer = new BackendServer();

        Kernel.RateLimitConfig rateLimit = frontendConfig.getRateLimit();
        var rateLimiter = new RateLimitInterceptor(
                rateLimit.getPollingRate(), rateLimit.getUnaryRate(),
                backendServers.services().getGrpcServices(), backendServer);

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
                    return; // transportReady was never called; don't decrement
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
                    ServerCall<ReqT, RespT> call, Metadata headers,
                    ServerCallHandler<ReqT, RespT> next) {
                String method = call.getMethodDescriptor().getFullMethodName();
                var remote = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
                String peer = remote != null ? remote.toString() : "unknown";
                logger.info("Node {} — {} from {}", grpcPort, method, peer);
                Context ctx = Context.current().withValue(PEER_KEY, peer);
                return Contexts.interceptCall(ctx, call, headers, next);
            }
        };

        // Build gRPC server with TLS (encryption only — client auth uses JWT tokens)
        ImmutableCertPair grpcTlsPair = ImmutableCertPair.from(cfg.getTls());
        SslContext grpcSslContext;
        try {
            SslContextBuilder sslBuilder = SslContextBuilder
                    .forServer(grpcTlsPair.getKey().getPrivateKey(), grpcTlsPair.getCert().getX509Certificate())
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

        // Create cluster state publisher (needs rateLimiter for gRPC stats)
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

        String clusterStateSvcName = "kernel.ClusterStateBackendService";
        for (ServerServiceDefinition svc : backendServers.services().getGrpcServices()) {
            if (svc.getServiceDescriptor().getName().equals(clusterStateSvcName)) {
                serverBuilder.addService(clusterSetLogLevelHandler.wrapWithSetLogLevel(svc));
            } else {
                serverBuilder.addService(svc);
            }
        }
        serverBuilder.addService(new BackendServiceImpl(backendServer, grpcPort, hazelcast, cfg.getClusterName()));
        serverBuilder.addService(io.grpc.ServerInterceptors.interceptForward(
            jwkViewServer.bindService(), backendServers.getAuthenticator().callerInterceptor()));
        serverBuilder.addService(healthManager.getHealthService());

        // Conditionally create and register the token exchanger
        if (frontendConfig.hasTokenExchanger()) {
            var exchangerCfg = frontendConfig.getTokenExchanger();
            var exchangerState = backendServers.services().getTokenExchangerStateMap();

            this.keyRotator = new KeyRotator(
                    exchangerCfg.getKeyRotationIntervalSeconds() > 0
                            ? exchangerCfg.getKeyRotationIntervalSeconds() : 86400,
                    jwk -> {
                        try { exchangerState.putVerifyingKeys(jwk.getKid(), jwk); }
                        catch (Exception e) { throw new RuntimeException("putVerifyingKeys failed", e); }
                    },
                    kid -> exchangerState.deleteVerifyingKeys(kid),
                    () -> {
                        try { return new java.util.ArrayList<>(exchangerState.proto().getVerifyingKeysList()); }
                        catch (Exception e) { logger.warn("Failed to read verifying keys: {}", e.getMessage()); return List.of(); }
                    });

            this.externalJwkResolver = new ExternalJwkResolver(allKeysSupplier);

            // CredPairs, entitlement mappings, and service entitlements are read directly from Config
            final var credPairs = frontendConfig.getCredPairsList();
            final var entitlementMappings = frontendConfig.getEntitlementMappingsList();
            final var serviceEntitlements = frontendConfig.getServiceEntitlementsList();
            var exchangerService = new TokenExchangerService(
                    exchangerCfg,
                    externalJwkResolver,
                    keyRotator,
                    allKeysSupplier,
                    () -> credPairs,
                    () -> entitlementMappings,
                    () -> serviceEntitlements);

            backendServers.services().registerTokenExchangerService(exchangerService);
            serverBuilder.addService(exchangerService);
            logger.info("TokenExchangerService registered on gRPC server (refreshAud={})",
                    exchangerCfg.getRefreshAudience());
        } else {
            this.keyRotator = null;
            this.externalJwkResolver = null;
        }

        this.grpcServer = serverBuilder.build();
    }

    /**
     * Installs trusted CA certificates from Config into TrustedCaState.
     * CAs are keyed by their cert ID.
     */
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

    /**
     * Installs Config.configs into per-service config state boundary maps.
     * Each config is written to its own state boundary for fine-grained
     * access control via the security policy.
     */
    private void installConfigHolder(Kernel.Config config) {
        if (!config.hasConfigs()) {
            logger.info("No configs in Config — config state maps unchanged");
            return;
        }
        int installed = backendServers.services().installConfigHolder(config.getConfigs());
        logger.info("Installed {} config(s) into per-service config state maps", installed);
    }

    /**
     * Starts the gRPC server.
     */
    public void start() throws IOException {
        grpcServer.start();
        clusterPublisher.start();
        if (keyRotator != null) {
            keyRotator.start();
        }
        if (externalJwkResolver != null) {
            externalJwkResolver.start();
        }
        logger.info("gRPC server started on port {}", grpcPort);
    }

    /**
     * Shuts down the gRPC server, backend services, persistence, and Hazelcast.
     */
    public void shutdown() {
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
        ratisLockManager.close();
        hazelcast.shutdown();
        logger.info("Node {} shut down", grpcPort);
    }

    /**
     * Blocks until the gRPC server terminates.
     */
    public void awaitTermination() throws InterruptedException {
        grpcServer.awaitTermination();
    }

    public int getGrpcPort() {
        return grpcPort;
    }
}
