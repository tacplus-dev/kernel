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
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.wrappers.views.JwkVerifyingKeysViewServer;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.BackendServers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SerializerRegistry;
import com.hazelcast.cluster.MembershipEvent;
import com.hazelcast.cluster.MembershipListener;
import com.hazelcast.config.TcpIpConfig;
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
import java.util.Objects;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A single cluster node: one Hazelcast instance paired with one gRPC server.
 * The constructor wires everything together; call {@link #start()} to begin
 * serving and {@link #shutdown()} to tear down.
 *
 * <p>
 * All kernel boundaries are convergent. There are no distributed locks,
 * no Raft consensus, and no core/edge distinction.
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

	/**
	 * @param protoConfig    the bootstrap configuration
	 * @param frontendConfig the frontend configuration (nullable)
	 * @param persistence    persistence provider
	 */
	public ClusterServer(
			Kernel.BootstrapConfig protoConfig,
			Kernel.Config frontendConfig,
			PersistenceProvider persistence) {

		Kernel.BootstrapConfig cfg = Helpers.bootstrapConfigDefaults(protoConfig).build();
		Kernel.Config effectiveFrontendConfig = frontendConfig != null ? frontendConfig
				: Kernel.Config.getDefaultInstance();

		this.persistence = persistence;

		this.grpcPort = cfg.getGrpcPort();
		int hzPort = cfg.getHazelcastPort();
		var members = cfg.getMembersList();

		String hostname = System.getenv("HOSTNAME");
		if (hostname == null || hostname.isEmpty()) {
			hostname = cfg.getListener().getHost();
		}
		String instanceName = (hostname != null && !hostname.isEmpty() && !hostname.equals("0.0.0.0"))
				? "node-" + hostname
				: "node-" + hzPort;

		var hzConfig = new com.hazelcast.config.Config();
		hzConfig.setClusterName(Objects.requireNonNull(cfg.getClusterName(), "clusterName"));
		hzConfig.setInstanceName(Objects.requireNonNull(instanceName, "instanceName"));
		hzConfig.setProperty(
				"hazelcast.partition.count",
				Objects.requireNonNull(String.valueOf(cfg.getPartitionCount()), "hazelcast.partition.count"));
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
		for (var member : members) {
			String memberHost = Objects.requireNonNull(member.getHost(), "member.host");
			tcp.addMember(memberHost + ":" + hzPort);
		}

		hzConfig.getRestConfig().setEnabled(false);

		SerializerRegistry.register(hzConfig);
		this.hazelcast = com.hazelcast.core.Hazelcast.newHazelcastInstance(hzConfig);

		logger.info(
				"Hazelcast {} started (cluster size={})",
				instanceName,
				hazelcast.getCluster().getMembers().size());

		// 2. Health management (start as NOT_SERVING until restore completes)
		this.healthManager = new HealthStatusManager();
		healthManager.setStatus("", ServingStatus.NOT_SERVING);

		// 3. Initialize persistence
		int nodeCount = cfg.getNodeCount() > 0 ? cfg.getNodeCount() : members.size();
		if (persistence.isEnabled()) {
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
		HazelcastManager manager = new HazelcastManager(hazelcast, persistence);
		this.backendServers = new BackendServers(manager);

		// All boundaries are convergent — quorum is always available
		backendServers.services().setQuorumAvailable(true);

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
							String kid = Objects.requireNonNull(jwk.getKid(), "jwk.kid");
							result.put(kid, jwk);
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
							String kid = Objects.requireNonNull(jwk.getKid(), "jwk.kid");
							result.put(kid, jwk);
						}
					} catch (Exception e) {
						logger.warn("Failed to read TokenExchangerInternal verifying keys: {}", e.getMessage());
					}
					return result;
				});

		// Capture delegate public keys from Config
		final var delegatePublicKeys = new java.util.ArrayList<JwkOuterClass.Jwk>();
		for (Kernel.Delegate delegate : effectiveFrontendConfig.getDelegatesList()) {
			delegatePublicKeys.addAll(delegate.getCredPairsList());
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
		installTrustedCas(effectiveFrontendConfig.getTrustedCasList());

		// Install Config.configs into ConfigHolder boundary maps
		installConfigHolder(effectiveFrontendConfig);

		// ClusterState SetLogLevel handler
		this.clusterSetLogLevelHandler = new ClusterSetLogLevelHandler();

		// 5. Membership listener for cluster state publishing
		hazelcast.getCluster().addMembershipListener(new MembershipListener() {
			@Override
			public void memberAdded(MembershipEvent e) {
				int totalSize = hazelcast.getCluster().getMembers().size();
				logger.info(
						"[node:{}] Member joined: {} — cluster size={}",
						grpcPort,
						e.getMember().getAddress(),
						totalSize);
				clusterPublisher.onMembershipChange();
			}

			@Override
			public void memberRemoved(MembershipEvent e) {
				int totalSize = hazelcast.getCluster().getMembers().size();
				logger.warn(
						"[node:{}] Member left: {} — cluster size={}",
						grpcPort,
						e.getMember().getAddress(),
						totalSize);
				clusterPublisher.onMembershipChange();
			}
		});

		// Cluster is always SERVING once construction completes.
		healthManager.setStatus("", ServingStatus.SERVING);

		// 6. Build gRPC server
		BackendServer backendServer = new BackendServer();

		Hazelcast.RateLimitConfig rateLimit = effectiveFrontendConfig.getRateLimit();
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
		String nodeId = Objects.requireNonNull(
				hazelcast.getCluster().getLocalMember().getUuid().toString(),
				"nodeId");
		this.clusterPublisher = new ClusterStatePublisher(
				hazelcast,
				backendServers.services().getClusterStateMap(),
				persistence,
				cfg,
				effectiveFrontendConfig,
				grpcPort,
				rateLimiter,
				() -> Hazelcast.AdminTokenCacheStats.newBuilder()
						.setNodeId(nodeId)
						.setTimestampMs(System.currentTimeMillis())
						.build());

		// Register all gRPC services
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

		// Health service is always registered
		serverBuilder.addService(healthManager.getHealthService());

		// Create and register the token exchanger.
		if (effectiveFrontendConfig.getDelegatesCount() > 0) {
			var exchangerState = backendServers.services().getTokenExchangerStateMap();

			this.keyRotator = new KeyRotator(
					effectiveFrontendConfig.getKeyRotationIntervalSeconds() > 0
							? effectiveFrontendConfig.getKeyRotationIntervalSeconds()
							: 86400,
					jwk -> {
						try {
							String kid = Objects.requireNonNull(jwk.getKid(), "jwk.kid");
							exchangerState.putVerifyingKeys(kid, jwk);
						} catch (Exception e) {
							throw new RuntimeException("putVerifyingKeys failed", e);
						}
					},
					kid -> exchangerState.deleteVerifyingKeys(Objects.requireNonNull(kid, "kid")),
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

			final var delegates = effectiveFrontendConfig.getDelegatesList();
			var exchangerService = new TokenExchangerService(
					effectiveFrontendConfig.getDefaultTokenExpirySeconds(),
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

		// Create and register the X509 cert exchanger.
		// Every node generates its own CA keypair so it can sign certs locally.
		{
			var caState = backendServers.services().getCaStateMap();

			this.caKeyHolder = new CaKeyHolder(
					effectiveFrontendConfig.getCaCertLifetimeSeconds() > 0
							? effectiveFrontendConfig.getCaCertLifetimeSeconds()
							: 31536000,
					cert -> {
						String certId = Objects.requireNonNull(cert.getId(), "cert.id");
						caState.putCaCerts(certId, cert);
					});

			var certExchangerService = new X509CertExchangerService(caKeyHolder);
			backendServers.services().registerX509CertExchangerService(certExchangerService);
			serverBuilder.addService(certExchangerService);
			logger.info("X509CertExchangerService registered on gRPC server");
		}

		this.grpcServer = serverBuilder.build();
		logger.info("Kernel node configured (grpcPort={})", grpcPort);
	}

	private void installTrustedCas(List<X509.X509Cert> configCas) {
		var map = backendServers.services().getTrustedCaStateMap();
		int installed = 0;
		for (var ca : configCas) {
			String caId = Objects.requireNonNull(ca.getId(), "trustedCa.id");
			if (caId.isEmpty()) {
				logger.warn("Skipping trusted CA without id");
				continue;
			}
			map.putTrustedCas(caId, ca);
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
