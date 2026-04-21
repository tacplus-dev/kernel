// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import static com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster.PeerContext.PEER_KEY;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.graphs.hazelcast.HazelcastManager;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.graphs.hazelcast.PersistenceProvider;
// StateServer is in this package
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCert;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.BackendServers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.views.JwkVerifyingKeysViewServer;
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
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
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

	/** Context key for the raw Bearer token (available for all methods, including auth-exempt). */
	static final Context.Key<String> RAW_AUTH_TOKEN_KEY = Context.key("raw-auth-token");

	private static final Metadata.Key<String> AUTH_HEADER_KEY =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

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
	private final ImmutableCertChain signingCa;
	private final TlsCertServiceImpl tlsCertService;

	/**
	 * @param config      the kernel configuration
	 * @param persistence persistence provider
	 */
	public ClusterServer(
			Kernel.Config config,
			PersistenceProvider persistence) {

		Kernel.Config cfg = Helpers.configDefaults(config).build();

		this.persistence = persistence;

		this.grpcPort = cfg.getListener().getPort();
		int hzPort = cfg.getHazelcastListener().getPort();
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
						"Persistence initialization failed — disabling persistence. "
								+ "Data will converge from peers.",
						e);
				persistence.disable();
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
								.getIdentityMap()
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
								.getIdentityMap()
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
		for (Kernel.Delegate delegate : cfg.getDelegatesList()) {
			delegatePublicKeys.addAll(delegate.getCredPairsList());
		}

		// Combined key supplier
		Supplier<List<JwkOuterClass.Jwk>> allKeysSupplier = () -> {
			var keys = new java.util.ArrayList<>(delegatePublicKeys);
			try {
				keys.addAll(backendServers
						.services()
						.getIdentityMap()
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
		installTrustedCas(cfg.getTrustedCasList());

		// Install Config.configs into ConfigHolder boundary maps
		installConfigHolder(cfg);

		// Seed GatewayTls configCerts from the node's TLS chain so the gateway
		// can start serving HTTPS immediately. The domain comes from the FQDN
		// configured in the cluster config.
		seedGatewayTlsCerts(cfg.getTls(), cfg.getFqdn());

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
		StateServer backendServer = new StateServer();

		Hazelcast.RateLimitConfig rateLimit = cfg.getRateLimit();
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
				// Forward raw Bearer token so auth-exempt services (MintService) can
				// manually validate the caller for specific RPCs like GetServiceCertificate.
				String authHeader = headers.get(AUTH_HEADER_KEY);
				if (authHeader != null && authHeader.startsWith("Bearer ")) {
					ctx = ctx.withValue(RAW_AUTH_TOKEN_KEY, authHeader.substring(7));
				}
				return Contexts.interceptCall(ctx, call, headers, next);
			}
		};

		// Build gRPC server with TLS
		ImmutableCertChain grpcTlsChain = ImmutableCertChain.from(cfg.getTls());
		SslContext grpcSslContext;
		try {
			SslContextBuilder sslBuilder = SslContextBuilder.forServer(
					grpcTlsChain.getEffectiveKey(),
					grpcTlsChain.leaf().getX509Certificate())
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

		// Load boundary metadata from registry.json (classpath resource generated by tacplus).
		RegistryReader registryReader;
		try {
			registryReader = RegistryReader.loadFromClasspath();
		} catch (java.io.IOException e) {
			logger.warn("Failed to load registry.json — map stats will lack boundary metadata", e);
			try {
				registryReader = RegistryReader.load(new java.io.ByteArrayInputStream("{}".getBytes()));
			} catch (java.io.IOException ignored) {
				throw new RuntimeException("unreachable");
			}
		}

		// Create cluster state publisher
		String nodeId = Objects.requireNonNull(
				hazelcast.getCluster().getLocalMember().getUuid().toString(),
				"nodeId");
		this.clusterPublisher = new ClusterStatePublisher(
				hazelcast,
				backendServers.services().getClusterMap(),
				persistence,
				cfg,
				grpcPort,
				rateLimiter,
				() -> Hazelcast.AdminTokenCacheStats.newBuilder()
						.setNodeId(nodeId)
						.setTimestampMs(System.currentTimeMillis())
						.build(),
				registryReader);

		// Register all gRPC services
		String clusterStateSvcName = "kernel.ClusterStateService";
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

		// Create and register the identity service (token minting + X509 signing).
		{
			var identityState = backendServers.services().getIdentityMap();
			var caState = backendServers.services().getCaMap();

			if (cfg.getDelegatesCount() > 0) {
				long maxTokenLifetime = cfg.getMaxTokenLifetimeSeconds() > 0
					? cfg.getMaxTokenLifetimeSeconds()
					: 2592000; // 30 days default
				this.keyRotator = new KeyRotator(
						cfg.getKeyRotationIntervalSeconds() > 0
								? cfg.getKeyRotationIntervalSeconds()
								: 86400,
						maxTokenLifetime,
						jwk -> {
							try {
								String kid = Objects.requireNonNull(jwk.getKid(), "jwk.kid");
								identityState.putVerifyingKeys(kid, jwk);
							} catch (Exception e) {
								throw new RuntimeException("putVerifyingKeys failed", e);
							}
						},
						kid -> identityState.deleteVerifyingKeys(Objects.requireNonNull(kid, "kid")),
						() -> {
							try {
								return new java.util.ArrayList<>(
										identityState.proto().getVerifyingKeysList());
							} catch (Exception e) {
								logger.warn("Failed to read verifying keys: {}", e.getMessage());
								return List.of();
							}
						});

				this.externalJwkResolver = new ExternalJwkResolver(allKeysSupplier);
			} else {
				this.keyRotator = null;
				this.externalJwkResolver = null;
			}

			// Use cavalier-issued signing chain from bootstrap config (intermediate CA).
			this.signingCa = ImmutableCertChain.from(cfg.getSigningCa());

			// Populate Ca.ca_certs with cluster root CA(s) from bootstrap config.
			for (X509.X509Cert rootCa : cfg.getClusterCaList()) {
				caState.putCaCerts(Objects.requireNonNull(rootCa.getId(), "rootCa.id"), rootCa);
			}

			final var delegates = cfg.getDelegatesList();
			// SPIFFE prefix for URI construction (defaults applied by Helpers).
			String configuredSpiffePrefix = cfg.getSpiffePrefix();
			final String spiffePrefix = (configuredSpiffePrefix != null && !configuredSpiffePrefix.isEmpty())
					? configuredSpiffePrefix : "local/dev";

			// Seed ServiceConfigState with spiffe_prefix so all services receive it.
			try {
				backendServers.libs().getServiceConfigStateMap().putConfig(
						Grpcconfig.Config.newBuilder()
								.setSpiffePrefix(spiffePrefix)
								.build());
				logger.info("Seeded ServiceConfigState spiffe_prefix={}", spiffePrefix);
			} catch (Exception e) {
				logger.warn("Failed to seed ServiceConfigState: {}", e.getMessage());
			}

			String fqdn = cfg.getFqdn();
			final String tokenIssuer;
			if (fqdn != null && !fqdn.isEmpty()) {
				tokenIssuer = "https://" + fqdn + Helpers.REST_ROOT_PATH;
				identityState.putFqdn(Kernel.IdentityFqdn.newBuilder().setFqdn(fqdn).build());
			} else {
				tokenIssuer = "kernel";
			}
			// ServiceMesh for outbound S2S connections (kernel → uncleopa, etc.).
			// Build client TLS context trusting cluster CAs + signing CA.
			// Service certs are signed by per-service CAs issued by the signing CA,
			// so we must trust the signing CA chain to verify service TLS certs.
			var trustCerts = new java.util.ArrayList<java.security.cert.X509Certificate>();
			for (ImmutableCert ic : grpcTlsChain.intermediates()) {
				trustCerts.add(ic.getX509Certificate());
			}
			for (X509.X509Cert rootCa : cfg.getClusterCaList()) {
				trustCerts.add(ImmutableCert.from(rootCa).getX509Certificate());
			}
			// Trust the signing CA — services get their TLS certs via X509Mint
			// which chains through per-service CAs signed by this CA.
			trustCerts.add(signingCa.leaf().getX509Certificate());
			for (ImmutableCert ic : signingCa.intermediates()) {
				trustCerts.add(ic.getX509Certificate());
			}
			SslContext clientSslContext;
			try {
				clientSslContext = GrpcSslContexts.configure(
						SslContextBuilder.forClient()
								.trustManager(trustCerts.toArray(new java.security.cert.X509Certificate[0])),
						SslProvider.JDK)
						.build();
			} catch (Exception e) {
				throw new RuntimeException("Failed to configure client TLS for S2S", e);
			}
			final SslContext s2sSslContext = clientSslContext;

			var serviceMesh = new com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.servicemesh.ServiceMesh(
					target -> io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder.forTarget(target)
							.sslContext(s2sSslContext)
							.build());

			// Feed ServiceHealthState into the mesh so it discovers service endpoints.
			var healthMap = backendServers.services().getServiceHealthMap();
			Thread meshPoller = new Thread(() -> {
				while (!Thread.currentThread().isInterrupted()) {
					try {
						var instances = new java.util.ArrayList<>(healthMap.proto().getInstancesList());
						logger.info("mesh-debug: instances.size={}", instances.size());
						for (var inst : instances) {
							var ep = inst.getGrpcEndpoint();
							logger.info("mesh-debug: svc=[{}], status={}, ep={}:{}, id=[{}]",
									inst.getServiceId(), inst.getStatus(),
									ep != null ? ep.getHost() : "null",
									ep != null ? ep.getPort() : 0, inst.getId());
						}
						serviceMesh.onHealthUpdate(instances);
					} catch (Exception e) {
						logger.warn("ServiceMesh health update failed: {}", e.getMessage());
					}
					try { Thread.sleep(5000); } catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
						break;
					}
				}
			}, "servicemesh-health-poller");
			meshPoller.setDaemon(true);
			meshPoller.start();

			// Create GrpcS2SClients with a kernel-local token provider that self-mints
			// service tokens using the KeyRotator. This avoids the bootstrap deadlock
			// (IdentityManager calls MintServiceToken, but kernel IS the token issuer).
			var grpcClients = new com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.s2sm.internal.grpc.clients.vservices.GrpcS2SClients(
					serviceMesh,
					aud -> () -> {
						try {
							return mintSelfToken(keyRotator, tokenIssuer, aud, () -> spiffePrefix);
						} catch (Exception e) {
							throw new RuntimeException("failed to self-mint token for " + aud, e);
						}
					});

			var identityService = new IdentityServiceImpl(
					cfg.getDefaultTokenExpirySeconds(),
					cfg.getMaxTokenLifetimeSeconds(),
					externalJwkResolver,
					keyRotator,
					allKeysSupplier,
					() -> delegates,
					com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SecurityInterceptor.SERVICE_ENTITLEMENTS,
					signingCa,
					serviceName -> caState.getServiceCas(serviceName),
					(serviceName, certPair) -> caState.putServiceCas(serviceName, certPair),
					() -> spiffePrefix,
					tokenIssuer,
					grpcClients.opaEval());

			serverBuilder.addService(identityService);
			logger.info("MintService registered on gRPC server ({} delegates)", delegates.size());

			// C2S token exchange — users exchange access tokens for service-scoped tokens.
			var tokenExchangeService = new TokenExchangeServiceImpl(
					cfg.getDefaultTokenExpirySeconds(),
					cfg.getMaxTokenLifetimeSeconds(),
					keyRotator,
					allKeysSupplier,
					tokenIssuer);
			serverBuilder.addService(tokenExchangeService);
			logger.info("TokenExchangeService registered on gRPC server");

			// TLS certificate lifecycle service (ManageCert bidi stream for auto_tls services).
			this.tlsCertService = new TlsCertServiceImpl(
					cfg.getTlsCertLifetimeSeconds() > 0
							? cfg.getTlsCertLifetimeSeconds()
							: 86400,
					signingCa,
					serviceName -> caState.getServiceCas(serviceName),
					(serviceName, certPair) -> caState.putServiceCas(serviceName, certPair),
					() -> spiffePrefix);
			serverBuilder.addService(tlsCertService);
			logger.info("TlsCertService registered on gRPC server (cert lifetime={}s)",
					cfg.getTlsCertLifetimeSeconds() > 0
							? cfg.getTlsCertLifetimeSeconds() : 86400);
		}

		this.grpcServer = serverBuilder.build();
		logger.info("Kernel node configured (grpcPort={})", grpcPort);
	}

	private void installTrustedCas(List<X509.X509Cert> configCas) {
		var map = backendServers.services().getTrustedCaMap();
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

	private void seedGatewayTlsCerts(X509.X509CertChain tlsChain, String fqdn) {
		if (tlsChain == null || tlsChain.getChainCount() == 0) {
			logger.info("No TLS chain in bootstrap — skipping GatewayTls cert seeding");
			return;
		}
		String domain = (fqdn != null && !fqdn.isEmpty()) ? fqdn : "localhost";
		try {
			var cert = Kernel.GatewayTlsCert.newBuilder()
					.setDomain(domain)
					.setCertChain(tlsChain)
					.build();
			backendServers.services().getGatewayTlsMap().putConfigCerts(domain, cert);
			logger.info("Seeded GatewayTls configCerts for domain={}", domain);
		} catch (Exception e) {
			logger.warn("Failed to seed GatewayTls configCerts: {}", e.getMessage());
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
		logger.info("gRPC server started on port {}", grpcPort);
	}

	public void shutdown() {
		if (tlsCertService != null) {
			tlsCertService.stop();
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

	/**
	 * Self-mints a service token using the kernel's own KeyRotator.
	 * Used for kernel's outgoing S2S calls (e.g., to uncleopa) where kernel
	 * cannot use IdentityManager (bootstrap ordering: IdentityManager calls
	 * MintServiceToken, but kernel IS the token issuer).
	 */
	private static String mintSelfToken(KeyRotator keyRotator, String tokenIssuer,
			String audience, Supplier<String> spiffePrefixReader) throws Exception {
		com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey signingKey =
				keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new IllegalStateException("no active signing key for self-mint");
		}
		long now = java.time.Instant.now().getEpochSecond();
		long exp = now + 3600; // 1 hour

		String spiffeId = "spiffe://" + spiffePrefixReader.get() + "/kernel";

		com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper token =
				com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper.create()
						.setIssuer(tokenIssuer)
						.setSubject(spiffeId)
						.setAudience(audience)
						.setIssuedAt(now)
						.setExpiration(exp)
						.setJTI(java.util.UUID.randomUUID().toString());

		token.setSubType("service");
		token.setTokenUse("service");
		token.setAzp(com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel.getDescriptor().getPackage());
		token.setPrincipal(spiffeId);

		token.sign(signingKey);
		return token.getBase64();
	}
}
