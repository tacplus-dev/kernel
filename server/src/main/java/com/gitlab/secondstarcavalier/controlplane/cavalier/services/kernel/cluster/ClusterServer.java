// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import static com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster.PeerContext.PEER_KEY;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.hazelcast.HazelcastManager;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.hazelcast.PersistenceProvider;
// StateServer is in this package
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.hazelcast.Hazelcast;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.BackendServers;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.views.JwkVerifyingKeysViewServer;
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
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Auth;
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

		// 2. Health management
		this.healthManager = new HealthStatusManager();
		healthManager.setStatus("", ServingStatus.NOT_SERVING);

		// 3. Create backend servers. The kernel's durable persistence layer has
		// been removed — `persistence` is now a no-op PersistenceProvider that
		// only tracks maps in the in-memory MapRegistry (for cluster stats) and
		// attaches no redo log / snapshot / restore. Hazelcast is in-memory
		// coordination only; every map is config-seeded, rebuildable, or
		// ephemeral.
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

		// BOOTSTRAP / SHORT-LIVED trust anchors. The operator seeds these public
		// keys (Config.bootstrap_verifying_keys) so the kernel — now a pure
		// pub/sub that mints nothing — TRUSTS mint's one-time bootstrap S2S call
		// that installs mint's REAL signing keys. Each entry carries an absolute
		// Unix `not_after`; we drop already-expired entries at boot (they are
		// short-TTL) and never refresh them — mint deletes its bootstrap key after
		// installing its real keys (cold-start only; see INTEGRATION_PLAN A0).
		// Folded into the SAME verifying-key trust set as delegate keys + the
		// runtime IdentityState verifying keys (allKeysSupplier below).
		final var bootstrapPublicKeys = new java.util.ArrayList<JwkOuterClass.Jwk>();
		{
			long nowSeconds = System.currentTimeMillis() / 1000;
			for (Kernel.BootstrapVerifyingKey bootstrap : cfg.getBootstrapVerifyingKeysList()) {
				long notAfter = bootstrap.getNotAfter();
				if (notAfter <= nowSeconds) {
					logger.warn("Ignoring expired bootstrap verifying key (kid={}, not_after={}, now={})",
							bootstrap.getKey().getKid(), notAfter, nowSeconds);
					continue;
				}
				bootstrapPublicKeys.add(bootstrap.getKey());
				logger.info("Trusting bootstrap verifying key (kid={}, not_after={}) — short-lived",
						bootstrap.getKey().getKid(), notAfter);
			}
		}

		// Combined key supplier
		Supplier<List<JwkOuterClass.Jwk>> allKeysSupplier = () -> {
			var keys = new java.util.ArrayList<>(delegatePublicKeys);
			keys.addAll(bootstrapPublicKeys);
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
				// Kernel no longer signs JWTs (minting moved to the mint service),
				// so there is no signing key to republish on cluster merge.
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
				.intercept(Auth.requestIdInterceptor())
				// Populate AUTH_HEADER_CTX_KEY so the generated Authorizer on the P2S
				// management wrappers (ClusterAdmin/TenantAdmin) can read the bearer.
				.intercept(com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.grpcserver.Authorizer.interceptor())
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

		// Kernel is now a PURE typed pub/sub state bus. It no longer signs
		// anything (JWTs or X.509 certs) and makes NO outbound S2S calls. The
		// former PKI + workload-identity authority (kernel.Mint: X509Mint /
		// WorkloadMint / WorkloadRevoke) and the cert-signing TlsCertService
		// (ManageCert) MOVED to the mint service, which is the cluster's sole
		// signing authority. The cluster-CA state (`Ca`) and the eventbus
		// self-mint trace publisher were removed with them. What remains here:
		// the CliTokenBroker (nonce matching only; token delivery via mint) and
		// the in-memory ServiceHealth self-registration so the gateway can
		// discover the kernel as a proxy backend.
		{
			var identityState = backendServers.services().getIdentityMap();

			final var delegates = cfg.getDelegatesList();
			// SPIFFE prefix for URI construction (defaults applied by Helpers).
			// This is the SPIFFE trust-domain (no leading slash); the leading-slash
			// namespace claim is derived from it via SpiffeIds / TokenWrapper bridges.
			String configuredSpiffePrefix = cfg.getSpiffePrefix();
			final String spiffePrefix = (configuredSpiffePrefix != null && !configuredSpiffePrefix.isEmpty())
					? configuredSpiffePrefix : "local/dev";

			// Mandatory, fail-closed Authorizer shared by the kernel's token-auth gRPC
			// wrappers (CliTokenBroker). The kernel verifies inbound caller tokens
			// against the published verifying keys via a LOCAL key source.
			var kernelAuthorizer = new com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.grpcserver.Authorizer(
					spiffePrefix, new LocalJwkSource(allKeysSupplier));

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

			// Publish the cluster FQDN to Identity state so services (e.g.
			// letsencrypt) can discover it. Kernel no longer mints tokens, so the
			// former token-issuer URL derived here is gone.
			String fqdn = cfg.getFqdn();
			if (fqdn != null && !fqdn.isEmpty()) {
				identityState.putFqdn(Kernel.IdentityFqdn.newBuilder().setFqdn(fqdn).build());
			}

			// ServiceHealth self-registration. This is a LOCAL Hazelcast map
			// write (kernel hosts the map), NOT an outbound S2S call — kernel
			// makes none. The former fan-out of health into per-service
			// ServiceConnections (for outbound calls, e.g. the eventbus trace
			// stream) was removed with the trace publisher.
			var healthMap = backendServers.services().getServiceHealthMap();
			// This pod's own hostname (e.g. "kernel-0") for self-registration; it
			// resolves via the per-pod service AND matches the pod's TLS cert SAN.
			final String selfGrpcHost = (hostname != null && !hostname.isEmpty()
					&& !hostname.equals("0.0.0.0")) ? hostname : "kernel-0";
			Thread healthPoller = new Thread(() -> {
				while (!Thread.currentThread().isInterrupted()) {
					// Self-register the kernel as a resolvable backend so the gateway
					// can proxy /kernel.* RPCs (CliTokenBroker) to it. Other services
					// publish ServiceInstanceHealth via S2S; the kernel hosts the map
					// and writes its own entry directly. Refreshed each cycle (well
					// within the 30s TTL). Endpoint is the headless "kernel" service
					// on the gRPC port (server-TLS, no client cert).
					try {
						var ib = com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.healthreport.Healthreport.ServiceInstanceHealth.newBuilder()
								.setId("kernel@" + instanceName)
								.setServiceId("kernel")
								.setInstanceId(instanceName)
								.setStatus(com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.healthreport.Healthreport.InstanceStatus.INSTANCE_STATUS_HEALTHY);
						ib.getGrpcEndpointBuilder().setHost(selfGrpcHost).setPort(grpcPort);
						healthMap.putInstances("kernel@" + instanceName, ib.build());
					} catch (Exception e) {
						logger.debug("kernel self-register failed: {}", e.getMessage());
					}
					try { Thread.sleep(5000); } catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
						break;
					}
				}
			}, "health-poller");
			healthPoller.setDaemon(true);
			healthPoller.start();

			// CLI token broker — mediates nonce matching between oauth instances.
			// Token SIGNING/delivery moved to the mint service (TODO(mint-wire)
			// inside CliTokenBrokerServiceImpl): this broker no longer holds any
			// signing identity, so no IdentityServiceImpl is passed.
			var cliTokenBroker = new CliTokenBrokerServiceImpl(hazelcast);

			// Register CLI token broker via tacplus-generated wrapper (handles auth).
			var cliTokenBrokerWrapper = new com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker(cliTokenBroker, kernelAuthorizer);
			serverBuilder.addService(cliTokenBrokerWrapper);
			logger.info("CliTokenBrokerService registered on gRPC server ({} delegates configured)", delegates.size());

			// EVERYTHING THAT SIGNS OR REACHES OUT HAS BEEN REMOVED FROM KERNEL:
			//   - kernel.Mint.{X509Mint,WorkloadMint,WorkloadRevoke} → mint.Mint.
			//   - kernel.Mint.{MintServiceToken,MintUserToken,TokenMint} → mint.Mint
			//     (already removed in a prior commit).
			//   - kernel.ExternalTokenMint / MintClient / TokenExchange → mint.Mint
			//     (already removed).
			//   - TlsCertService.ManageCert (auto_tls cert signing) → mint
			//     (TODO(mint): re-home ManageCert on mint; it shares the same CA
			//     authority as X509Mint, which moved to mint).
			//   - eventbus trace self-mint + outbound trace stream → removed
			//     (kernel makes no outbound S2S calls).
			//   - cluster-CA state (`Ca`) + signing chain wiring → moved to mint.
			// Tenancy (ClusterAdmin/TenantAdmin) moved to the `config` service.
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
		logger.info("gRPC server started on port {}", grpcPort);
	}

	public void shutdown() {
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