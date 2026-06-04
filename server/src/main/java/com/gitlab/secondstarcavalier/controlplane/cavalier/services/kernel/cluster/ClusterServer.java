// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import static com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster.PeerContext.PEER_KEY;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.MetaData;

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
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
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
 *
 * <p>Kernel is the cluster TRUST ROOT: it mints all tokens (via the
 * {@link IdentityServiceImpl} {@code Mint} handler with the dual-key
 * {@link KeyRotator}), signs X.509 certs, owns tenancy (the
 * {@link TenantAdminServiceImpl} {@code TenantAdmin} handler), and persists its
 * OWN state via the diskstore ({@link KernelPersistence}).
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
	private final KernelPersistence kernelPersistence;
	private final ImmutableCertChain signingCa;

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

		// 3. Create backend servers. Kernel coordinates state in-memory via
		// Hazelcast; its OWN durable state is persisted as a single atomic disk
		// snapshot (KernelDiskState) by KernelPersistence — NOT via the legacy
		// redo-log PersistenceProvider, which is now a no-op map tracker for
		// cluster stats only. Every Hazelcast map is config-seeded, rebuilt from
		// the disk snapshot at boot, or ephemeral.
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

		// Capture delegate public keys from Config. Delegate cred_pair keys are
		// trusted verifying keys folded into the same trust set as the runtime
		// IdentityState verifying keys.
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

		// ClusterState SetLogLevel handler
		this.clusterSetLogLevelHandler = new ClusterSetLogLevelHandler();

		final var identityState = backendServers.services().getIdentityMap();
		final var caState = backendServers.services().getCaMap();
		final var workloadState = backendServers.services().getWorkloadMap();
		final var kernelConfigMap = backendServers.services().getConfigMap();

		// KeyRotator: kernel's dual-key (EdDSA + ES256) signing authority. The
		// publisher/remover/reader operate on the IdentityState verifying_keys
		// boundary; onKeysChanged persists a fresh disk snapshot (the snapshot is
		// taken lazily via the kernelPersistence field, assigned just below).
		this.keyRotator = new KeyRotator(
				cfg.getKeyRotationIntervalSeconds() > 0 ? cfg.getKeyRotationIntervalSeconds() : 86400,
				cfg.getMaxTokenLifetimeSeconds() > 0 ? cfg.getMaxTokenLifetimeSeconds() : 2592000,
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
						return new java.util.ArrayList<>(identityState.proto().getVerifyingKeysList());
					} catch (Exception e) {
						logger.warn("Failed to read verifying keys: {}", e.getMessage());
						return List.of();
					}
				},
				this::persistKernelState);

		// KernelPersistence builds the KernelDiskState snapshot from the rotator's
		// signing-key records plus the live boundary maps.
		this.kernelPersistence = new KernelPersistence(
				cfg.getPersistenceDir(),
				keyRotator,
				() -> {
					try {
						return new java.util.ArrayList<>(identityState.proto().getVerifyingKeysList());
					} catch (Exception e) {
						logger.warn("Failed to read verifying keys for snapshot: {}", e.getMessage());
						return List.of();
					}
				},
				() -> {
					try {
						return caState.proto();
					} catch (Exception e) {
						logger.warn("Failed to read Ca for snapshot: {}", e.getMessage());
						return Kernel.Ca.getDefaultInstance();
					}
				},
				() -> {
					try {
						return kernelConfigMap.proto();
					} catch (Exception e) {
						logger.warn("Failed to read ConfigState for snapshot: {}", e.getMessage());
						return Kernel.ConfigState.getDefaultInstance();
					}
				},
				() -> {
					try {
						return new java.util.ArrayList<>(workloadState.proto().getRevocationsList());
					} catch (Exception e) {
						logger.warn("Failed to read revocations for snapshot: {}", e.getMessage());
						return List.of();
					}
				});

		// Load the persisted snapshot and rehydrate Hazelcast-backed state before
		// the rotator starts (signing_keys are restored into the rotator; the
		// public verifying set + Ca + ConfigState + revocations are restored into
		// their boundary maps). A cold start returns null.
		Kernel.KernelDiskState snapshot = kernelPersistence.load();
		rehydrateFromSnapshot(snapshot, identityState, caState, workloadState, kernelConfigMap);
		keyRotator.restore(snapshot != null ? snapshot.getSigningKeysList() : List.of());

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
				// Re-publish this node's signing keys into the now-merged IMap so
				// all nodes in the cluster can validate tokens this node issues.
				if (keyRotator != null) {
					keyRotator.republishCurrentKeys();
				}
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
				// Forward raw Bearer token so auth-exempt services (Mint) can
				// manually validate the caller for specific RPCs.
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
				// Populate AUTH_HEADER_CTX_KEY so the generated Authorizer on the
				// C2S management wrappers (TenantAdmin) can read the bearer.
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

		// Kernel identity + tenancy control plane (the cluster trust root).
		{
			final var delegates = cfg.getDelegatesList();
			// SPIFFE prefix for URI construction (defaults applied by Helpers).
			// This is the SPIFFE trust-domain (no leading slash); the leading-slash
			// namespace claim is derived from it via SpiffeIds / TokenWrapper bridges.
			String configuredSpiffePrefix = cfg.getSpiffePrefix();
			final String spiffePrefix = (configuredSpiffePrefix != null && !configuredSpiffePrefix.isEmpty())
					? configuredSpiffePrefix : "local/dev";

			// Mandatory, fail-closed Authorizer shared by the kernel's token-auth
			// gRPC wrappers. The kernel is the JWKS authority, so it uses a LOCAL
			// key source (verify against its own keys) rather than the
			// RemoteJwkSource consumers use.
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

			// Use cavalier-issued signing chain from bootstrap config (intermediate CA).
			this.signingCa = ImmutableCertChain.from(cfg.getSigningCa());

			// Populate Ca.ca_certs with cluster root CA(s) from bootstrap config.
			for (X509.X509Cert rootCa : cfg.getClusterCaList()) {
				try {
					caState.putCaCerts(Objects.requireNonNull(rootCa.getId(), "rootCa.id"), rootCa);
				} catch (Exception e) {
					logger.warn("Failed to install cluster CA {}: {}", rootCa.getId(), e.getMessage());
				}
			}

			// Token issuer derived from the cluster FQDN.
			String fqdn = cfg.getFqdn();
			final String tokenIssuer;
			if (fqdn != null && !fqdn.isEmpty()) {
				tokenIssuer = "https://" + fqdn + Helpers.REST_ROOT_PATH;
				try {
					identityState.putFqdn(Kernel.IdentityFqdn.newBuilder().setFqdn(fqdn).build());
				} catch (Exception e) {
					logger.warn("Failed to publish FQDN: {}", e.getMessage());
				}
			} else {
				tokenIssuer = MetaData.PROJECT_NAME;
			}

			// Per-service connections for outbound S2S (OPA). Uses tacplus
			// ServiceConnection.channelFactory() — single code path for TLS context
			// + channel creation.
			java.util.function.Function<String, io.grpc.ManagedChannel> s2sChannelFactory;
			try {
				s2sChannelFactory = com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.serviceconnection.ServiceConnection.channelFactory(cfg.getTrustedCasList());
			} catch (Exception e) {
				throw new RuntimeException("Failed to create S2S channel factory", e);
			}

			var opaConn = new com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.serviceconnection.ServiceConnection("opa", s2sChannelFactory);

			// Feed ServiceHealthState into the OPA ServiceConnection.
			var healthMap = backendServers.services().getServiceHealthMap();
			final String selfGrpcHost = (hostname != null && !hostname.isEmpty()
					&& !hostname.equals("0.0.0.0")) ? hostname : "kernel-0";
			Thread healthPoller = new Thread(() -> {
				while (!Thread.currentThread().isInterrupted()) {
					// Self-register the kernel as a resolvable backend so the gateway
					// can proxy /kernel.* RPCs (Mint / TenantAdmin / CliTokenBroker)
					// to it. Endpoint is the headless "kernel" service on the gRPC
					// port (server-TLS, no client cert).
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
					try {
						var instances = new java.util.ArrayList<>(healthMap.proto().getInstancesList());
						var relevant = new java.util.ArrayList<com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.healthreport.Healthreport.ServiceInstanceHealth>();
						for (var inst : instances) {
							var ep = inst.getGrpcEndpoint();
							if (ep == null || ep.getHost().isEmpty() || ep.getPort() <= 0) continue;
							if (inst.getServiceId().equals(opaConn.serviceId())) {
								relevant.add(inst);
							}
						}
						opaConn.reconcileFromHealth(relevant);
					} catch (Exception e) {
						logger.warn("Health update failed: {}", e.getMessage());
					}
					try { Thread.sleep(5000); } catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
						break;
					}
				}
			}, "health-poller");
			healthPoller.setDaemon(true);

			// GrpcS2SClients with a per-target ChannelProvider for OPA. The token
			// provider self-mints a kernel service token (kernel IS the issuer).
			var grpcClients = new com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.clients.vservices.GrpcS2SClients(
					new com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.serviceconnection.ServiceConnection.ChannelProvider(opaConn),
					aud -> () -> {
						try {
							return mintSelfToken(keyRotator, tokenIssuer, aud, () -> spiffePrefix);
						} catch (Exception e) {
							throw new RuntimeException("failed to self-mint token for " + aud, e);
						}
					});

			healthPoller.start();

			// Both OPA clients (user-entitlement eval + proxy-policy eval). Each is
			// @Nullable in IdentityServiceImpl — null when OPA isn't reachable.
			var userEntitlementsOpa = grpcClients.userentitlementsOpaEval();
			var proxyPolicyOpa = grpcClients.proxypolicyOpaEval();

			var identityService = new IdentityServiceImpl(
					cfg.getDefaultTokenExpirySeconds(),
					cfg.getMaxTokenLifetimeSeconds(),
					cfg.getOfflineTokenLifetimeSeconds(),
					keyRotator,
					allKeysSupplier,
					() -> delegates,
					com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.SecurityInterceptor.SERVICE_ENTITLEMENTS,
					signingCa,
					serviceName -> caState.getServiceCas(serviceName),
					(serviceName, certPair) -> {
						try {
							caState.putServiceCas(serviceName, certPair);
							// A new per-service intermediate CA must survive a restart.
							persistKernelState();
						} catch (Exception e) {
							throw new RuntimeException("putServiceCas failed", e);
						}
					},
					() -> spiffePrefix,
					tokenIssuer,
					userEntitlementsOpa,
					proxyPolicyOpa,
					kernelConfigMap);

			Mint mintWrapper = new Mint(identityService, kernelAuthorizer);
			serverBuilder.addService(mintWrapper);
			logger.info("MintService registered on gRPC server ({} delegates)", delegates.size());

			// CLI token broker — mediates nonce matching between oauth instances.
			var cliTokenBroker = new CliTokenBrokerServiceImpl(identityService, hazelcast);
			var cliTokenBrokerWrapper = new com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker(cliTokenBroker, kernelAuthorizer);
			serverBuilder.addService(cliTokenBrokerWrapper);
			logger.info("CliTokenBrokerService registered on gRPC server");

			// Multi-tenancy control plane (uniform ROOT/TENANT/PROJECT tree). The
			// shared kernelAuthorizer enforces the entitlement + level-or-below
			// check (target_namespace_field) declaratively per the generated
			// wrapper. Mutating writes trigger a fresh disk snapshot.
			var tenantAdminImpl = new TenantAdminServiceImpl(
					kernelConfigMap, () -> spiffePrefix, this::persistKernelState);
			var tenantAdminWrapper = new TenantAdmin(tenantAdminImpl, kernelAuthorizer);
			serverBuilder.addService(tenantAdminWrapper);
			logger.info("TenantAdminService registered on gRPC server");
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
			try {
				map.putTrustedCas(caId, ca);
				installed++;
			} catch (Exception e) {
				logger.warn("Failed to install trusted CA {}: {}", caId, e.getMessage());
			}
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

	/** Persists the kernel disk snapshot; safe to call from any thread. */
	private void persistKernelState() {
		if (kernelPersistence != null) {
			kernelPersistence.save();
		}
	}

	/**
	 * Rehydrates Hazelcast-backed state from the loaded disk snapshot: the public
	 * verifying set, the cluster CA + per-service intermediate CAs, the
	 * tenant/project tree, and workload revocations. Signing keys are restored
	 * separately into the KeyRotator. A null snapshot (cold start) is a no-op.
	 */
	private void rehydrateFromSnapshot(
			Kernel.KernelDiskState snapshot,
			com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.IdentityMap identityState,
			com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.CaMap caState,
			com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.WorkloadMap workloadState,
			com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap configMap) {
		if (snapshot == null) {
			return;
		}
		try {
			for (JwkOuterClass.Jwk jwk : snapshot.getVerifyingKeysList()) {
				identityState.putVerifyingKeys(Objects.requireNonNull(jwk.getKid(), "jwk.kid"), jwk);
			}
			for (X509.X509Cert cert : snapshot.getCaCertsList()) {
				caState.putCaCerts(Objects.requireNonNull(cert.getId(), "caCert.id"), cert);
			}
			// NOTE: service_cas are NOT rehydrated. The Ca.service_cas map is keyed
			// by service name, but X509CertChain carries no service-name field, so
			// the key cannot be recovered from the snapshot's flat list without
			// parsing the leaf cert's URI SAN. Per the proto, each per-service
			// intermediate CA is lazily (re)created on the next X509Mint for that
			// service, so dropping them across a restart is non-fatal. (See report
			// assumption: service_cas restore is intentionally a no-op.)
			if (snapshot.getServiceCasCount() > 0) {
				logger.info("Skipping rehydrate of {} service_cas (re-created on next X509Mint)",
						snapshot.getServiceCasCount());
			}
			// tenants/tenant_configs/project_configs are keyed by full namespace.
			// Tenant.name is the leaf only; the snapshot mirrors ConfigState where
			// the map key is the full path, so the full path is recovered below
			// from the parallel tenant_configs (kept in lockstep) and project keys.
			for (Kernel.TenantConfigEntry e : snapshot.getTenantConfigsList()) {
				configMap.putTenantConfigs(e.getTenantName(), e);
			}
			for (Kernel.ProjectConfigEntry e : snapshot.getProjectConfigsList()) {
				configMap.putProjectConfigs(e.getProjectNamespace(), e);
			}
			// Restore tenant records keyed by full namespace. The full path is the
			// project's parent for each "/tenant/project" project key, or the
			// tenant_config key (both keyed by full path).
			java.util.Set<String> tenantKeys = new java.util.LinkedHashSet<>();
			for (Kernel.TenantConfigEntry e : snapshot.getTenantConfigsList()) {
				tenantKeys.add(e.getTenantName());
			}
			for (Kernel.ProjectConfigEntry e : snapshot.getProjectConfigsList()) {
				String pk = e.getProjectNamespace();
				int slash = pk.lastIndexOf('/');
				if (slash > 0) {
					tenantKeys.add(pk.substring(0, slash));
				}
			}
			// Map full-path keys to the matching Tenant record by leaf name.
			java.util.Map<String, Kernel.Tenant> byLeaf = new java.util.HashMap<>();
			for (Kernel.Tenant t : snapshot.getTenantsList()) {
				byLeaf.put(t.getName(), t);
			}
			for (String key : tenantKeys) {
				int slash = key.lastIndexOf('/');
				String leaf = slash < 0 ? key : key.substring(slash + 1);
				Kernel.Tenant t = byLeaf.get(leaf);
				if (t != null) {
					configMap.putTenants(key, t);
				}
			}
			for (Kernel.WorkloadRevocation rev : snapshot.getWorkloadRevocationsList()) {
				workloadState.putRevocations(Objects.requireNonNull(rev.getSpiffeId(), "rev.spiffe_id"), rev);
			}
			logger.info("Rehydrated kernel state from disk snapshot");
		} catch (Exception e) {
			logger.warn("Failed to fully rehydrate kernel snapshot (continuing): {}", e.getMessage(), e);
		}
	}

	public void start() throws IOException {
		grpcServer.start();
		clusterPublisher.start();
		if (keyRotator != null) {
			keyRotator.start();
		}
		logger.info("gRPC server started on port {}", grpcPort);
	}

	public void shutdown() {
		if (keyRotator != null) {
			keyRotator.stop();
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
	 * Self-mints a service token using the kernel's own KeyRotator. Used for
	 * kernel's outgoing S2S calls (e.g. to OPA) where kernel cannot exchange a
	 * token because kernel IS the token issuer.
	 */
	private static String mintSelfToken(KeyRotator keyRotator, String tokenIssuer,
			String audience, Supplier<String> spiffePrefixReader) throws Exception {
		com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.key.ImmutableKey signingKey =
				keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new IllegalStateException("no active signing key for self-mint");
		}
		long now = java.time.Instant.now().getEpochSecond();
		long exp = now + 3600; // 1 hour

		String spiffeId = SpiffeIds.build(spiffePrefixReader.get(), "kernel");

		com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.token.TokenWrapper token =
				com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.token.TokenWrapper.create()
						.setIssuer(tokenIssuer)
						.setSubject(spiffeId)
						.setAudience(audience)
						.setIssuedAt(now)
						.setExpiration(exp)
						.setJTI(java.util.UUID.randomUUID().toString());

		token.setSubType("service");
		token.setTokenUse("service");
		token.setAzp(com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel.getDescriptor().getPackage());
		token.setPrincipal(spiffeId);
		token.setNamespace(SpiffeIds.namespaceFromSpiffe(spiffeId));

		token.sign(signingKey);
		return token.getBase64();
	}

}
