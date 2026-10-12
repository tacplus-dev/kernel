// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import static com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster.PeerContext.PEER_KEY;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.MetaData;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.hazelcast.HazelcastManager;
// StateServer is in this package
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Helpers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.BackendServers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.views.JwkVerifyingKeysViewServer;
import com.hazelcast.cluster.MembershipEvent;
import com.hazelcast.cluster.MembershipListener;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.Attributes;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerMethodDefinition;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.ServerTransportFilter;
import io.grpc.protobuf.ProtoUtils;
import io.grpc.health.v1.HealthCheckResponse.ServingStatus;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.protobuf.services.HealthStatusManager;
import io.grpc.stub.ServerCalls;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Auth;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.fencedlock.RatisFencedLock;
import org.apache.ratis.protocol.RaftGroup;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.FencedLock;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.PersonalIdentity;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.UserMint;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
import java.io.IOException;
import java.util.ArrayList;
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
 * {@link TenantAdminServiceImpl} {@code TenantAdmin} handler).
 *
 * <p>Kernel does NO durability for service state and holds no user data. Every
 * boundary is in-memory coordination, rebuilt from config seeding and from
 * peers on every start; durable data belongs in stratum records. The one thing
 * kernel writes to disk is its OWN identity snapshot ({@link IdentitySnapshot}
 * — signing keys, CAs, the tenant tree, grants, links, principals).
 */
public class ClusterServer {

	private static final Logger logger = LoggerFactory.getLogger(ClusterServer.class);
	private static final String DEFAULT_KUBERNETES_TOKEN_AUDIENCE = "schematic-kernel";

	/** Context key for the raw Bearer token (available for all methods, including auth-exempt). */
	static final Context.Key<String> RAW_AUTH_TOKEN_KEY = Context.key("raw-auth-token");

	private static final Metadata.Key<String> AUTH_HEADER_KEY =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
	private static final String MINT_SERVICE_NAME = "kernel.Mint";
	private static final String MINT_X509_CERT_METHOD_NAME = MINT_SERVICE_NAME + "/MintX509Cert";
	private static final MethodDescriptor<Tokenrequest.X509MintRequest, X509.X509CertChain> MINT_X509_CERT_METHOD =
			MethodDescriptor.<Tokenrequest.X509MintRequest, X509.X509CertChain>newBuilder()
					.setType(MethodDescriptor.MethodType.UNARY)
					.setFullMethodName(MINT_X509_CERT_METHOD_NAME)
					.setRequestMarshaller(ProtoUtils.marshaller(Tokenrequest.X509MintRequest.getDefaultInstance()))
					.setResponseMarshaller(ProtoUtils.marshaller(X509.X509CertChain.getDefaultInstance()))
					.build();

	private static StatusRuntimeException toGrpcError(Exception e) {
		if (e instanceof StatusRuntimeException statusRuntimeException) {
			return statusRuntimeException;
		}
		if (e instanceof ProtoException protoException) {
			return Status.fromCodeValue(protoException.getCode())
					.withDescription(protoException.getMessage())
					.withCause(protoException)
					.asRuntimeException();
		}
		return Status.INTERNAL
				.withDescription(e.getMessage() == null ? e.toString() : e.getMessage())
				.withCause(e)
				.asRuntimeException();
	}

	/**
	 * The WebAuthn relying party the device flows check assertions against, read
	 * from the environment beside kernel's other per-deployment values the
	 * bundle's {@code Config} has no field for.
	 *
	 * <p>Absent configuration is not "no check": it is a relying party that
	 * refuses every assertion. Logged at startup so an operator who meant to run
	 * the device flows sees why they are all being refused, and at INFO rather
	 * than WARN because most deployments never touch them.
	 */
	private static WebauthnProof.RelyingParty webauthnRelyingParty() {
		WebauthnProof.RelyingParty relyingParty =
				WebauthnProof.RelyingParty.fromEnvironment(System.getenv());
		if (!relyingParty.isConfigured()) {
			logger.info("No WebAuthn relying party configured ({} and {}); "
					+ "device link and device approval assertions will be refused",
					WebauthnProof.RelyingParty.RP_ID_ENV,
					WebauthnProof.RelyingParty.ORIGINS_ENV);
		}
		return relyingParty;
	}

	private static String kubernetesTokenAudience() {
		String audience = System.getenv("KERNEL_K8S_TOKEN_AUDIENCE");
		return audience == null || audience.isBlank() ? DEFAULT_KUBERNETES_TOKEN_AUDIENCE : audience.strip();
	}

	private static KubernetesTokenVerifier kubernetesTokenVerifier() {
		try {
			return TokenReviewKubernetesTokenVerifier.inCluster();
		} catch (IllegalStateException e) {
			logger.info("Kubernetes TokenReview verifier not configured: {}", e.getMessage());
			return null;
		} catch (Exception e) {
			logger.warn("Kubernetes TokenReview verifier is unavailable: {}", e.getMessage());
			return (token, requiredAudience) -> {
				throw new KubernetesTokenVerifier.K8sTokenVerificationException(
						Status.UNAVAILABLE,
						"kubernetes TokenReview verifier is unavailable: " + e.getMessage());
			};
		}
	}

	private static ServerServiceDefinition ensureMintX509CertBinding(
			ServerServiceDefinition base,
			IdentityServiceImpl identityService) {
		boolean hasMintX509Cert = base.getMethods().stream()
				.anyMatch(method -> method.getMethodDescriptor().getFullMethodName().equals(MINT_X509_CERT_METHOD_NAME));
		if (hasMintX509Cert) {
			return base;
		}

		ServerServiceDefinition.Builder builder = ServerServiceDefinition.builder(base.getServiceDescriptor().getName());
		for (ServerMethodDefinition<?, ?> method : base.getMethods()) {
			builder.addMethod((ServerMethodDefinition<?, ?>) method);
		}
		builder.addMethod(
				MINT_X509_CERT_METHOD,
				ServerCalls.asyncUnaryCall((Tokenrequest.X509MintRequest request,
						io.grpc.stub.StreamObserver<X509.X509CertChain> responseObserver) -> {
					try {
						com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Helpers.validateX509MintRequest(request);
						X509.X509CertChain response = identityService.mintX509Cert(null, request);
						responseObserver.onNext(response);
						responseObserver.onCompleted();
					} catch (Exception e) {
						logger.error("MintX509Cert direct binding failed", e);
						responseObserver.onError(toGrpcError(e));
					}
				}));
		logger.warn("{} missing from generated Mint service definition; installed direct kernel binding",
				MINT_X509_CERT_METHOD_NAME);
		return builder.build();
	}

	private static List<String> methodNames(ServerServiceDefinition serviceDefinition) {
		List<String> methods = new ArrayList<>();
		for (ServerMethodDefinition<?, ?> method : serviceDefinition.getMethods()) {
			methods.add(method.getMethodDescriptor().getFullMethodName());
		}
		return methods;
	}

	private final int grpcPort;
	private final HazelcastInstance hazelcast;
	private final BackendServers backendServers;
	private final JwkVerifyingKeysViewServer jwkViewServer;
	private final ClusterStatePublisher clusterPublisher;
	private final ClusterSetLogLevelHandler clusterSetLogLevelHandler;
	private final HealthStatusManager healthManager;
	private final Server healthProbeServer;
	private final Server grpcServer;
	private final KeyRotator keyRotator;
	private final IdentitySnapshot identitySnapshot;
	private final ImmutableCertChain signingCa;
	private final RatisFencedLock fencedLock;
	/**
	 * The kernel Authorizer's key source, assigned during construction (below the
	 * KeyRotator) and refreshed by {@link #onSigningKeysChanged}.
	 */
	private LocalJwkSource kernelJwkSource;

	/**
	 * @param config the kernel configuration
	 */
	public ClusterServer(Kernel.Config config) {

		Kernel.Config cfg = Helpers.configDefaults(config).build();

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

		// Start plaintext health probe server BEFORE any kernel-dependent init,
		// matching the pattern in the generated ServiceManager. This lets k8s
		// startup probes connect while kernel is still initialising.
		//
		// The `> 0` guard mirrors the generated path. Without it a config that
		// somehow carries 0 would bind an EPHEMERAL port rather than disabling the
		// listener — silently wrong, and exactly the sort of gap that made this
		// defect survive four rounds of diagnosis.
		if (cfg.getHealthProbePort() > 0) {
			try {
				this.healthProbeServer = com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.GrpcServer
						.startHealthProbeServer(cfg.getHealthProbePort(), healthManager);
			} catch (Exception e) {
				throw new RuntimeException("Failed to start health probe server on port " + cfg.getHealthProbePort(), e);
			}
		} else {
			this.healthProbeServer = null;
		}

		// 3. Create backend servers. Kernel coordinates state in-memory via
		// Hazelcast and writes none of it to disk: every boundary is
		// config-seeded, rebuildable from peers, or ephemeral. Durable data is
		// stratum's, not kernel's.
		HazelcastManager manager = new HazelcastManager(hazelcast);
		this.backendServers = new BackendServers(manager);

		// All boundaries are convergent — quorum is always available
		backendServers.services().setQuorumAvailable(true);

		// Every verifying-key read below goes through ONE last-known-good guard.
		// A read that throws — or that comes back empty after keys have been
		// seen — is a failed read, not "the cluster has zero valid keys", and
		// returning an empty list for it used to empty the served key set
		// through every consumer at once: the JWK view watchers, the WatchJwks
		// subscribers and kernel's own Authorizer all read from here, so one
		// Hazelcast partition-migration timeout became platform-wide
		// UNAUTHENTICATED until the next successful poll.
		final Supplier<List<JwkOuterClass.Jwk>> allKeysSupplier = lastKnownGoodVerifyingKeys(
				() -> backendServers.services().getIdentityMap().proto().getVerifyingKeysList());

		final Supplier<java.util.Map<String, JwkOuterClass.Jwk>> keysByKid = () -> {
			java.util.Map<String, JwkOuterClass.Jwk> result = new java.util.LinkedHashMap<>();
			for (JwkOuterClass.Jwk jwk : allKeysSupplier.get()) {
				result.put(Objects.requireNonNull(jwk.getKid(), "jwk.kid"), jwk);
			}
			return result;
		};

		// Create JWK verifying keys view server. Both member maps the generated
		// view declares (IdentityState and TokenExchangerInternal) resolve to
		// the same IdentityState verifying_keys boundary, as they did before;
		// buildMergedResponse merges them by kid.
		this.jwkViewServer = new JwkVerifyingKeysViewServer(
				backendServers.getAuthenticator(), keysByKid, keysByKid);

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
		this.clusterSetLogLevelHandler = new ClusterSetLogLevelHandler(backendServers.getAuthenticator());

		final var identityState = backendServers.services().getIdentityMap();
		final var caState = backendServers.services().getCaMap();
		final var workloadState = backendServers.services().getWorkloadMap();
		final var kernelConfigMap = backendServers.services().getConfigMap();
		final var principalState = backendServers.services().getPrincipalMap();

		// KeyRotator: kernel's dual-key (EdDSA + ES256) signing authority. The
		// publisher/remover/reader operate on the IdentityState verifying_keys
		// boundary; onKeysChanged writes a fresh identity snapshot (the snapshot is
		// taken lazily via the identitySnapshot field, assigned just below).
		// Retention must outlast every token signed with the key, so it is
		// derived from the rotation interval and BOTH mint ceilings rather than
		// set to max_token_lifetime alone — see KeyRotator.retentionSecondsFor.
		// The defaults here mirror IdentityServiceImpl's own.
		final long keyRotationIntervalSeconds =
				cfg.getKeyRotationIntervalSeconds() > 0 ? cfg.getKeyRotationIntervalSeconds() : 604800;
		this.keyRotator = new KeyRotator(
				keyRotationIntervalSeconds,
				KeyRotator.retentionSecondsFor(
						keyRotationIntervalSeconds,
						cfg.getMaxTokenLifetimeSeconds() > 0 ? cfg.getMaxTokenLifetimeSeconds() : 2592000,
						cfg.getOfflineTokenLifetimeSeconds() > 0 ? cfg.getOfflineTokenLifetimeSeconds() : 7776000),
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
				this::onSigningKeysChanged);

		// Standing delegation grants (item 6, piece B): a live in-memory store
		// seeded from Config.grants at boot, mirroring how delegates (below) are
		// seeded. This is what MintDelegatedToken looks grants up by id against,
		// and what finally gives IdentitySnapshot's grantsReader (below) real
		// data instead of the former List::of stub.
		final var liveGrants = new java.util.concurrent.CopyOnWriteArrayList<>(cfg.getGrantsList());

		// IdentitySnapshot builds the KernelDiskState snapshot from the rotator's
		// signing-key records plus the live boundary maps.
		this.identitySnapshot = new IdentitySnapshot(
				cfg.getDiskDir(),
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
						return snapshotConfigState(kernelConfigMap);
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
				},
				// Standing delegation grants have a real live store now (liveGrants,
				// above), seeded from Config.grants at boot — the snapshot round-trip
				// this supplier feeds is genuinely populated as of item 6, piece B.
				() -> java.util.List.copyOf(liveGrants),
				() -> {
					try {
						return principalState.proto();
					} catch (Exception e) {
						logger.warn("Failed to read the principal registry for snapshot: {}", e.getMessage());
						return Kernel.PrincipalState.getDefaultInstance();
					}
				});

		// Load the identity snapshot from disk and rehydrate Hazelcast-backed state before
		// the rotator starts (signing_keys are restored into the rotator; the
		// public verifying set + Ca + ConfigState + revocations are restored into
		// their boundary maps). An absent snapshot returns null.
		//
		// Replayed on every boot, rejoin included. Every restore leg below is
		// additive or config-subordinate — revocations only ever SET
		// revoked_at_ms on a live grant that has none, expired verifying keys
		// are dropped, and the tenant/project tree is reseeded from the bundle
		// on every boot regardless — so a pod that rejoins live peers cannot
		// un-revoke or roll back what the cluster did while it was down.
		Kernel.KernelDiskState snapshot = identitySnapshot.load();
		rehydrateFromSnapshot(snapshot, identityState, caState, workloadState, kernelConfigMap);
		restorePersonalPrincipals(snapshot, principalState);
		restorePeople(snapshot, principalState);
		restoreTenantUserLinks(snapshot, principalState);
		restoreGrantRevocations(snapshot, liveGrants);
		keyRotator.restore(snapshot != null ? snapshot.getSigningKeysList() : List.of());

		// Cluster is always SERVING once construction completes.
		healthManager.setStatus("", ServingStatus.SERVING);

		// 5. Build gRPC server
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
				// C2S management wrappers (TenantAdmin) can read the bearer. This
				// interceptor only captures the header; it rejects nothing. The
				// authenticator installed immediately below is what enforces.
				.intercept(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer.headerCaptureInterceptor());

		// gRPC runs the last-added interceptor outermost, so the rate limiter must
		// be added before the authenticator to run *inside* it: the limiter reads
		// the verified caller service path the authenticator publishes, to tell an
		// internal service->kernel state read from an end-user poll.
		serverBuilder.intercept(rateLimiter);
		serverBuilder.intercept(backendServers.getAuthenticator().callerInterceptor());

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
				manager.getMapRegistry(),
				cfg,
				grpcPort,
				rateLimiter,
				() -> Hazelcast.AdminTokenCacheStats.newBuilder()
						.setNodeId(nodeId)
						.setTimestampMs(System.currentTimeMillis())
						.build(),
				registryReader);

		// 6. Membership listener for cluster state publishing. Registered only
		// once clusterPublisher above is assigned: a join or leave landing before
		// that runs on a Hazelcast event thread, so the NPE it used to throw never
		// reached the constructor and the node came up looking healthy with the
		// publisher never told about the event. Startup is exactly when membership
		// events are most likely — this node is joining.
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
		for (ServerServiceDefinition svc : backendServers.sys().getGrpcServices()) {
			serverBuilder.addService(svc);
		}
		// allKeysSupplier (declared above) is the same source the authenticator's
		// key provider reads, so WatchJwks cannot disagree with verification.
		serverBuilder.addService(new BackendServiceImpl(
				backendServer, grpcPort, hazelcast, cfg.getClusterName(), allKeysSupplier));
		serverBuilder.addService(io.grpc.ServerInterceptors.interceptForward(
				jwkViewServer.bindService(),
				backendServers.getAuthenticator().callerInterceptor()));

		// Health service is always registered
		serverBuilder.addService(healthManager.getHealthService());

		// Kernel identity + tenancy control plane (the cluster trust root).
		{
			final var delegates = cfg.getDelegatesList();
			// SPIFFE trust domain (URI authority, no slash) plus deployment
			// location path. These replace the retired combined spiffe_prefix.
			String configuredTrustDomain = cfg.getSpiffeTrustDomain();
			final String spiffeTrustDomain = (configuredTrustDomain != null && !configuredTrustDomain.isEmpty())
					? configuredTrustDomain : "local.dev";
			final String spiffeLocationPath = cfg.getLocationPath();

			// Seed/refresh the root-admin cred_pairs (kernel.Config.root_cred_pairs)
			// into the root namespace's TenantConfig so MintClientToken can resolve
			// them (token namespace = root, full entitlements). This is what lets
			// the cluster/root admin call TenantAdmin to provision tenants/projects.
			try {
				TenantAdminServiceImpl.seedRootCredPairs(kernelConfigMap, cfg.getRootCredPairsList(),
						SpiffeIds.namespaceRoot());
			} catch (Exception e) {
				logger.warn("Failed to seed root cred_pairs: {}", e.getMessage());
			}

			// Create the RESERVED `people` tenant and write its fixed Apple/Google
			// provider set into its oauth config slice. The platform knows this
			// tenant exists ahead of time — that is the one deliberate special case
			// (see PeopleTenant) — so it is seeded here rather than created through
			// TenantAdmin, which refuses the name.
			try {
				PeopleTenant.seed(kernelConfigMap, cfg.getPeopleIdpCredentialsList());
			} catch (Exception e) {
				logger.warn("Failed to seed the reserved people tenant: {}", e.getMessage());
			}

			// Mandatory, fail-closed Authorizer shared by the kernel's token-auth
			// gRPC wrappers. The kernel is the JWKS authority, so it uses a LOCAL
			// key source (verify against its own keys) rather than the
			// RemoteJwkSource consumers use. SPIFFE IDs are self-describing, so the
			// Authorizer derives caller scope from token subjects instead of a
			// configured prefix.
			this.kernelJwkSource = new LocalJwkSource(allKeysSupplier);
			var kernelAuthorizer = new com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer(
					this.kernelJwkSource);
			Mint.registerMethodAuth(kernelAuthorizer);
			com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker.registerMethodAuth(kernelAuthorizer);
			TenantAdmin.registerMethodAuth(kernelAuthorizer);
			FencedLock.registerMethodAuth(kernelAuthorizer);

			// Seed ServiceConfigState with the trust domain and location path so all
			// services build identities under the same self-describing SPIFFE root.
			try {
				backendServers.sys().getServiceConfigStateMap().putConfig(
						Grpcconfig.Config.newBuilder()
								.setSpiffeTrustDomain(spiffeTrustDomain)
								.setLocationPath(spiffeLocationPath)
								.build());
				logger.info("Seeded ServiceConfigState spiffe_trust_domain={}, location_path={}",
						spiffeTrustDomain, spiffeLocationPath);
			} catch (Exception e) {
				logger.warn("Failed to seed ServiceConfigState: {}", e.getMessage());
			}

			// Use schematic-issued signing chain from bootstrap config (intermediate CA).
			this.signingCa = ImmutableCertChain.from(cfg.getSigningCa());

			// Populate Ca.ca_certs with cluster root CA(s) from bootstrap config.
			for (X509.X509Cert rootCa : cfg.getClusterCaList()) {
				try {
					caState.putCaCerts(Objects.requireNonNull(rootCa.getId(), "rootCa.id"), rootCa);
				} catch (Exception e) {
					logger.warn("Failed to install cluster CA {}: {}", rootCa.getId(), e.getMessage());
				}
			}

			// Token issuer is the bare fleet origin, matching the gateway's
			// OIDC discovery issuer.
			String fqdn = cfg.getFqdn();
			final String tokenIssuer;
			if (fqdn != null && !fqdn.isEmpty()) {
				tokenIssuer = "https://" + fqdn;
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
			com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.serviceconnection.ServiceConnection.ChannelFactory s2sChannelFactory;
			try {
				s2sChannelFactory = com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.serviceconnection.ServiceConnection.channelFactory(cfg.getTrustedCasList(), spiffeTrustDomain);
			} catch (Exception e) {
				throw new RuntimeException("Failed to create S2S channel factory", e);
			}

			var opaConn = new com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.serviceconnection.ServiceConnection("opa", s2sChannelFactory);

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
						var ib = com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.healthreport.Healthreport.ServiceInstanceHealth.newBuilder()
								.setId("kernel@" + instanceName)
								.setServiceId("kernel")
								.setInstanceId(instanceName)
								.setStatus(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.healthreport.Healthreport.InstanceStatus.INSTANCE_STATUS_HEALTHY);
						ib.getGrpcEndpointBuilder().setHost(selfGrpcHost).setPort(grpcPort);
						healthMap.putInstances("kernel@" + instanceName, ib.build());
					} catch (Exception e) {
						logger.debug("kernel self-register failed: {}", e.getMessage());
					}
					try {
						var instances = new java.util.ArrayList<>(healthMap.proto().getInstancesList());
						var relevant = new java.util.ArrayList<com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.healthreport.Healthreport.ServiceInstanceHealth>();
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

			// GrpcClients with a per-target ChannelProvider for OPA. The token
			// provider self-mints a kernel service token (kernel IS the issuer).
			// (tacplus v1.2.187 folded the vservices.GrpcS2SClients aggregator into
			// the generated s2sm.internal.grpc.clients.GrpcClients.)
			var grpcClients = new com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.GrpcClients(
					new com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.serviceconnection.ServiceConnection.ChannelProvider(opaConn),
					aud -> () -> {
						try {
							return mintSelfToken(keyRotator, tokenIssuer, aud, () -> spiffeTrustDomain);
						} catch (Exception e) {
							throw new RuntimeException("failed to self-mint token for " + aud, e);
						}
					});

			healthPoller.start();

			// Both OPA clients (user-entitlement eval + proxy-policy eval). Each is
			// @Nullable in IdentityServiceImpl — null when OPA isn't reachable.
			var userEntitlementsOpa = grpcClients.vservices().userentitlementsOpaEval();
			var proxyPolicyOpa = grpcClients.vservices().proxypolicyOpaEval();
			KubernetesTokenVerifier kubernetesTokenVerifier = kubernetesTokenVerifier();
			String kubernetesTokenAudience = kubernetesTokenAudience();

			var identityService = new IdentityServiceImpl(
					cfg.getDefaultTokenExpirySeconds(),
					cfg.getMaxTokenLifetimeSeconds(),
					cfg.getOfflineTokenLifetimeSeconds(),
					keyRotator,
					allKeysSupplier,
					() -> delegates,
					() -> liveGrants,
					// RevokeGrant's single write path: replace the record carrying the
					// same id in place, so the live list a concurrent mint reads is
					// never briefly missing the grant. A grant is marked revoked, never
					// removed, so the list length is stable and the audit trail survives.
					updated -> {
						for (int i = 0; i < liveGrants.size(); i++) {
							if (liveGrants.get(i).getId().equals(updated.getId())) {
								liveGrants.set(i, updated);
								return;
							}
						}
						throw new IllegalStateException("grant " + updated.getId() + " is no longer in the live store");
					},
					com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SecurityInterceptor.SERVICE_ENTITLEMENTS,
					signingCa,
					serviceName -> caState.getServiceCas(serviceName),
					(serviceName, certPair) -> {
						try {
							caState.putServiceCas(serviceName, certPair);
							// service_cas are currently rebuilt on demand at startup, not
							// rehydrated from disk, so keep cert minting off the identity
							// snapshot hot path.
						} catch (Exception e) {
							throw new RuntimeException("putServiceCas failed", e);
						}
					},
					() -> spiffeTrustDomain,
					tokenIssuer,
					userEntitlementsOpa,
					proxyPolicyOpa,
					kernelConfigMap,
					workloadState,
					principalState,
					this::saveIdentitySnapshot,
					kubernetesTokenVerifier,
					kubernetesTokenAudience,
					webauthnRelyingParty());

			Mint mintWrapper = new Mint(identityService, kernelAuthorizer) {
				@Override
				public void mintX509Cert(Tokenrequest.X509MintRequest request,
						io.grpc.stub.StreamObserver<X509.X509CertChain> responseObserver) {
					try {
						logger.info("X509Mint direct dispatch aud={}, inputToken={}, keyId={}, issuer={}, exp={}",
								request.getAud(),
								!request.getInputToken().isEmpty(),
								request.hasCertRequest() && request.getCertRequest().hasKey()
										? request.getCertRequest().getKey().getId()
										: "",
								request.hasCertRequest() ? request.getCertRequest().getIssuer() : "",
								request.hasCertRequest() ? request.getCertRequest().getExp() : 0);
						X509.X509CertChain response = identityService.mintX509Cert(null, request);
						responseObserver.onNext(response);
						responseObserver.onCompleted();
					} catch (Exception e) {
						logger.error("X509Mint direct dispatch failed", e);
						responseObserver.onError(toGrpcError(e));
					}
				}
			};
			ServerServiceDefinition mintServiceDefinition =
					ensureMintX509CertBinding(mintWrapper.bindService(), identityService);
			serverBuilder.addService(mintServiceDefinition);
			// The rate limiter was built before this service existed, so its
			// classification map has no entry for the Mint methods — and an
			// unclassified method is exempt. Register them now so credential
			// issuance is bounded per caller.
			rateLimiter.registerServices(List.of(mintServiceDefinition));
			logger.info("MintService registered on gRPC server ({} delegates, methods={})",
					delegates.size(), methodNames(mintServiceDefinition));

			// UserMint — the same IdentityServiceImpl, seen from the client side.
			// MintDelegateOfflineToken's caller is a PERSON holding their own
			// bearer token, so it is declared (spec.service_c2s) on its own
			// service (tacplus refuses two caller surfaces on one service) and
			// the gateway reaches it through its ordinary generic C2S routing —
			// no hand-written gateway front (token-management decision item 7).
			//
			// The authenticate func is token-only for the same reason
			// PersonalIdentity's is: the wrapper passes no target namespace for an
			// auth_any_user RPC with no target_namespace_field, and the
			// at-or-below rule would refuse the ordinary user callers this RPC
			// exists for. The handler re-reads and re-verifies the caller's token
			// itself (verifiedCallerToken) to get the subject it mints against.
			var userMintWrapper = new UserMint(identityService, kernelAuthorizer);
			userMintWrapper.setAuthenticateFunc((UserMint.Authenticator) targetNamespace ->
					com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer
							.identityClaims(kernelAuthorizer.authenticateWithToken(
									com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer.AUTH_HEADER_CTX_KEY
											.get())));
			ServerServiceDefinition userMintServiceDefinition = userMintWrapper.bindService();
			serverBuilder.addService(userMintServiceDefinition);
			// Rate-limited for the same reason Mint is: this RPC issues a
			// credential, and it kept that property when it moved off Mint.
			rateLimiter.registerServices(List.of(userMintServiceDefinition));
			logger.info("UserMintService registered on gRPC server (methods={})",
					methodNames(userMintServiceDefinition));

			// TLS certificate lifecycle service (tlscert.TlsCertService/ManageCert
			// bidi stream): kernel is the cluster cert authority for auto_tls
			// services. Each service streams here to obtain/renew its per-instance
			// TLS cert under its per-service intermediate CA (Ca state). Without
			// this, services cannot get serving certs and never become ready.
			var tlsCertService = new TlsCertServiceImpl(
					cfg.getTlsCertLifetimeSeconds() > 0 ? cfg.getTlsCertLifetimeSeconds() : 86400,
					signingCa,
					serviceName -> caState.getServiceCas(serviceName),
					(serviceName, certPair) -> {
						try {
							caState.putServiceCas(serviceName, certPair);
							// service_cas are currently rebuilt on demand at startup, not
							// rehydrated from disk, so keep cert minting off the identity
							// snapshot hot path.
						} catch (Exception e) {
							throw new RuntimeException("putServiceCas failed", e);
						}
					},
					() -> spiffeTrustDomain,
					allKeysSupplier,
					workloadState);
			serverBuilder.addService(tlsCertService);
			logger.info("TlsCertService registered (ManageCert auto-TLS, cert lifetime={}s)",
					cfg.getTlsCertLifetimeSeconds() > 0 ? cfg.getTlsCertLifetimeSeconds() : 86400);

			// CLI token broker — mediates nonce matching between oauth instances.
			var cliTokenBroker = new CliTokenBrokerServiceImpl(identityService, hazelcast);
			var cliTokenBrokerWrapper = new com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker(cliTokenBroker, kernelAuthorizer);
			serverBuilder.addService(cliTokenBrokerWrapper);
			logger.info("CliTokenBrokerService registered on gRPC server");

			// Multi-tenancy control plane (uniform ROOT/TENANT/PROJECT tree). The
			// shared kernelAuthorizer enforces the entitlement + level-or-below
			// check (target_namespace_field) declaratively per the generated
			// wrapper. Mutating writes trigger a fresh disk snapshot.
			var tenantAdminImpl = new TenantAdminServiceImpl(
					kernelConfigMap, () -> spiffeTrustDomain, this::saveIdentitySnapshot);
			var tenantAdminWrapper = new TenantAdmin(tenantAdminImpl, kernelAuthorizer);
			serverBuilder.addService(tenantAdminWrapper);
			logger.info("TenantAdminService registered on gRPC server");

			// A personal principal's own view of itself. auth_any_user: the
			// wrapper verifies the token and nothing else, and the handler scopes
			// the read to the caller's own PrincipalState row by resolving the
			// principal from the verified token subject.
			//
			// The authenticate func is token-only (authenticateWithToken), NOT the
			// generated ServiceManager's authenticateAtOrBelowWithToken: the
			// wrapper passes the fixed target "/" for an auth_any_user RPC with no
			// target_namespace_field, and the at-or-below rule against "/" admits
			// only a root-namespace caller — which would refuse every
			// /people/<pid> caller this RPC exists for. See the item's decision doc.
			var personalIdentityImpl = new PersonalIdentityServiceImpl(
					backendServers.services().getPrincipalMap(),
					this::saveIdentitySnapshot);
			var personalIdentityWrapper = new PersonalIdentity(personalIdentityImpl, kernelAuthorizer);
			personalIdentityWrapper.setAuthenticateFunc((PersonalIdentity.Authenticator) targetNamespace ->
					com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer
							.identityClaims(kernelAuthorizer.authenticateWithToken(
									com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer.AUTH_HEADER_CTX_KEY
											.get())));
			serverBuilder.addService(personalIdentityWrapper);
			logger.info("PersonalIdentityService registered on gRPC server");

			// FencedLock — kernel is the ONE service that embeds Ratis; every other
			// service calls this s2s surface instead of running its own Raft group.
			// Peers are the configured cluster members on ratis_listener's port, so
			// lock membership tracks cluster membership rather than a second topology.
			int ratisPort = cfg.getRatisListener().getPort();
			var ratisGroup = RaftGroup.valueOf(RatisFencedLock.GROUP_ID, ratisPeers(members, ratisPort));
			// The Raft log, under kernel's on-disk directory (Config.disk_dir).
			// Raft-log durability is what makes a fence token monotonic; it is not the
			// generic state durability kernel does not do.
			var ratisStorage = new java.io.File(cfg.getDiskDir(), "fencedlock");
			try {
				this.fencedLock = RatisFencedLock.start(
						selfRatisPeerId(members, ratisPort, hostname), ratisGroup, ratisStorage);
			} catch (java.io.IOException e) {
				throw new IllegalStateException("failed to start the FencedLock Ratis peer", e);
			}
			var fencedLockWrapper = new FencedLock(new FencedLockServiceImpl(fencedLock), kernelAuthorizer);
			serverBuilder.addService(fencedLockWrapper);
			logger.info("FencedLockService registered on gRPC server (ratisPort={}, peers={})",
					ratisPort, ratisGroup.getPeers().size());
		}

		this.grpcServer = serverBuilder.build();
		logger.info("Kernel node configured (grpcPort={})", grpcPort);
	}

	/**
	 * ratisPeers maps the configured cluster members onto Raft peers on the
	 * FencedLock port. The peer id IS the "host:port" string, so every kernel
	 * instance derives the same ids from the same config without a second
	 * identity to keep in sync.
	 */
	private static List<org.apache.ratis.protocol.RaftPeer> ratisPeers(List<com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.host.HostOuterClass.Host> members, int port) {
		List<org.apache.ratis.protocol.RaftPeer> peers = new ArrayList<>(members.size());
		for (var member : members) {
			String host = Objects.requireNonNull(member.getHost(), "member.host");
			peers.add(RatisFencedLock.peer(host + ":" + port, host, port));
		}
		return peers;
	}

	/**
	 * selfRatisPeerId picks which of the configured members this process is.
	 *
	 * <p>A member whose host is this node's hostname, or whose first DNS label
	 * is (StatefulSet pod {@code kernel-1} is member {@code kernel-1.kernel}),
	 * is this node, decided by name alone. DNS cannot decide it on a rolling
	 * restart: the replaced pod comes back on a new IP while kube-dns keeps
	 * serving the old one for up to its cache TTL, so the new process resolved
	 * its own member to an address that was not its own, found no member, and
	 * exited — once per pod, every rolling restart.
	 *
	 * <p>Without a name match it falls back to resolving each member's host and
	 * asking whether the address is one of this machine's own, the way
	 * Hazelcast identifies itself from the same member list. Deriving it rather
	 * than configuring it keeps a node from being told it is a peer it is not.
	 */
	static org.apache.ratis.protocol.RaftPeerId selfRatisPeerId(List<com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.host.HostOuterClass.Host> members, int port, String hostname) {
		for (var member : members) {
			String host = Objects.requireNonNull(member.getHost(), "member.host");
			if (!hostname.isEmpty() && (host.equals(hostname) || host.startsWith(hostname + "."))) {
				return org.apache.ratis.protocol.RaftPeerId.valueOf(host + ":" + port);
			}
		}
		for (var member : members) {
			String host = Objects.requireNonNull(member.getHost(), "member.host");
			try {
				var address = java.net.InetAddress.getByName(host);
				if (address.isAnyLocalAddress() || address.isLoopbackAddress()
						|| java.net.NetworkInterface.getByInetAddress(address) != null) {
					return org.apache.ratis.protocol.RaftPeerId.valueOf(host + ":" + port);
				}
			} catch (java.io.IOException e) {
				logger.debug("member {} is not a local address: {}", host, e.getMessage());
			}
		}
		throw new IllegalStateException(
				"none of the configured members resolves to a local address; "
						+ "this node cannot tell which FencedLock Raft peer it is");
	}

	/**
	 * Wraps a {@code verifying_keys} state read so that one failed read cannot
	 * empty the key set kernel serves.
	 *
	 * <p>Kernel keeps its own two active signing keys published for as long as
	 * it is running, and {@link KeyRotator}'s sweep never evicts them, so the
	 * set going empty is not a state the cluster reaches legitimately. Both an
	 * outright exception and an empty result after keys have been seen are
	 * therefore treated as a failed read, and the last successfully-read set is
	 * returned instead. Only a genuine cold start, where no read has ever
	 * succeeded, yields an empty list.
	 *
	 * <p>Serving a stale verifying key is the safe direction to fail: every JWK
	 * carries its own {@code exp} and every consumer still checks token expiry,
	 * whereas serving none rejects every caller on the platform at once.
	 */
	static Supplier<List<JwkOuterClass.Jwk>> lastKnownGoodVerifyingKeys(
			Supplier<List<JwkOuterClass.Jwk>> reader) {
		final java.util.concurrent.atomic.AtomicReference<List<JwkOuterClass.Jwk>> lastGood =
				new java.util.concurrent.atomic.AtomicReference<>(List.of());
		return () -> {
			List<JwkOuterClass.Jwk> keys;
			try {
				keys = List.copyOf(reader.get());
			} catch (Exception e) {
				List<JwkOuterClass.Jwk> previous = lastGood.get();
				logger.warn("Failed to read verifying keys ({}); serving last-known-good set of {} key(s)",
						e.getMessage(), previous.size());
				return previous;
			}
			if (keys.isEmpty()) {
				List<JwkOuterClass.Jwk> previous = lastGood.get();
				if (!previous.isEmpty()) {
					logger.warn("verifying_keys read came back empty; serving last-known-good set of {} key(s)",
							previous.size());
					return previous;
				}
				return keys;
			}
			lastGood.set(keys);
			return keys;
		};
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

	/**
	 * Installs the bundle's per-service configs into the ConfigHolder boundary maps.
	 * Kernel runs this on every start and the bundle always wins: every root the
	 * bundle carries is overwritten, whether or not it already holds a config.
	 * Config is code, so the git-committed bundle is the single source of truth —
	 * a changed bundle value always becomes live on the next restart or roll, and
	 * the bundle is the only writer: a config change is a bundle change plus a
	 * deploy, for every service alike.
	 */
	private void installConfigHolder(Kernel.Config config) {
		if (!config.hasConfigs()) {
			logger.info("No configs in Config — config state maps unchanged");
			return;
		}
		int installed = backendServers.services().installServices(config.getConfigs());
		logger.info("Installed {} config(s) into per-service config state maps "
				+ "(bundle wins; every seeded root overwritten)", installed);
	}

	/**
	 * The KeyRotator's key-change hook: writes a fresh identity snapshot and pushes
	 * the new key set to the kernel's own Authorizer at once.
	 *
	 * <p>Without the second half the Authorizer stayed up to LocalJwkSource's
	 * refresh interval behind a rotation and rejected tokens signed with the key
	 * this node had just published as "unknown signing key", so an RPC to
	 * TenantAdmin or FencedLock right after a rotation failed UNAUTHENTICATED —
	 * a status the caller cannot usefully retry.
	 *
	 * <p>Safe to call from any thread. The rotator only invokes it from
	 * {@code start()} onward, which is {@link #start()}, i.e. after construction;
	 * the guard mirrors {@link #saveIdentitySnapshot}'s.
	 */
	private void onSigningKeysChanged() {
		saveIdentitySnapshot();
		LocalJwkSource source = kernelJwkSource;
		if (source != null) {
			source.refreshNow();
		}
	}

	/** Writes kernel's identity snapshot to disk; safe to call from any thread. */
	private void saveIdentitySnapshot() {
		if (identitySnapshot != null) {
			identitySnapshot.save();
		}
	}

	/**
	 * Rehydrates Hazelcast-backed state from the loaded disk snapshot: the public
	 * verifying set, the cluster CA + per-service intermediate CAs, the
	 * tenant/project tree, and workload revocations. Signing keys are restored
	 * separately into the KeyRotator. A null snapshot (cold start) is a no-op.
	 */
	/**
	 * Re-applies the identity snapshot's grant revocations onto the boot-seeded live grants.
	 *
	 * <p>Config.grants remains the source of truth for WHICH grants exist — the
	 * catalog is seeded from config at every boot, so a grant added to config
	 * appears without a snapshot round-trip. Only {@code revoked_at_ms} is
	 * restored from the snapshot, because that is the one field the runtime
	 * (RevokeGrant) writes and config cannot know about: without this, a restart
	 * would silently resurrect every revoked delegation.
	 *
	 * <p>Package-private so the restart half of the revocation proof can exercise
	 * the real boot path rather than a copy of it.
	 */
	static void restoreGrantRevocations(
			Kernel.KernelDiskState snapshot, java.util.List<Kernel.Grant> liveGrants) {
		if (snapshot == null || snapshot.getGrantsCount() == 0) {
			return;
		}
		java.util.Map<String, Long> revokedById = new java.util.HashMap<>();
		for (Kernel.Grant g : snapshot.getGrantsList()) {
			if (g.getRevokedAtMs() != 0) {
				revokedById.put(g.getId(), g.getRevokedAtMs());
			}
		}
		int restored = 0;
		for (int i = 0; i < liveGrants.size(); i++) {
			Kernel.Grant live = liveGrants.get(i);
			Long revokedAtMs = revokedById.get(live.getId());
			if (revokedAtMs != null && live.getRevokedAtMs() == 0) {
				liveGrants.set(i, live.toBuilder().setRevokedAtMs(revokedAtMs).build());
				restored++;
			}
		}
		if (restored > 0) {
			logger.info("Restored {} revoked standing delegation(s) from the disk snapshot", restored);
		}
	}

	/**
	 * Restores the registered personal principals from the disk snapshot into the
	 * live {@code PrincipalState} boundary.
	 *
	 * <p>Unlike grants (seeded from Config.grants at every boot), a personal
	 * principal exists only because someone registered at runtime — the snapshot
	 * is its ONLY source, so the whole row is restored, not just a mutated field.
	 * Rows are written through the generated {@code putPersonalPrincipals}
	 * accessor, so the same validation the write path enforces applies here.
	 *
	 * <p>Package-private and static so the restart half of the durability proof can
	 * exercise the real boot path rather than a copy of it (same reason as
	 * {@link #restoreGrantRevocations}).
	 *
	 * <p>Fails closed, like {@link IdentitySnapshot#load()}: a row that cannot be
	 * applied aborts the restore and the node refuses to boot. Continuing would
	 * bring the kernel up with an arbitrary prefix of the registered people —
	 * someone who registered is simply gone, and silently.
	 */
	static void restorePersonalPrincipals(
			Kernel.KernelDiskState snapshot,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap principalState) {
		if (snapshot == null || snapshot.getPersonalPrincipalsCount() == 0) {
			return;
		}
		try {
			for (Kernel.PersonalPrincipal p : snapshot.getPersonalPrincipalsList()) {
				principalState.putPersonalPrincipals(
						Objects.requireNonNull(p.getPrincipalId(), "principal.principal_id"), p);
			}
			logger.info("Restored {} personal principal(s) from the disk snapshot",
					snapshot.getPersonalPrincipalsCount());
		} catch (Exception e) {
			logger.error("Failed to restore personal principals from the disk snapshot — refusing "
					+ "to start with a partial restore: {}", e.getMessage(), e);
			throw new IllegalStateException(
					"kernel refuses to start: personal principals could not be restored from the "
							+ "disk snapshot", e);
		}
	}

	/**
	 * Restores the {@code people} tenant's user rows from the disk snapshot into
	 * the live {@code PrincipalState} boundary.
	 *
	 * <p>Separate from {@link #restorePersonalPrincipals} rather than folded into
	 * it because the two collections are independently populated: a cluster can
	 * hold people and no personal principals, and that method returns early on an
	 * empty principal list.
	 *
	 * <p>Fails closed for the same reason: a person whose row does not come back
	 * is not merely absent, they are re-created with a fresh {@code created_at_ms}
	 * on their next login, so a partial restore is a silently rewritten identity
	 * rather than a missing one.
	 */
	static void restorePeople(
			Kernel.KernelDiskState snapshot,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap principalState) {
		if (snapshot == null || snapshot.getPeopleCount() == 0) {
			return;
		}
		try {
			for (Kernel.Person person : snapshot.getPeopleList()) {
				principalState.putPeople(
						Objects.requireNonNull(person.getUserId(), "person.user_id"), person);
			}
			logger.info("Restored {} person row(s) from the disk snapshot", snapshot.getPeopleCount());
		} catch (Exception e) {
			logger.error("Failed to restore people from the disk snapshot — refusing to start with "
					+ "a partial restore: {}", e.getMessage(), e);
			throw new IllegalStateException(
					"kernel refuses to start: people could not be restored from the disk snapshot", e);
		}
	}

	/**
	 * Restores the tenant-user link registry from the disk snapshot, fail-closed
	 * like its {@link #restorePeople} neighbour and more sharply than it: a link
	 * is proved once, by two live IdP logins sharing a nonce, and nothing kernel
	 * holds can re-derive it. A partial restore silently unlinks users, and the
	 * only symptom is a {@code linked} claim that stops appearing.
	 */
	static void restoreTenantUserLinks(
			Kernel.KernelDiskState snapshot,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap principalState) {
		if (snapshot == null || snapshot.getTenantUserLinksCount() == 0) {
			return;
		}
		try {
			for (Kernel.TenantUserLinks links : snapshot.getTenantUserLinksList()) {
				principalState.putTenantUserLinks(
						Objects.requireNonNull(links.getUserKey(), "tenant_user_links.user_key"), links);
			}
			logger.info("Restored {} tenant-user link row(s) from the disk snapshot",
					snapshot.getTenantUserLinksCount());
		} catch (Exception e) {
			logger.error("Failed to restore tenant user links from the disk snapshot — refusing to "
					+ "start with a partial restore: {}", e.getMessage(), e);
			throw new IllegalStateException(
					"kernel refuses to start: tenant user links could not be restored from the "
							+ "disk snapshot", e);
		}
	}

	/**
	 * Collects every full tenant namespace a {@code ConfigState} implies.
	 *
	 * <p>{@code tenant_configs} is keyed by the full tenant path and kept in
	 * lockstep with {@code tenants}; each {@code project_configs} key is
	 * "/tenant/project", so its parent is a tenant path too. This is the only
	 * place the full paths survive: {@code ConfigMap.proto()} projects each
	 * boundary to its values and drops the map keys.
	 */
	static java.util.Set<String> tenantNamespaces(
			List<Kernel.TenantConfigEntry> tenantConfigs, List<Kernel.ProjectConfigEntry> projectConfigs) {
		java.util.Set<String> keys = new java.util.LinkedHashSet<>();
		for (Kernel.TenantConfigEntry e : tenantConfigs) {
			keys.add(e.getTenantName());
		}
		for (Kernel.ProjectConfigEntry e : projectConfigs) {
			String pk = e.getProjectNamespace();
			int slash = pk.lastIndexOf('/');
			if (slash > 0) {
				keys.add(pk.substring(0, slash));
			}
		}
		return keys;
	}

	/**
	 * Builds the {@code ConfigState} written to the disk snapshot, stamping each
	 * tenant record with its FULL namespace in {@code Tenant.name}.
	 *
	 * <p>The live boundary stores a tenant under its full path but with only the
	 * leaf in {@code Tenant.name} (see {@code TenantAdminServiceImpl}), and
	 * {@code ConfigMap.proto()} keeps the values and throws the keys away — so a
	 * plain {@code proto()} snapshot cannot tell {@code /tenants/acme/prod} from
	 * {@code /tenants/beta/prod}. Restoring one then handed both namespaces
	 * whichever record happened to win, so after a restart a tenant could carry
	 * another tenant's status and entitlements ceiling. Each record is looked up
	 * by its own key here, so the snapshot is unambiguous;
	 * {@link #rehydrateFromSnapshot} puts the leaf back when it restores.
	 */
	static Kernel.ConfigState snapshotConfigState(
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap configMap)
			throws Exception {
		Kernel.ConfigState live = configMap.proto();
		Kernel.ConfigState.Builder b = live.toBuilder().clearTenants();
		for (String namespace : tenantNamespaces(live.getTenantConfigsList(), live.getProjectConfigsList())) {
			Kernel.Tenant t = configMap.getTenants(namespace);
			if (t.getName().isEmpty()) {
				continue;
			}
			b.addTenants(t.toBuilder().setName(namespace).build());
		}
		return b.build();
	}

	static void rehydrateFromSnapshot(
			Kernel.KernelDiskState snapshot,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.IdentityMap identityState,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.CaMap caState,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap workloadState,
			com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap configMap) {
		if (snapshot == null) {
			return;
		}
		try {
			long nowEpoch = java.time.Instant.now().getEpochSecond();
			for (JwkOuterClass.Jwk jwk : snapshot.getVerifyingKeysList()) {
				// A key whose exp has already passed is dropped rather than
				// republished. putVerifyingKeys turns exp into a TTL of
				// exp - now, and a TTL of zero or less means "never expire" to
				// the state store — so restoring a stale snapshot would turn
				// exactly the keys that should be gone into permanent ones.
				if (jwk.getExp() > 0 && jwk.getExp() <= nowEpoch) {
					logger.info("Dropping expired verifying key from snapshot: kid={}, exp={}",
							jwk.getKid(), jwk.getExp());
					continue;
				}
				identityState.putVerifyingKeys(Objects.requireNonNull(jwk.getKid(), "jwk.kid"), jwk);
			}
			for (X509.X509Cert cert : snapshot.getCaCertsList()) {
				caState.putCaCerts(Objects.requireNonNull(cert.getId(), "caCert.id"), cert);
			}
			// NOTE: service_cas are NOT rehydrated here yet. X509CertChain.id now
			// carries the service-name key, so this can become a normal restore path
			// once the identity snapshot is wired to replay service_cas.
			if (snapshot.getServiceCasCount() > 0) {
				logger.info("Skipping rehydrate of {} service_cas (re-created on next X509Mint)",
						snapshot.getServiceCasCount());
			}
			// tenants/tenant_configs/project_configs are keyed by full namespace.
			for (Kernel.TenantConfigEntry e : snapshot.getTenantConfigsList()) {
				configMap.putTenantConfigs(e.getTenantName(), e);
			}
			for (Kernel.ProjectConfigEntry e : snapshot.getProjectConfigsList()) {
				configMap.putProjectConfigs(e.getProjectNamespace(), e);
			}
			// snapshotConfigState stamps Tenant.name with the full namespace, so
			// each record maps to exactly one key. The live boundary holds the
			// leaf in Tenant.name, so the leaf goes back on the way in — the
			// restored row is field-identical to what TenantAdmin wrote.
			java.util.Map<String, Kernel.Tenant> byNamespace = new java.util.HashMap<>();
			java.util.Map<String, Kernel.Tenant> byLeaf = new java.util.HashMap<>();
			for (Kernel.Tenant t : snapshot.getTenantsList()) {
				if (t.getName().indexOf('/') >= 0) {
					byNamespace.put(t.getName(), t);
				} else {
					byLeaf.put(t.getName(), t);
				}
			}
			if (!byLeaf.isEmpty()) {
				// Snapshot written before Tenant.name carried the full namespace.
				// Leaf matching is ambiguous across same-named tenants under
				// different parents, which is the bug this format replaced.
				logger.warn("Snapshot carries {} tenant record(s) keyed by leaf name only "
						+ "(pre-namespace snapshot) — falling back to leaf matching, which cannot "
						+ "distinguish same-named tenants under different parents", byLeaf.size());
			}
			for (String key : tenantNamespaces(
					snapshot.getTenantConfigsList(), snapshot.getProjectConfigsList())) {
				Kernel.Tenant t = byNamespace.get(key);
				if (t == null) {
					int slash = key.lastIndexOf('/');
					t = byLeaf.get(slash < 0 ? key : key.substring(slash + 1));
				}
				if (t != null) {
					int slash = key.lastIndexOf('/');
					String leaf = slash < 0 ? key : key.substring(slash + 1);
					configMap.putTenants(key, t.toBuilder().setName(leaf).build());
				}
			}
			for (Kernel.WorkloadRevocation rev : snapshot.getWorkloadRevocationsList()) {
				workloadState.putRevocations(Objects.requireNonNull(rev.getSpiffeId(), "rev.spiffe_id"), rev);
			}
			logger.info("Rehydrated kernel state from disk snapshot");
		} catch (Exception e) {
			// Fail closed, at the severity IdentitySnapshot.load() already uses
			// for an unreadable snapshot. One bad tenant, CA or revocation row
			// used to abort the rest of the loop and let the node come up with an
			// arbitrary prefix of the snapshot applied — revocations restored but
			// tenants not, or the reverse — which is exactly the silent-partial-
			// state the load hardening closed, one layer up.
			logger.error("Failed to rehydrate kernel snapshot — refusing to start with a partial "
					+ "restore: {}", e.getMessage(), e);
			throw new IllegalStateException(
					"kernel refuses to start: disk snapshot could not be fully rehydrated", e);
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
		if (healthProbeServer != null) {
			healthProbeServer.shutdown();
		}
		grpcServer.shutdown();
		jwkViewServer.close();
		backendServers.services().close();
		try {
			fencedLock.close();
		} catch (java.io.IOException e) {
			logger.warn("FencedLock Ratis peer did not shut down cleanly: {}", e.getMessage());
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

	/**
	 * Self-mints a service token using the kernel's own KeyRotator. Used for
	 * kernel's outgoing S2S calls (e.g. to OPA) where kernel cannot exchange a
	 * token because kernel IS the token issuer.
	 */
	private static String mintSelfToken(KeyRotator keyRotator, String tokenIssuer,
			String audience, Supplier<String> trustDomainReader) throws Exception {
		com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey signingKey =
				keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new IllegalStateException("no active signing key for self-mint");
		}
		long now = java.time.Instant.now().getEpochSecond();
		long exp = now + 3600; // 1 hour

		String spiffeId = SpiffeIds.build(trustDomainReader.get(), "kernel");

		com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper token =
				com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper.create()
						.setIssuer(tokenIssuer)
						.setSubject(spiffeId)
						.setAudience(audience)
						.setIssuedAt(now)
						.setExpiration(exp)
						.setJTI(java.util.UUID.randomUUID().toString());

		token.setSubType("service");
		token.setTokenUse("service");
		token.setAzp(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel.getDescriptor().getPackage());
		token.setPrincipal(spiffeId);
		token.setNamespace(SpiffeIds.namespaceFromSpiffe(spiffeId));

		token.sign(signingKey);
		return token.getBase64();
	}
}
