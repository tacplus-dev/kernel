// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.jwk.ImmutableJwk;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tlscert.Tlscert;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tlscert.TlsCertServiceGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the TlsCertService.ManageCert bidi streaming RPC.
 *
 * <p>Services with auto_tls open a bidi stream. The protocol is:
 * <ol>
 *   <li>Service sends Init (service_name, instance_id) + Csr (Ed25519 public key)</li>
 *   <li>Kernel signs cert under per-service intermediate CA, returns CertDelivery</li>
 *   <li>At half-life, kernel sends Renew</li>
 *   <li>Service generates new keypair, sends Csr</li>
 *   <li>Kernel signs, returns CertDelivery — repeat from 3</li>
 * </ol>
 *
 * <p>Authentication is handled by SecurityInterceptor (JWT Bearer token validated
 * before the stream handler runs). The Init message's service_name is verified
 * against the authenticated caller subject.
 */
public class TlsCertServiceImpl extends TlsCertServiceGrpc.TlsCertServiceImplBase {

	private static final Logger logger = LoggerFactory.getLogger(TlsCertServiceImpl.class);

	private final long certLifetimeSeconds;
	private final ImmutableCertChain signingCa;
	private final Function<String, X509.X509CertChain> serviceCaReader;
	private final BiConsumer<String, X509.X509CertChain> serviceCaWriter;
	private final Supplier<String> trustDomainReader;
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	/**
	 * WorkloadState boundary access, read on every cert issuance so a revoked
	 * workload stops getting certs — the same {@code revocations} collection
	 * every kernel-signed token exchange consults. Required, never null: a
	 * kernel that cannot see revocations must refuse to issue, not issue blind.
	 */
	private final WorkloadMap workloadMap;
	private final ScheduledExecutorService scheduler;

	/**
	 * @param certLifetimeSeconds  lifetime for leaf TLS certs (renewal at half-life)
	 * @param signingCa            schematic-issued signing chain (intermediate CA)
	 * @param serviceCaReader      reads per-service intermediate CA from Ca state
	 * @param serviceCaWriter      writes per-service intermediate CA to Ca state
	 * @param trustDomainReader    SPIFFE trust domain
	 * @param verifyingKeysReader  active kernel JWKs for validating caller tokens
	 * @param workloadMap          WorkloadState access carrying workload revocations
	 */
	public TlsCertServiceImpl(
			long certLifetimeSeconds,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter,
			Supplier<String> trustDomainReader,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			WorkloadMap workloadMap) {
		this.certLifetimeSeconds = certLifetimeSeconds;
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
		this.trustDomainReader = trustDomainReader;
		this.verifyingKeysReader = verifyingKeysReader;
		this.workloadMap = java.util.Objects.requireNonNull(workloadMap,
				"workloadMap is required — workload revocation must be enforced on cert issuance");
		this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "tls-cert-renewal");
			t.setDaemon(true);
			return t;
		});
	}

	public void stop() {
		scheduler.shutdown();
	}

	@Override
	public StreamObserver<Tlscert.TlsCertClientMsg> manageCert(
			StreamObserver<Tlscert.TlsCertServerMsg> responseObserver) {
		// The cluster gRPC server's callerInterceptor explicitly bypasses
		// TlsCertService (it's in the "services that handle their own auth"
		// list). We validate the Bearer token here from RAW_AUTH_TOKEN_KEY
		// (set by rpcInterceptor on every cluster RPC).
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			logger.warn("ManageCert: missing Authorization header");
			responseObserver.onError(Status.UNAUTHENTICATED
					.withDescription("missing authorization header")
					.asRuntimeException());
			return new StreamObserver<>() {
				@Override public void onNext(Tlscert.TlsCertClientMsg value) {}
				@Override public void onError(Throwable t) {}
				@Override public void onCompleted() {}
			};
		}

		String callerSubject;
		String callerInstanceId;
		try {
			TokenWrapper token = verifiedServiceToken(rawToken, verifyingKeysReader.get());
			callerSubject = token.getSubject();
			callerInstanceId = token.getCustomField("instance_id");
		} catch (Exception e) {
			logger.warn("ManageCert: token validation failed: {}", e.getMessage());
			responseObserver.onError(Status.UNAUTHENTICATED
					.withDescription("token validation failed: " + e.getMessage())
					.asRuntimeException());
			return new StreamObserver<>() {
				@Override public void onNext(Tlscert.TlsCertClientMsg value) {}
				@Override public void onError(Throwable t) {}
				@Override public void onCompleted() {}
			};
		}

		logger.info("ManageCert stream opened: caller={}, instanceId={}", callerSubject, callerInstanceId);

		return new ManageCertObserver(responseObserver, callerSubject, callerInstanceId);
	}

	/**
	 * Parses and fully verifies the caller's bearer for a ManageCert stream.
	 *
	 * <p>ManageCert authenticates itself: the cluster gRPC server's
	 * callerInterceptor deliberately bypasses this service, so the checks
	 * {@code IdentityServiceImpl.doX509Mint} makes on the same class of token
	 * have to be made here too. This method used to be inline and was missing two
	 * of them:
	 *
	 * <ul>
	 *   <li>the {@link IdentityServiceImpl#isPlausibleKid} fast-reject. Without
	 *       it an attacker-supplied oversized or garbage kid forced a full
	 *       O(verifying keys) scan on every stream open — exactly the Phase 0.1
	 *       DoS gate whose javadoc says every externally-influenced kid scan
	 *       calls it.</li>
	 *   <li>a subject-class check. {@code handleInit} requires the subject to be
	 *       a SPIFFE URI, but nothing required the token to be a SERVICE-class
	 *       token at all, so any token whose {@code sub} happened to be a SPIFFE
	 *       URI opened a stream. A mesh identity is issued to workloads; a user
	 *       or bootstrap token is not one.</li>
	 * </ul>
	 *
	 * <p>{@code token.verify} covers {@code exp}, {@code nbf}, {@code alg} and
	 * the signature, so this was hardening drift rather than an auth bypass.
	 *
	 * @return the verified token
	 * @throws IllegalStateException if the token is not an acceptable service
	 *                               bearer; the caller maps it to UNAUTHENTICATED
	 */
	static TokenWrapper verifiedServiceToken(String rawToken, List<JwkOuterClass.Jwk> verifyingKeys) {
		TokenWrapper token = TokenWrapper.parse(rawToken);
		String kid = token.getKid();
		// Fast-reject before the key scan, same gate and same message shape as
		// the unknown-key miss below so the two are indistinguishable to a caller.
		if (!IdentityServiceImpl.isPlausibleKid(kid)) {
			throw new IllegalStateException("token signed with unknown key: " + kid);
		}
		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeys) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw new IllegalStateException("token signed with unknown key: " + kid);
		}
		token.verify(ImmutableJwk.from(matchingKey));

		String subType = token.getSubType();
		if (!IdentityServiceImpl.SUB_TYPE_SERVICE.equals(subType)) {
			throw new IllegalStateException(
					"ManageCert requires a service token; sub_type is " + subType);
		}
		return token;
	}

	// ========================================================================
	// Stream Observer
	// ========================================================================

	private class ManageCertObserver implements StreamObserver<Tlscert.TlsCertClientMsg> {

		private final StreamObserver<Tlscert.TlsCertServerMsg> responseObserver;
		private final String callerSubject;
		private final String callerInstanceId;

		/** Canonical SPIFFE URI for this stream — copied from the caller's authenticated identity. */
		private String spiffeId;
		/** Bare service name derived from the SPIFFE URI's last path segment. */
		private String serviceName;
		/** Client-supplied instance identifier (used for DNS SAN and logging). */
		private String instanceId;
		private boolean initialized;
		private volatile ScheduledFuture<?> renewalTask;

		ManageCertObserver(
				StreamObserver<Tlscert.TlsCertServerMsg> responseObserver,
				String callerSubject,
				String callerInstanceId) {
			this.responseObserver = responseObserver;
			this.callerSubject = callerSubject;
			this.callerInstanceId = callerInstanceId;
		}

		@Override
		public void onNext(Tlscert.TlsCertClientMsg msg) {
			switch (msg.getMsgCase()) {
				case INIT:
					handleInit(msg.getInit());
					break;
				case CSR:
					handleCsr(msg.getCsr());
					break;
				default:
					responseObserver.onError(Status.INVALID_ARGUMENT
							.withDescription("unknown message type")
							.asRuntimeException());
			}
		}

		@Override
		public void onError(Throwable t) {
			cancelRenewal();
			logger.warn("ManageCert stream error for {}/{}: {}",
					serviceName, instanceId, t.getMessage());
		}

		@Override
		public void onCompleted() {
			cancelRenewal();
			responseObserver.onCompleted();
			logger.info("ManageCert stream completed for {}/{}", serviceName, instanceId);
		}

		private void handleInit(Tlscert.TlsCertInit init) {
			if (initialized) {
				responseObserver.onError(Status.FAILED_PRECONDITION
						.withDescription("init already received")
						.asRuntimeException());
				return;
			}

			// The authenticated caller subject is the canonical SPIFFE URI
			// (kernel-minted service tokens set sub = SPIFFE URI). The client's
			// init.service_name is the bare service name; verify it matches the
			// last path segment of the SPIFFE URI as defense in depth.
			if (callerSubject == null || callerSubject.isEmpty()) {
				responseObserver.onError(Status.UNAUTHENTICATED
						.withDescription("ManageCert requires an authenticated caller")
						.asRuntimeException());
				return;
			}
			if (!SpiffeIds.isSpiffeUri(callerSubject)) {
				responseObserver.onError(Status.PERMISSION_DENIED
						.withDescription("ManageCert requires a kernel-minted service token; "
								+ "sub is not a SPIFFE URI: " + callerSubject)
						.asRuntimeException());
				return;
			}
			String expectedServiceName = SpiffeIds.serviceName(callerSubject);
			if (!expectedServiceName.equals(init.getServiceName())) {
				responseObserver.onError(Status.PERMISSION_DENIED
						.withDescription("init.service_name '" + init.getServiceName()
								+ "' does not match authenticated SPIFFE identity '" + callerSubject + "'")
						.asRuntimeException());
				return;
			}

			this.spiffeId = callerSubject;
			this.serviceName = expectedServiceName;
			this.instanceId = init.getInstanceId();
			this.initialized = true;

			logger.info("ManageCert Init: spiffeId={}, instance={}", spiffeId, instanceId);
		}

		private void handleCsr(Tlscert.TlsCertCsr csr) {
			if (!initialized) {
				responseObserver.onError(Status.FAILED_PRECONDITION
						.withDescription("init required before csr")
						.asRuntimeException());
				return;
			}

			// Same revocation gate every kernel-signed token exchange goes through,
			// applied per CSR rather than per stream: the stream is long-lived and
			// renews at half-life, so a revocation that lands mid-stream has to stop
			// the next renewal. Without this a revoked workload keeps a valid mesh
			// identity for as long as it holds the stream open.
			try {
				IdentityServiceImpl.assertNotRevoked(workloadMap, spiffeId, "workload");
			} catch (IdentityServiceImpl.StatusException e) {
				responseObserver.onError(e.toGrpcStatus().asRuntimeException());
				return;
			}

			try {
				signAndDeliver(csr);
			} catch (Exception e) {
				logger.error("ManageCert cert signing failed for {}/{}", serviceName, instanceId, e);
				responseObserver.onNext(Tlscert.TlsCertServerMsg.newBuilder()
						.setError("cert signing failed: " + e.getMessage())
						.build());
			}
		}

		private void signAndDeliver(Tlscert.TlsCertCsr csr) throws Exception {
			// Cancel any pending renewal from a previous cert.
			cancelRenewal();

			// Intermediate CA state is keyed by bare service name so both
			// X509Mint and ManageCert produce certs under the same per-service
			// intermediate. The full SPIFFE URI remains the leaf cert identity.
			ImmutableCertChain intermediateCa = getOrCreateIntermediateCa(serviceName, signingCa);

			// Build cert request from the CSR's public key. URI SAN is the
			// canonical SPIFFE URI (already validated against the caller's
			// authenticated identity in handleInit). DNS SANs cover hostname
			// verification when callers connect by short k8s service name.
			long now = Instant.now().getEpochSecond();
			long exp = now + certLifetimeSeconds;

			X509.X509CertRequest certRequest = kernelCertRequest(
					csr.getPublicKey(), spiffeId, serviceName, instanceId, exp);

			// Sign with the intermediate CA.
			X509.X509Cert leafCert = intermediateCa.sign(certRequest);

			// Build response: leaf cert + intermediate CA cert.
			X509.X509CertChain certChain = X509.X509CertChain.newBuilder()
					.addChain(leafCert)
					.addChain(intermediateCa.leaf().getProto())
					.build();

			// Deliver cert to service.
			responseObserver.onNext(Tlscert.TlsCertServerMsg.newBuilder()
					.setCert(Tlscert.TlsCertDelivery.newBuilder()
							.setChain(certChain)
							.build())
					.build());

			logger.info("ManageCert: delivered cert for {}/{}, spiffeId={}, expires={}",
					serviceName, instanceId, spiffeId, exp);

			// Schedule renewal at half-life.
			long halfLife = certLifetimeSeconds / 2;
			renewalTask = scheduler.schedule(() -> {
				try {
					responseObserver.onNext(Tlscert.TlsCertServerMsg.newBuilder()
							.setRenew(Tlscert.TlsCertRenew.newBuilder()
									.setReason("half-life reached")
									.build())
							.build());
					logger.info("ManageCert: sent renewal for {}/{}", serviceName, instanceId);
				} catch (Exception e) {
					logger.warn("ManageCert: failed to send renewal for {}/{}: {}",
							serviceName, instanceId, e.getMessage());
				}
			}, halfLife, TimeUnit.SECONDS);
		}

		private void cancelRenewal() {
			ScheduledFuture<?> task = renewalTask;
			if (task != null) {
				task.cancel(false);
				renewalTask = null;
			}
		}
	}

	/**
	 * Builds the X509CertRequest kernel actually signs for a ManageCert stream.
	 *
	 * <p>Cert identity: the URI SAN carries the canonical SPIFFE ID kernel
	 * verified from the caller's own token (used for SPIFFE-based peer
	 * verification). DNS SANs cover hostname-based verification for callers
	 * connecting by k8s short name or pod hostname. The X509CertRequest message
	 * has no dedicated CN/subject field — issuer carries the bare service name
	 * for human-readability, the signer fills in subject DN from request/key
	 * metadata.
	 *
	 * <p>The one caller-supplied field is {@code init.instance_id}, which the
	 * generated service managers set to the pod hostname so peers connecting by
	 * hostname pass hostname verification. It is bound to the caller's verified
	 * identity here: the name must be the service name itself or under it
	 * ({@code svc-0}, {@code svc.ns.svc}, {@code svc0}), the shapes every k8s
	 * workload name in this platform takes. Anything else is another service's
	 * name — kernel
	 * would otherwise sign, under a trusted CA, a cert asserting a hostname the
	 * caller does not own, letting it impersonate that peer in TLS. Unowned
	 * names are dropped, not refused, so a stale client cannot be locked out of
	 * cert renewal. Same rule and same disposition as
	 * {@code IdentityServiceImpl.kernelCertRequest} applies on the X509Mint path.
	 *
	 * <p>The token's own {@code instance_id} claim is deliberately not the thing
	 * matched against: kernel mints it as a random UUID (see
	 * {@code IdentityServiceImpl}), so it is not a DNS name and carries no
	 * hostname ownership.
	 */
	static X509.X509CertRequest kernelCertRequest(
			KeyOuterClass.PublicKey publicKey,
			String spiffeId,
			String serviceName,
			String instanceId,
			long exp) {
		LinkedHashSet<String> dnsNames = new LinkedHashSet<>();
		dnsNames.add(serviceName);
		dnsNames.add("*." + serviceName);
		if (instanceId != null && !instanceId.isEmpty()) {
			if (instanceId.equals(serviceName)
					|| instanceId.startsWith(serviceName + "-")
					|| instanceId.startsWith(serviceName + ".")
					|| instanceId.equals("*." + serviceName)
					// <service><replica-index> with no separator, e.g. "eventbus0" —
					// the actual pod hostname convention every chart uses
					// (scotty/backend/looper/charts/schematic/templates/*/deployment.yaml).
					|| instanceId.matches(java.util.regex.Pattern.quote(serviceName) + "[0-9]+")) {
				dnsNames.add(instanceId);
			} else {
				logger.warn("ManageCert: dropping DNS SAN '{}' requested by {} — not a name that service owns",
						instanceId, spiffeId);
			}
		}

		return X509.X509CertRequest.newBuilder()
				.setKey(publicKey)
				.setExp(exp)
				.setIssuer(serviceName)
				.addUriSans(spiffeId)
				.addAllDnsNames(dnsNames)
				.build();
	}

	// ========================================================================
	// Intermediate CA
	// ========================================================================

	/**
	 * Delegates to {@link ServiceIntermediateCa}, the single implementation
	 * shared with {@code IdentityServiceImpl.X509Mint}. This method used to be a
	 * near-verbatim copy of that one, each guarded by {@code synchronized} on its
	 * own instance — two different monitors, so a concurrent X509Mint and
	 * ManageCert for the same service could both sign an intermediate and race
	 * the write, leaving the loser's leaf chaining to a CA no longer in state.
	 */
	private ImmutableCertChain getOrCreateIntermediateCa(
			String serviceName, ImmutableCertChain rootCa) throws Exception {
		return ServiceIntermediateCa.getOrCreate(
				serviceName, serviceCaReader, serviceCaWriter, rootCa, null, logger);
	}
}
