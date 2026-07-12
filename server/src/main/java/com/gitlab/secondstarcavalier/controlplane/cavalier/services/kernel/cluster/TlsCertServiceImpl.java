// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.tlscert.Tlscert;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.tlscert.TlsCertServiceGrpc;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
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

	/** Intermediate CA lifetime: 10 years. */
	private static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	private final long certLifetimeSeconds;
	private final ImmutableCertChain signingCa;
	private final Function<String, X509.X509CertChain> serviceCaReader;
	private final BiConsumer<String, X509.X509CertChain> serviceCaWriter;
	private final Supplier<String> trustDomainReader;
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	private final ScheduledExecutorService scheduler;

	/**
	 * @param certLifetimeSeconds  lifetime for leaf TLS certs (renewal at half-life)
	 * @param signingCa            cavalier-issued signing chain (intermediate CA)
	 * @param serviceCaReader      reads per-service intermediate CA from Ca state
	 * @param serviceCaWriter      writes per-service intermediate CA to Ca state
	 * @param trustDomainReader    SPIFFE trust domain
	 * @param verifyingKeysReader  active kernel JWKs for validating caller tokens
	 */
	public TlsCertServiceImpl(
			long certLifetimeSeconds,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter,
			Supplier<String> trustDomainReader,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader) {
		this.certLifetimeSeconds = certLifetimeSeconds;
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
		this.trustDomainReader = trustDomainReader;
		this.verifyingKeysReader = verifyingKeysReader;
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
			TokenWrapper token = TokenWrapper.parse(rawToken);
			String kid = token.getKid();
			JwkOuterClass.Jwk matchingKey = null;
			for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
				if (kid.equals(jwk.getKid())) {
					matchingKey = jwk;
					break;
				}
			}
			if (matchingKey == null) {
				throw new IllegalStateException("token signed with unknown key: " + kid);
			}
			token.verify(ImmutableJwk.from(matchingKey));
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

			// Cert identity: URI SAN carries the canonical SPIFFE ID (used for
			// SPIFFE-based peer verification). DNS SANs cover hostname-based
			// verification for callers connecting by k8s short name or pod
			// hostname. The X509CertRequest message has no dedicated CN/subject
			// field — issuer carries the bare service name for human-readability,
			// the signer fills in subject DN from request/key metadata.
			X509.X509CertRequest certRequest = X509.X509CertRequest.newBuilder()
					.setKey(csr.getPublicKey())
					.setExp(exp)
					.setIssuer(serviceName)
					.addUriSans(spiffeId)
					.addDnsNames(serviceName)
					.addDnsNames("*." + serviceName)
					.addDnsNames(instanceId)
					.build();

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

	// ========================================================================
	// Intermediate CA (same pattern as IdentityServiceImpl)
	// ========================================================================

	private synchronized ImmutableCertChain getOrCreateIntermediateCa(
			String serviceName, ImmutableCertChain rootCa) throws Exception {

		// Check if intermediate CA already exists for this service.
		X509.X509CertChain existing = serviceCaReader.apply(serviceName);
		if (existing != null && existing.getChainCount() > 0) {
			ImmutableCertChain reusable = ServiceIntermediateCa.reusable(serviceName, existing, rootCa, logger);
			if (reusable != null) {
				return reusable;
			}
			logger.info("Recreating intermediate CA for service: {}", serviceName);
		}

		// Generate EC P-384 keypair for the intermediate CA.
		// Ed25519 is avoided because Netty (used by Keycloak/Quarkus) has known
		// compatibility issues with Ed25519 in TLS certificate chains.
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair intermediateKeyPair = kpg.generateKeyPair();

		String intermediateId = serviceName + "-intermediate-ca";
		long now = Instant.now().getEpochSecond();
		long intermediateExp = now + INTERMEDIATE_CA_LIFETIME_SECONDS;

		// Build public key proto for signing request.
		byte[] pubKeyBytes = intermediateKeyPair.getPublic().getEncoded();
		String pubKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubKeyBytes);
		KeyOuterClass.PublicKey intermediatePubKey = KeyOuterClass.PublicKey.newBuilder()
				.setId(intermediateId)
				.setBase64(pubKeyBase64)
				.build();

		// Sign the intermediate CA cert with the root CA (CA:TRUE, pathlen:0).
		X509.X509CertRequest intermediateRequest = X509.X509CertRequest.newBuilder()
				.setKey(intermediatePubKey)
				.setExp(intermediateExp)
				.setIssuer(serviceName + " Intermediate CA")
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN)
				.setIsCa(true)
				.setPathLenConstraint(0)
				.build();

		X509.X509Cert intermediateCert = rootCa.sign(intermediateRequest);

		// Build the private key proto.
		byte[] privKeyBytes = intermediateKeyPair.getPrivate().getEncoded();
		String privKeyPem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privKeyBytes)
				+ "\n-----END PRIVATE KEY-----\n";
		String privKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(privKeyPem.getBytes());

		KeyOuterClass.Key intermediateKey = KeyOuterClass.Key.newBuilder()
				.setId(intermediateId)
				.setBase64(privKeyBase64)
				.setCreated(now)
				.build();

		// Store the intermediate CA keypair in the Ca state.
		X509.X509CertChain intermediateProto = X509.X509CertChain.newBuilder()
				.setId(serviceName)
				.setKey(intermediateKey)
				.addChain(intermediateCert)
				.build();

		serviceCaWriter.accept(serviceName, intermediateProto);
		logger.info("Created intermediate CA for service: {}", serviceName);

		return ImmutableCertChain.from(intermediateProto);
	}
}
