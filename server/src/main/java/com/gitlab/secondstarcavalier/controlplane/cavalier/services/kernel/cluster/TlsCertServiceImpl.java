// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.tlscert.Tlscert;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.tlscert.TlsCertServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.SecurityInterceptor;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
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
	private final Supplier<String> spiffePrefixReader;
	private final ScheduledExecutorService scheduler;

	/**
	 * @param certLifetimeSeconds  lifetime for leaf TLS certs (renewal at half-life)
	 * @param signingCa            cavalier-issued signing chain (intermediate CA)
	 * @param serviceCaReader      reads per-service intermediate CA from Ca state
	 * @param serviceCaWriter      writes per-service intermediate CA to Ca state
	 * @param spiffePrefixReader    SPIFFE deployment prefix
	 */
	public TlsCertServiceImpl(
			long certLifetimeSeconds,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter,
			Supplier<String> spiffePrefixReader) {
		this.certLifetimeSeconds = certLifetimeSeconds;
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
		this.spiffePrefixReader = spiffePrefixReader;
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
		// Capture authenticated caller identity from gRPC context (set by SecurityInterceptor).
		String callerSubject = SecurityInterceptor.CALLER_SUBJECT_KEY.get();
		String callerInstanceId = SecurityInterceptor.CALLER_INSTANCE_ID_KEY.get();

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

		private String serviceName;
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

			// Verify service_name matches the authenticated caller.
			if (callerSubject != null && !callerSubject.isEmpty()
					&& !callerSubject.equals(init.getServiceName())) {
				responseObserver.onError(Status.PERMISSION_DENIED
						.withDescription("service_name '" + init.getServiceName()
								+ "' does not match authenticated subject '" + callerSubject + "'")
						.asRuntimeException());
				return;
			}

			this.serviceName = init.getServiceName();
			this.instanceId = init.getInstanceId();
			this.initialized = true;

			logger.info("ManageCert Init: service={}, instance={}", serviceName, instanceId);
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

			// Get or create per-service intermediate CA (signed by cavalier-issued signing chain).
			ImmutableCertChain intermediateCa = getOrCreateIntermediateCa(serviceName, signingCa);

			// Build SPIFFE SAN.
			String spiffePrefix = spiffePrefixReader.get();
			String spiffeId = "spiffe://" + spiffePrefix + "/" + serviceName + "/" + instanceId;

			// Build cert request from the CSR's public key.
			long now = Instant.now().getEpochSecond();
			long exp = now + certLifetimeSeconds;

			X509.X509CertRequest certRequest = X509.X509CertRequest.newBuilder()
					.setKey(csr.getPublicKey())
					.setExp(exp)
					.setIssuer(serviceName)
					.addUriSans(spiffeId)
					// Add DNS SANs so Java gRPC hostname verification passes when kernel
					// connects to this service via its short hostname (e.g., "opa0").
					.addDnsNames(serviceName)
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
			return ImmutableCertChain.from(existing);
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
				.setKey(intermediateKey)
				.addChain(intermediateCert)
				.build();

		serviceCaWriter.accept(serviceName, intermediateProto);
		logger.info("Created intermediate CA for service: {}", serviceName);

		return ImmutableCertChain.from(intermediateProto);
	}
}
