// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.BiConsumer;
import java.util.function.Function;
import javax.annotation.Nullable;
import org.slf4j.Logger;

/**
 * The single get-or-create for a per-service intermediate CA.
 *
 * <p>{@code X509Mint} ({@code IdentityServiceImpl}) and {@code ManageCert}
 * ({@code TlsCertServiceImpl}) both need one, and each used to carry its own
 * near-identical copy guarded by {@code synchronized} on its own instance. Two
 * different monitors buy nothing across the two services: a concurrent X509Mint
 * and ManageCert for the same service both read, both missed, both generated a
 * P-384 intermediate and both wrote. The last write won, and the loser had
 * already signed a leaf chaining to an intermediate no longer in state — a leaf
 * that fails chain verification for its whole lifetime.
 *
 * <p>Both call sites now delegate here, so the {@link #CREATE_LOCKS} monitor is
 * shared: a second arrival blocks, then re-reads under the lock and finds the
 * first arrival's write instead of signing a second intermediate.
 *
 * <p><b>Node-local.</b> This closes the race inside one kernel JVM, which is
 * where both RPCs land in the single-node and leader-pinned deployments. Two
 * kernel pods handling the two RPCs concurrently can still both create; closing
 * that needs a real cluster-wide lock, and there is none available to these
 * services today — {@code Manager.getLock} is a no-op in the Hazelcast
 * implementation and the FencedLock is not wired here. Tracked as a follow-up.
 */
final class ServiceIntermediateCa {

	/** Intermediate CA lifetime: 10 years. */
	static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	/**
	 * One monitor per service name, shared by every caller in this JVM. Not
	 * evicted: the key set is the platform's service names, a small fixed set.
	 */
	private static final ConcurrentMap<String, Object> CREATE_LOCKS = new ConcurrentHashMap<>();

	private ServiceIntermediateCa() {
	}

	/**
	 * Returns the service's intermediate CA, creating and storing one if there is
	 * no usable existing CA.
	 *
	 * <p>The intermediate CA is signed by {@code signingCa} with BasicConstraints
	 * CA:TRUE, pathlen:0, and stored in the Ca state's {@code service_cas}
	 * collection keyed by bare service name — the same key both X509Mint and
	 * ManageCert use, so both produce leaves under one intermediate per service.
	 *
	 * @param serviceName bare service name (the state key)
	 * @param reader      reads the stored CA for a service, null when absent
	 * @param writer      stores the CA for a service
	 * @param signingCa   the chain that signs the intermediate
	 * @param traceId     X509Mint's trace id for the per-step timing logs; null
	 *                    on the ManageCert path, which does not trace
	 * @param logger      the calling service's logger, so the lines stay
	 *                    attributed to the RPC that triggered the work
	 */
	static ImmutableCertChain getOrCreate(
			String serviceName,
			Function<String, X509.X509CertChain> reader,
			BiConsumer<String, X509.X509CertChain> writer,
			ImmutableCertChain signingCa,
			@Nullable String traceId,
			Logger logger) throws Exception {
		long startNanos = System.nanoTime();

		ImmutableCertChain existing = existingUsable(serviceName, reader, signingCa, traceId, startNanos, logger);
		if (existing != null) {
			return existing;
		}

		// Creation is serialized per service so two concurrent misses do not both
		// sign an intermediate and race the write. The winner's CA is visible to
		// the loser on the re-read below.
		synchronized (CREATE_LOCKS.computeIfAbsent(serviceName, name -> new Object())) {
			ImmutableCertChain raced = existingUsable(serviceName, reader, signingCa, traceId, startNanos, logger);
			if (raced != null) {
				return raced;
			}
			return create(serviceName, writer, signingCa, traceId, startNanos, logger);
		}
	}

	/**
	 * The stored CA for {@code serviceName} if there is one and it is still usable
	 * under the current signing CA, else null.
	 */
	@Nullable
	private static ImmutableCertChain existingUsable(
			String serviceName,
			Function<String, X509.X509CertChain> reader,
			ImmutableCertChain signingCa,
			@Nullable String traceId,
			long startNanos,
			Logger logger) {
		X509.X509CertChain existing = reader.apply(serviceName);
		if (existing == null || existing.getChainCount() == 0) {
			return null;
		}
		ImmutableCertChain reusable = reusable(serviceName, existing, signingCa, logger);
		if (reusable == null) {
			logger.info("Recreating intermediate CA for service: {}{}", serviceName,
					traceId != null ? " traceId=" + traceId : "");
			return null;
		}
		if (traceId != null) {
			logger.info("X509Mint[{}] found existing intermediate CA service={}, chainLength={} in {}ms",
					traceId, serviceName, existing.getChainCount(), elapsedMillis(startNanos));
		}
		return reusable;
	}

	private static ImmutableCertChain create(
			String serviceName,
			BiConsumer<String, X509.X509CertChain> writer,
			ImmutableCertChain signingCa,
			@Nullable String traceId,
			long startNanos,
			Logger logger) throws Exception {
		// Generate EC P-384 keypair for the intermediate CA.
		// Ed25519 is avoided because Netty (used by Keycloak/Quarkus) has known
		// compatibility issues with Ed25519 in TLS certificate chains.
		if (traceId != null) {
			logger.info("X509Mint[{}] generating intermediate CA key service={}", traceId, serviceName);
		}
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair intermediateKeyPair = kpg.generateKeyPair();
		if (traceId != null) {
			logger.info("X509Mint[{}] generated intermediate CA key service={} in {}ms",
					traceId, serviceName, elapsedMillis(startNanos));
		}

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

		if (traceId != null) {
			logger.info("X509Mint[{}] signing intermediate CA service={} issuer={}",
					traceId, serviceName, intermediateRequest.getIssuer());
		}
		X509.X509Cert intermediateCert = signingCa.sign(intermediateRequest);
		if (traceId != null) {
			logger.info("X509Mint[{}] signed intermediate CA service={} in {}ms",
					traceId, serviceName, elapsedMillis(startNanos));
		}

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

		if (traceId != null) {
			logger.info("X509Mint[{}] writing intermediate CA service={}", traceId, serviceName);
		}
		writer.accept(serviceName, intermediateProto);
		logger.info("Created intermediate CA for service: {}{}", serviceName,
				traceId != null ? " traceId=" + traceId : "");

		return ImmutableCertChain.from(intermediateProto);
	}

	private static long elapsedMillis(long startNanos) {
		return (System.nanoTime() - startNanos) / 1_000_000L;
	}

	static ImmutableCertChain reusable(
			String serviceName,
			X509.X509CertChain existing,
			ImmutableCertChain signingCa,
			Logger logger) {
		if (existing == null || existing.getChainCount() == 0) {
			return null;
		}

		try {
			ImmutableCertChain existingChain = ImmutableCertChain.from(existing);
			if (existingChain.getEffectiveKey() == null) {
				logger.warn("Discarding service CA without private key: {}", serviceName);
				return null;
			}

			X509Certificate existingCert = existingChain.leaf().getX509Certificate();
			X509Certificate signingCert = signingCa.leaf().getX509Certificate();
			existingCert.checkValidity();
			signingCert.checkValidity();

			if (!existingCert.getIssuerX500Principal().equals(signingCert.getSubjectX500Principal())) {
				logger.info(
						"Rotating service CA for {}: issuer {} does not match current signing CA subject {}",
						serviceName,
						existingCert.getIssuerX500Principal().getName(),
						signingCert.getSubjectX500Principal().getName());
				return null;
			}

			existingCert.verify(signingCert.getPublicKey());
			return existingChain;
		} catch (Exception e) {
			logger.info("Rotating service CA for {}: existing CA is not valid under current signing CA: {}",
					serviceName, e.getMessage());
			return null;
		}
	}
}
