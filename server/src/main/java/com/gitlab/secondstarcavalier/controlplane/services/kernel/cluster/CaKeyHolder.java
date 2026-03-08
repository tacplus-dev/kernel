// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CaKeyHolder manages a per-node CA keypair for signing X.509 certificates.
 *
 * <p>
 * On start, generates an EC P-521 keypair, self-signs a CA certificate,
 * and publishes the CA cert to the CaState collection. The private key
 * is held in memory only (never persisted). Rotates at half the CA
 * certificate lifetime; old CA certs remain in the collection for trust
 * continuity until they expire naturally.
 */
public class CaKeyHolder {

    private static final Logger logger = LoggerFactory.getLogger(CaKeyHolder.class);

    private final long caLifetimeSeconds;
    private final Consumer<X509.X509Cert> caCertPublisher;
    private final ScheduledExecutorService scheduler;

    private volatile ImmutableCertPair activeCaPair;

    /**
     * @param caLifetimeSeconds lifetime for CA certificates in seconds
     * @param caCertPublisher   publishes a CA cert to the CaState ca_certs collection
     */
    public CaKeyHolder(long caLifetimeSeconds, Consumer<X509.X509Cert> caCertPublisher) {
        this.caLifetimeSeconds = caLifetimeSeconds;
        this.caCertPublisher = caCertPublisher;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ca-key-holder");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Generates the initial CA keypair, publishes the CA cert, and schedules
     * rotation at half the CA certificate lifetime.
     */
    public void start() {
        try {
            generateAndPublish();
        } catch (Exception e) {
            logger.error("Failed to generate initial CA keypair", e);
            throw new RuntimeException("CaKeyHolder failed to start", e);
        }

        long rotateInterval = caLifetimeSeconds / 2;
        scheduler.scheduleAtFixedRate(
                () -> {
                    try {
                        rotate();
                    } catch (Exception e) {
                        logger.error("CA key rotation failed", e);
                    }
                },
                rotateInterval,
                rotateInterval,
                TimeUnit.SECONDS);

        logger.info("CaKeyHolder started: lifetime={}s, rotation every {}s",
                caLifetimeSeconds, rotateInterval);
    }

    public void stop() {
        scheduler.shutdown();
    }

    /**
     * Returns the current CA keypair for signing certificate requests.
     */
    public ImmutableCertPair getActiveCaPair() {
        return activeCaPair;
    }

    private void rotate() throws Exception {
        logger.info("Rotating CA keypair");
        generateAndPublish();
    }

    private void generateAndPublish() throws Exception {
        // Generate EC P-521 keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        String id = UUID.randomUUID().toString();
        long now = Instant.now().getEpochSecond();

        // Build PEM-encoded private key for ImmutableKey
        byte[] pkcs8Bytes = keyPair.getPrivate().getEncoded();
        String pemKey = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8Bytes)
                + "\n-----END PRIVATE KEY-----\n";
        String keyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pemKey.getBytes());

        KeyOuterClass.Key protoKey = KeyOuterClass.Key.newBuilder()
                .setId(id)
                .setBase64(keyBase64)
                .setCreated(now)
                .build();

        ImmutableKey immutableKey = ImmutableKey.from(protoKey);

        // Create ImmutableCertPair for self-signing
        ImmutableCertPair forSigning = ImmutableCertPair.forSelfSigning(immutableKey);

        // Self-sign a CA certificate
        long exp = now + caLifetimeSeconds;
        X509.X509Cert caCert = forSigning.selfSign(
                id + " CA",
                exp,
                X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN,
                List.of());

        // Build the full cert pair (key + signed CA cert) for subsequent signing operations
        X509.X509CertPair certPairProto = X509.X509CertPair.newBuilder()
                .setKey(protoKey)
                .setCert(caCert)
                .build();
        this.activeCaPair = ImmutableCertPair.from(certPairProto);

        // Publish CA cert to CaState collection
        caCertPublisher.accept(caCert);
        logger.info("Published CA cert: id={}, expires={}", id, exp);
    }
}
