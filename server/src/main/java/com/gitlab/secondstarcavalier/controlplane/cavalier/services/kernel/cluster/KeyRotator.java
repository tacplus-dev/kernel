// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KeyRotator manages the signing key lifecycle for the token exchanger.
 *
 * <p>
 * On start, ensures at least one signing key exists. Periodically rotates
 * keys by generating new Ed25519 key pairs. Old keys are removed after
 * 2 × rotation_interval.
 */
public class KeyRotator {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotator.class);

    private final long rotationIntervalSeconds;
    private final long keyRetentionSeconds;
    private final Consumer<JwkOuterClass.Jwk> keyPublisher;
    private final Consumer<String> keyRemover;
    private final Supplier<java.util.List<JwkOuterClass.Jwk>> keyReader;
    private final ScheduledExecutorService scheduler;

    private volatile String activeKid;
    private volatile ImmutableKey activeSigningKey;
    private volatile JwkOuterClass.Jwk activeJwk;

    /**
     * @param rotationIntervalSeconds interval between key rotations
     * @param keyRetentionSeconds     how long to retain old keys after rotation (must be ≥ max token lifetime)
     * @param keyPublisher            writes a JWK to the verifying_keys boundary
     * @param keyRemover              removes a JWK by kid from verifying_keys
     * @param keyReader               reads current verifying_keys
     */
    public KeyRotator(
            long rotationIntervalSeconds,
            long keyRetentionSeconds,
            Consumer<JwkOuterClass.Jwk> keyPublisher,
            Consumer<String> keyRemover,
            Supplier<java.util.List<JwkOuterClass.Jwk>> keyReader) {
        this.rotationIntervalSeconds = rotationIntervalSeconds;
        this.keyRetentionSeconds = keyRetentionSeconds;
        this.keyPublisher = keyPublisher;
        this.keyRemover = keyRemover;
        this.keyReader = keyReader;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "key-rotator");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Starts the key rotator. Generates an initial key if none exists,
     * then schedules periodic rotation.
     */
    public void start() {
        try {
            ensureActiveKey();
        } catch (Exception e) {
            logger.error("Failed to generate initial signing key", e);
            throw new RuntimeException("KeyRotator failed to start", e);
        }

        scheduler.scheduleAtFixedRate(
                () -> {
                    try {
                        rotate();
                    } catch (Exception e) {
                        logger.error("Key rotation failed", e);
                    }
                },
                rotationIntervalSeconds,
                rotationIntervalSeconds,
                TimeUnit.SECONDS);

        logger.info("KeyRotator started: rotation every {}s, key retention {}s, active kid={}",
                rotationIntervalSeconds, keyRetentionSeconds, activeKid);
    }

    public void stop() {
        scheduler.shutdown();
    }

    /**
     * Re-publishes the current signing JWK to the verifying_keys boundary.
     * Called after a Hazelcast cluster topology change so that newly-merged nodes
     * see this node's signing key and can validate tokens this node has issued.
     */
    public void republishCurrentKey() {
        JwkOuterClass.Jwk jwk = activeJwk;
        if (jwk == null) {
            logger.warn("republishCurrentKey: no active JWK to republish");
            return;
        }
        keyPublisher.accept(jwk);
        logger.info("Republished signing key after cluster topology change: kid={}", activeKid);
    }

    public String getActiveKeyId() {
        return activeKid;
    }

    public ImmutableKey getActiveSigningKey() {
        return activeSigningKey;
    }

    private void ensureActiveKey() throws Exception {
        var existing = keyReader.get();
        if (!existing.isEmpty()) {
            // Find the newest key by created timestamp
            JwkOuterClass.Jwk newest = existing.get(0);
            for (JwkOuterClass.Jwk jwk : existing) {
                if (jwk.getCreated() > newest.getCreated()) {
                    newest = jwk;
                }
            }
            activeKid = newest.getKid();
            logger.info("Using existing signing key: kid={}", activeKid);
            // We don't have the private key for existing keys, so generate a new one
        }

        // Always generate a fresh key pair so we have the private key
        generateAndPublishKey();
    }

    private void rotate() throws Exception {
        logger.info("Rotating signing key (previous kid={})", activeKid);

        generateAndPublishKey();

        // Remove keys older than the retention period (max token lifetime).
        // Tokens signed with a rotated key must remain verifiable until they expire.
        long cutoff = Instant.now().getEpochSecond() - keyRetentionSeconds;
        var keys = keyReader.get();
        for (JwkOuterClass.Jwk jwk : keys) {
            if (jwk.getCreated() > 0
                    && jwk.getCreated() < cutoff
                    && !jwk.getKid().equals(activeKid)) {
                logger.info("Removing expired signing key: kid={}, created={}", jwk.getKid(), jwk.getCreated());
                keyRemover.accept(jwk.getKid());
            }
        }
    }

    private void generateAndPublishKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = kpg.generateKeyPair();

        String kid = UUID.randomUUID().toString();
        long now = Instant.now().getEpochSecond();

        // Build PEM-encoded private key for ImmutableKey
        byte[] pkcs8Bytes = keyPair.getPrivate().getEncoded();
        String pemKey = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8Bytes)
                + "\n-----END PRIVATE KEY-----\n";
        String keyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pemKey.getBytes());

        KeyOuterClass.Key protoKey = KeyOuterClass.Key.newBuilder()
                .setId(kid)
                .setBase64(keyBase64)
                .setCreated(now)
                .build();

        activeSigningKey = ImmutableKey.from(protoKey);
        activeKid = kid;

        // Extract public key bytes for JWK
        PublicKey pub = keyPair.getPublic();
        // Ed25519 X.509 encoding: last 32 bytes are the raw public key
        byte[] x509Encoded = pub.getEncoded();
        byte[] rawPub = new byte[32];
        System.arraycopy(x509Encoded, x509Encoded.length - 32, rawPub, 0, 32);
        String xB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawPub);

        JwkOuterClass.Jwk jwk = JwkOuterClass.Jwk.newBuilder()
                .setKid(kid)
                .setAlg("EdDSA")
                .setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
                .setCrv("Ed25519")
                .setX(xB64)
                .setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG)
                .setCreated(now)
                .build();

        activeJwk = jwk;
        keyPublisher.accept(jwk);
        logger.info("Published new signing key: kid={}", kid);
    }
}
