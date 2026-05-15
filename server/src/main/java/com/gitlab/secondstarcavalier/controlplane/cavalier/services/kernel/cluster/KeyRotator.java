// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.google.protobuf.util.JsonFormat;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
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
 * On start, attempts to load a previously persisted signing key from
 * {@code signingKeyPath}. If none exists (first boot) or the file is
 * unreadable, a new Ed25519 key pair is generated instead. In both cases
 * the active JWK is re-injected into Hazelcast if it is missing (e.g. after
 * a Hazelcast wipe).
 *
 * <p>
 * Periodically rotates keys by generating new Ed25519 key pairs. Old keys
 * are removed after {@code keyRetentionSeconds}. Each rotation overwrites
 * the persisted key file so the newest key survives the next restart.
 */
public class KeyRotator {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotator.class);

    private final long rotationIntervalSeconds;
    private final long keyRetentionSeconds;
    private final Consumer<JwkOuterClass.Jwk> keyPublisher;
    private final Consumer<String> keyRemover;
    private final Supplier<List<JwkOuterClass.Jwk>> keyReader;
    private final ScheduledExecutorService scheduler;
    private final Path signingKeyPath;

    private volatile String activeKid;
    private volatile ImmutableKey activeSigningKey;
    private volatile JwkOuterClass.Jwk activeJwk;

    /**
     * @param rotationIntervalSeconds interval between key rotations
     * @param keyRetentionSeconds     how long to retain old keys after rotation (must be ≥ max token lifetime)
     * @param keyPublisher            writes a JWK to the verifying_keys boundary
     * @param keyRemover              removes a JWK by kid from verifying_keys
     * @param keyReader               reads current verifying_keys
     * @param signingKeyPath          path to persist the active signing key; may be null to disable persistence
     */
    public KeyRotator(
            long rotationIntervalSeconds,
            long keyRetentionSeconds,
            Consumer<JwkOuterClass.Jwk> keyPublisher,
            Consumer<String> keyRemover,
            Supplier<List<JwkOuterClass.Jwk>> keyReader,
            Path signingKeyPath) {
        this.rotationIntervalSeconds = rotationIntervalSeconds;
        this.keyRetentionSeconds = keyRetentionSeconds;
        this.keyPublisher = keyPublisher;
        this.keyRemover = keyRemover;
        this.keyReader = keyReader;
        this.signingKeyPath = signingKeyPath;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "key-rotator");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Starts the key rotator. Loads the persisted signing key if available,
     * otherwise generates a new one. Ensures the JWK is present in Hazelcast.
     * Then schedules periodic rotation.
     */
    public void start() {
        try {
            ensureActiveKey();
        } catch (Exception e) {
            logger.error("Failed to initialize signing key", e);
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
        if (signingKeyPath != null && Files.exists(signingKeyPath)) {
            try {
                loadPersistedKey();
            } catch (Exception e) {
                logger.error("Failed to load persisted signing key from {}, generating new key: {}",
                        signingKeyPath, e.getMessage());
            }
        }

        if (activeSigningKey == null) {
            generateAndPublishKey();
        }

        ensureJwkPublished();
    }

    /**
     * Checks whether the active JWK is already present in Hazelcast and
     * publishes it if missing. Called on boot to handle the case where
     * Hazelcast state was wiped while the signing key file survived.
     */
    private void ensureJwkPublished() {
        if (activeJwk == null) {
            return;
        }
        String kid = activeKid;
        boolean found = keyReader.get().stream().anyMatch(k -> kid.equals(k.getKid()));
        if (!found) {
            keyPublisher.accept(activeJwk);
            logger.info("Re-injected signing JWK into Hazelcast on boot: kid={}", kid);
        }
    }

    /**
     * Loads the persisted {@link Kernel.SigningKeyRecord} from {@code signingKeyPath},
     * restoring the active signing key and JWK without generating a new key pair.
     */
    private void loadPersistedKey() throws Exception {
        String json = Files.readString(signingKeyPath, StandardCharsets.UTF_8);
        Kernel.SigningKeyRecord.Builder builder = Kernel.SigningKeyRecord.newBuilder();
        JsonFormat.parser().ignoringUnknownFields().merge(json, builder);
        Kernel.SigningKeyRecord record = builder.build();
        activeSigningKey = ImmutableKey.from(record.getKey());
        activeKid = record.getKey().getId();
        activeJwk = record.getJwk();
        logger.info("Loaded persisted signing key: kid={}", activeKid);
    }

    /**
     * Serializes the current active key and JWK to {@code signingKeyPath} atomically.
     * Writes to a {@code .tmp} sibling then renames to prevent partial reads on crash.
     * File permissions are set to {@code rw-------} (owner-read-only).
     * Errors are logged but do not interrupt signing operations.
     */
    private void persistActiveKey() {
        if (signingKeyPath == null) {
            return;
        }
        try {
            Kernel.SigningKeyRecord record = Kernel.SigningKeyRecord.newBuilder()
                    .setKey(activeSigningKey.getProto())
                    .setJwk(activeJwk)
                    .build();
            String json = JsonFormat.printer().print(record);
            Path tmp = signingKeyPath.resolveSibling(signingKeyPath.getFileName() + ".tmp");
            Files.createDirectories(signingKeyPath.getParent());
            Files.writeString(tmp, json, StandardCharsets.UTF_8);
            Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
            Files.move(tmp, signingKeyPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            logger.info("Persisted signing key: kid={}, path={}", activeKid, signingKeyPath);
        } catch (Exception e) {
            logger.error("Failed to persist signing key (continuing in-memory): {}", e.getMessage());
        }
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

        persistActiveKey();
    }
}
