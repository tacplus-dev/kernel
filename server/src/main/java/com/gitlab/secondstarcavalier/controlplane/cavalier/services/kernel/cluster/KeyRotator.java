// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.services.kernel.Kernel;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KeyRotator manages kernel's signing key lifecycle. Kernel is the cluster
 * trust root and the sole token authority; it holds TWO active signing keys:
 *
 * <ul>
 *   <li><b>EdDSA</b> (Ed25519) — signs all internal tokens (S2S, U2S, refresh).</li>
 *   <li><b>ES256</b> (NIST P-256) — signs WIF external-token assertions only
 *       (Anthropic's {@code /v1/oauth/token} rejects EdDSA). Selected per-request
 *       by the Mint handler for {@code MintExternalToken}.</li>
 * </ul>
 *
 * <p>On start the rotator restores any persisted keys handed to it from the
 * kernel disk snapshot ({@link #restore}); for any algorithm without a restored
 * key it generates a fresh pair. Both active public JWKs are (re)published into
 * the {@code verifying_keys} boundary so every node can verify tokens this node
 * signs.
 *
 * <p>Periodically both keys rotate. Public keys older than
 * {@code keyRetentionSeconds} (≥ max token lifetime) are evicted so tokens
 * signed by a rotated key stay verifiable until they expire. After any key
 * change the rotator invokes {@code onKeysChanged} so the kernel writes a fresh
 * disk snapshot — persistence is the snapshot, NOT a per-key file.
 */
public class KeyRotator {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotator.class);

    /** Signing algorithms kernel maintains. */
    public enum SigAlg {
        ED25519("EdDSA", KeyOuterClass.KeyType.KEY_TYPE_OKP, "Ed25519"),
        ES256("ES256", KeyOuterClass.KeyType.KEY_TYPE_EC, "P-256");

        final String alg;            // JWK/JWT "alg"
        final KeyOuterClass.KeyType kty;
        final String crv;            // JWK "crv"

        SigAlg(String alg, KeyOuterClass.KeyType kty, String crv) {
            this.alg = alg;
            this.kty = kty;
            this.crv = crv;
        }
    }

    /** Per-algorithm active key material. */
    private static final class ActiveKey {
        volatile String kid;
        volatile ImmutableKey signingKey;
        volatile JwkOuterClass.Jwk jwk;
    }

    private final long rotationIntervalSeconds;
    private final long keyRetentionSeconds;
    private final Consumer<JwkOuterClass.Jwk> keyPublisher;
    private final Consumer<String> keyRemover;
    private final Supplier<List<JwkOuterClass.Jwk>> keyReader;
    private final Runnable onKeysChanged;
    private final ScheduledExecutorService scheduler;

    private final EnumMap<SigAlg, ActiveKey> active = new EnumMap<>(SigAlg.class);

    /**
     * @param rotationIntervalSeconds interval between key rotations
     * @param keyRetentionSeconds     how long to retain old keys after rotation (must be ≥ max token lifetime)
     * @param keyPublisher            writes a JWK to the verifying_keys boundary
     * @param keyRemover              removes a JWK by kid from verifying_keys
     * @param keyReader               reads current verifying_keys
     * @param onKeysChanged           invoked after any key change so the kernel persists a new disk snapshot
     */
    public KeyRotator(
            long rotationIntervalSeconds,
            long keyRetentionSeconds,
            Consumer<JwkOuterClass.Jwk> keyPublisher,
            Consumer<String> keyRemover,
            Supplier<List<JwkOuterClass.Jwk>> keyReader,
            Runnable onKeysChanged) {
        this.rotationIntervalSeconds = rotationIntervalSeconds;
        this.keyRetentionSeconds = keyRetentionSeconds;
        this.keyPublisher = keyPublisher;
        this.keyRemover = keyRemover;
        this.keyReader = keyReader;
        this.onKeysChanged = onKeysChanged != null ? onKeysChanged : () -> {};
        for (SigAlg a : SigAlg.values()) {
            active.put(a, new ActiveKey());
        }
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "key-rotator");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Restores persisted signing keys from the kernel disk snapshot. Each record
     * is matched to its algorithm by the JWK {@code alg}. Must be called (with
     * the snapshot's records, possibly empty) before {@link #start}.
     */
    public void restore(List<Kernel.SigningKeyRecord> records) {
        if (records == null) {
            return;
        }
        for (Kernel.SigningKeyRecord record : records) {
            SigAlg alg = algOf(record.getJwk().getAlg());
            if (alg == null) {
                logger.warn("Ignoring persisted signing key with unknown alg={}", record.getJwk().getAlg());
                continue;
            }
            ActiveKey k = active.get(alg);
            k.signingKey = ImmutableKey.from(record.getKey());
            k.kid = record.getKey().getId();
            k.jwk = record.getJwk();
            logger.info("Restored persisted signing key: alg={}, kid={}", alg.alg, k.kid);
        }
    }

    /**
     * Starts the rotator. Generates a fresh key for any algorithm without a
     * restored key, ensures both active JWKs are published, then schedules
     * periodic rotation.
     */
    public void start() {
        try {
            boolean changed = false;
            for (SigAlg a : SigAlg.values()) {
                if (active.get(a).signingKey == null) {
                    generateKey(a);
                    changed = true;
                }
            }
            ensureJwksPublished();
            if (changed) {
                onKeysChanged.run();
            }
        } catch (Exception e) {
            logger.error("Failed to initialize signing keys", e);
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

        logger.info("KeyRotator started: rotation every {}s, key retention {}s, EdDSA kid={}, ES256 kid={}",
                rotationIntervalSeconds, keyRetentionSeconds,
                active.get(SigAlg.ED25519).kid, active.get(SigAlg.ES256).kid);
    }

    public void stop() {
        scheduler.shutdown();
    }

    /**
     * Re-publishes both current signing JWKs to the verifying_keys boundary.
     * Called after a Hazelcast cluster topology change so newly-merged nodes
     * can validate tokens this node has issued.
     */
    public void republishCurrentKeys() {
        for (SigAlg a : SigAlg.values()) {
            JwkOuterClass.Jwk jwk = active.get(a).jwk;
            if (jwk != null) {
                keyPublisher.accept(jwk);
            }
        }
        logger.info("Republished signing keys after cluster topology change: EdDSA kid={}, ES256 kid={}",
                active.get(SigAlg.ED25519).kid, active.get(SigAlg.ES256).kid);
    }

    /** Active key id for the given algorithm (the JWT {@code kid}). */
    public String getActiveKeyId(SigAlg alg) {
        return active.get(alg).kid;
    }

    /** Active private signing key for the given algorithm. */
    public ImmutableKey getActiveSigningKey(SigAlg alg) {
        return active.get(alg).signingKey;
    }

    /** Active public JWK for the given algorithm (carries the {@code alg}). */
    public JwkOuterClass.Jwk getActiveJwk(SigAlg alg) {
        return active.get(alg).jwk;
    }

    /**
     * Snapshot of the active signing keys (one record per algorithm), for the
     * kernel disk snapshot ({@code KernelDiskState.signing_keys}).
     */
    public List<Kernel.SigningKeyRecord> getSigningKeyRecords() {
        List<Kernel.SigningKeyRecord> out = new ArrayList<>();
        for (SigAlg a : SigAlg.values()) {
            ActiveKey k = active.get(a);
            if (k.signingKey != null && k.jwk != null) {
                out.add(Kernel.SigningKeyRecord.newBuilder()
                        .setKey(k.signingKey.getProto())
                        .setJwk(k.jwk)
                        .build());
            }
        }
        return out;
    }

    private static SigAlg algOf(String jwkAlg) {
        for (SigAlg a : SigAlg.values()) {
            if (a.alg.equals(jwkAlg)) {
                return a;
            }
        }
        return null;
    }

    /**
     * Publishes any active JWK that is missing from verifying_keys. Handles the
     * case where Hazelcast state was wiped while a key survived in the snapshot.
     */
    private void ensureJwksPublished() {
        List<JwkOuterClass.Jwk> current = keyReader.get();
        for (SigAlg a : SigAlg.values()) {
            JwkOuterClass.Jwk jwk = active.get(a).jwk;
            if (jwk == null) {
                continue;
            }
            String kid = jwk.getKid();
            boolean found = current.stream().anyMatch(k -> kid.equals(k.getKid()));
            if (!found) {
                keyPublisher.accept(jwk);
                logger.info("Re-injected signing JWK into verifying_keys on boot: alg={}, kid={}", a.alg, kid);
            }
        }
    }

    private void rotate() throws Exception {
        logger.info("Rotating signing keys (EdDSA kid={}, ES256 kid={})",
                active.get(SigAlg.ED25519).kid, active.get(SigAlg.ES256).kid);

        for (SigAlg a : SigAlg.values()) {
            generateKey(a);
        }

        // Remove keys older than the retention period (≥ max token lifetime).
        // Tokens signed with a rotated key must remain verifiable until they expire.
        long cutoff = Instant.now().getEpochSecond() - keyRetentionSeconds;
        for (JwkOuterClass.Jwk jwk : keyReader.get()) {
            boolean isActive = false;
            for (SigAlg a : SigAlg.values()) {
                if (jwk.getKid().equals(active.get(a).kid)) {
                    isActive = true;
                    break;
                }
            }
            if (!isActive && jwk.getCreated() > 0 && jwk.getCreated() < cutoff) {
                logger.info("Removing expired signing key: kid={}, created={}", jwk.getKid(), jwk.getCreated());
                keyRemover.accept(jwk.getKid());
            }
        }

        onKeysChanged.run();
    }

    /** Generates a fresh key pair for the given algorithm and publishes its JWK. */
    private void generateKey(SigAlg alg) throws Exception {
        String kid = UUID.randomUUID().toString();
        long now = Instant.now().getEpochSecond();

        KeyPair keyPair;
        JwkOuterClass.Jwk.Builder jwkBuilder = JwkOuterClass.Jwk.newBuilder()
                .setKid(kid)
                .setAlg(alg.alg)
                .setKty(alg.kty)
                .setCrv(alg.crv)
                .setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG)
                .setCreated(now);

        if (alg == SigAlg.ED25519) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            keyPair = kpg.generateKeyPair();
            // Ed25519 X.509 encoding: the last 32 bytes are the raw public key.
            byte[] x509Encoded = keyPair.getPublic().getEncoded();
            byte[] rawPub = new byte[32];
            System.arraycopy(x509Encoded, x509Encoded.length - 32, rawPub, 0, 32);
            jwkBuilder.setX(b64Url(rawPub));
        } else { // ES256 (P-256)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            keyPair = kpg.generateKeyPair();
            ECPublicKey ecPub = (ECPublicKey) keyPair.getPublic();
            jwkBuilder.setX(b64Url(toFixed(ecPub.getW().getAffineX(), 32)));
            jwkBuilder.setY(b64Url(toFixed(ecPub.getW().getAffineY(), 32)));
        }

        // PEM-encoded PKCS#8 private key for ImmutableKey (works for any key type).
        byte[] pkcs8 = keyPair.getPrivate().getEncoded();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8)
                + "\n-----END PRIVATE KEY-----\n";
        String keyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pem.getBytes());

        KeyOuterClass.Key protoKey = KeyOuterClass.Key.newBuilder()
                .setId(kid)
                .setBase64(keyBase64)
                .setCreated(now)
                .build();

        JwkOuterClass.Jwk jwk = jwkBuilder.build();
        ActiveKey k = active.get(alg);
        k.signingKey = ImmutableKey.from(protoKey);
        k.kid = kid;
        k.jwk = jwk;

        keyPublisher.accept(jwk);
        logger.info("Published new signing key: alg={}, kid={}", alg.alg, kid);
    }

    /** Base64url (no padding) encode. */
    private static String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Converts a BigInteger coordinate to a fixed-length big-endian byte array,
     * stripping any sign byte and left-padding with zeros (per RFC 7518 EC JWK).
     */
    private static byte[] toFixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        if (raw.length == len) {
            return raw;
        }
        byte[] out = new byte[len];
        if (raw.length > len) {
            // Drop the leading sign byte (or extra high bytes).
            System.arraycopy(raw, raw.length - len, out, 0, len);
        } else {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        }
        return out;
    }

    // Retained for callers that iterate per-algorithm key material.
    Map<SigAlg, String> activeKids() {
        Map<SigAlg, String> kids = new EnumMap<>(SigAlg.class);
        for (SigAlg a : SigAlg.values()) {
            kids.put(a, active.get(a).kid);
        }
        return kids;
    }
}
