// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
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
 * <p>On start the rotator restores any keys handed to it from the kernel
 * identity snapshot ({@link #restore}); for any algorithm without a restored
 * key it generates a fresh pair. Both active public JWKs are (re)published into
 * the {@code verifying_keys} boundary so every node can verify tokens this node
 * signs.
 *
 * <p>Periodically both keys rotate. After any key change the rotator invokes
 * {@code onKeysChanged} so the kernel writes a fresh identity snapshot — the
 * snapshot is the whole of it, NOT a per-key file.
 *
 * <p><b>A key is kept exactly until the last token it signed expires, plus
 * clock skew</b> (decisions/d-keyrotator-retirement). Its published JWK
 * {@code exp} tracks its USE, not its birth: a new key is published with
 * {@code exp = created + EXTEND_STEP_SECONDS}, and every signer obtains the
 * key through {@link #reserve}, which first publishes a later {@code exp} if
 * the token would outlive the current one. {@code verifying_keys} is an
 * {@code epoch_expiration} boundary, so the state store evicts each entry at
 * its {@code exp} — including a key abandoned by a node that restarted, which
 * nothing reserves again and which therefore leaves one step after its last
 * use. Only a locally active key is ever reserved, so a superseded key is
 * never extended either.
 *
 * <p>{@link #sweepVerifyingKeys} is the backstop for what the TTL does not
 * cover: a missed TTL, keys published before {@code exp} was set (kept until
 * {@code created + keyRetentionSeconds}, the rule they were published under),
 * and a set that has outgrown what kernel can snapshot or publish. It runs on
 * start, on rotation, and every {@link #SWEEP_INTERVAL_SECONDS} via
 * {@link #sweepExpired}, which also retires an active key nothing has
 * reserved past its {@code exp} and rewrites the snapshot once any key it
 * held has expired. The generated snapshot loader rejects a JWK with
 * {@code exp <= now}, so no expired key may sit on disk longer than that.
 */
public class KeyRotator {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotator.class);

    /**
     * Hard bound on the shared {@code verifying_keys} set.
     *
     * <p>Kernel keeps ONE active signing key per algorithm PER REPLICA (the
     * private keys live in each node's own disk snapshot and are never
     * shared), and a public key stays published until the last token it
     * signed expires. The worst case is an EdDSA key that signed an offline
     * token (90 days) every rotation; ES256 keys sign only ≤ 600 s WIF
     * assertions and leave about a step after their last use. With the
     * shipped defaults (rotation 604800s — weekly) the steady-state bound is
     *
     *   replicas × (ceil(offline / rotation) + 1) + replicas × 2
     *   = 3 × 14 + 3 × 2 = 48 keys
     *
     * against a set published as a {@code jwk.Jwks}, whose {@code keys} field
     * is capped at 128 by {@code sys/jwk.proto} — a shared, do-not-modify
     * proto. 128 is therefore the ceiling kernel actually has, and the two
     * kernel-owned caps ({@code Identity.verifying_keys} and
     * {@code KernelDiskState.verifying_keys}) are set to match it.
     *
     * <p>48 ≤ 128, so at the shipped defaults the TTL rule is the one that
     * binds and no key is evicted while tokens it signed are still live. This
     * is why rotation is weekly and not daily: daily rotation lets offline
     * tokens pin 3 × (90 + 1) = 273 EdDSA keys.
     *
     * <p>The count rule remains as a backstop for configurations that do not
     * fit — a larger replica count, or a longer
     * {@code offline_token_lifetime_seconds} (retention tracks the LONGER of
     * the two mint ceilings, see {@link #retentionSecondsFor}). When it binds
     * the OLDEST keys go first: they are the ones whose tokens are closest to
     * expiry, and the sweep logs a warning naming this each time it does.
     * Keeping it from binding is a config change, not a code one: hold
     * replicas × 2 × (retention/rotation + 1) ≤ 128.
     */
    static final int MAX_VERIFYING_KEYS = 128;

    /**
     * The retention window a key must get for every token signed with it to
     * stay verifiable until it expires.
     *
     * <p>A key is not retired the moment a newer one appears: it stays THE
     * active signing key for a full rotation interval, so the last token it
     * signs is minted just before the next tick and then lives its own full
     * lifetime on top of that. Retention has to cover both — rotation interval
     * PLUS the longest lifetime kernel will mint with the key.
     *
     * <p>That longest lifetime is the OFFLINE-token ceiling, not the ordinary
     * max-token one: {@code IdentityServiceImpl} mints offline-access tokens
     * against {@code offline_token_lifetime_seconds} (90 days by default)
     * while {@code max_token_lifetime_seconds} is 30. Retaining for the
     * max-token ceiling alone left offline tokens hitting "unknown kid" two
     * months before their own expiry, and any max-lifetime token minted just
     * before a rotation outliving its key by up to a rotation interval.
     */
    static long retentionSecondsFor(
            long rotationIntervalSeconds,
            long maxTokenLifetimeSeconds,
            long offlineTokenLifetimeSeconds) {
        return rotationIntervalSeconds
                + Math.max(maxTokenLifetimeSeconds, offlineTokenLifetimeSeconds);
    }

    /**
     * How far a key's published {@code exp} runs ahead of its use. A new key is
     * published with {@code exp = created + EXTEND_STEP_SECONDS}, and
     * {@link #reserve} rounds every extension up to a whole step, so a key under
     * steady load costs at most about one {@code verifying_keys} write per step.
     */
    static final long EXTEND_STEP_SECONDS = 3600;

    /** Clock-skew allowance past a token's {@code exp}, matching {@code TokenWrapper.verify}. */
    static final long CLOCK_SKEW_SECONDS = 60;

    /**
     * How often {@link #sweepExpired} runs, and so the longest an expired key
     * stays in {@code verifying_keys} or the disk snapshot. A restart inside
     * that window still reads the expired key off disk, so it is kept to a
     * minute: 1/60 of each {@link #EXTEND_STEP_SECONDS}. A sweep with nothing
     * expired reads the verifying set and writes nothing.
     */
    static final long SWEEP_INTERVAL_SECONDS = 60;

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
    private final Clock clock;
    private final ScheduledExecutorService scheduler;

    private final EnumMap<SigAlg, ActiveKey> active = new EnumMap<>(SigAlg.class);

    /** The earliest {@link #retiresAt} among the keys the last sweep left in place. */
    private long nextRetirement = Long.MAX_VALUE;

    /**
     * @param rotationIntervalSeconds interval between key rotations
     * @param keyRetentionSeconds     how long a key published without an {@code exp} is kept after creation (must be ≥ rotation + max token lifetime)
     * @param keyPublisher            writes a JWK to the verifying_keys boundary
     * @param keyRemover              removes a JWK by kid from verifying_keys
     * @param keyReader               reads current verifying_keys
     * @param onKeysChanged           invoked after any key change so the kernel writes a new identity snapshot
     */
    public KeyRotator(
            long rotationIntervalSeconds,
            long keyRetentionSeconds,
            Consumer<JwkOuterClass.Jwk> keyPublisher,
            Consumer<String> keyRemover,
            Supplier<List<JwkOuterClass.Jwk>> keyReader,
            Runnable onKeysChanged) {
        this(rotationIntervalSeconds, keyRetentionSeconds, keyPublisher, keyRemover, keyReader,
                onKeysChanged, Clock.systemUTC());
    }

    KeyRotator(
            long rotationIntervalSeconds,
            long keyRetentionSeconds,
            Consumer<JwkOuterClass.Jwk> keyPublisher,
            Consumer<String> keyRemover,
            Supplier<List<JwkOuterClass.Jwk>> keyReader,
            Runnable onKeysChanged,
            Clock clock) {
        this.clock = clock;
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
     * Restores signing keys from the kernel identity snapshot. Each record
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
                logger.warn("Ignoring snapshotted signing key with unknown alg={}", record.getJwk().getAlg());
                continue;
            }
            ActiveKey k = active.get(alg);
            k.signingKey = ImmutableKey.from(record.getKey());
            k.kid = record.getKey().getId();
            k.jwk = record.getJwk();
            logger.info("Restored signing key from identity snapshot: alg={}, kid={}", alg.alg, k.kid);
        }
    }

    /**
     * Starts the rotator. Generates a fresh key for any algorithm without a
     * restored key or whose restored key has expired, ensures both active
     * JWKs are published, then schedules periodic rotation.
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
            changed |= ensureJwksPublished();
            // Sweep on start, not only on rotation: rotation is a day away by
            // default, and a node that just cold-started has abandoned its
            // previous keys into the shared set. Keys published before exp was
            // set carry no TTL and would otherwise sit there until a rotation
            // happened to run.
            if (sweepVerifyingKeys() || changed) {
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
        scheduler.scheduleAtFixedRate(
                () -> {
                    try {
                        sweepExpired();
                    } catch (Exception e) {
                        logger.error("Expired signing key sweep failed", e);
                    }
                },
                SWEEP_INTERVAL_SECONDS,
                SWEEP_INTERVAL_SECONDS,
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
     * can validate tokens this node has issued. An active key past its
     * {@code exp} (between two sweeps) is retired by {@link #sweepExpired}
     * first rather than republished.
     */
    public synchronized void republishCurrentKeys() {
        try {
            sweepExpired();
        } catch (Exception e) {
            logger.error("Expired signing key sweep failed", e);
        }
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

    /**
     * Active private signing key for the given algorithm. Does NOT extend the
     * key's published lifetime — anything that signs a token uses
     * {@link #reserve} instead.
     */
    public ImmutableKey getActiveSigningKey(SigAlg alg) {
        return active.get(alg).signingKey;
    }

    /**
     * Returns the active signing key for {@code alg} with its published
     * {@code exp} covering a token that expires at {@code tokenExp}.
     *
     * <p>If {@code tokenExp + CLOCK_SKEW_SECONDS} is past the key's published
     * {@code exp}, the same JWK is first republished with that time rounded up
     * to a whole {@link #EXTEND_STEP_SECONDS}, synchronously, and the snapshot
     * is rewritten so a restart does not republish the shorter one. Only then
     * is the key handed out. A failed publish throws and nothing is handed out:
     * a token is never signed by a key whose published lifetime does not cover
     * it.
     *
     * <p>An active key already past its {@code exp} is never extended: it is
     * retired through {@link #ensureJwksPublished} first, exactly as
     * {@link #start} retires an expired restored key.
     *
     * <p>Synchronized with {@link #rotate} so the key returned is the one whose
     * {@code exp} was extended, never one rotated in between.
     *
     * @return the signing key, or {@code null} if there is no active key for {@code alg}
     */
    public synchronized ImmutableKey reserve(SigAlg alg, long tokenExp) {
        ActiveKey k = active.get(alg);
        if (k.signingKey == null) {
            return null;
        }
        // A restored key reserved before start() (ClusterServer serves first)
        // is past its exp: it is retired as start() retires it, never extended.
        if (retiresAt(k.jwk) <= clock.instant().getEpochSecond()) {
            try {
                if (ensureJwksPublished()) {
                    onKeysChanged.run();
                }
            } catch (Exception e) {
                throw new IllegalStateException("failed to retire expired signing key", e);
            }
        }
        long needed = tokenExp + CLOCK_SKEW_SECONDS;
        if (needed > retiresAt(k.jwk)) {
            long exp = Math.ceilDiv(needed, EXTEND_STEP_SECONDS) * EXTEND_STEP_SECONDS;
            JwkOuterClass.Jwk extended = k.jwk.toBuilder().setExp(exp).build();
            keyPublisher.accept(extended);
            k.jwk = extended;
            onKeysChanged.run();
        }
        return k.signingKey;
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
     *
     * <p>A restored key that IS still published may carry a later {@code exp}
     * there than in the snapshot ({@link #reserve} extended it after the
     * snapshot was taken). That later {@code exp} is adopted, never overwritten:
     * republishing the snapshot's would cut off tokens the key has signed since.
     *
     * <p>A restored key whose {@code exp}, after that, has passed is retired as
     * {@link #sweepExpired} retires one, never republished: no live token used
     * it, and the boundary rejects {@code exp <= now}.
     *
     * @return whether a restored key was replaced
     */
    private boolean ensureJwksPublished() throws Exception {
        long now = clock.instant().getEpochSecond();
        boolean replaced = false;
        List<JwkOuterClass.Jwk> current = keyReader.get();
        for (SigAlg a : SigAlg.values()) {
            ActiveKey k = active.get(a);
            JwkOuterClass.Jwk jwk = k.jwk;
            if (jwk == null) {
                continue;
            }
            String kid = jwk.getKid();
            JwkOuterClass.Jwk published = current.stream()
                    .filter(p -> kid.equals(p.getKid())).findFirst().orElse(null);
            if (published != null && published.getExp() > jwk.getExp()) {
                k.jwk = jwk.toBuilder().setExp(published.getExp()).build();
            }
            if (retiresAt(k.jwk) <= now) {
                logger.info("Retiring expired restored signing key: alg={}, kid={}, exp={}",
                        a.alg, kid, k.jwk.getExp());
                generateKey(a);
                replaced = true;
            } else if (published == null) {
                keyPublisher.accept(jwk);
                logger.info("Re-injected signing JWK into verifying_keys on boot: alg={}, kid={}", a.alg, kid);
            }
        }
        return replaced;
    }

    synchronized void rotate() throws Exception {
        logger.info("Rotating signing keys (EdDSA kid={}, ES256 kid={})",
                active.get(SigAlg.ED25519).kid, active.get(SigAlg.ES256).kid);

        for (SigAlg a : SigAlg.values()) {
            generateKey(a);
        }

        sweepVerifyingKeys();

        onKeysChanged.run();
    }

    /**
     * Retires every key whose {@code exp} has passed, from the verifying set
     * and from the disk snapshot.
     *
     * <p>An active key past its {@code exp} has no live token — {@link #reserve}
     * keeps {@code exp} past every token it signs — so it is replaced by a
     * fresh one and then swept like any other. A reserved key's {@code exp} is
     * still ahead, so it stays.
     *
     * <p>The snapshot is rewritten when this sweep removed or replaced a key, or
     * when a key the previous sweep saw has reached its {@code exp}: the state
     * store's TTL drops such a key on its own, but the snapshot written before
     * still holds it until something writes a new one.
     */
    synchronized void sweepExpired() throws Exception {
        long now = clock.instant().getEpochSecond();
        boolean changed = nextRetirement <= now;
        for (SigAlg a : SigAlg.values()) {
            JwkOuterClass.Jwk jwk = active.get(a).jwk;
            if (retiresAt(jwk) <= now) {
                logger.info("Retiring expired active signing key: alg={}, kid={}, exp={}",
                        a.alg, jwk.getKid(), jwk.getExp());
                generateKey(a);
                changed = true;
            }
        }
        changed |= sweepVerifyingKeys();
        if (changed) {
            try {
                onKeysChanged.run();
            } catch (RuntimeException e) {
                // The snapshot on disk still holds the expired key: retry next sweep.
                nextRetirement = now;
                throw e;
            }
        }
    }

    /**
     * Evicts keys the cluster no longer needs from the shared verifying set.
     *
     * <p>Two rules, in order. First by AGE: a key past its {@code exp} can no
     * longer be carrying a live token, because {@link #reserve} published an
     * {@code exp} past every token it signed — this is the backstop for a missed
     * TTL. A key with no {@code exp} (published before {@code exp} existed)
     * keeps the rule it was published under: gone {@code keyRetentionSeconds}
     * after creation. Then by COUNT: if the set is still over {@link #MAX_VERIFYING_KEYS}
     * — more than kernel can snapshot or publish — the oldest survivors go until
     * it fits, since those are the keys whose tokens expire soonest.
     *
     * <p>This node's own active keys are never evicted, by either rule: it is
     * still signing with them. Another node's active key is not distinguishable
     * from here, but cannot be reached by the age rule either — that node
     * reserves it ahead of every token it signs.
     *
     * @return whether any key was removed
     */
    private boolean sweepVerifyingKeys() {
        long now = clock.instant().getEpochSecond();
        long earliest = Long.MAX_VALUE;

        // Candidates for eviction, newest last. This node's own active keys are
        // excluded outright and are not candidates under either rule.
        List<JwkOuterClass.Jwk> candidates = new ArrayList<>();
        int live = 0;
        boolean removed = false;
        for (JwkOuterClass.Jwk jwk : keyReader.get()) {
            boolean dated = jwk.getExp() > 0 || jwk.getCreated() > 0;
            if (isLocallyActive(jwk.getKid())) {
                live++;
                if (dated) {
                    earliest = Math.min(earliest, retiresAt(jwk));
                }
                continue;
            }
            if (dated && retiresAt(jwk) <= now) {
                logger.info("Removing expired signing key: kid={}, created={}, exp={}",
                        jwk.getKid(), jwk.getCreated(), jwk.getExp());
                keyRemover.accept(jwk.getKid());
                removed = true;
                continue;
            }
            if (dated) {
                earliest = Math.min(earliest, retiresAt(jwk));
            }
            candidates.add(jwk);
            live++;
        }
        nextRetirement = earliest;

        int excess = Math.min(live - MAX_VERIFYING_KEYS, candidates.size());
        if (excess <= 0) {
            return removed;
        }
        // Oldest first; a key with no created stamp sorts oldest of all.
        candidates.sort(java.util.Comparator.comparingLong(
                jwk -> jwk.getCreated() > 0 ? jwk.getCreated() : Long.MIN_VALUE));
        logger.warn("verifying_keys holds {} keys, over the bound of {}; evicting the {} oldest "
                        + "un-expired keys. Tokens signed by them stop verifying early — see "
                        + "KeyRotator.MAX_VERIFYING_KEYS for the rotation/retention arithmetic.",
                live, MAX_VERIFYING_KEYS, excess);
        for (int i = 0; i < excess; i++) {
            JwkOuterClass.Jwk jwk = candidates.get(i);
            logger.warn("Evicting over-bound signing key: kid={}, created={}", jwk.getKid(), jwk.getCreated());
            keyRemover.accept(jwk.getKid());
        }
        return true;
    }

    /**
     * When a published key stops being needed: its {@code exp}, or for a key
     * published before {@code exp} existed, {@code created + keyRetentionSeconds}.
     */
    private long retiresAt(JwkOuterClass.Jwk jwk) {
        return jwk.getExp() > 0 ? jwk.getExp() : jwk.getCreated() + keyRetentionSeconds;
    }

    private boolean isLocallyActive(String kid) {
        for (SigAlg a : SigAlg.values()) {
            if (kid.equals(active.get(a).kid)) {
                return true;
            }
        }
        return false;
    }

    /** Generates a fresh key pair for the given algorithm and publishes its JWK. */
    private void generateKey(SigAlg alg) throws Exception {
        String kid = UUID.randomUUID().toString();
        long now = clock.instant().getEpochSecond();

        KeyPair keyPair;
        JwkOuterClass.Jwk.Builder jwkBuilder = JwkOuterClass.Jwk.newBuilder()
                .setKid(kid)
                .setAlg(alg.alg)
                .setKty(alg.kty)
                .setCrv(alg.crv)
                .setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG)
                .setCreated(now)
                // exp is what bounds the shared verifying set. verifying_keys is
                // an epoch_expiration boundary, so the state store evicts this
                // entry on its own at exp — no sweep, no schedule, and it still
                // happens for a key this node abandons by restarting. One step:
                // the key has signed nothing yet, and reserve() moves exp out
                // ahead of every token it does sign.
                .setExp(now + EXTEND_STEP_SECONDS);

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
