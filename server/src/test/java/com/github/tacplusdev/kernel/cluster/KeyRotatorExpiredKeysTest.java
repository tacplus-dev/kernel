// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Dev incident 2026-10-19: kernel-2 refused to boot because its disk snapshot
 * held a JWK whose {@code exp} had passed ~8 h earlier, and the generated
 * loader then rejected {@code exp <= now}. It now loads such a snapshot and
 * leaves retiring the key to its owner. An expired key must leave both the
 * shared {@code verifying_keys} set and the disk snapshot within one
 * {@link KeyRotator#SWEEP_INTERVAL_SECONDS}.
 */
class KeyRotatorExpiredKeysTest {

	private static final long ROTATION_SECONDS = 604800;         // weekly
	private static final long RETENTION = KeyRotator.retentionSecondsFor(
			ROTATION_SECONDS, 2592000, 7776000);

	private static final long STEP = KeyRotator.EXTEND_STEP_SECONDS;

	/** A clock the test moves by hand. */
	private static final class FakeClock extends Clock {
		Instant now;

		FakeClock(long epoch) {
			now = Instant.ofEpochSecond(epoch);
		}

		void set(long epoch) {
			now = Instant.ofEpochSecond(epoch);
		}

		long epoch() {
			return now.getEpochSecond();
		}

		@Override
		public ZoneId getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return now;
		}
	}

	private final FakeClock clock = new FakeClock(1_800_000_000L);

	/** The shared verifying_keys boundary, with no TTL: the worst case, a missed one. */
	private final Map<String, JwkOuterClass.Jwk> shared = new LinkedHashMap<>();

	private int snapshots;

	private KeyRotator replica(Runnable onKeysChanged) {
		return new KeyRotator(
				ROTATION_SECONDS,
				RETENTION,
				jwk -> shared.put(jwk.getKid(), jwk),
				shared::remove,
				() -> new ArrayList<>(shared.values()),
				onKeysChanged,
				clock);
	}

	private KeyRotator replica() {
		return replica(() -> snapshots++);
	}

	private static JwkOuterClass.Jwk foreignKey(String kid, long created, long exp) {
		return JwkOuterClass.Jwk.newBuilder()
				.setKid(kid)
				.setAlg("EdDSA")
				.setCreated(created)
				.setExp(exp)
				.build();
	}

	/**
	 * The bound: an expired key is gone at most one sweep period after its
	 * exp. A minute against the one-hour step keeps the window in which a
	 * restart can still read an expired key off disk to 1/60 of each step.
	 */
	@Test
	void sweepPeriodIsAMinute() {
		assertTrue(KeyRotator.SWEEP_INTERVAL_SECONDS <= 60,
				"sweep every " + KeyRotator.SWEEP_INTERVAL_SECONDS + "s");
	}

	/** Another replica's key, once past its exp, is gone at the next sweep — not at the next rotation. */
	@Test
	void expiredKeyLeavesTheVerifyingSetAtTheNextSweep() throws Exception {
		KeyRotator r = replica();
		r.start();
		long exp = clock.epoch() + STEP;
		shared.put("abandoned", foreignKey("abandoned", clock.epoch(), exp));

		clock.set(exp - 1);
		r.sweepExpired();
		assertTrue(shared.containsKey("abandoned"), "still within its exp");

		clock.set(exp);
		r.sweepExpired();
		assertFalse(shared.containsKey("abandoned"), "exp <= now is expired, as the loader sees it");
	}

	/**
	 * An active key nothing signed with (the incident's key: its exp was
	 * created + 3600, never step-aligned by a reserve) used to sit in
	 * signing_keys past its exp until the next rotation, days away. Its exp
	 * covers every token it signed, so it is retired and replaced.
	 */
	@Test
	void idleActiveKeyIsReplacedWhenItsExpPasses() throws Exception {
		KeyRotator r = replica();
		r.start();
		String oldKid = r.getActiveKeyId(KeyRotator.SigAlg.ES256);
		long exp = r.getActiveJwk(KeyRotator.SigAlg.ES256).getExp();

		clock.set(exp);
		r.sweepExpired();

		String newKid = r.getActiveKeyId(KeyRotator.SigAlg.ES256);
		assertNotEquals(oldKid, newKid);
		assertFalse(shared.containsKey(oldKid), "the retired key leaves the verifying set");
		assertEquals(clock.epoch() + STEP, r.getActiveJwk(KeyRotator.SigAlg.ES256).getExp());
		for (Kernel.SigningKeyRecord rec : r.getSigningKeyRecords()) {
			assertTrue(rec.getJwk().getExp() > clock.epoch(), "signing key " + rec.getJwk().getKid() + " expired");
		}
	}

	/** A key reserve() has extended is still in use: it stays active and published. */
	@Test
	void reservedActiveKeyIsNeverRemoved() throws Exception {
		KeyRotator r = replica();
		r.start();
		String kid = r.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		long firstExp = r.getActiveJwk(KeyRotator.SigAlg.ED25519).getExp();
		assertNotNull(r.reserve(KeyRotator.SigAlg.ED25519, clock.epoch() + 2 * STEP));

		clock.set(firstExp + 1);
		r.sweepExpired();

		assertEquals(kid, r.getActiveKeyId(KeyRotator.SigAlg.ED25519));
		assertTrue(shared.containsKey(kid));
	}

	/** A sweep that finds nothing expired does not rewrite the snapshot. */
	@Test
	void quietSweepWritesNoSnapshot() throws Exception {
		KeyRotator r = replica();
		r.start();
		int before = snapshots;

		clock.set(clock.epoch() + STEP / 2);
		r.sweepExpired();

		assertEquals(before, snapshots);
	}

	/**
	 * The state store's TTL drops a key on its own, but the snapshot taken
	 * before still holds it. The sweep that follows its exp rewrites the
	 * snapshot even though it has nothing left to remove.
	 */
	@Test
	void keyDroppedByTheStateStoreTtlStillTriggersASnapshot() throws Exception {
		KeyRotator r = replica();
		r.start();
		long exp = clock.epoch() + STEP / 2;
		shared.put("foreign", foreignKey("foreign", clock.epoch(), exp));
		r.sweepExpired();                 // the sweep sees it
		int before = snapshots;

		shared.remove("foreign");         // TTL eviction at exp
		clock.set(exp);
		r.sweepExpired();

		assertEquals(before + 1, snapshots);
	}

	/**
	 * End to end through the generated disk store, against the wall clock: the
	 * snapshot written before a key expired still holds it once its exp has
	 * passed (the generated loader skips time-relative checks at rest), and the
	 * one written by the sweep after it holds no JWK with exp <= now.
	 */
	@Test
	void snapshotAfterTheSweepHoldsNoExpiredKey(@TempDir Path dir) throws Exception {
		long realNow = Instant.now().getEpochSecond();
		clock.set(realNow - 2 * STEP);
		IdentitySnapshot[] snapshot = new IdentitySnapshot[1];
		KeyRotator r = replica(() -> snapshot[0].save());
		snapshot[0] = new IdentitySnapshot(
				dir.toString(), r, () -> new ArrayList<>(shared.values()), null, null, null, null, null);
		r.start();                        // writes keys that expire at realNow - STEP

		Kernel.KernelDiskState stale = snapshot[0].load();
		assertEquals(2, stale.getSigningKeysCount());
		for (Kernel.SigningKeyRecord rec : stale.getSigningKeysList()) {
			assertTrue(rec.getJwk().getExp() <= realNow, "snapshot before the sweep holds " + rec.getJwk().getKid());
		}

		clock.set(realNow);
		r.sweepExpired();

		Kernel.KernelDiskState loaded = snapshot[0].load();
		List<JwkOuterClass.Jwk> written = new ArrayList<>(loaded.getVerifyingKeysList());
		loaded.getSigningKeysList().forEach(rec -> written.add(rec.getJwk()));
		assertEquals(2, loaded.getSigningKeysCount());
		assertEquals(2, loaded.getVerifyingKeysCount());
		for (JwkOuterClass.Jwk jwk : written) {
			assertTrue(jwk.getExp() > clock.epoch(), "snapshot holds " + jwk.getKid() + " exp=" + jwk.getExp());
		}
	}
}
