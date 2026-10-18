// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import org.junit.jupiter.api.Test;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * decisions/d-keyrotator-retirement: a key is kept exactly until the last token
 * it signed expires, plus clock skew. Its published JWK {@code exp} tracks its
 * USE, not its birth — so a key abandoned by a restart, or superseded by a
 * rotation, leaves the shared {@code verifying_keys} set at its own
 * {@code signed_until} instead of ~91 days after it was created.
 */
class KeyRotatorRetirementTest {

	private static final long ROTATION_SECONDS = 604800;         // weekly
	private static final long MAX_TOKEN_LIFETIME = 2592000;      // 30 days
	private static final long OFFLINE_TOKEN_LIFETIME = 7776000;  // 90 days
	private static final long RETENTION = KeyRotator.retentionSecondsFor(
			ROTATION_SECONDS, MAX_TOKEN_LIFETIME, OFFLINE_TOKEN_LIFETIME);

	private static final long STEP = KeyRotator.EXTEND_STEP_SECONDS;
	private static final long SKEW = KeyRotator.CLOCK_SKEW_SECONDS;

	/** A clock the test moves by hand. */
	private static final class FakeClock extends Clock {
		Instant now = Instant.ofEpochSecond(1_800_000_000L);

		void advance(long seconds) {
			now = now.plusSeconds(seconds);
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

	private final FakeClock clock = new FakeClock();

	/** The shared verifying_keys boundary. */
	private final Map<String, JwkOuterClass.Jwk> shared = new LinkedHashMap<>();

	/** Every publish, in order, so a test can see what was written and when. */
	private final List<JwkOuterClass.Jwk> published = new ArrayList<>();

	private boolean publisherFails;
	private int snapshots;

	private KeyRotator replica() {
		return new KeyRotator(
				ROTATION_SECONDS,
				RETENTION,
				jwk -> {
					if (publisherFails) {
						throw new RuntimeException("putVerifyingKeys failed");
					}
					published.add(jwk);
					shared.put(jwk.getKid(), jwk);
				},
				shared::remove,
				() -> new ArrayList<>(shared.values()),
				() -> snapshots++,
				clock);
	}

	private static JwkOuterClass.Jwk legacyKey(String kid, long created, long exp) {
		return JwkOuterClass.Jwk.newBuilder()
				.setKid(kid)
				.setAlg("EdDSA")
				.setCreated(created)
				.setExp(exp)
				.build();
	}

	/** (a) A new key's exp is created + STEP, not created + retention. */
	@Test
	void newKeyExpiresOneStepAfterCreation() {
		replica().start();

		assertEquals(2, shared.size(), "one active key per algorithm");
		for (JwkOuterClass.Jwk jwk : shared.values()) {
			assertEquals(clock.epoch(), jwk.getCreated());
			assertEquals(jwk.getCreated() + STEP, jwk.getExp(),
					"a key that has signed nothing must not be published for ~91 days");
		}
	}

	/** (b) reserve publishes exp ≥ tokenExp + SKEW before handing out the key. */
	@Test
	void reservePublishesTheCoveringExpBeforeReturningTheKey() {
		KeyRotator rotator = replica();
		rotator.start();
		String kid = rotator.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		int snapshotsBefore = snapshots;

		long tokenExp = clock.epoch() + 86400;
		ImmutableKey key = rotator.reserve(KeyRotator.SigAlg.ED25519, tokenExp);

		assertNotNull(key);
		JwkOuterClass.Jwk live = shared.get(kid);
		assertTrue(live.getExp() >= tokenExp + SKEW,
				"published exp " + live.getExp() + " does not cover token exp " + tokenExp + " + skew");
		assertEquals(0, live.getExp() % STEP, "extensions are rounded up to whole steps");
		assertTrue(live.getExp() < tokenExp + SKEW + STEP, "rounded up by less than one step");
		assertEquals(live, rotator.getActiveJwk(KeyRotator.SigAlg.ED25519),
				"the rotator's own copy tracks what it published");
		assertEquals(snapshotsBefore + 1, snapshots,
				"an extension is snapshotted so a full-cluster restart does not republish a stale exp");
	}

	/** (b) A token the published exp already covers costs no write. */
	@Test
	void reserveInsideThePublishedExpDoesNotWrite() {
		KeyRotator rotator = replica();
		rotator.start();
		int writes = published.size();

		ImmutableKey key = rotator.reserve(KeyRotator.SigAlg.ED25519, clock.epoch() + 900);

		assertNotNull(key);
		assertEquals(writes, published.size(), "a 15-minute token fits the first step");
	}

	/** (b) Fail closed: no published lifetime, no key. */
	@Test
	void reserveFailsWhenThePublishFails() {
		KeyRotator rotator = replica();
		rotator.start();
		String kid = rotator.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		long expBefore = shared.get(kid).getExp();

		publisherFails = true;
		assertThrows(RuntimeException.class,
				() -> rotator.reserve(KeyRotator.SigAlg.ED25519, clock.epoch() + 86400),
				"a token must never be signed by a key whose published lifetime does not cover it");

		assertEquals(expBefore, rotator.getActiveJwk(KeyRotator.SigAlg.ED25519).getExp(),
				"a failed publish must not be remembered as published");
	}

	/** (c) Only the active key is reserved: a superseded key is never extended again. */
	@Test
	void supersededKeyIsNotExtendedByLaterReserves() throws Exception {
		KeyRotator rotator = replica();
		rotator.start();
		String oldKid = rotator.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		long oldExp = shared.get(oldKid).getExp();

		rotator.rotate();
		String newKid = rotator.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		assertNotEquals(oldKid, newKid);

		ImmutableKey key = rotator.reserve(KeyRotator.SigAlg.ED25519, clock.epoch() + 86400);

		assertEquals(newKid, key.getProto().getId(), "reserve hands out the active key");
		assertEquals(oldExp, shared.get(oldKid).getExp(), "the superseded key keeps its exp");
		assertTrue(shared.get(newKid).getExp() >= clock.epoch() + 86400 + SKEW);
	}

	/** (d) A key that signed nothing is gone at created + STEP. */
	@Test
	void keyThatSignedNothingExpiresOneStepAfterCreation() {
		KeyRotator first = replica();
		first.start();
		String abandoned = first.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		first.stop();

		assertEquals(shared.get(abandoned).getCreated() + STEP, shared.get(abandoned).getExp());

		// Still inside its step: a second replica's start must keep it.
		clock.advance(STEP - 1);
		replica().start();
		assertTrue(shared.containsKey(abandoned));

		// Past it: swept, without waiting ~91 days.
		clock.advance(2);
		replica().start();
		assertFalse(shared.containsKey(abandoned),
				"a key abandoned by a restart must leave within one step");
	}

	/** (e) The sweep evicts exp < now, and keeps exp == 0 keys until created + retention. */
	@Test
	void sweepEvictsPastExpAndKeepsLegacyKeysUntilRetention() {
		long now = clock.epoch();
		shared.put("expired", legacyKey("expired", now - 7200, now - 1));
		shared.put("live", legacyKey("live", now - 7200, now + 1));
		shared.put("legacy-inside", legacyKey("legacy-inside", now - RETENTION + 1, 0));
		shared.put("legacy-past", legacyKey("legacy-past", now - RETENTION - 1, 0));

		replica().start();

		assertFalse(shared.containsKey("expired"), "exp in the past is evicted");
		assertTrue(shared.containsKey("live"), "exp in the future is kept");
		assertTrue(shared.containsKey("legacy-inside"), "exp == 0 keeps the created + retention rule");
		assertFalse(shared.containsKey("legacy-past"), "exp == 0 past created + retention is evicted");
	}

	/**
	 * (f) The bound at weekly rotation, 3 replicas and 90-day offline tokens.
	 * Under the new rule an EdDSA key stays only while an offline token it signed
	 * can be live: every key whose signing window overlaps the last offline
	 * lifetime. An ES256 key (WIF assertions, ≤ 600 s) stays about a step past its
	 * last use, so each replica holds its active key and at most one superseded one.
	 */
	@Test
	void steadyStateBoundAtWeeklyRotationFitsUnderTheCap() {
		int replicas = 3;
		long edGenerations = (OFFLINE_TOKEN_LIFETIME + SKEW + STEP + ROTATION_SECONDS - 1) / ROTATION_SECONDS + 1;
		long es256PerReplica = 2;
		long bound = replicas * edGenerations + replicas * es256PerReplica;

		assertEquals(14, edGenerations, "ceil(90 d / 7 d) + the active one");
		assertEquals(48, bound, "3 x 14 EdDSA + 3 x 2 ES256");
		assertTrue(bound <= KeyRotator.MAX_VERIFYING_KEYS,
				bound + " keys against a cap of " + KeyRotator.MAX_VERIFYING_KEYS);
	}

	/**
	 * A restart that restores its key must not shrink what is already published:
	 * the snapshot can predate an extension, and republishing its stale exp would
	 * cut off tokens the key signed after it was taken.
	 */
	@Test
	void restoredKeyAdoptsTheLongerPublishedExp() {
		KeyRotator first = replica();
		first.start();
		var records = first.getSigningKeyRecords(); // taken before the extension
		first.reserve(KeyRotator.SigAlg.ED25519, clock.epoch() + 30L * 86400);
		String kid = first.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		long extended = shared.get(kid).getExp();
		first.stop();

		KeyRotator second = replica();
		second.restore(records);
		second.start();
		second.reserve(KeyRotator.SigAlg.ED25519, clock.epoch() + 900);

		assertEquals(extended, shared.get(kid).getExp(),
				"a restored key must not republish an exp shorter than the live one");
		assertEquals(extended, second.getActiveJwk(KeyRotator.SigAlg.ED25519).getExp());
	}
}
