// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression for the incident where kernel's shared {@code verifying_keys} set
 * grew without bound until the disk snapshot no longer validated on load, at
 * which point every boot became a cold start that published two MORE keys.
 *
 * <p>The set is cluster-wide (a convergent Hazelcast map), while each kernel
 * replica runs its own {@link KeyRotator} and publishes into it. These tests
 * model that: one shared map, several independent rotators.
 */
class VerifyingKeysGrowthTest {

	// Synthetic fixture values, not the shipped defaults: these tests exercise
	// the sweep's two rules (age, then count) and the exp stamping, none of
	// which depend on the production cadence. The shipped weekly default and
	// the fleet arithmetic it has to satisfy are covered by
	// KeyRetentionWindowTest.
	private static final long ROTATION_SECONDS = 86400;
	private static final long RETENTION_SECONDS = 2592000;

	/** The shared verifying_keys boundary: one map, every replica writing to it. */
	private final Map<String, JwkOuterClass.Jwk> shared = new LinkedHashMap<>();

	/** Starts one replica and lets the process "die", abandoning its keys. */
	private void bootAndDie() {
		KeyRotator rotator = replica();
		rotator.start();
		rotator.stop();
	}

	private KeyRotator replica() {
		return new KeyRotator(
				ROTATION_SECONDS,
				RETENTION_SECONDS,
				jwk -> shared.put(jwk.getKid(), jwk),
				shared::remove,
				() -> new ArrayList<>(shared.values()),
				() -> {});
	}

	@Test
	void everyPublishedKeyCarriesAnExpiry() {
		replica().start();

		assertEquals(2, shared.size(), "one active key per algorithm");
		for (JwkOuterClass.Jwk jwk : shared.values()) {
			assertTrue(jwk.getCreated() > 0, "created must be stamped: " + jwk.getKid());
			assertEquals(jwk.getCreated() + RETENTION_SECONDS, jwk.getExp(),
					"exp is what lets the state store evict the key on its own");
		}
	}

	/**
	 * The incident itself. Three replicas cold-starting over and over — each
	 * start abandons the previous pair into the shared set — must not grow the
	 * set past what kernel can persist. Before the fix this grew by two per
	 * start forever; the live cluster reached 47 against a cap of 32.
	 */
	@Test
	void repeatedColdStartsLeaveASnapshotThatStillValidates() {
		for (int boot = 0; boot < 200; boot++) {
			bootAndDie();
		}

		assertTrue(shared.size() <= KeyRotator.MAX_VERIFYING_KEYS,
				"verifying_keys must stay within the bound, got " + shared.size());

		Kernel.KernelDiskState snapshot = Kernel.KernelDiskState.newBuilder()
				.addAllVerifyingKeys(shared.values())
				.build();
		assertDoesNotThrow(() -> Helpers.validateKernelDiskState(snapshot),
				"kernel must never persist a snapshot it will then refuse to load");
	}

	/** A key past the retention horizon is swept on start, not only on rotation. */
	@Test
	void keysPastRetentionAreSweptOnStart() {
		long stale = Instant.now().getEpochSecond() - RETENTION_SECONDS - 1;
		shared.put("stale", JwkOuterClass.Jwk.newBuilder()
				.setKid("stale")
				.setAlg("EdDSA")
				.setCreated(stale)
				.build());

		replica().start();

		assertFalse(shared.containsKey("stale"),
				"a key older than the retention period must be evicted");
		assertEquals(2, shared.size());
	}

	/** A key still inside the retention window survives a start. */
	@Test
	void keysInsideRetentionSurviveAStart() {
		long recent = Instant.now().getEpochSecond() - 60;
		shared.put("recent", JwkOuterClass.Jwk.newBuilder()
				.setKid("recent")
				.setAlg("EdDSA")
				.setCreated(recent)
				.build());

		replica().start();

		assertTrue(shared.containsKey("recent"),
				"tokens signed by a recently-rotated key must still verify");
	}

	/** Over-bound eviction takes the oldest keys, whose tokens expire soonest. */
	@Test
	void overBoundEvictionTakesTheOldestFirst() {
		long now = Instant.now().getEpochSecond();
		List<String> kids = new ArrayList<>();
		for (int i = 0; i < KeyRotator.MAX_VERIFYING_KEYS; i++) {
			String kid = "k" + i;
			kids.add(kid);
			shared.put(kid, JwkOuterClass.Jwk.newBuilder()
					.setKid(kid)
					.setAlg("EdDSA")
					// k0 oldest, ascending from there, all inside retention.
					.setCreated(now - KeyRotator.MAX_VERIFYING_KEYS + i)
					.build());
		}

		// Starting adds two active keys, so two of the existing keys must go.
		replica().start();

		assertEquals(KeyRotator.MAX_VERIFYING_KEYS, shared.size());
		assertFalse(shared.containsKey(kids.get(0)), "oldest key should have been evicted");
		assertFalse(shared.containsKey(kids.get(1)), "second-oldest key should have been evicted");
		assertTrue(shared.containsKey(kids.get(2)), "third-oldest key should have survived");
	}
}
