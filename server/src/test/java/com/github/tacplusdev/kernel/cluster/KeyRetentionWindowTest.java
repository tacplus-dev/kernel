// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression for the audit finding that kernel's verifying-key retention window
 * was shorter than the longest token it will mint, so already-issued, still-valid
 * tokens became "unknown kid" before their own expiry.
 *
 * <p>Two things were wrong with retaining for {@code max_token_lifetime_seconds}:
 *
 * <ul>
 *   <li>A key does not stop signing when it is created — it stays the active
 *       signing key for a whole rotation interval, so the last token it signs
 *       is minted just before the next tick and runs its full lifetime from
 *       there. Retention has to cover rotation interval PLUS a token lifetime.</li>
 *   <li>The longest lifetime kernel mints is the OFFLINE ceiling
 *       ({@code offline_token_lifetime_seconds}, 90 days by default), not
 *       {@code max_token_lifetime_seconds} (30 days). Offline tokens were
 *       outliving their signing key by two months.</li>
 * </ul>
 */
class KeyRetentionWindowTest {

	/** The shipped defaults, matching ClusterServer's fallbacks. */
	private static final long ROTATION_SECONDS = 604800;         // 7 days
	private static final long MAX_TOKEN_LIFETIME = 2592000;      // 30 days
	private static final long OFFLINE_TOKEN_LIFETIME = 7776000;  // 90 days

	/** The fleet the defaults are sized for. */
	private static final int REPLICAS = 3;
	private static final int ALGORITHMS = KeyRotator.SigAlg.values().length;

	private static final long RETENTION = KeyRotator.retentionSecondsFor(
			ROTATION_SECONDS, MAX_TOKEN_LIFETIME, OFFLINE_TOKEN_LIFETIME);

	private final Map<String, JwkOuterClass.Jwk> shared = new LinkedHashMap<>();

	private KeyRotator replica() {
		return new KeyRotator(
				ROTATION_SECONDS,
				RETENTION,
				jwk -> shared.put(jwk.getKid(), jwk),
				shared::remove,
				() -> new ArrayList<>(shared.values()),
				() -> {});
	}

	/**
	 * The arithmetic itself. Retention must cover the whole window during which
	 * a token signed by the key can still be live.
	 */
	@Test
	void retentionCoversRotationIntervalPlusTheLongestMintCeiling() {
		assertEquals(ROTATION_SECONDS + OFFLINE_TOKEN_LIFETIME, RETENTION,
				"retention must cover a full signing interval plus the longest token lifetime");

		assertTrue(RETENTION >= ROTATION_SECONDS + MAX_TOKEN_LIFETIME,
				"a max-lifetime token minted just before rotation must stay verifiable");
		assertTrue(RETENTION >= ROTATION_SECONDS + OFFLINE_TOKEN_LIFETIME,
				"an offline token minted just before rotation must stay verifiable");
	}

	/**
	 * Why rotation is weekly and not daily. Every replica publishes one key per
	 * algorithm per rotation and each is kept for the retention window, so the
	 * shared set settles at replicas x algorithms x (retention/rotation + 1).
	 * That has to fit under {@link KeyRotator#MAX_VERIFYING_KEYS}, or the sweep's
	 * count rule evicts keys whose tokens are still live.
	 */
	@Test
	void steadyStateFleetKeyCountFitsUnderTheCap() {
		long generationsRetained = RETENTION / ROTATION_SECONDS + 1;
		long steadyStateKeys = (long) REPLICAS * ALGORITHMS * generationsRetained;

		assertEquals(14, generationsRetained, "8380800s retention / 604800s rotation + 1");
		assertEquals(84, steadyStateKeys, "3 replicas x 2 algorithms x 14 generations");
		assertTrue(steadyStateKeys <= KeyRotator.MAX_VERIFYING_KEYS,
				"the shipped defaults must not need the over-bound eviction rule, got "
						+ steadyStateKeys + " against a cap of " + KeyRotator.MAX_VERIFYING_KEYS);

		// Daily rotation is what this replaced: it did not fit.
		long daily = KeyRotator.retentionSecondsFor(86400, MAX_TOKEN_LIFETIME, OFFLINE_TOKEN_LIFETIME);
		assertTrue((long) REPLICAS * ALGORITHMS * (daily / 86400 + 1) > KeyRotator.MAX_VERIFYING_KEYS,
				"daily rotation overran the cap; that is the regression this guards");
	}

	/** The offline ceiling wins even when it is the smaller of the two configured values. */
	@Test
	void retentionTracksWhicheverMintCeilingIsLonger() {
		assertEquals(100 + 900, KeyRotator.retentionSecondsFor(100, 900, 500),
				"max-token ceiling is the longer one here");
		assertEquals(100 + 900, KeyRotator.retentionSecondsFor(100, 500, 900),
				"offline ceiling is the longer one here");
	}

	/**
	 * The published JWK's own {@code exp} is what the state store evicts on, so
	 * it — not just the sweep — has to outlast the last token the key signs.
	 * Signing goes through {@link KeyRotator#reserve}, which moves it out first.
	 */
	@Test
	void publishedKeyExpiryOutlastsTheLastTokenItCanSign() {
		KeyRotator rotator = replica();
		rotator.start();

		for (KeyRotator.SigAlg alg : KeyRotator.SigAlg.values()) {
			long offlineTokenExp = Instant.now().getEpochSecond() + OFFLINE_TOKEN_LIFETIME;
			rotator.reserve(alg, offlineTokenExp);
			JwkOuterClass.Jwk jwk = shared.get(rotator.getActiveKeyId(alg));
			assertTrue(jwk.getExp() >= offlineTokenExp,
					"key " + jwk.getKid() + " expires at " + jwk.getExp()
							+ ", before a token it signed expires at " + offlineTokenExp);
		}
	}

	/**
	 * The concrete incident: an offline token minted just before this key rotated
	 * out still has a second to live, so the key must not have been swept.
	 */
	@Test
	void keyIsNotSweptWhileAnOfflineTokenItSignedIsStillValid() {
		long now = Instant.now().getEpochSecond();
		// Created a full rotation interval plus almost the whole offline lifetime
		// ago: the last offline token it signed expires one second from now.
		long created = now - ROTATION_SECONDS - OFFLINE_TOKEN_LIFETIME + 1;
		shared.put("rotated-out", JwkOuterClass.Jwk.newBuilder()
				.setKid("rotated-out")
				.setAlg("EdDSA")
				.setCreated(created)
				.build());

		replica().start();

		assertTrue(shared.containsKey("rotated-out"),
				"a key whose offline tokens are still valid must stay verifiable");
	}

	/** Once nothing it signed can still be live, the key is swept as before. */
	@Test
	void keyIsSweptOnceEveryTokenItSignedHasExpired() {
		long now = Instant.now().getEpochSecond();
		long created = now - ROTATION_SECONDS - OFFLINE_TOKEN_LIFETIME - 1;
		shared.put("fully-expired", JwkOuterClass.Jwk.newBuilder()
				.setKid("fully-expired")
				.setAlg("EdDSA")
				.setCreated(created)
				.build());

		replica().start();

		assertTrue(!shared.containsKey("fully-expired"),
				"retention must not be open-ended once no signed token can be live");
	}
}
