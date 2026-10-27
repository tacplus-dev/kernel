// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Helpers;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rotation interval kernel actually SHIPS — the generated
 * {@code Helpers.configDefaults}, which ClusterServer applies before it reads
 * the config — must keep a three-replica fleet minting 90-day offline tokens
 * under {@link KeyRotator#MAX_VERIFYING_KEYS}. Past the cap the sweep's count
 * rule evicts the oldest keys while offline tokens they signed are still live,
 * and those tokens then fail as "signed with unknown key".
 *
 * <p>{@link KeyRetentionWindowTest} checks the same arithmetic against a
 * hard-coded weekly interval; this one reads the default from the generated
 * config so a proto default that drifts from it fails here.
 */
class ShippedKeyRotationFleetTest {

	/** The dev/prod kernel StatefulSet. */
	private static final int REPLICAS = 3;

	/** A clock the test moves by hand. */
	private static final class FakeClock extends Clock {
		Instant now = Instant.ofEpochSecond(1_800_000_000L);

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

	@Test
	void everyReplicaMintingOfflineTokensEveryRotationNeverEvictsALiveKey() throws Exception {
		Kernel.Config cfg = Helpers.configDefaults(Kernel.Config.getDefaultInstance()).build();
		long rotation = cfg.getKeyRotationIntervalSeconds();
		long offline = cfg.getOfflineTokenLifetimeSeconds();
		long retention = KeyRotator.retentionSecondsFor(rotation, cfg.getMaxTokenLifetimeSeconds(), offline);

		FakeClock clock = new FakeClock();
		Map<String, JwkOuterClass.Jwk> shared = new LinkedHashMap<>();
		List<KeyRotator> fleet = new ArrayList<>();
		for (int i = 0; i < REPLICAS; i++) {
			KeyRotator replica = new KeyRotator(
					rotation,
					retention,
					jwk -> shared.put(jwk.getKid(), jwk),
					shared::remove,
					() -> new ArrayList<>(shared.values()),
					() -> {},
					clock);
			replica.start();
			fleet.add(replica);
		}

		// kid -> exp of the last offline token it signed.
		Map<String, Long> liveUntil = new LinkedHashMap<>();
		try {
			// Long enough for the first keys' offline tokens to expire, so the
			// fleet reaches its steady state.
			long rotations = offline / rotation + 2;
			for (long r = 0; r < rotations; r++) {
				for (KeyRotator replica : fleet) {
					long tokenExp = clock.epoch() + offline;
					replica.reserve(KeyRotator.SigAlg.ED25519, tokenExp);
					liveUntil.put(replica.getActiveKeyId(KeyRotator.SigAlg.ED25519), tokenExp);
				}
				clock.now = clock.now.plusSeconds(rotation);
				for (KeyRotator replica : fleet) {
					replica.rotate();
				}
				for (Map.Entry<String, Long> e : liveUntil.entrySet()) {
					if (e.getValue() > clock.epoch()) {
						assertTrue(shared.containsKey(e.getKey()),
								"rotation " + (r + 1) + " at the shipped " + rotation + "s interval evicted key "
										+ e.getKey() + " while an offline token it signed has "
										+ (e.getValue() - clock.epoch()) + "s left; verifying_keys holds "
										+ shared.size() + " against a cap of " + KeyRotator.MAX_VERIFYING_KEYS);
					}
				}
			}
		} finally {
			fleet.forEach(KeyRotator::stop);
		}
	}
}
