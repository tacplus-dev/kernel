// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.CaMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.IdentityMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A key a kernel member signs with stays in {@code verifying_keys} until the
 * last token it signed has expired.
 *
 * <p>The dev incident (68cf984, 10-26 01:00Z): after a rolling restart the
 * gateway rejected tokens signed by a live kernel with "unknown signing key"
 * for about a minute. Every pod replays its disk snapshot's
 * {@code verifying_keys} into the shared set on boot, and that snapshot holds
 * its PEERS' keys too, at whatever {@code exp} they had when it was written.
 * A plain put of that copy shortened a live peer's key to the stale
 * {@code exp}. The owner still held the later {@code exp} in memory, so
 * {@link KeyRotator#reserve} saw nothing to extend and kept signing, while
 * the state store (and every sweep) dropped the key at the stale one.
 */
class LiveSigningKeyStaysPublishedTest {

	private static final long ROTATION_SECONDS = 604800;         // weekly
	private static final long RETENTION = KeyRotator.retentionSecondsFor(
			ROTATION_SECONDS, 2592000, 7776000);

	/** A clock the test moves by hand. */
	private static final class FakeClock extends Clock {
		Instant now;

		FakeClock(long epoch) {
			now = Instant.ofEpochSecond(epoch);
		}

		void set(long epoch) {
			now = Instant.ofEpochSecond(epoch);
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

	private final long realNow = Instant.now().getEpochSecond();

	/** The shared verifying_keys boundary every member publishes into. */
	private final IdentityMap identity = new IdentityMap(new InMemoryManager());

	private KeyRotator member(Clock clock) {
		return new KeyRotator(
				ROTATION_SECONDS,
				RETENTION,
				jwk -> {
					try {
						identity.putVerifyingKeys(jwk.getKid(), jwk);
					} catch (Exception e) {
						throw new RuntimeException("putVerifyingKeys failed", e);
					}
				},
				identity::deleteVerifyingKeys,
				this::published,
				() -> {},
				clock);
	}

	private List<JwkOuterClass.Jwk> published() {
		try {
			return new ArrayList<>(identity.proto().getVerifyingKeysList());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private boolean isPublished(String kid) {
		return published().stream().anyMatch(j -> j.getKid().equals(kid));
	}

	private long publishedExp(String kid) {
		return identity.getVerifyingKeys(kid).getExp();
	}

	/** Boots a pod's snapshot into the shared set, exactly as ClusterServer does. */
	private void rehydrate(Kernel.KernelDiskState snapshot) {
		InMemoryManager other = new InMemoryManager();
		ClusterServer.rehydrateFromSnapshot(
				snapshot, identity, new CaMap(other), new WorkloadMap(other), new ConfigMap(other));
	}

	/**
	 * The incident. kernel-0 is signing with its EdDSA key, reserved for a
	 * one-hour token; kernel-1 restarts and replays a snapshot holding the same
	 * key at an exp that has since been extended. Once that stale exp passes,
	 * kernel-0 is still signing with the key and the key must still verify.
	 */
	@Test
	void aPeersBootDoesNotShortenAKeyAMemberIsStillSigningWith() throws Exception {
		FakeClock kernel0Clock = new FakeClock(realNow);
		KeyRotator kernel0 = member(kernel0Clock);
		kernel0.start();
		kernel0.stop();
		kernel0.reserve(KeyRotator.SigAlg.ED25519, realNow + 3600);
		JwkOuterClass.Jwk live = kernel0.getActiveJwk(KeyRotator.SigAlg.ED25519);
		String kid = live.getKid();

		long stale = realNow + 60;
		rehydrate(Kernel.KernelDiskState.newBuilder()
				.addVerifyingKeys(live.toBuilder().setExp(stale).build())
				.build());

		assertEquals(live.getExp(), publishedExp(kid),
				"a peer's snapshot copy must not shorten a live key's published exp");

		// Past the stale exp: kernel-1's sweep runs, kernel-0 signs a short token.
		FakeClock kernel1Clock = new FakeClock(realNow);
		KeyRotator kernel1 = member(kernel1Clock);
		kernel1.start();
		kernel1.stop();
		kernel1Clock.set(stale + 1);
		kernel1.sweepExpired();
		kernel0Clock.set(stale + 1);
		assertEquals(kid, kernel0.reserve(KeyRotator.SigAlg.ED25519, stale + 1 + 300).getProto().getId(),
				"kernel-0 still signs with its key");

		assertTrue(isPublished(kid), "kernel-0 is signing with " + kid + " but it is not published");
	}

	/**
	 * The owner side of the same invariant. A member starting from its snapshot
	 * finds its own key already published with an earlier exp than it holds:
	 * written by a peer that booted first on a full-cluster restart, or by a
	 * peer still on an older kernel during a roll. Before its first token the
	 * member publishes its own exp; it is the one that reserved it.
	 */
	@Test
	void startRepublishesAnOwnKeyPublishedWithAnEarlierExp() throws Exception {
		KeyRotator previous = member(new FakeClock(realNow));
		previous.start();
		previous.stop();
		previous.reserve(KeyRotator.SigAlg.ED25519, realNow + 3600);
		List<Kernel.SigningKeyRecord> records = previous.getSigningKeyRecords();
		JwkOuterClass.Jwk own = previous.getActiveJwk(KeyRotator.SigAlg.ED25519);
		identity.putVerifyingKeys(own.getKid(), own.toBuilder().setExp(realNow + 60).build());

		KeyRotator restarted = member(new FakeClock(realNow));
		restarted.restore(records);
		restarted.start();
		restarted.stop();

		assertEquals(own.getKid(), restarted.getActiveKeyId(KeyRotator.SigAlg.ED25519));
		assertEquals(own.getExp(), publishedExp(own.getKid()),
				"start must publish the exp this member reserved, not leave the earlier one in place");
	}
}
