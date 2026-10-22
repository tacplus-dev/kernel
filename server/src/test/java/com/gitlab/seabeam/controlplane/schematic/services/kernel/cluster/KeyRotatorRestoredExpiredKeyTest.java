// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.IdentityMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Once the generated snapshot loader accepts a snapshot whose active signing
 * key has already expired (tacplus #47), {@link KeyRotator} must not try to
 * publish that key: the generated {@code IdentityMap.putVerifyingKeys}
 * validates {@code exp > now} and the throw fails kernel's start. Publishing
 * here goes through the real {@link IdentityMap}, exactly as ClusterServer
 * wires it, against the wall clock the generated validator uses.
 */
class KeyRotatorRestoredExpiredKeyTest {

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

	private final long realNow = Instant.now().getEpochSecond();

	private final FakeClock clock = new FakeClock(realNow);

	private final IdentityMap identity = new IdentityMap(new InMemoryManager());

	/** Off only while a key goes into state that was valid at the time it was published. */
	private boolean validating = true;

	private KeyRotator rotator(Runnable onKeysChanged) {
		return new KeyRotator(
				ROTATION_SECONDS,
				RETENTION,
				jwk -> {
					if (!validating) {
						return;
					}
					try {
						identity.putVerifyingKeys(jwk.getKid(), jwk);
					} catch (Exception e) {
						throw new RuntimeException("putVerifyingKeys failed", e);
					}
				},
				identity::deleteVerifyingKeys,
				this::published,
				onKeysChanged,
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

	/** The signing records a node wrote an hour before its keys expired, both keys now past exp. */
	private List<Kernel.SigningKeyRecord> expiredRecords() {
		FakeClock then = new FakeClock(realNow - 2 * STEP);
		KeyRotator previous = new KeyRotator(
				ROTATION_SECONDS, RETENTION, jwk -> {}, kid -> {}, List::of, () -> {}, then);
		previous.start();
		previous.stop();
		List<Kernel.SigningKeyRecord> records = previous.getSigningKeyRecords();
		for (Kernel.SigningKeyRecord rec : records) {
			assertTrue(rec.getJwk().getExp() <= realNow, "fixture key " + rec.getJwk().getKid() + " not expired");
		}
		return records;
	}

	private static String kidOf(List<Kernel.SigningKeyRecord> records, KeyRotator.SigAlg alg) {
		return records.stream()
				.filter(r -> r.getJwk().getAlg().equals(alg.alg))
				.findFirst().orElseThrow().getJwk().getKid();
	}

	/**
	 * kernel-2's shape after #47: the snapshot loads, its active keys are past
	 * exp and state was wiped. start() retires them instead of republishing
	 * them, and the snapshot it writes holds no expired JWK.
	 */
	@Test
	void restoredExpiredActiveKeyIsRetiredOnStart(@TempDir Path dir) throws Exception {
		List<Kernel.SigningKeyRecord> records = expiredRecords();
		IdentitySnapshot[] snapshot = new IdentitySnapshot[1];
		KeyRotator r = rotator(() -> snapshot[0].save());
		snapshot[0] = new IdentitySnapshot(
				dir.toString(), r, this::published, null, null, null, null, null);
		r.restore(records);

		assertDoesNotThrow(r::start);
		r.stop();

		for (KeyRotator.SigAlg a : KeyRotator.SigAlg.values()) {
			String oldKid = kidOf(records, a);
			String newKid = r.getActiveKeyId(a);
			assertNotEquals(oldKid, newKid, a.alg + " kept its expired key");
			assertFalse(isPublished(oldKid), a.alg + " expired key published");
			assertTrue(isPublished(newKid), a.alg + " fresh key not published");
		}
		Kernel.KernelDiskState loaded = snapshot[0].load();
		List<JwkOuterClass.Jwk> written = new ArrayList<>(loaded.getVerifyingKeysList());
		loaded.getSigningKeysList().forEach(rec -> written.add(rec.getJwk()));
		assertEquals(2, loaded.getSigningKeysCount());
		for (JwkOuterClass.Jwk jwk : written) {
			assertTrue(jwk.getExp() > clock.epoch(), "snapshot holds " + jwk.getKid() + " exp=" + jwk.getExp());
		}
	}

	/**
	 * A restored key whose snapshot exp has passed but which reserve() extended
	 * in state after the snapshot was taken is still in use: the later exp is
	 * adopted and the key kept.
	 */
	@Test
	void restoredKeyWithALaterPublishedExpIsKept() throws Exception {
		List<Kernel.SigningKeyRecord> records = expiredRecords();
		JwkOuterClass.Jwk es256 = records.stream()
				.filter(rec -> rec.getJwk().getAlg().equals(KeyRotator.SigAlg.ES256.alg))
				.findFirst().orElseThrow().getJwk();
		long extended = realNow + STEP;
		identity.putVerifyingKeys(es256.getKid(), es256.toBuilder().setExp(extended).build());
		KeyRotator r = rotator(() -> {});
		r.restore(records);

		assertDoesNotThrow(r::start);
		r.stop();

		assertEquals(es256.getKid(), r.getActiveKeyId(KeyRotator.SigAlg.ES256));
		assertEquals(extended, r.getActiveJwk(KeyRotator.SigAlg.ES256).getExp());
		assertTrue(isPublished(es256.getKid()));
		assertNotEquals(kidOf(records, KeyRotator.SigAlg.ED25519), r.getActiveKeyId(KeyRotator.SigAlg.ED25519),
				"the EdDSA key had no later exp and is retired");
	}

	/**
	 * ClusterServer opens the gRPC server before KeyRotator.start(), so a Mint
	 * can reserve() a restored key first. An expired one is retired exactly as
	 * start() would retire it, never extended and signed with.
	 */
	@Test
	void reserveBeforeStartNeverExtendsAnExpiredRestoredKey() throws Exception {
		List<Kernel.SigningKeyRecord> records = expiredRecords();
		KeyRotator r = rotator(() -> {});
		r.restore(records);

		for (KeyRotator.SigAlg a : KeyRotator.SigAlg.values()) {
			String oldKid = kidOf(records, a);

			assertNotEquals(oldKid, r.reserve(a, clock.epoch() + 600).getProto().getId(),
					a.alg + " signed with its expired key");
			assertNotEquals(oldKid, r.getActiveKeyId(a));
			// Extending it would have published it with a later exp.
			assertFalse(isPublished(oldKid), a.alg + " expired key republished with a later exp");
		}
	}

	/**
	 * A topology change republishes this node's active keys. One past its exp
	 * (between two sweeps) is retired, not republished.
	 */
	@Test
	void republishNeverPublishesAnExpiredActiveKey() throws Exception {
		clock.set(realNow - 2 * STEP);
		validating = false;               // published while still valid
		KeyRotator r = rotator(() -> {});
		r.start();
		r.stop();
		String oldEd = r.getActiveKeyId(KeyRotator.SigAlg.ED25519);
		String oldEs = r.getActiveKeyId(KeyRotator.SigAlg.ES256);

		clock.set(realNow);
		validating = true;
		assertDoesNotThrow(r::republishCurrentKeys);

		assertFalse(isPublished(oldEd));
		assertFalse(isPublished(oldEs));
		for (KeyRotator.SigAlg a : KeyRotator.SigAlg.values()) {
			assertTrue(isPublished(r.getActiveKeyId(a)), a.alg + " active key not republished");
			assertTrue(r.getActiveJwk(a).getExp() > clock.epoch());
		}
	}
}
