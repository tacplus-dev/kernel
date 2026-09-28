// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.fencedlock.RatisFencedLock;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;

import java.nio.file.Path;

import org.apache.ratis.protocol.RaftGroup;
import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.util.NetUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Drives the s2s handler kernel actually registers, against a real single-peer
 * Ratis group — the same path a calling service reaches over gRPC, minus the
 * transport. Multi-peer replication is covered by
 * {@code RatisFencedLockTest}; what this pins is that the handler returns the
 * state machine's answer unaltered (including the two "no" answers that are
 * ordinary replies rather than errors), and that the holder it records and
 * enforces is the verified caller rather than anything the request stated.
 */
class FencedLockServiceImplTest {

	private static final Caller ALICE = caller("spiffe://schematic/ns/alice/sa/alice");
	private static final Caller MALLORY = caller("spiffe://schematic/ns/mallory/sa/mallory");

	/** A Caller built the way the generated wrapper builds one: from a verified token payload. */
	private static Caller caller(String subject) {
		return new Caller("{\"sub\":\"" + subject + "\"}", "test-req");
	}

	@TempDir
	Path storage;

	private RatisFencedLock lock;
	private FencedLockServiceImpl service;

	@BeforeEach
	void start() throws Exception {
		int port = NetUtils.getFreePort();
		RaftPeer peer = RatisFencedLock.peer("127.0.0.1:" + port, "127.0.0.1", port);
		RaftGroup group = RaftGroup.valueOf(RatisFencedLock.GROUP_ID, peer);
		lock = RatisFencedLock.start(RaftPeerId.valueOf(peer.getId().toString()), group, storage.toFile());
		service = new FencedLockServiceImpl(lock);
	}

	@AfterEach
	void stop() throws Exception {
		lock.close();
	}

	private Kernel.FencedLockAcquireResponse acquire(Caller caller, String key, String statedHolder) throws Exception {
		return service.acquire(caller, Kernel.FencedLockAcquireRequest.newBuilder()
				.setKey(key).setHolderId(statedHolder).build());
	}

	private Kernel.FencedLockReleaseResponse release(Caller caller, String key, long token) throws Exception {
		return service.release(caller, Kernel.FencedLockReleaseRequest.newBuilder()
				.setKey(key).setFencingToken(token).build());
	}

	@Test
	void handlerServesAcquireAndReleaseAndReportsRefusalsAsReplies() throws Exception {
		Kernel.FencedLockAcquireResponse granted = acquire(ALICE, "k", "h1");
		assertTrue(granted.getGranted());
		assertTrue(granted.getFencingToken() > 0);

		// A contender is refused with a reply, not an exception.
		Kernel.FencedLockAcquireResponse refused = acquire(MALLORY, "k", "h2");
		assertFalse(refused.getGranted());

		// A stale token is refused with a reply, not an exception.
		Kernel.FencedLockReleaseResponse stale = release(ALICE, "k", granted.getFencingToken() - 1);
		assertFalse(stale.getOk());

		Kernel.FencedLockReleaseResponse released = release(ALICE, "k", granted.getFencingToken());
		assertTrue(released.getOk());

		Kernel.FencedLockAcquireResponse next = acquire(MALLORY, "k", "h2");
		assertTrue(next.getGranted());
		assertTrue(next.getFencingToken() > granted.getFencingToken());
	}

	/**
	 * The request's holder_id is not an identity. Alice acquiring while claiming
	 * to be Mallory holds the lock as Alice — so Mallory is still refused, and
	 * Alice can still release with her own identity.
	 */
	@Test
	void statedHolderIdInTheRequestIsIgnoredInFavourOfTheVerifiedCaller() throws Exception {
		Kernel.FencedLockAcquireResponse held = acquire(ALICE, "spoof/acquire", MALLORY.getSubject());
		assertTrue(held.getGranted());

		assertFalse(acquire(MALLORY, "spoof/acquire", MALLORY.getSubject()).getGranted(),
				"a caller must not reach a lock by putting its own id in someone else's acquire");

		assertTrue(release(ALICE, "spoof/acquire", held.getFencingToken()).getOk(),
				"the verified holder must still be able to release its own lock");
	}

	/**
	 * The fencing token is a Raft log index — small, monotonic and therefore
	 * guessable — so knowing it must not be enough to unlock somebody else's key.
	 */
	@Test
	void anotherCallerCannotReleaseALockItDoesNotHoldEvenWithTheRightToken() throws Exception {
		Kernel.FencedLockAcquireResponse held = acquire(ALICE, "steal/release", ALICE.getSubject());
		assertTrue(held.getGranted());

		assertFalse(release(MALLORY, "steal/release", held.getFencingToken()).getOk(),
				"a caller that does not hold the lock must not release it");

		// The hold really is intact: Mallory still cannot take the key, and the
		// real holder's own release still works.
		assertFalse(acquire(MALLORY, "steal/release", MALLORY.getSubject()).getGranted());
		assertTrue(release(ALICE, "steal/release", held.getFencingToken()).getOk());
	}

	/**
	 * Reacquire is idempotent for the same verified caller, which is what a
	 * retried Acquire depends on — and the identity it matches on is the token's,
	 * not the field's.
	 */
	@Test
	void sameCallerReacquiringKeepsItsTokenRegardlessOfTheStatedHolder() throws Exception {
		Kernel.FencedLockAcquireResponse first = acquire(ALICE, "retry/key", "label-a");
		assertTrue(first.getGranted());

		Kernel.FencedLockAcquireResponse again = acquire(ALICE, "retry/key", "label-b");
		assertTrue(again.getGranted());
		assertEquals(first.getFencingToken(), again.getFencingToken());
	}

	/** A call with nothing verified has no holder to record, so it is refused outright. */
	@Test
	void callWithNoVerifiedCallerIsRejected() {
		assertThrows(ProtoException.class, () -> acquire(null, "unauth", "h1"));
		assertThrows(ProtoException.class, () -> release(null, "unauth", 1));
		assertThrows(ProtoException.class, () -> acquire(caller(""), "unauth", "h1"));
	}
}
