// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.fencedlock;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.apache.ratis.protocol.RaftGroup;
import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.util.NetUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises kernel's FencedLock against a real, running three-peer Apache Ratis
 * group on loopback — not a stub. Every assertion here is about what the
 * replicated state machine actually decided after the operation was committed
 * to the Raft log.
 */
class RatisFencedLockTest {

	private static final int PEERS = 3;

	private final List<RatisFencedLock> nodes = new ArrayList<>();

	@TempDir
	Path storageRoot;

	private RaftGroup group;
	private RatisFencedLock lock;

	@BeforeEach
	void startCluster() throws Exception {
		final List<RaftPeer> peers = new ArrayList<>(PEERS);
		for (int i = 0; i < PEERS; i++) {
			int port = NetUtils.getFreePort();
			peers.add(RatisFencedLock.peer("127.0.0.1:" + port, "127.0.0.1", port));
		}
		group = RaftGroup.valueOf(RatisFencedLock.GROUP_ID, peers);
		startPeers();
	}

	/** startPeers brings every peer up against its own (persistent) storage dir. */
	private void startPeers() throws Exception {
		for (RaftPeer peer : group.getPeers()) {
			File storage = storageRoot.resolve(peer.getId().toString().replace(':', '-')).toFile();
			nodes.add(RatisFencedLock.start(RaftPeerId.valueOf(peer.getId().toString()), group, storage));
		}
		// Any peer's client routes to the leader; use the first.
		lock = nodes.get(0);
	}

	@AfterEach
	void stopCluster() {
		stopPeers();
	}

	private void stopPeers() {
		for (RatisFencedLock node : nodes) {
			try {
				node.close();
			} catch (Exception e) {
				// A peer that is already down must not mask the test result.
			}
		}
		nodes.clear();
	}

	private Kernel.FencedLockAcquireResponse acquire(String key, String holder) throws Exception {
		return lock.acquire(Kernel.FencedLockAcquireRequest.newBuilder()
				.setKey(key).setHolderId(holder).build());
	}

	private Kernel.FencedLockReleaseResponse release(String key, long token) throws Exception {
		return lock.release(Kernel.FencedLockReleaseRequest.newBuilder()
				.setKey(key).setFencingToken(token).build());
	}

	@Test
	void firstAcquireGrantsAndSecondHolderIsRefused() throws Exception {
		Kernel.FencedLockAcquireResponse first = acquire("workspace/a", "holder-1");
		assertTrue(first.getGranted(), "an unheld key must grant");
		assertTrue(first.getFencingToken() > 0, "a granted acquire must carry a fencing token");

		Kernel.FencedLockAcquireResponse second = acquire("workspace/a", "holder-2");
		assertFalse(second.getGranted(), "a held key must not grant to a different holder");
		assertEquals(0, second.getFencingToken(), "a refused acquire must carry no token");
	}

	@Test
	void twoConcurrentAcquiresForTheSameKeyGrantExactlyOne() throws Exception {
		final int contenders = 8;
		final CyclicBarrier startLine = new CyclicBarrier(contenders);
		final ExecutorService pool = Executors.newFixedThreadPool(contenders);
		try {
			final List<Callable<Kernel.FencedLockAcquireResponse>> calls = new ArrayList<>();
			for (int i = 0; i < contenders; i++) {
				final String holder = "holder-" + i;
				calls.add(() -> {
					startLine.await(30, TimeUnit.SECONDS);
					return acquire("workspace/contended", holder);
				});
			}
			int granted = 0;
			long grantedToken = 0;
			for (Future<Kernel.FencedLockAcquireResponse> future : pool.invokeAll(calls)) {
				Kernel.FencedLockAcquireResponse response = future.get(60, TimeUnit.SECONDS);
				if (response.getGranted()) {
					granted++;
					grantedToken = response.getFencingToken();
				} else {
					assertEquals(0, response.getFencingToken());
				}
			}
			assertEquals(1, granted, contenders + " simultaneous acquires must produce exactly one grant");
			assertTrue(grantedToken > 0);
		} finally {
			pool.shutdownNow();
		}
	}

	@Test
	void releaseThenReacquireGrantsAStrictlyHigherToken() throws Exception {
		Kernel.FencedLockAcquireResponse first = acquire("workspace/b", "holder-1");
		assertTrue(first.getGranted());

		assertTrue(release("workspace/b", first.getFencingToken()).getOk(), "the holder's own token must release");

		Kernel.FencedLockAcquireResponse second = acquire("workspace/b", "holder-2");
		assertTrue(second.getGranted(), "a released key must grant to the next contender");
		assertTrue(second.getFencingToken() > first.getFencingToken(),
				"the new token (" + second.getFencingToken() + ") must exceed the old one ("
						+ first.getFencingToken() + "): a fencing token that can repeat fences nothing");
	}

	@Test
	void aStaleFencingTokenIsDistinguishableFromTheCurrentOne() throws Exception {
		Kernel.FencedLockAcquireResponse stale = acquire("workspace/c", "holder-1");
		assertTrue(stale.getGranted());
		assertTrue(release("workspace/c", stale.getFencingToken()).getOk());

		Kernel.FencedLockAcquireResponse current = acquire("workspace/c", "holder-2");
		assertTrue(current.getGranted());

		// This is the property a resource owner relies on: the stale holder's
		// token is strictly below the live one, so a write carrying it is
		// rejectable without asking kernel anything.
		assertTrue(stale.getFencingToken() < current.getFencingToken());

		// And the stale holder cannot unlock the live one.
		assertFalse(release("workspace/c", stale.getFencingToken()).getOk(),
				"a stale token must not release the current holder");
		assertFalse(acquire("workspace/c", "holder-3").getGranted(),
				"the live holder must still hold the lock after a stale release attempt");
	}

	@Test
	void reacquireBySameHolderIsIdempotentAndKeepsItsToken() throws Exception {
		Kernel.FencedLockAcquireResponse first = acquire("workspace/d", "holder-1");
		assertTrue(first.getGranted());

		Kernel.FencedLockAcquireResponse again = acquire("workspace/d", "holder-1");
		assertTrue(again.getGranted(), "a holder re-asking for a lock it holds must not be refused");
		assertEquals(first.getFencingToken(), again.getFencingToken(),
				"a retried acquire must not move the token under a resource owner that already saw it");
	}

	@Test
	void distinctKeysDoNotContend() throws Exception {
		Kernel.FencedLockAcquireResponse a = acquire("workspace/e", "holder-1");
		Kernel.FencedLockAcquireResponse b = acquire("workspace/f", "holder-2");
		assertTrue(a.getGranted());
		assertTrue(b.getGranted());
		assertTrue(b.getFencingToken() > a.getFencingToken(),
				"tokens are global Raft log indexes, so a later grant on any key is higher");
	}

	@Test
	void releasingAnUnheldKeyReportsNotOk() throws Exception {
		assertFalse(release("workspace/never-held", 1).getOk());
	}

	/**
	 * Tokens must not restart from zero. This is the property that picking the
	 * Raft log index buys: the log is durable, so a whole-cluster restart resumes
	 * numbering above every token any resource owner has already seen. A counter
	 * held only in memory would hand out a token a stale holder still carries.
	 */
	@Test
	void tokensStayMonotonicAcrossAWholeClusterRestart() throws Exception {
		Kernel.FencedLockAcquireResponse held = acquire("workspace/durable", "holder-1");
		assertTrue(held.getGranted());
		Kernel.FencedLockAcquireResponse other = acquire("workspace/other", "holder-2");
		assertTrue(other.getGranted());

		stopPeers();
		startPeers();

		// The hold survived the restart: a different holder is still refused.
		assertFalse(acquire("workspace/durable", "holder-9").getGranted(),
				"a hold committed to the Raft log must survive a restart");
		// And the next grant is above every token issued before the restart.
		assertTrue(release("workspace/other", other.getFencingToken()).getOk());
		Kernel.FencedLockAcquireResponse afterRestart = acquire("workspace/other", "holder-3");
		assertTrue(afterRestart.getGranted());
		assertTrue(afterRestart.getFencingToken() > other.getFencingToken(),
				"post-restart token (" + afterRestart.getFencingToken() + ") must exceed the pre-restart one ("
						+ other.getFencingToken() + ")");
		assertTrue(afterRestart.getFencingToken() > held.getFencingToken());
	}
}
