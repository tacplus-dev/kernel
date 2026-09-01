// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.fencedlock.RatisFencedLock;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

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
 * state machine's answer unaltered, including the two "no" answers that are
 * ordinary replies rather than errors.
 */
class FencedLockServiceImplTest {

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

	@Test
	void handlerServesAcquireAndReleaseAndReportsRefusalsAsReplies() throws Exception {
		Kernel.FencedLockAcquireResponse granted = service.acquire(null,
				Kernel.FencedLockAcquireRequest.newBuilder().setKey("k").setHolderId("h1").build());
		assertTrue(granted.getGranted());
		assertTrue(granted.getFencingToken() > 0);

		// A contender is refused with a reply, not an exception.
		Kernel.FencedLockAcquireResponse refused = service.acquire(null,
				Kernel.FencedLockAcquireRequest.newBuilder().setKey("k").setHolderId("h2").build());
		assertFalse(refused.getGranted());

		// A stale token is refused with a reply, not an exception.
		Kernel.FencedLockReleaseResponse stale = service.release(null,
				Kernel.FencedLockReleaseRequest.newBuilder()
						.setKey("k").setFencingToken(granted.getFencingToken() - 1).build());
		assertFalse(stale.getOk());

		Kernel.FencedLockReleaseResponse released = service.release(null,
				Kernel.FencedLockReleaseRequest.newBuilder()
						.setKey("k").setFencingToken(granted.getFencingToken()).build());
		assertTrue(released.getOk());

		Kernel.FencedLockAcquireResponse next = service.acquire(null,
				Kernel.FencedLockAcquireRequest.newBuilder().setKey("k").setHolderId("h2").build());
		assertTrue(next.getGranted());
		assertTrue(next.getFencingToken() > granted.getFencingToken());
	}
}
