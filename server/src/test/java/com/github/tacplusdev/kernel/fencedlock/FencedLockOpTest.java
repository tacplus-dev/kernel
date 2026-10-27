// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.fencedlock;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;

import org.junit.jupiter.api.Test;

/**
 * Pins the Raft log framing. Two things matter here: the verified holder
 * survives a round trip intact, and an entry written by a kernel that predates
 * the holder still decodes — the log is replayed from its first entry on every
 * restart, so a framing change that orphaned old entries would fail startup.
 */
class FencedLockOpTest {

	@Test
	void acquireCarriesTheVerifiedHolderNotTheStatedOne() throws Exception {
		byte[] entry = FencedLockOp.encodeAcquire("spiffe://schematic/ns/a/sa/a",
				Kernel.FencedLockAcquireRequest.newBuilder().setKey("k").setHolderId("stated").build());

		assertEquals(FencedLockOp.ACQUIRE, FencedLockOp.opcode(entry));
		Kernel.FencedLockAcquireRequest decoded = FencedLockOp.decodeAcquire(entry);
		assertEquals("k", decoded.getKey());
		assertEquals("spiffe://schematic/ns/a/sa/a", decoded.getHolderId());
	}

	@Test
	void releaseRoundTripsHolderAndRequest() throws Exception {
		byte[] entry = FencedLockOp.encodeRelease("spiffe://schematic/ns/a/sa/a",
				Kernel.FencedLockReleaseRequest.newBuilder().setKey("k").setFencingToken(42).build());

		assertEquals(FencedLockOp.RELEASE, FencedLockOp.opcode(entry));
		FencedLockOp.Release decoded = FencedLockOp.decodeRelease(entry);
		assertEquals("spiffe://schematic/ns/a/sa/a", decoded.holderId());
		assertEquals("k", decoded.request().getKey());
		assertEquals(42, decoded.request().getFencingToken());
	}

	/** An empty holder is not a special case in the framing; it round-trips as itself. */
	@Test
	void releaseRoundTripsAnEmptyHolder() throws Exception {
		byte[] entry = FencedLockOp.encodeRelease("",
				Kernel.FencedLockReleaseRequest.newBuilder().setKey("k").setFencingToken(7).build());

		FencedLockOp.Release decoded = FencedLockOp.decodeRelease(entry);
		assertEquals("", decoded.holderId());
		assertEquals(7, decoded.request().getFencingToken());
	}

	/** The pre-holder framing: opcode 'R' followed by the bare proto. */
	@Test
	void aReleaseWrittenBeforeTheHolderWasCarriedStillDecodes() throws Exception {
		Kernel.FencedLockReleaseRequest request =
				Kernel.FencedLockReleaseRequest.newBuilder().setKey("k").setFencingToken(9).build();
		byte[] body = request.toByteArray();
		byte[] legacy = new byte[body.length + 1];
		legacy[0] = FencedLockOp.RELEASE_UNVERIFIED;
		System.arraycopy(body, 0, legacy, 1, body.length);

		assertEquals(FencedLockOp.RELEASE_UNVERIFIED, FencedLockOp.opcode(legacy));
		assertEquals(request, FencedLockOp.decodeUnverifiedRelease(legacy));
	}
}
