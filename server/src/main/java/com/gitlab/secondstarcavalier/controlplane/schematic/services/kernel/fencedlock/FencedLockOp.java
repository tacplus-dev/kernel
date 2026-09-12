// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.fencedlock;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.google.protobuf.InvalidProtocolBufferException;

import java.nio.charset.StandardCharsets;

/**
 * FencedLockOp is the encoding of one lock operation as it appears in the Ratis
 * log: a single leading opcode byte, the verified holder identity, and the
 * wire-encoded request proto.
 *
 * <p>The request messages are the ones already declared on the s2s surface
 * ({@code kernel.FencedLockAcquireRequest} / {@code kernel.FencedLockReleaseRequest});
 * only the discriminator between them is added here, because a Ratis log entry
 * carries one opaque byte string and protobuf has no self-describing framing.
 *
 * <p><b>The holder is not read off the request.</b> Acquire's request does carry
 * a {@code holder_id} field, so the caller's verified identity is written into
 * it before encoding; Release's request carries no such field, so the identity
 * is length-prefixed ahead of the proto. Either way the holder recorded in the
 * log is the one kernel verified, never the one the client stated.
 */
final class FencedLockOp {
	static final byte ACQUIRE = 'A';

	/**
	 * Release carrying the verified holder identity.
	 *
	 * <p>A distinct opcode from {@link #RELEASE_UNVERIFIED} because the two have
	 * different framing and the Raft log is replayed from its first entry: an
	 * entry written before kernel carried the holder must still decode after the
	 * upgrade.
	 */
	static final byte RELEASE = 'V';

	/**
	 * Release as it was written before the holder was verified — key and fencing
	 * token only. Decoded when replaying a log written by an older kernel; never
	 * encoded.
	 */
	static final byte RELEASE_UNVERIFIED = 'R';

	/** Release is a release request together with the holder that submitted it. */
	record Release(String holderId, Kernel.FencedLockReleaseRequest request) {}

	private FencedLockOp() {}

	static byte[] encodeAcquire(String holderId, Kernel.FencedLockAcquireRequest request) {
		return prefix(ACQUIRE, request.toBuilder().setHolderId(holderId).build().toByteArray());
	}

	static byte[] encodeRelease(String holderId, Kernel.FencedLockReleaseRequest request) {
		final byte[] holder = holderId.getBytes(StandardCharsets.UTF_8);
		final byte[] body = request.toByteArray();
		final byte[] out = new byte[1 + 4 + holder.length + body.length];
		out[0] = RELEASE;
		out[1] = (byte) (holder.length >>> 24);
		out[2] = (byte) (holder.length >>> 16);
		out[3] = (byte) (holder.length >>> 8);
		out[4] = (byte) holder.length;
		System.arraycopy(holder, 0, out, 5, holder.length);
		System.arraycopy(body, 0, out, 5 + holder.length, body.length);
		return out;
	}

	static byte opcode(byte[] entry) {
		if (entry.length == 0) {
			throw new IllegalArgumentException("empty FencedLock log entry");
		}
		return entry[0];
	}

	static Kernel.FencedLockAcquireRequest decodeAcquire(byte[] entry) throws InvalidProtocolBufferException {
		return Kernel.FencedLockAcquireRequest.parseFrom(payload(entry));
	}

	static Release decodeRelease(byte[] entry) throws InvalidProtocolBufferException {
		if (entry.length < 5) {
			throw new IllegalArgumentException("truncated FencedLock release entry");
		}
		final int holderLength = ((entry[1] & 0xFF) << 24) | ((entry[2] & 0xFF) << 16)
				| ((entry[3] & 0xFF) << 8) | (entry[4] & 0xFF);
		if (holderLength < 0 || 5 + holderLength > entry.length) {
			throw new IllegalArgumentException("FencedLock release entry declares a holder longer than the entry");
		}
		final String holderId = new String(entry, 5, holderLength, StandardCharsets.UTF_8);
		final byte[] body = new byte[entry.length - 5 - holderLength];
		System.arraycopy(entry, 5 + holderLength, body, 0, body.length);
		return new Release(holderId, Kernel.FencedLockReleaseRequest.parseFrom(body));
	}

	/** decodeUnverifiedRelease reads the pre-holder framing: opcode plus proto. */
	static Kernel.FencedLockReleaseRequest decodeUnverifiedRelease(byte[] entry) throws InvalidProtocolBufferException {
		return Kernel.FencedLockReleaseRequest.parseFrom(payload(entry));
	}

	private static byte[] prefix(byte opcode, byte[] body) {
		byte[] out = new byte[body.length + 1];
		out[0] = opcode;
		System.arraycopy(body, 0, out, 1, body.length);
		return out;
	}

	private static byte[] payload(byte[] entry) {
		byte[] body = new byte[entry.length - 1];
		System.arraycopy(entry, 1, body, 0, body.length);
		return body;
	}
}
