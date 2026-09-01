// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.fencedlock;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.google.protobuf.InvalidProtocolBufferException;

/**
 * FencedLockOp is the encoding of one lock operation as it appears in the Ratis
 * log: a single leading opcode byte followed by the wire-encoded request proto.
 *
 * <p>The two request messages are the ones already declared on the s2s surface
 * ({@code kernel.FencedLockAcquireRequest} / {@code kernel.FencedLockReleaseRequest});
 * only the discriminator between them is added here, because a Ratis log entry
 * carries one opaque byte string and protobuf has no self-describing framing.
 */
final class FencedLockOp {
	static final byte ACQUIRE = 'A';
	static final byte RELEASE = 'R';

	private FencedLockOp() {}

	static byte[] encodeAcquire(Kernel.FencedLockAcquireRequest request) {
		return prefix(ACQUIRE, request.toByteArray());
	}

	static byte[] encodeRelease(Kernel.FencedLockReleaseRequest request) {
		return prefix(RELEASE, request.toByteArray());
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

	static Kernel.FencedLockReleaseRequest decodeRelease(byte[] entry) throws InvalidProtocolBufferException {
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
