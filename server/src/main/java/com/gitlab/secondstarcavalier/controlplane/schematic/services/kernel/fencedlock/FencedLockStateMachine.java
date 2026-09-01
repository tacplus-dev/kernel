// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.fencedlock;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.ratis.protocol.Message;
import org.apache.ratis.proto.RaftProtos.LogEntryProto;
import org.apache.ratis.statemachine.TransactionContext;
import org.apache.ratis.statemachine.impl.BaseStateMachine;
import org.apache.ratis.thirdparty.com.google.protobuf.ByteString;

/**
 * FencedLockStateMachine is the replicated state behind kernel's FencedLock
 * service: a map from lock key to the (holder, fencing token) currently holding
 * it. Every mutation arrives as a committed Raft log entry, so every kernel
 * instance applies the same operations in the same order and reaches the same
 * map.
 *
 * <p><b>The fencing token is the Raft log index of the granting Acquire.</b>
 * That single choice is what makes the token useful: the log index is assigned
 * by Raft consensus, is strictly increasing over the whole group, is never
 * reused, and never goes backwards across a leader change or a restart (the log
 * is durable). A resource owner that records the highest token it has honoured
 * can therefore reject a write from a stale holder — a holder that paused, lost
 * the lock, and woke up still believing it holds it — because that holder's
 * token is necessarily lower than the current one. A lock without a fencing
 * token only shrinks that race; it cannot close it.
 *
 * <p>Not thread-safe by design: Ratis applies committed transactions to a state
 * machine serially, and the map is read only from within {@link #applyTransaction}.
 */
public class FencedLockStateMachine extends BaseStateMachine {

	/** Hold is the current owner of one key. */
	private record Hold(String holderId, long fencingToken) {}

	private final Map<String, Hold> holds = new HashMap<>();

	@Override
	public CompletableFuture<Message> applyTransaction(TransactionContext trx) {
		final LogEntryProto entry = trx.getLogEntry();
		final long index = entry.getIndex();
		final byte[] op = entry.getStateMachineLogEntry().getLogData().toByteArray();

		updateLastAppliedTermIndex(entry.getTerm(), index);

		try {
			return switch (FencedLockOp.opcode(op)) {
				case FencedLockOp.ACQUIRE -> CompletableFuture.completedFuture(
						reply(applyAcquire(FencedLockOp.decodeAcquire(op), index).toByteArray()));
				case FencedLockOp.RELEASE -> CompletableFuture.completedFuture(
						reply(applyRelease(FencedLockOp.decodeRelease(op)).toByteArray()));
				default -> CompletableFuture.failedFuture(
						new IllegalArgumentException("unknown FencedLock opcode " + (char) FencedLockOp.opcode(op)));
			};
		} catch (Exception e) {
			return CompletableFuture.failedFuture(e);
		}
	}

	/**
	 * applyAcquire grants the key when it is unheld, and re-grants it — with the
	 * token already issued, not a new one — when the same holder asks again. The
	 * idempotent arm matters because Acquire is retried: a holder whose reply was
	 * lost in flight must not be told it lost a lock it actually holds, and must
	 * not have its token silently move under a resource owner that already saw it.
	 */
	private Kernel.FencedLockAcquireResponse applyAcquire(Kernel.FencedLockAcquireRequest request, long index) {
		final Hold current = holds.get(request.getKey());
		if (current != null && !current.holderId().equals(request.getHolderId())) {
			return Kernel.FencedLockAcquireResponse.newBuilder().setGranted(false).setFencingToken(0).build();
		}
		final long token = current != null ? current.fencingToken() : index;
		if (current == null) {
			holds.put(request.getKey(), new Hold(request.getHolderId(), token));
		}
		return Kernel.FencedLockAcquireResponse.newBuilder().setGranted(true).setFencingToken(token).build();
	}

	/**
	 * applyRelease drops the hold only when the presented token is the one the
	 * current holder was granted. A stale token releases nothing: that is the
	 * whole point — a holder that no longer holds the lock must not be able to
	 * unlock the holder that does.
	 */
	private Kernel.FencedLockReleaseResponse applyRelease(Kernel.FencedLockReleaseRequest request) {
		final Hold current = holds.get(request.getKey());
		final boolean ok = current != null && current.fencingToken() == request.getFencingToken();
		if (ok) {
			holds.remove(request.getKey());
		}
		return Kernel.FencedLockReleaseResponse.newBuilder().setOk(ok).build();
	}

	private static Message reply(byte[] bytes) {
		return Message.valueOf(ByteString.copyFrom(bytes));
	}
}
