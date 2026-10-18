// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.fencedlock;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.ratis.protocol.Message;
import org.apache.ratis.protocol.RaftGroupId;
import org.apache.ratis.proto.RaftProtos.LogEntryProto;
import org.apache.ratis.server.RaftServer;
import org.apache.ratis.server.protocol.TermIndex;
import org.apache.ratis.server.raftlog.RaftLog;
import org.apache.ratis.server.storage.RaftStorage;
import org.apache.ratis.statemachine.StateMachineStorage;
import org.apache.ratis.statemachine.TransactionContext;
import org.apache.ratis.statemachine.impl.BaseStateMachine;
import org.apache.ratis.statemachine.impl.SimpleStateMachineStorage;
import org.apache.ratis.statemachine.impl.SingleFileSnapshotInfo;
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
 * <p>The holder recorded against a key is the identity kernel verified for the
 * RPC, carried into the log by {@link FencedLockOp}. It is never the
 * client-supplied {@code holder_id} field, which any authenticated caller could
 * set to somebody else's id.
 *
 * <p><b>A hold has no lease and nothing sweeps it.</b> That is the contract, not
 * an omission: the safety of this lock rests on the fencing token, not on the
 * hold being short-lived. A lease that expired a hold would let two processes
 * believe they hold the same key at the same time, and the whole point of
 * handing out a monotonic token is that the resource owner — not kernel —
 * settles that race by rejecting the lower token. Expiring holds here would add
 * a second, weaker arbiter of the same question. The cost is that a holder that
 * dies without releasing leaves its key held; recovering it is an operator
 * action, and kernel deliberately exposes no way for one caller to take a key
 * from another (see {@link #applyRelease}).
 *
 * <p>Not thread-safe by design: Ratis applies committed transactions to a state
 * machine serially, and the map is read only from within {@link #applyTransaction}.
 *
 * <p>The map is snapshotted so the Raft log has a purge point — see
 * {@link #takeSnapshot()}.
 */
public class FencedLockStateMachine extends BaseStateMachine {

	/**
	 * Hold is the current owner of one key. It carries no expiry: see the
	 * lease-free contract on the class.
	 */
	private record Hold(String holderId, long fencingToken) {}

	private final Map<String, Hold> holds = new HashMap<>();

	private final SimpleStateMachineStorage storage = new SimpleStateMachineStorage();

	@Override
	public void initialize(RaftServer server, RaftGroupId groupId, RaftStorage raftStorage) throws IOException {
		super.initialize(server, groupId, raftStorage);
		storage.init(raftStorage);
		loadSnapshot(storage.getLatestSnapshot());
	}

	@Override
	public void reinitialize() throws IOException {
		loadSnapshot(storage.getLatestSnapshot());
	}

	@Override
	public StateMachineStorage getStateMachineStorage() {
		return storage;
	}

	/**
	 * takeSnapshot writes the whole holds map, which is what lets Ratis purge the
	 * log. Without it nothing ever gives Ratis a purge point: the segment log
	 * accumulates every Acquire and Release for the life of the cluster, and every
	 * restart replays the lot from index 0 — on the service that gates cluster
	 * leadership.
	 *
	 * <p>Snapshotting is safe for the {@link FencedLockOp#RELEASE_UNVERIFIED}
	 * compatibility path. That opcode exists so entries written by a pre-hardening
	 * kernel still DECODE during replay; a snapshot records the state those
	 * entries already produced, so purging them loses nothing. Fencing tokens
	 * survive too, because a token is the Raft log index that granted it and the
	 * index is preserved in the snapshot's last-applied term/index — the next
	 * grant is still numbered above every token already handed out.
	 *
	 * @return the log index the snapshot covers, or {@link RaftLog#INVALID_LOG_INDEX}
	 *         when nothing has been applied yet
	 */
	@Override
	public long takeSnapshot() throws IOException {
		final TermIndex last = getLastAppliedTermIndex();
		if (last == null) {
			return RaftLog.INVALID_LOG_INDEX;
		}
		final File file = storage.getSnapshotFile(last.getTerm(), last.getIndex());
		try (DataOutputStream out = new DataOutputStream(
				new BufferedOutputStream(new FileOutputStream(file)))) {
			out.writeInt(holds.size());
			for (Map.Entry<String, Hold> e : holds.entrySet()) {
				writeString(out, e.getKey());
				writeString(out, e.getValue().holderId());
				out.writeLong(e.getValue().fencingToken());
			}
		}
		return last.getIndex();
	}

	/** loadSnapshot replaces the in-memory holds with the ones the snapshot recorded. */
	private void loadSnapshot(SingleFileSnapshotInfo snapshot) throws IOException {
		if (snapshot == null) {
			return;
		}
		final File file = snapshot.getFile().getPath().toFile();
		if (!file.exists()) {
			throw new FileNotFoundException("FencedLock snapshot " + file + " is listed but missing");
		}
		final Map<String, Hold> loaded = new HashMap<>();
		try (DataInputStream in = new DataInputStream(
				new BufferedInputStream(new FileInputStream(file)))) {
			final int count = in.readInt();
			for (int i = 0; i < count; i++) {
				final String key = readString(in);
				final String holderId = readString(in);
				loaded.put(key, new Hold(holderId, in.readLong()));
			}
		}
		holds.clear();
		holds.putAll(loaded);
		setLastAppliedTermIndex(SimpleStateMachineStorage.getTermIndexFromSnapshotFile(file));
	}

	private static void writeString(DataOutputStream out, String value) throws IOException {
		// Length-prefixed UTF-8 rather than writeUTF: a lock key is caller-chosen
		// and writeUTF caps at 64KB.
		final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		out.writeInt(bytes.length);
		out.write(bytes);
	}

	private static String readString(DataInputStream in) throws IOException {
		final byte[] bytes = new byte[in.readInt()];
		in.readFully(bytes);
		return new String(bytes, StandardCharsets.UTF_8);
	}

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
				case FencedLockOp.RELEASE -> {
					final FencedLockOp.Release release = FencedLockOp.decodeRelease(op);
					yield CompletableFuture.completedFuture(
							reply(applyRelease(release.holderId(), release.request()).toByteArray()));
				}
				case FencedLockOp.RELEASE_UNVERIFIED -> CompletableFuture.completedFuture(
						reply(applyUnverifiedRelease(FencedLockOp.decodeUnverifiedRelease(op)).toByteArray()));
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
	 *
	 * <p>The {@code holder_id} read here is the one {@link FencedLockOp} wrote
	 * from the verified caller, not whatever the client put in the field.
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
	 * applyRelease drops the hold only when the caller is the current holder AND
	 * the presented token is the one that holder was granted. A stale token
	 * releases nothing: that is the whole point — a holder that no longer holds
	 * the lock must not be able to unlock the holder that does. The identity
	 * check is the other half of the same rule: the fencing token is a Raft log
	 * index, so it is guessable, and a token alone must not be enough to unlock
	 * somebody else's key.
	 *
	 * @param holderId the caller kernel verified for the RPC, never a request field
	 */
	private Kernel.FencedLockReleaseResponse applyRelease(String holderId, Kernel.FencedLockReleaseRequest request) {
		final Hold current = holds.get(request.getKey());
		final boolean ok = current != null
				&& current.holderId().equals(holderId)
				&& current.fencingToken() == request.getFencingToken();
		if (ok) {
			holds.remove(request.getKey());
		}
		return Kernel.FencedLockReleaseResponse.newBuilder().setOk(ok).build();
	}

	/**
	 * applyUnverifiedRelease replays a release written before kernel carried the
	 * holder identity in the log. Replay must reproduce the history the log
	 * actually recorded, so it applies the rule that was in force when the entry
	 * was committed — token only. Nothing writes this opcode any more.
	 */
	private Kernel.FencedLockReleaseResponse applyUnverifiedRelease(Kernel.FencedLockReleaseRequest request) {
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
