// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.elvis.raft;

import org.apache.ratis.proto.RaftProtos;
import org.apache.ratis.protocol.Message;
import org.apache.ratis.protocol.RaftGroupId;
import org.apache.ratis.server.RaftServer;
import org.apache.ratis.server.protocol.TermIndex;
import org.apache.ratis.server.storage.RaftStorage;
import org.apache.ratis.statemachine.TransactionContext;
import org.apache.ratis.statemachine.impl.BaseStateMachine;
import org.apache.ratis.statemachine.impl.SimpleStateMachineStorage;
import org.apache.ratis.statemachine.impl.SingleFileSnapshotInfo;
import org.apache.ratis.thirdparty.com.google.protobuf.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Raft state machine for distributed fenced locks.
 *
 * <p>Commands are simple text messages:
 * <ul>
 *   <li>{@code ACQUIRE:<lockName>:<owner>} — acquire or re-enter the lock</li>
 *   <li>{@code RELEASE:<lockName>:<owner>} — release the lock</li>
 *   <li>{@code QUERY:<lockName>} — query current lock state</li>
 * </ul>
 *
 * <p>Each successful acquire increments a monotonic fence token.
 */
public class LockStateMachine extends BaseStateMachine {

    private static final Logger logger = LoggerFactory.getLogger(LockStateMachine.class);

    private final SimpleStateMachineStorage storage = new SimpleStateMachineStorage();
    private final Map<String, LockState> locks = new ConcurrentHashMap<>();
    private final AtomicLong fenceCounter = new AtomicLong(0);

    static class LockState implements Serializable {
        String owner;
        long fenceToken;
        int reentrantCount;

        LockState(String owner, long fenceToken) {
            this.owner = owner;
            this.fenceToken = fenceToken;
            this.reentrantCount = 1;
        }
    }

    @Override
    public void initialize(RaftServer server, RaftGroupId groupId, RaftStorage raftStorage)
            throws IOException {
        super.initialize(server, groupId, raftStorage);
        storage.init(raftStorage);
        loadSnapshot(storage.getLatestSnapshot());
    }

    @Override
    public CompletableFuture<Message> applyTransaction(TransactionContext trx) {
        RaftProtos.LogEntryProto entry = trx.getLogEntry();
        String command = entry.getStateMachineLogEntry().getLogData().toStringUtf8();
        String[] parts = command.split(":", 3);
        String response;

        try {
            switch (parts[0]) {
                case "ACQUIRE":
                    response = handleAcquire(parts[1], parts[2]);
                    break;
                case "RELEASE":
                    response = handleRelease(parts[1], parts[2]);
                    break;
                case "QUERY":
                    response = handleQuery(parts[1]);
                    break;
                default:
                    response = "ERROR:unknown command";
            }
        } catch (Exception e) {
            response = "ERROR:" + e.getMessage();
        }

        updateLastAppliedTermIndex(entry.getTerm(), entry.getIndex());
        return CompletableFuture.completedFuture(
                Message.valueOf(ByteString.copyFromUtf8(response)));
    }

    private String handleAcquire(String lockName, String owner) {
        LockState state = locks.get(lockName);
        if (state == null) {
            long fence = fenceCounter.incrementAndGet();
            locks.put(lockName, new LockState(owner, fence));
            return "OK:" + fence;
        }
        if (state.owner.equals(owner)) {
            state.reentrantCount++;
            return "OK:" + state.fenceToken;
        }
        return "LOCKED:" + state.owner + ":" + state.fenceToken;
    }

    private String handleRelease(String lockName, String owner) {
        LockState state = locks.get(lockName);
        if (state == null) {
            return "OK:not_held";
        }
        if (!state.owner.equals(owner)) {
            return "ERROR:not_owner";
        }
        state.reentrantCount--;
        if (state.reentrantCount <= 0) {
            locks.remove(lockName);
        }
        return "OK:released";
    }

    private String handleQuery(String lockName) {
        LockState state = locks.get(lockName);
        if (state == null) {
            return "FREE";
        }
        return "HELD:" + state.owner + ":" + state.fenceToken + ":" + state.reentrantCount;
    }

    @Override
    public long takeSnapshot() {
        TermIndex termIndex = getLastAppliedTermIndex();
        if (termIndex == null) {
            return -1;
        }
        final long endIndex = termIndex.getIndex();
        try {
            File snapshotFile = storage.getSnapshotFile(termIndex.getTerm(), endIndex);
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(snapshotFile))) {
                out.writeLong(fenceCounter.get());
                out.writeInt(locks.size());
                for (Map.Entry<String, LockState> e : locks.entrySet()) {
                    out.writeUTF(e.getKey());
                    out.writeObject(e.getValue());
                }
            }
        } catch (IOException e) {
            logger.error("Failed to take snapshot", e);
        }
        return endIndex;
    }

    private void loadSnapshot(SingleFileSnapshotInfo info) {
        if (info == null) {
            return;
        }
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(info.getFile().getPath().toFile()))) {
            fenceCounter.set(in.readLong());
            int count = in.readInt();
            locks.clear();
            for (int i = 0; i < count; i++) {
                String key = in.readUTF();
                LockState state = (LockState) in.readObject();
                locks.put(key, state);
            }
            logger.info("Loaded snapshot with {} locks, fence={}", count, fenceCounter.get());
        } catch (Exception e) {
            logger.error("Failed to load snapshot", e);
        }
    }
}
