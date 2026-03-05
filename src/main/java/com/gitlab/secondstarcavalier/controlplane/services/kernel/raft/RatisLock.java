// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.raft;

import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Lock;

import java.util.concurrent.TimeUnit;

/**
 * Distributed fenced lock backed by Ratis consensus.
 * Implements the {@link Lock} interface so generated code never touches Ratis
 * types directly.
 *
 * <p>Each thread tracks its own fence token via a ThreadLocal. The fence token
 * is a monotonically increasing value assigned by the Raft state machine on
 * each successful acquire, preventing stale lock holders from corrupting state.
 */
public class RatisLock implements Lock {

    private final RatisLockManager manager;
    private final String lockName;
    private final ThreadLocal<Long> fenceToken = new ThreadLocal<>();

    public RatisLock(RatisLockManager manager, String lockName) {
        this.manager = manager;
        this.lockName = lockName;
    }

    /** Returns the fence token for the current thread, or -1 if not held. */
    public long getFenceToken() {
        Long token = fenceToken.get();
        return token != null ? token : -1;
    }

    @Override
    public void lock() {
        while (true) {
            long token = manager.acquire(lockName);
            if (token >= 0) {
                fenceToken.set(token);
                return;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while waiting for lock: " + lockName, e);
            }
        }
    }

    @Override
    public void lockInterruptibly() throws InterruptedException {
        while (true) {
            long token = manager.acquire(lockName);
            if (token >= 0) {
                fenceToken.set(token);
                return;
            }
            Thread.sleep(50);
        }
    }

    @Override
    public boolean tryLock() {
        long token = manager.acquire(lockName);
        if (token >= 0) {
            fenceToken.set(token);
            return true;
        }
        return false;
    }

    @Override
    public boolean tryLock(long time, TimeUnit unit) throws InterruptedException {
        long deadline = System.nanoTime() + unit.toNanos(time);
        while (System.nanoTime() < deadline) {
            long token = manager.acquire(lockName);
            if (token >= 0) {
                fenceToken.set(token);
                return true;
            }
            Thread.sleep(10);
        }
        return false;
    }

    @Override
    public void unlock() {
        manager.release(lockName);
        fenceToken.remove();
    }

    @Override
    public boolean isLocked() {
        String state = manager.query(lockName);
        return state != null && state.startsWith("HELD:");
    }

    @Override
    public boolean isLockedByCurrentThread() {
        String state = manager.query(lockName);
        if (state == null || !state.startsWith("HELD:")) {
            return false;
        }
        String owner = state.split(":")[1];
        return owner.equals(manager.getOwnerId());
    }

    @Override
    public int getLockCount() {
        String state = manager.query(lockName);
        if (state == null || !state.startsWith("HELD:")) {
            return 0;
        }
        String[] parts = state.split(":");
        return parts.length >= 4 ? Integer.parseInt(parts[3]) : 1;
    }
}
