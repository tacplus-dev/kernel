// Copyright (c) 2024 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.services.elvis.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Lock;
import com.hazelcast.cp.lock.FencedLock;

import java.util.concurrent.TimeUnit;

/**
 * HazelcastLock adapts a Hazelcast {@link FencedLock} to the {@link Lock}
 * interface, keeping Hazelcast types out of generated code.
 */
class HazelcastLock implements Lock {

    private final FencedLock delegate;

    HazelcastLock(FencedLock delegate) {
        this.delegate = delegate;
    }

    @Override
    public void lock() {
        delegate.lock();
    }

    @Override
    public void lockInterruptibly() throws InterruptedException {
        delegate.lockInterruptibly();
    }

    @Override
    public boolean tryLock() {
        return delegate.tryLock();
    }

    @Override
    public boolean tryLock(long time, TimeUnit unit) throws InterruptedException {
        return delegate.tryLock(time, unit);
    }

    @Override
    public void unlock() {
        delegate.unlock();
    }

    @Override
    public boolean isLocked() {
        return delegate.isLocked();
    }

    @Override
    public boolean isLockedByCurrentThread() {
        return delegate.isLockedByCurrentThread();
    }

    @Override
    public int getLockCount() {
        return delegate.getLockCount();
    }
}
