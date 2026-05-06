// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs;

import java.util.concurrent.TimeUnit;

/**
 * Distributed lock interface.
 */
public interface Lock {
	void lock();
	void lockInterruptibly() throws InterruptedException;
	boolean tryLock();
	boolean tryLock(long time, TimeUnit unit) throws InterruptedException;
	void unlock();
	boolean isLocked();
	boolean isLockedByCurrentThread();
	int getLockCount();
}
