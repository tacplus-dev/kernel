// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

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
