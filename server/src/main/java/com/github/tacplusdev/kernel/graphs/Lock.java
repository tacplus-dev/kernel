// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

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
