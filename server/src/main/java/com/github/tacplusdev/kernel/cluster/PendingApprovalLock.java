// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

/**
 * The one mutex over the pending-approval registry ({@code PrincipalState.pending_approvals}).
 *
 * <p>It serializes a pending approval's read-check-write. One lock, static, and
 * shared by the two services that write the collection, because
 * {@code PersonalIdentityServiceImpl.createPendingApproval} proposes from the
 * C2S side and {@code IdentityServiceImpl.brokerPendingApproval} consumes from
 * the S2S side, and a lock per service would serialize nothing. It is what
 * makes an approval SINGLE-USE.
 *
 * <p>The lock object itself is private to this class: a monitor another class
 * can name is a monitor another class can hold (SpotBugs
 * {@code USO_UNSAFE_OBJECT_SYNCHRONIZATION}, kernel#62). Callers hand the
 * guarded section in instead.
 *
 * <p>It is node-local, with the same limitation every other guard in
 * {@code IdentityServiceImpl} has: two kernel nodes serving two copies of the
 * same request could each consume the same approval once. Recorded in the
 * slice's decision doc rather than papered over — the absent cluster CAS is the
 * same gap {@code seenProofJtis} has for proof replay, and closing it needs the
 * FencedLock, not a second mutex.
 */
final class PendingApprovalLock {
	private static final Object LOCK = new Object();

	private PendingApprovalLock() {
	}

	/** A guarded section that yields a value. */
	@FunctionalInterface
	interface Guarded<T, E extends Exception> {
		T call() throws E;
	}

	/** A guarded section that yields nothing. */
	@FunctionalInterface
	interface GuardedAction<E extends Exception> {
		void run() throws E;
	}

	/** Runs {@code section} holding the pending-approval lock and returns its value. */
	static <T, E extends Exception> T under(Guarded<T, E> section) throws E {
		synchronized (LOCK) {
			return section.call();
		}
	}

	/** Runs {@code section} holding the pending-approval lock. */
	static <E extends Exception> void run(GuardedAction<E> section) throws E {
		synchronized (LOCK) {
			section.run();
		}
	}
}
