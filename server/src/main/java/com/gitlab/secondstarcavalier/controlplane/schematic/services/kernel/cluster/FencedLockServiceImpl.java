// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.fencedlock.RatisFencedLock;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.FencedLock;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;

import java.io.IOException;

/**
 * FencedLockServiceImpl is the s2s edge of kernel's FencedLock primitive: it
 * hands the request to the embedded Ratis peer and returns what the replicated
 * state machine decided.
 *
 * <p>There is deliberately no logic here. A "not granted" and a "release
 * refused" are ordinary replicated answers, not errors — only a failure to
 * reach consensus is an error, and that is the one case that becomes a
 * {@code ProtoException}.
 */
public class FencedLockServiceImpl implements FencedLock.FencedLockHandler {

	private final RatisFencedLock lock;

	public FencedLockServiceImpl(RatisFencedLock lock) {
		this.lock = lock;
	}

	@Override
	public Kernel.FencedLockAcquireResponse acquire(Caller caller, Kernel.FencedLockAcquireRequest request)
			throws ProtoException {
		try {
			return lock.acquire(request);
		} catch (IOException e) {
			throw new ProtoException(ProtoException.UNAVAILABLE,
					"FencedLock could not reach consensus on acquire: " + e.getMessage(), e);
		}
	}

	@Override
	public Kernel.FencedLockReleaseResponse release(Caller caller, Kernel.FencedLockReleaseRequest request)
			throws ProtoException {
		try {
			return lock.release(request);
		} catch (IOException e) {
			throw new ProtoException(ProtoException.UNAVAILABLE,
					"FencedLock could not reach consensus on release: " + e.getMessage(), e);
		}
	}
}
