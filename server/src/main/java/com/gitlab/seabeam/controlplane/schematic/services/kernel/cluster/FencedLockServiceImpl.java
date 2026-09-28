// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.fencedlock.RatisFencedLock;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.FencedLock;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;

import java.io.IOException;

/**
 * FencedLockServiceImpl is the s2s edge of kernel's FencedLock primitive: it
 * hands the request to the embedded Ratis peer and returns what the replicated
 * state machine decided.
 *
 * <p>There is deliberately no logic here beyond one thing: <b>the holder is the
 * verified caller</b>. Who holds a lock — and therefore who may release it — is
 * taken from the token the authorizer verified for this RPC, never from the
 * request's {@code holder_id} field. The field is client-supplied, so trusting
 * it would let any authenticated service acquire or release a lock under
 * another service's identity.
 *
 * <p>Otherwise the handler is a pass-through. A "not granted" and a "release
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
		final String holderId = verifiedHolderId(caller);
		try {
			return lock.acquire(holderId, request);
		} catch (IOException e) {
			throw new ProtoException(ProtoException.UNAVAILABLE,
					"FencedLock could not reach consensus on acquire: " + e.getMessage(), e);
		}
	}

	@Override
	public Kernel.FencedLockReleaseResponse release(Caller caller, Kernel.FencedLockReleaseRequest request)
			throws ProtoException {
		final String holderId = verifiedHolderId(caller);
		try {
			return lock.release(holderId, request);
		} catch (IOException e) {
			throw new ProtoException(ProtoException.UNAVAILABLE,
					"FencedLock could not reach consensus on release: " + e.getMessage(), e);
		}
	}

	/**
	 * The holder identity, out of the token's {@code sub}. A lock whose holder
	 * cannot be established is a lock nobody can be held to, so a call with no
	 * verified caller is refused rather than recorded under an empty holder that
	 * a second caller would match.
	 */
	private static String verifiedHolderId(Caller caller) throws ProtoException {
		if (caller == null) {
			throw ProtoException.newErrUnauthorized(null, "no verified caller");
		}
		final String subject = caller.getSubject();
		if (subject.isEmpty()) {
			throw ProtoException.newErrUnauthorized(null, "verified caller carries no subject");
		}
		return subject;
	}
}
