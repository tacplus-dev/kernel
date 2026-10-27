// Copyright (c) 2026 Seabeam LLC. All rights reserved.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.PersonalIdentity;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

/**
 * PersonalIdentityServiceImpl is a user's own view of their approvals
 * (the {@code PersonalIdentity} C2S service). It exists because kernel state
 * RPCs are service-only, so a person cannot read or write their own
 * {@code PrincipalState} rows over the state plane.
 *
 * <p>Every call takes its owner from the caller's verified token, never from a
 * request field, so there is no field an attacker can point at somebody else.
 * ({@code GetMyIdentity}, the retired {@code /people/<pid>} principal's view of
 * itself, went with that principal in kernel#18; {@code RevokeTenantUserLink}
 * went with the tenant-user links in kernel#4.)
 */
public class PersonalIdentityServiceImpl implements PersonalIdentity.PersonalIdentityHandler {
	private static final Logger logger = LoggerFactory.getLogger(PersonalIdentityServiceImpl.class);

	/** SHA-256, the one digest {@code PendingApproval.request_hash} may be. */
	private static final int REQUEST_HASH_LENGTH = 32;

	/**
	 * How long a pending approval lives when the proposer asks for nothing
	 * specific. Long enough to unlock a phone and read a prompt, short enough
	 * that an approval nobody acted on is gone before it could be found and used.
	 */
	private static final long DEFAULT_APPROVAL_TTL_SECONDS = 120;

	/**
	 * Ceiling on a proposer's requested TTL. An approval is consent to one call
	 * happening now; past a few minutes it is a standing permission, which is the
	 * thing §5 exists to refuse. A caller asking for more gets this, not an error.
	 */
	private static final long MAX_APPROVAL_TTL_SECONDS = 600;

	/**
	 * Live approvals one person may have outstanding. This is the bound on the
	 * collection: any user token can reach this RPC, so without it one caller
	 * could fill the registry. Sixteen is far past any real UX (a prompt is
	 * answered or abandoned within the TTL) and far below anything that costs
	 * memory.
	 */
	private static final int MAX_LIVE_APPROVALS_PER_PERSON = 16;

	private final PrincipalMap principalMap;

	/**
	 * @param principalMap kernel PrincipalState accessor (pending_approvals)
	 */
	public PersonalIdentityServiceImpl(PrincipalMap principalMap) {
		this.principalMap = principalMap;
		logger.info("PersonalIdentityServiceImpl initialised");
	}

	/**
	 * Proposes something that will need a device tap (identity decision doc §5).
	 *
	 * <p>Proposing is all this does. The row it writes authorizes nothing: it is
	 * the thing {@code Mint.BrokerPendingApproval} verifies a device signature
	 * AGAINST, and until one arrives it grants no more than the caller already
	 * had. That is why a proposer needs no privilege beyond being the user — a
	 * browser session and an agent holding a delegated token may both propose,
	 * and neither can approve.
	 *
	 * <p>The person is the CALLER'S: their verified {@code sub}, which is their
	 * XID in whichever tenant the token is for — never a request field.
	 *
	 * <p>The challenge is computed here rather than by the client: it is what the
	 * device must sign, and two implementations of the same digest are two
	 * implementations that can disagree.
	 */
	@Override
	public Kernel.CreatePendingApprovalResponse createPendingApproval(Caller caller,
			Kernel.CreatePendingApprovalRequest request) throws ProtoException {
		if (caller == null) {
			throw ProtoException.newErrUnauthorized(null, "no verified caller");
		}
		// Kernel compares this hash for equality and never re-derives it, so the
		// one thing it can usefully check is that it IS a SHA-256 digest. A short
		// or empty hash would otherwise pin an approval to nothing.
		if (request.getRequestHash().size() != REQUEST_HASH_LENGTH) {
			throw ProtoException.newErrMissingInvalidData(null,
					"request_hash must be a %d-byte SHA-256 digest", REQUEST_HASH_LENGTH);
		}
		// The minted pair as it stands in the token, not a re-derivation of it —
		// the same reason revokeTenantUserLink reads the claims directly.
		String personKey = IdentityServiceImpl.personUserKey(caller.getSubject());
		if (personKey == null) {
			// A caller who is not an XID has no devices to approve with.
			throw ProtoException.newErrPermissionDenied(null, "the caller is not a person");
		}

		long nowMs = System.currentTimeMillis();
		long ttlSeconds = request.getTtlSeconds() <= 0
				? DEFAULT_APPROVAL_TTL_SECONDS
				: Math.min(request.getTtlSeconds(), MAX_APPROVAL_TTL_SECONDS);
		String approvalId = UUID.randomUUID().toString();
		Kernel.PendingApproval approval = Kernel.PendingApproval.newBuilder()
				.setApprovalId(approvalId)
				.setPersonUserKey(personKey)
				.setRpcMethod(request.getRpcMethod())
				.setRequestHash(request.getRequestHash())
				.setCreatedAtMs(nowMs)
				.setExpiresAtMs(nowMs + ttlSeconds * 1000)
				.build();

		synchronized (IdentityServiceImpl.PENDING_APPROVAL_LOCK) {
			if (sweepExpired(nowMs, personKey) >= MAX_LIVE_APPROVALS_PER_PERSON) {
				throw ProtoException.newErrResourceExhausted(
						"too many pending approvals; answer or abandon one first");
			}
			principalMap.putPendingApprovals(approvalId, approval);
		}
		logger.info("Pending approval created: rpc={} person={} ttl={}s",
				request.getRpcMethod(), personKey, ttlSeconds);
		return Kernel.CreatePendingApprovalResponse.newBuilder()
				.setApprovalId(approvalId)
				.setExpiresAtMs(approval.getExpiresAtMs())
				.setChallenge(WebauthnProof.approvalBinding(approvalId, request.getRpcMethod(),
						request.getRequestHash().toByteArray()))
				.build();
	}

	/**
	 * Deletes every approval whose expiry has passed and returns how many LIVE
	 * ones {@code personKey} still has.
	 *
	 * <p>This is the whole cleanup story, and it is here rather than in a timer
	 * or in stratum's record lifecycle because creation is the only path that
	 * grows the collection: sweeping on it keeps the registry proportional to the
	 * approvals actually outstanding in one TTL window, with no scheduler to own
	 * and nothing to notice if it stops running. Kernel's registries are not
	 * stratum records — no {@code (spec.record)}, no retention tier to configure
	 * — and an approval is never read by anything but this service.
	 *
	 * <p>An expired row is DELETED rather than marked: unlike a link or a
	 * membership there is nothing to audit in "nobody tapped it", and the audit
	 * that matters — a tap that was accepted — belongs to the RPC the approval
	 * let through. A CONSUMED row is kept until it expires, so a replay inside
	 * the window is refused as already used rather than as an unknown id.
	 *
	 * <p>Call under {@link IdentityServiceImpl#PENDING_APPROVAL_LOCK}.
	 */
	private int sweepExpired(long nowMs, String personKey) throws ProtoException {
		int live = 0;
		for (Kernel.PendingApproval row : principalMap.proto().getPendingApprovalsList()) {
			if (row.getExpiresAtMs() <= nowMs) {
				principalMap.deletePendingApprovals(row.getApprovalId());
				continue;
			}
			if (row.getConsumedAtMs() == 0 && personKey.equals(row.getPersonUserKey())) {
				live++;
			}
		}
		return live;
	}
}
