// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.PersonalIdentity;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

/**
 * PersonalIdentityServiceImpl is a personal principal's own view of itself (the
 * {@code PersonalIdentity} C2S service). It exists because kernel state RPCs are
 * service-only, so a person cannot read their own {@code PrincipalState} row over
 * the state plane.
 *
 * <p>{@code GetMyIdentity} takes no principal argument by construction: the
 * principal is resolved from the caller's verified token subject, so there is no
 * field an attacker can point at somebody else. The subject must be a person
 * identity ({@code spiffe://<td>/people/&lt;pid&gt;/users/&lt;pid&gt;}, namespace
 * {@code /people/&lt;pid&gt;}); every other caller shape is refused.
 *
 * <p>Registration — how a {@code PersonalPrincipal} row first appears — is a
 * separate item and does not exist yet, so today every call reaches the
 * NOT_FOUND arm. That is the honest answer: nothing mints a
 * {@code /people/&lt;pid&gt;} token, and fabricating a default identity would
 * invent an authorization record.
 */
public class PersonalIdentityServiceImpl implements PersonalIdentity.PersonalIdentityHandler {
	private static final Logger logger = LoggerFactory.getLogger(PersonalIdentityServiceImpl.class);

	/** Canonical root of the personal-principal subtree. */
	private static final String PEOPLE_PREFIX = "/" + Spiffe.PEOPLE_SEGMENT + "/";

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
	private final Runnable writeIdentitySnapshot;

	/**
	 * @param principalMap kernel PrincipalState accessor (personal_principals, keyed by principal_id)
	 * @param writeIdentitySnapshot writes the kernel identity snapshot to disk after a write;
	 *                              nullable, for tests that assert on the live map instead
	 */
	public PersonalIdentityServiceImpl(PrincipalMap principalMap, Runnable writeIdentitySnapshot) {
		this.principalMap = principalMap;
		this.writeIdentitySnapshot = writeIdentitySnapshot;
		logger.info("PersonalIdentityServiceImpl initialised");
	}

	@Override
	public Kernel.GetMyIdentityResponse getMyIdentity(Caller caller, Kernel.GetMyIdentityRequest request)
			throws ProtoException {
		String principalId = callerPrincipalId(caller);
		Kernel.PersonalPrincipal principal = principalMap.getPersonalPrincipals(principalId);
		// An absent row reads back as the default instance, so the key/field
		// agreement check answers "no such principal" and "the row under this key
		// is not this principal" with the same non-enumerating NOT_FOUND.
		if (!principal.getPrincipalId().equals(principalId)) {
			throw ProtoException.newErrNotFound("no personal principal");
		}

		Kernel.GetMyIdentityResponse.Builder response = Kernel.GetMyIdentityResponse.newBuilder()
				.setPrincipalId(principal.getPrincipalId());
		long nowMs = System.currentTimeMillis();
		for (Kernel.TenantMembership membership : principal.getMembershipsList()) {
			if (isLive(membership, nowMs)) {
				response.addMemberships(membership);
			}
		}
		return response.build();
	}

	/**
	 * Unlink: marks the caller's own edge to the named peer revoked, in both
	 * directions.
	 *
	 * <p>The owning side is the caller's verified {@code sub} and the namespace
	 * inside it — never a request field, for the same reason
	 * {@link #getMyIdentity} takes no argument. The request names only the peer,
	 * so the worst a caller can do with it is revoke a link they already hold.
	 *
	 * <p>Both directions, because the mint reads the registry by the caller's own
	 * key: a mark on one row only would leave the other side's token still
	 * carrying the {@code linked} claim, which is the entire thing unlink exists
	 * to withdraw.
	 *
	 * <p>Marked, never deleted. A link is proved once by two live credentials and
	 * nothing kernel holds can re-derive it, so a deleted edge is
	 * indistinguishable from one that was never proved — see
	 * {@code TenantUserLink.revoked_at_ms}.
	 */
	@Override
	public Kernel.RevokeTenantUserLinkResponse revokeTenantUserLink(Caller caller,
			Kernel.RevokeTenantUserLinkRequest request) throws ProtoException {
		if (caller == null) {
			throw ProtoException.newErrUnauthorized(null, "no verified caller");
		}
		// The registry is keyed on the pair kernel MINTED — the `namespace` and
		// `sub` claims as they stand in the token — not on anything re-derived
		// from the subject. Deriving would disagree for exactly the callers §2
		// built the key this way for: an ordinary tenant's `sub` is whatever its
		// IdP broker supplied and need not be a SPIFFE id at all.
		String ownerSubject = caller.getSubject();
		String ownerNamespace = caller.getNamespace();
		if (ownerSubject.isEmpty() || ownerNamespace.isEmpty()) {
			throw ProtoException.newErrPermissionDenied(null, "caller is not a linkable identity");
		}
		String ownerKey = IdentityServiceImpl.linkKey(ownerNamespace, ownerSubject);
		String peerKey = IdentityServiceImpl.linkKey(
				request.getPeerNamespace(), request.getPeerSubject());

		long revokedAtMs;
		synchronized (IdentityServiceImpl.LINK_REGISTRY_LOCK) {
			revokedAtMs = markRevoked(ownerKey, request.getPeerNamespace(),
					request.getPeerSubject(), System.currentTimeMillis());
			if (revokedAtMs == 0) {
				// Non-enumerating: "no such link" and "that link is not yours" are
				// the same answer, because the owner half is the caller's own key.
				throw ProtoException.newErrNotFound("no such link");
			}
			// The mirror may legitimately be absent if a half-written pair survived
			// a crash between the two writes; marking what is there is still the
			// right outcome, and the owner's own claim has already stopped.
			markRevoked(peerKey, ownerNamespace, ownerSubject, revokedAtMs);
		}
		if (writeIdentitySnapshot != null) {
			writeIdentitySnapshot.run();
		}
		logger.info("Unlinked tenant users: {} -x- {}", ownerKey, peerKey);
		return Kernel.RevokeTenantUserLinkResponse.newBuilder()
				.setRevokedAtMs(revokedAtMs)
				.build();
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
	 * <p>The person is the CALLER'S, resolved from their verified claims through
	 * the link registry — never a request field, for the same reason
	 * {@link #getMyIdentity} takes none.
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
		String personKey = IdentityServiceImpl.personUserKey(
				principalMap, caller.getNamespace(), caller.getSubject());
		if (personKey == null) {
			// One answer for "not linked to a person" and "linked to more than
			// one": neither caller can be approved for, and distinguishing them
			// would report on links the caller cannot see.
			throw ProtoException.newErrPermissionDenied(null,
					"the caller is not linked to exactly one person");
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

	/**
	 * Marks one edge out of {@code ownerKey} revoked and returns the mark, or 0
	 * if there is no such edge. An edge that was already revoked returns the mark
	 * it already carried — unlinking twice is the same fact, not an error.
	 *
	 * <p>Call under {@link IdentityServiceImpl#LINK_REGISTRY_LOCK}.
	 */
	private long markRevoked(String ownerKey, String peerNamespace, String peerSubject,
			long nowMs) throws ProtoException {
		Kernel.TenantUserLinks row = principalMap.getTenantUserLinks(ownerKey);
		for (int i = 0; i < row.getLinksCount(); i++) {
			Kernel.TenantUserLink link = row.getLinks(i);
			if (!link.getPeerNamespace().equals(peerNamespace)
					|| !link.getPeerSubject().equals(peerSubject)) {
				continue;
			}
			if (link.getRevokedAtMs() != 0) {
				return link.getRevokedAtMs();
			}
			principalMap.putTenantUserLinks(ownerKey, row.toBuilder()
					.setLinks(i, link.toBuilder().setRevokedAtMs(nowMs))
					.build());
			return nowMs;
		}
		return 0;
	}

	/**
	 * The caller's own principal id, out of the token's {@code sub}. Never out of
	 * a request field: {@code GetMyIdentityRequest} is empty precisely so this is
	 * the only source.
	 */
	private static String callerPrincipalId(Caller caller) throws ProtoException {
		if (caller == null) {
			throw ProtoException.newErrUnauthorized(null, "no verified caller");
		}
		String namespace;
		try {
			namespace = Spiffe.namespaceFromSpiffe(caller.getSubject());
		} catch (IllegalArgumentException e) {
			throw ProtoException.newErrPermissionDenied(null, "caller is not a personal principal");
		}
		// The person arm of the SPIFFE grammar yields exactly "/people/<pid>", so a
		// remaining separator means some other namespace shape reached here.
		if (!namespace.startsWith(PEOPLE_PREFIX)) {
			throw ProtoException.newErrPermissionDenied(null, "caller is not a personal principal");
		}
		String principalId = namespace.substring(PEOPLE_PREFIX.length());
		if (principalId.isEmpty() || principalId.contains("/")) {
			throw ProtoException.newErrPermissionDenied(null, "caller is not a personal principal");
		}
		return principalId;
	}

	/**
	 * Whether a membership is live, as the mint path defines it: not revoked and
	 * not expired. Zero means "never" for both marks — a revocation and an expiry
	 * are recorded by being set, and the response's own contract is the caller's
	 * LIVE memberships.
	 */
	private static boolean isLive(Kernel.TenantMembership membership, long nowMs) {
		if (membership.getRevokedAtMs() != 0) {
			return false;
		}
		return membership.getExpiresAtMs() == 0 || membership.getExpiresAtMs() > nowMs;
	}
}
