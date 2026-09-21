// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.PersonalIdentity;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private final PrincipalMap principalMap;
	private final Runnable persistState;

	/**
	 * @param principalMap kernel PrincipalState accessor (personal_principals, keyed by principal_id)
	 * @param persistState fires the disk snapshot after a write; nullable, for tests that
	 *                     assert on the live map rather than on durability
	 */
	public PersonalIdentityServiceImpl(PrincipalMap principalMap, Runnable persistState) {
		this.principalMap = principalMap;
		this.persistState = persistState;
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
		if (persistState != null) {
			persistState.run();
		}
		logger.info("Unlinked tenant users: {} -x- {}", ownerKey, peerKey);
		return Kernel.RevokeTenantUserLinkResponse.newBuilder()
				.setRevokedAtMs(revokedAtMs)
				.build();
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
