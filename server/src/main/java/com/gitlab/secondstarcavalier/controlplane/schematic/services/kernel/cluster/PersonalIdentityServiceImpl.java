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

	/**
	 * @param principalMap kernel PrincipalState accessor (personal_principals, keyed by principal_id)
	 */
	public PersonalIdentityServiceImpl(PrincipalMap principalMap) {
		this.principalMap = principalMap;
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
