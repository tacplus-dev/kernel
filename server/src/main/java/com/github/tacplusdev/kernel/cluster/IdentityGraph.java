// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;

import java.util.function.Predicate;

/**
 * The identity graph: XIDs, the {@code (idp_id, provider_subject)} links that
 * resolve to them, and each person's tenant memberships.
 *
 * <p>This is the contract of the people service (decision records
 * {@code identity-session-credential-2026-10-25} and
 * {@code stratum-per-tenant-2026-10-25}): a service in the {@code people}
 * tenant owns the graph on that tenant's Stratum, and kernel calls it. Until
 * that service exists, {@link KernelIdentityGraph} implements this contract on
 * kernel's own state, so moving the graph is swapping the implementation, not
 * changing a caller. Every write here is one of the record's: the first-login
 * create, a membership the first time an org routes a person, Link (merge),
 * Unlink, delete account and sign out everywhere, and a device enrolled on or
 * revoked from a person. Everything else kernel does
 * with identity — the session credential, its proofs, Merge and Unmerge, the
 * per-tenant exchange — is stateless and stays in kernel.
 *
 * <p>Each operation is atomic on its own. The invariants are per entry: a link
 * key resolves to at most one XID, and an XID is never reused.
 */
interface IdentityGraph {

	/** A login's person, and whether this call created it (the XID began here). */
	record Resolved(Kernel.Person person, boolean created) {
	}

	/**
	 * The person a verified login resolves to, created on first sight with this
	 * link and the {@code people} membership. Refuses a disabled or deleted
	 * person, and a new person while sign-ups are paused.
	 */
	Resolved resolveOrCreate(String idpId, String providerSubject) throws IdentityServiceImpl.StatusException;

	/**
	 * Records that {@code tenantNamespace}'s IdP routed this person into it, the
	 * first time; later calls read and write nothing. A revoked membership is
	 * refused, never revived.
	 */
	Kernel.Person addMembership(String xid, String tenantNamespace) throws IdentityServiceImpl.StatusException;

	/** The person with this XID, or the default (empty) instance when there is none. */
	Kernel.Person person(String xid);

	/** The XID a link resolves to, or {@code ""} when the link is not bound. */
	String xidForLink(String idpId, String providerSubject);

	/**
	 * Link: the loser's links and memberships move to the survivor, its index
	 * rows are repointed, and it is tombstoned with a redirect. {@code mayAbsorb}
	 * is evaluated on the loser as stored at the moment of the write; when it
	 * refuses, nothing moves and FAILED_PRECONDITION is thrown.
	 */
	Kernel.Person mergePeople(String survivorXid, String loserXid, Predicate<Kernel.Person> mayAbsorb)
			throws IdentityServiceImpl.StatusException;

	/** Unlink: removes one link from the person; the next login with it starts a new person. */
	Kernel.Person removeLink(String xid, String idpId, String providerSubject) throws IdentityServiceImpl.StatusException;

	/** Delete account: every link revoked, the generation bumped, the person tombstoned. */
	void deleteAccount(String xid) throws IdentityServiceImpl.StatusException;

	/** Sign out everywhere: one bump of the person's generation. */
	Kernel.Person bumpGeneration(String xid) throws IdentityServiceImpl.StatusException;

	/**
	 * The person holding the device credential {@code credentialId} (revoked or
	 * not), or the default (empty) instance when no person does. One key belongs
	 * to at most one person.
	 */
	Kernel.Person deviceOwner(String credentialId);

	/**
	 * Enrols a device credential on the person. Enrolling one the person already
	 * holds changes nothing; one held by another person, a revoked one, or one
	 * past the per-person cap is refused.
	 */
	Kernel.Person addDevice(String xid, Kernel.PersonalCredential credential)
			throws IdentityServiceImpl.StatusException;

	/**
	 * Marks one of the person's device credentials revoked and returns it;
	 * NOT_FOUND when the person holds no such credential. Revoking twice returns
	 * the mark already there.
	 */
	Kernel.PersonalCredential revokeDevice(String xid, String credentialId)
			throws IdentityServiceImpl.StatusException;
}
