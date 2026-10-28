// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.cluster.IdentityServiceImpl.StatusException;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;

import io.grpc.Status;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The interim {@link IdentityGraph}: the graph on kernel's own
 * {@code PrincipalState} (people and the link index), made durable by the
 * identity snapshot. It is the backend the people service replaces
 * (stratum-per-tenant-2026-10-25); nothing outside this class touches those
 * collections.
 *
 * <p>Writes are serialized on one node-local lock, like the other guards in
 * kernel that want a cluster lock and have none: two concurrent first logins
 * for one link must not mint two XIDs.
 */
final class KernelIdentityGraph implements IdentityGraph {

	private static final Logger logger = LoggerFactory.getLogger(KernelIdentityGraph.class);

	/**
	 * Cap on {@code PrincipalState.people}, matching the proto's
	 * {@code assert_max_size}: a registry grown past the bound fails validation
	 * on the way into the disk snapshot, so every later write would be lost
	 * rather than the one that overflowed.
	 */
	private static final int MAX_PEOPLE = 65536;

	/** Cap on one person's devices, matching {@code Person.devices}'s {@code assert_max_size}. */
	private static final int MAX_DEVICES_PER_PERSON = 16;

	/** Separates the two halves of a link key; neither half may contain it. */
	private static final String LINK_KEY_SEPARATOR = "|";

	private static final SecureRandom XID_RANDOM = new SecureRandom();

	/**
	 * How stale {@code Person.last_signed_in_at_ms} may get before a sign-in
	 * rewrites it. XID ageing counts in days, so an hour costs it nothing and
	 * spares the identity snapshot a write on every login.
	 */
	static final long SIGN_IN_RECORD_GRANULARITY_MS = 3_600_000L;

	private final PrincipalMap principalMap;
	private final Runnable persist;
	private final BooleanSupplier signupsPaused;
	private final LongSupplier clock;
	private final Object lock = new Object();

	/**
	 * @param principalMap  kernel's principal registry
	 * @param persist       makes a write durable (the identity snapshot)
	 * @param signupsPaused the sign-ups kill switch, read on every create
	 */
	KernelIdentityGraph(PrincipalMap principalMap, Runnable persist, BooleanSupplier signupsPaused) {
		this(principalMap, persist, signupsPaused, System::currentTimeMillis);
	}

	/** As above, with the clock every recorded time is read from (epoch ms). */
	KernelIdentityGraph(PrincipalMap principalMap, Runnable persist, BooleanSupplier signupsPaused,
			LongSupplier clock) {
		this.principalMap = principalMap;
		this.persist = persist;
		this.signupsPaused = signupsPaused;
		this.clock = clock;
	}

	/** The link index key: {@code <idp_id>|<provider_subject>}. */
	static String linkKey(String idpId, String providerSubject) {
		return idpId + LINK_KEY_SEPARATOR + providerSubject;
	}

	@Override
	public Resolved resolveOrCreate(String idpId, String providerSubject) throws StatusException {
		synchronized (lock) {
			String key = linkKey(idpId, providerSubject);
			String bound = principalMap.getIdentityLinks(key).getXid();
			if (!bound.isEmpty()) {
				Kernel.Person existing = principalMap.getPeople(bound);
				if (existing.getXid().isEmpty()) {
					// The index names a person the registry does not hold. The write
					// side cannot produce this; refuse rather than mint a second XID
					// for a link that already has one.
					throw new StatusException(Status.INTERNAL, "identity link names an unknown person");
				}
				if (existing.getDisabledAtMs() != 0 || existing.getDeletedAtMs() != 0) {
					throw new StatusException(Status.PERMISSION_DENIED, "person is disabled");
				}
				long nowMs = clock.getAsLong();
				if (nowMs - existing.getLastSignedInAtMs() < SIGN_IN_RECORD_GRANULARITY_MS) {
					return new Resolved(existing, false);
				}
				Kernel.Person signedIn = existing.toBuilder().setLastSignedInAtMs(nowMs).build();
				write(() -> principalMap.putPeople(bound, signedIn), "sign-in time");
				return new Resolved(signedIn, false);
			}
			// The sign-ups kill switch refuses the create half only: everyone with a
			// row signed in above, and a link kernel has never seen mints nothing.
			if (signupsPaused.getAsBoolean()) {
				throw new StatusException(Status.PERMISSION_DENIED, "sign-ups are paused: no new person is created");
			}
			try {
				if (principalMap.proto().getPeopleCount() >= MAX_PEOPLE) {
					throw new StatusException(Status.RESOURCE_EXHAUSTED, "people registry is full");
				}
			} catch (ProtoException e) {
				throw new StatusException(Status.INTERNAL, "principal registry unavailable");
			}
			String candidate = newXid();
			while (!principalMap.getPeople(candidate).getXid().isEmpty()) {
				// Never reused: a collision, however unlikely, must not land on an
				// existing person.
				candidate = newXid();
			}
			String xid = candidate;
			long nowMs = clock.getAsLong();
			Kernel.Person person = Kernel.Person.newBuilder()
					.setXid(xid)
					.setCreatedAtMs(nowMs)
					.setLastSignedInAtMs(nowMs)
					.addLinks(Kernel.IdentityLink.newBuilder()
							.setIdpId(idpId)
							.setProviderSubject(providerSubject)
							.setCreatedAtMs(nowMs))
					.addMemberships(Kernel.PersonMembership.newBuilder()
							.setTenantNamespace(PeopleTenant.NAMESPACE)
							.setCreatedAtMs(nowMs))
					.build();
			write(() -> {
				principalMap.putPeople(xid, person);
				principalMap.putIdentityLinks(key, Kernel.IdentityLinkRow.newBuilder()
						.setLinkKey(key).setXid(xid).build());
			}, "person");
			logger.info("Created person: xid={} idp_id={}", xid, idpId);
			return new Resolved(person, true);
		}
	}

	@Override
	public Kernel.Person addMembership(String xid, String tenantNamespace) throws StatusException {
		synchronized (lock) {
			Kernel.Person person = requirePerson(xid);
			for (Kernel.PersonMembership membership : person.getMembershipsList()) {
				if (tenantNamespace.equals(membership.getTenantNamespace())) {
					if (membership.getRevokedAtMs() != 0) {
						throw new StatusException(Status.PERMISSION_DENIED,
								"membership of " + tenantNamespace + " is revoked");
					}
					return person;
				}
			}
			Kernel.Person updated = person.toBuilder()
					.addMemberships(Kernel.PersonMembership.newBuilder()
							.setTenantNamespace(tenantNamespace)
							.setCreatedAtMs(clock.getAsLong()))
					.build();
			write(() -> principalMap.putPeople(xid, updated), "membership");
			logger.info("Recorded membership: xid={} tenant={}", xid, tenantNamespace);
			return updated;
		}
	}

	@Override
	public int removeTenantMemberships(String tenantNamespace) throws StatusException {
		synchronized (lock) {
			java.util.List<Kernel.Person> updated = new java.util.ArrayList<>();
			try {
				for (Kernel.Person person : principalMap.proto().getPeopleList()) {
					Kernel.Person.Builder kept = person.toBuilder().clearMemberships();
					for (Kernel.PersonMembership membership : person.getMembershipsList()) {
						if (!TenantIds.isWithin(membership.getTenantNamespace(), tenantNamespace)) {
							kept.addMemberships(membership);
						}
					}
					if (kept.getMembershipsCount() != person.getMembershipsCount()) {
						updated.add(kept.build());
					}
				}
			} catch (ProtoException e) {
				throw new StatusException(Status.INTERNAL, "principal registry unavailable");
			}
			if (updated.isEmpty()) {
				return 0;
			}
			write(() -> {
				for (Kernel.Person person : updated) {
					principalMap.putPeople(person.getXid(), person);
				}
			}, "membership removal");
			logger.info("Removed the memberships of deleted tenant {} from {} person(s)",
					tenantNamespace, updated.size());
			return updated.size();
		}
	}

	@Override
	public Kernel.Person person(String xid) {
		return principalMap.getPeople(xid);
	}

	@Override
	public String xidForLink(String idpId, String providerSubject) {
		return principalMap.getIdentityLinks(linkKey(idpId, providerSubject)).getXid();
	}

	@Override
	public Kernel.Person mergePeople(String survivorXid, String loserXid, Predicate<Kernel.Person> mayAbsorb)
			throws StatusException {
		synchronized (lock) {
			// Read under the lock: rows a caller saw before may have moved.
			Kernel.Person survivor = requirePerson(survivorXid);
			Kernel.Person loser = requirePerson(loserXid);
			if (!mayAbsorb.test(loser)) {
				throw new StatusException(Status.FAILED_PRECONDITION,
						"that sign-in already belongs to another account; merging moves that account into this one "
								+ "— confirm to proceed");
			}
			Kernel.Person.Builder merged = survivor.toBuilder();
			for (Kernel.IdentityLink link : loser.getLinksList()) {
				if (!hasLink(survivor, link.getIdpId(), link.getProviderSubject())) {
					merged.addLinks(link);
				}
			}
			for (Kernel.PersonMembership membership : loser.getMembershipsList()) {
				boolean present = false;
				for (Kernel.PersonMembership have : survivor.getMembershipsList()) {
					present |= have.getTenantNamespace().equals(membership.getTenantNamespace());
				}
				if (!present) {
					merged.addMemberships(membership);
				}
			}
			// The loser's devices are the survivor's now: one key, one person, so
			// they leave the tombstone rather than being copied.
			merged.addAllDevices(loser.getDevicesList());
			// A merge presents both people's sign-ins: the survivor signed in now.
			merged.setLastSignedInAtMs(clock.getAsLong());
			if (merged.getDevicesCount() > MAX_DEVICES_PER_PERSON) {
				throw new StatusException(Status.RESOURCE_EXHAUSTED,
						"the merged account would hold more than " + MAX_DEVICES_PER_PERSON + " devices");
			}
			Kernel.Person result = merged.build();
			write(() -> {
				principalMap.putPeople(survivorXid, result);
				for (Kernel.IdentityLink link : loser.getLinksList()) {
					String key = linkKey(link.getIdpId(), link.getProviderSubject());
					principalMap.putIdentityLinks(key, Kernel.IdentityLinkRow.newBuilder()
							.setLinkKey(key).setXid(survivorXid).build());
				}
				principalMap.putPeople(loserXid,
						loser.toBuilder().clearDevices().setMergedIntoXid(survivorXid).build());
			}, "merge");
			logger.info("MergePeople: xid={} absorbed into xid={} ({} link(s) moved)",
					loserXid, survivorXid, loser.getLinksCount());
			return result;
		}
	}

	@Override
	public Kernel.Person removeLink(String xid, String idpId, String providerSubject) throws StatusException {
		synchronized (lock) {
			Kernel.Person person = requirePerson(xid);
			if (!hasLink(person, idpId, providerSubject)) {
				throw new StatusException(Status.NOT_FOUND, "that sign-in is not linked to this account");
			}
			Kernel.Person.Builder updated = person.toBuilder().clearLinks();
			for (Kernel.IdentityLink link : person.getLinksList()) {
				if (!(link.getIdpId().equals(idpId) && link.getProviderSubject().equals(providerSubject))) {
					updated.addLinks(link);
				}
			}
			Kernel.Person result = updated.build();
			String key = linkKey(idpId, providerSubject);
			write(() -> {
				principalMap.putPeople(xid, result);
				if (xid.equals(principalMap.getIdentityLinks(key).getXid())) {
					principalMap.deleteIdentityLinks(key);
				}
			}, "unlink");
			logger.info("Unlinked: xid={} idp_id={}", xid, idpId);
			return result;
		}
	}

	@Override
	public void deleteAccount(String xid) throws StatusException {
		synchronized (lock) {
			Kernel.Person person = requirePerson(xid);
			tombstone(person, "account deletion");
			logger.info("Deleted account: xid={} ({} link(s) revoked)", xid, person.getLinksCount());
		}
	}

	@Override
	public List<String> ageOut(long signedInBeforeMs) throws StatusException {
		List<Kernel.Person> people;
		try {
			people = principalMap.proto().getPeopleList();
		} catch (ProtoException e) {
			// Fail closed: a sweep that cannot read the people ages out nobody.
			throw new StatusException(Status.INTERNAL, "principal registry unavailable");
		}
		List<String> agedOut = new ArrayList<>();
		for (Kernel.Person listed : people) {
			synchronized (lock) {
				// Read again under the lock: a sign-in since the listing resets the clock.
				Kernel.Person person = principalMap.getPeople(listed.getXid());
				if (person.getXid().isEmpty() || person.getDisabledAtMs() != 0 || person.getDeletedAtMs() != 0
						|| !person.getMergedIntoXid().isEmpty()) {
					continue;
				}
				if (person.getLastSignedInAtMs() == 0) {
					// No recorded sign-in (a person from before kernel#20): the
					// clock starts now rather than the person being aged out on a
					// time kernel never read.
					Kernel.Person started = person.toBuilder().setLastSignedInAtMs(clock.getAsLong()).build();
					write(() -> principalMap.putPeople(person.getXid(), started), "sign-in time");
					continue;
				}
				if (person.getLastSignedInAtMs() >= signedInBeforeMs) {
					continue;
				}
				tombstone(person, "XID ageing");
				agedOut.add(person.getXid());
				logger.info("Aged out: xid={} last signed in at {} ({} link(s) revoked)",
						person.getXid(), Instant.ofEpochMilli(person.getLastSignedInAtMs()),
						person.getLinksCount());
			}
		}
		return agedOut;
	}

	/**
	 * Delete account's write: every link revoked, the generation bumped, the
	 * person tombstoned (the row kept, so the XID is never reused). The devices
	 * go with the links: a deleted person's keys authenticate nobody, and the
	 * same key may be enrolled on a new person later.
	 */
	private void tombstone(Kernel.Person person, String what) throws StatusException {
		String xid = person.getXid();
		Kernel.Person tombstone = person.toBuilder()
				.clearLinks()
				.clearDevices()
				.setGeneration(person.getGeneration() + 1)
				.setDeletedAtMs(clock.getAsLong())
				.build();
		write(() -> {
			for (Kernel.IdentityLink link : person.getLinksList()) {
				String key = linkKey(link.getIdpId(), link.getProviderSubject());
				if (xid.equals(principalMap.getIdentityLinks(key).getXid())) {
					principalMap.deleteIdentityLinks(key);
				}
			}
			principalMap.putPeople(xid, tombstone);
		}, what);
	}

	@Override
	public Kernel.Person bumpGeneration(String xid) throws StatusException {
		synchronized (lock) {
			Kernel.Person person = requirePerson(xid);
			Kernel.Person updated = person.toBuilder().setGeneration(person.getGeneration() + 1).build();
			write(() -> principalMap.putPeople(xid, updated), "generation");
			logger.info("Signed out everywhere: xid={} generation={}", xid, updated.getGeneration());
			return updated;
		}
	}

	@Override
	public Kernel.Person deviceOwner(String credentialId) {
		try {
			for (Kernel.Person person : principalMap.proto().getPeopleList()) {
				for (Kernel.PersonalCredential device : person.getDevicesList()) {
					if (credentialId.equals(device.getCredentialId())) {
						return person;
					}
				}
			}
		} catch (ProtoException e) {
			logger.warn("people registry unavailable: {}", e.getMessage());
		}
		return Kernel.Person.getDefaultInstance();
	}

	@Override
	public Kernel.Person addDevice(String xid, Kernel.PersonalCredential credential) throws StatusException {
		synchronized (lock) {
			Kernel.Person person = requirePerson(xid);
			Kernel.Person owner = deviceOwner(credential.getCredentialId());
			if (!owner.getXid().isEmpty() && !owner.getXid().equals(xid)) {
				throw new StatusException(Status.PERMISSION_DENIED, "that device belongs to another account");
			}
			for (Kernel.PersonalCredential device : person.getDevicesList()) {
				if (device.getCredentialId().equals(credential.getCredentialId())) {
					if (device.getRevokedAtMs() != 0) {
						throw new StatusException(Status.PERMISSION_DENIED, "that device credential is revoked");
					}
					return person;
				}
			}
			if (person.getDevicesCount() >= MAX_DEVICES_PER_PERSON) {
				throw new StatusException(Status.RESOURCE_EXHAUSTED,
						"this account is at the " + MAX_DEVICES_PER_PERSON + "-device cap");
			}
			Kernel.Person updated = person.toBuilder().addDevices(credential).build();
			write(() -> principalMap.putPeople(xid, updated), "device");
			logger.info("Enrolled device: xid={} platform_synced={}", xid, credential.getPlatformSynced());
			return updated;
		}
	}

	@Override
	public Kernel.PersonalCredential revokeDevice(String xid, String credentialId) throws StatusException {
		synchronized (lock) {
			Kernel.Person person = requirePerson(xid);
			for (int i = 0; i < person.getDevicesCount(); i++) {
				Kernel.PersonalCredential device = person.getDevices(i);
				if (!device.getCredentialId().equals(credentialId)) {
					continue;
				}
				if (device.getRevokedAtMs() != 0) {
					return device;
				}
				Kernel.PersonalCredential revoked = device.toBuilder()
						.setRevokedAtMs(clock.getAsLong()).build();
				Kernel.Person updated = person.toBuilder().setDevices(i, revoked).build();
				write(() -> principalMap.putPeople(xid, updated), "device revocation");
				logger.info("Revoked device: xid={}", xid);
				return revoked;
			}
			throw new StatusException(Status.NOT_FOUND, "that device is not one of this account's");
		}
	}

	/** A live person: present, not disabled, deleted or merged away. */
	private Kernel.Person requirePerson(String xid) throws StatusException {
		Kernel.Person person = principalMap.getPeople(xid);
		if (person.getXid().isEmpty() || person.getDisabledAtMs() != 0 || person.getDeletedAtMs() != 0
				|| !person.getMergedIntoXid().isEmpty()) {
			throw new StatusException(Status.PERMISSION_DENIED, "this session is no longer valid: sign in again");
		}
		return person;
	}

	private static boolean hasLink(Kernel.Person person, String idpId, String providerSubject) {
		for (Kernel.IdentityLink link : person.getLinksList()) {
			if (link.getIdpId().equals(idpId) && link.getProviderSubject().equals(providerSubject)) {
				return true;
			}
		}
		return false;
	}

	/** One write's puts, then the snapshot that makes them durable. */
	private void write(Puts puts, String what) throws StatusException {
		try {
			puts.run();
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL, what + " could not be recorded: " + e.getMessage());
		}
		persist.run();
	}

	@FunctionalInterface
	private interface Puts {
		void run() throws ProtoException;
	}

	/**
	 * A fresh XID: 128 random bits as lower-case hex, a legal SPIFFE path
	 * segment as it stands. Random rather than derived, so it names no tenant,
	 * cluster or IdP and survives every change to all three.
	 */
	private static String newXid() {
		byte[] bytes = new byte[16];
		XID_RANDOM.nextBytes(bytes);
		return HexFormat.of().formatHex(bytes);
	}
}
