// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The one-time migration of kernel#18: a snapshot written before it holds
 * {@code /people/<pid>} device principals, the tenant-user link edges that tie
 * each to a person, and people without devices. Booting it must leave every
 * linked device's credentials on its person's XID and drop (and count) the
 * rest. The link edges themselves are retired (kernel#4): read from the
 * snapshot for this migration, never restored, never written again.
 *
 * <p>Driven through the real boot entry points in the order the
 * {@code ClusterServer} constructor calls them — {@code restorePeople},
 * {@code migratePersonalPrincipals} — and, for the restart half, the real
 * {@link IdentitySnapshot} over a temp dir.
 */
class PersonalPrincipalMigrationTest {

	private static final String TD = "test.schematic.io";
	private static final String ALICE = "a11ce0000000000000000000000000aa";
	private static final String BOB = "b0b00000000000000000000000000bbb";

	/** A pre-#18 device principal's link key: {@code /people/<pid>|<its /people subject>}. */
	private static String deviceKey(String pid) {
		return "/people/" + pid + "|spiffe://" + TD + "/people/" + pid + "/users/" + pid;
	}

	private static String personSubject(String xid) {
		return SpiffeIds.userSubject(TD, xid);
	}

	private static String personKey(String xid) {
		return PeopleTenant.NAMESPACE + "|" + personSubject(xid);
	}

	private static Kernel.PersonalCredential credential(String id, long revokedAtMs) {
		return Kernel.PersonalCredential.newBuilder()
				.setCredentialId(id)
				.setPublicKey(JwkOuterClass.Jwk.newBuilder()
						.setKid(id)
						.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
						.setAlg("EdDSA")
						.setCreated(1_770_000_000L)
						.build())
				.setLabel("iPhone")
				.setPlatformSynced(true)
				.setCreatedAtMs(1_700_000_000_000L)
				.setRevokedAtMs(revokedAtMs)
				.build();
	}

	private static Kernel.PersonalPrincipal principal(String pid, Kernel.PersonalCredential... credentials) {
		return Kernel.PersonalPrincipal.newBuilder()
				.setPrincipalId(pid)
				.addAllCredentials(List.of(credentials))
				.setCreatedAtMs(1_700_000_000_000L)
				.build();
	}

	private static Kernel.Person person(String xid) {
		return Kernel.Person.newBuilder()
				.setXid(xid)
				.setCreatedAtMs(1_700_000_000_000L)
				.addMemberships(Kernel.PersonMembership.newBuilder()
						.setTenantNamespace(PeopleTenant.NAMESPACE)
						.setCreatedAtMs(1_700_000_000_000L))
				.build();
	}

	private static Kernel.TenantUserLink edge(String peerKey, long revokedAtMs) {
		int bar = peerKey.indexOf('|');
		return Kernel.TenantUserLink.newBuilder()
				.setPeerNamespace(peerKey.substring(0, bar))
				.setPeerSubject(peerKey.substring(bar + 1))
				.setCreatedAtMs(1_700_000_000_000L)
				.setRevokedAtMs(revokedAtMs)
				.build();
	}

	private static Kernel.TenantUserLinks row(String userKey, Kernel.TenantUserLink... links) {
		return Kernel.TenantUserLinks.newBuilder().setUserKey(userKey).addAllLinks(List.of(links)).build();
	}

	/** Both directions of a pre-#18 device link, as CreateTenantUserLink wrote them. */
	private static void linkDevice(Kernel.KernelDiskState.Builder snapshot, String pid, String xid,
			long revokedAtMs) {
		snapshot.addTenantUserLinks(row(deviceKey(pid), edge(personKey(xid), revokedAtMs)));
	}

	private static PrincipalMap boot(Kernel.KernelDiskState snapshot) {
		PrincipalMap map = new PrincipalMap(new InMemoryManager());
		ClusterServer.restorePeople(snapshot, map);
		ClusterServer.migratePersonalPrincipals(snapshot, map);
		return map;
	}

	/**
	 * The migration's purpose: a device principal linked to a person becomes
	 * that person's devices — every credential, its key, label and revocation
	 * mark kept. The three link rows it was found through, the person's tenant
	 * link included, are counted as ignored.
	 */
	@Test
	void aLinkedDevicePrincipalMovesOntoItsPersonsXid() throws Exception {
		Kernel.KernelDiskState.Builder snapshot = Kernel.KernelDiskState.newBuilder()
				.addPeople(person(ALICE))
				.addPersonalPrincipals(principal("p1", credential("cred-1", 0),
						credential("cred-2", 1_700_000_500_000L)));
		linkDevice(snapshot, "p1", ALICE, 0);
		snapshot.addTenantUserLinks(row(personKey(ALICE),
				edge(deviceKey("p1"), 0),
				edge("/tenants/acme|jody@acme.example", 0)));

		PrincipalMap map = new PrincipalMap(new InMemoryManager());
		ClusterServer.restorePeople(snapshot.build(), map);
		ClusterServer.PersonalPrincipalMigration result =
				ClusterServer.migratePersonalPrincipals(snapshot.build(), map);

		assertEquals(new ClusterServer.PersonalPrincipalMigration(1, 2, 0, 2), result);
		Kernel.Person alice = map.getPeople(ALICE);
		assertEquals(List.of(credential("cred-1", 0), credential("cred-2", 1_700_000_500_000L)),
				alice.getDevicesList());
	}

	/**
	 * Everything that is not one device linked to one live person is dropped,
	 * and counted: no link, a revoked link, a link to a deleted person, links to
	 * two people, and a disabled principal. None of their keys lands on anyone.
	 */
	@Test
	void everyOtherPrincipalIsDroppedAndCounted() throws Exception {
		Kernel.KernelDiskState.Builder snapshot = Kernel.KernelDiskState.newBuilder()
				.addPeople(person(ALICE))
				.addPeople(person(BOB))
				.addPeople(person("dead0000000000000000000000000ddd").toBuilder().setDeletedAtMs(5))
				.addPersonalPrincipals(principal("unlinked", credential("cred-a", 0)))
				.addPersonalPrincipals(principal("unlinked-since", credential("cred-b", 0)))
				.addPersonalPrincipals(principal("of-the-deleted", credential("cred-c", 0)))
				.addPersonalPrincipals(principal("of-two-people", credential("cred-d", 0)))
				.addPersonalPrincipals(principal("disabled", credential("cred-e", 0)).toBuilder()
						.setDisabledAtMs(7).build());
		linkDevice(snapshot, "unlinked-since", ALICE, 9);
		linkDevice(snapshot, "of-the-deleted", "dead0000000000000000000000000ddd", 0);
		snapshot.addTenantUserLinks(row(deviceKey("of-two-people"),
				edge(personKey(ALICE), 0), edge(personKey(BOB), 0)));
		linkDevice(snapshot, "disabled", BOB, 0);

		PrincipalMap map = new PrincipalMap(new InMemoryManager());
		ClusterServer.restorePeople(snapshot.build(), map);
		ClusterServer.PersonalPrincipalMigration result =
				ClusterServer.migratePersonalPrincipals(snapshot.build(), map);

		assertEquals(0, result.migrated());
		assertEquals(5, result.dropped());
		for (Kernel.Person person : map.proto().getPeopleList()) {
			assertEquals(0, person.getDevicesCount(), person.getXid());
		}
	}

	/**
	 * A person merged away since the device was linked: the device follows the
	 * tombstone's redirect to the survivor, as the person's links did.
	 */
	@Test
	void aDeviceOfAMergedPersonFollowsTheRedirect() throws Exception {
		Kernel.KernelDiskState.Builder snapshot = Kernel.KernelDiskState.newBuilder()
				.addPeople(person(ALICE))
				.addPeople(person(BOB).toBuilder().setMergedIntoXid(ALICE))
				.addPersonalPrincipals(principal("p1", credential("cred-1", 0)));
		linkDevice(snapshot, "p1", BOB, 0);

		PrincipalMap map = boot(snapshot.build());

		assertEquals(1, map.getPeople(ALICE).getDevicesCount());
		assertEquals(0, map.getPeople(BOB).getDevicesCount());
	}

	/**
	 * One key, one person: a credential some person already holds is not copied
	 * onto a second one, and a key already on the right person is not doubled.
	 */
	@Test
	void aCredentialAlreadyHeldIsNotCopiedAgain() throws Exception {
		Kernel.KernelDiskState.Builder snapshot = Kernel.KernelDiskState.newBuilder()
				.addPeople(person(ALICE).toBuilder().addDevices(credential("cred-1", 0)))
				.addPeople(person(BOB))
				.addPersonalPrincipals(principal("p1", credential("cred-1", 0)))
				.addPersonalPrincipals(principal("p2", credential("cred-1", 0), credential("cred-2", 0)));
		linkDevice(snapshot, "p1", ALICE, 0);
		linkDevice(snapshot, "p2", BOB, 0);

		PrincipalMap map = boot(snapshot.build());

		assertEquals(List.of(credential("cred-1", 0)), map.getPeople(ALICE).getDevicesList());
		assertEquals(List.of(credential("cred-2", 0)), map.getPeople(BOB).getDevicesList());
	}

	/**
	 * The restart half. The next snapshot written carries no device principals
	 * and no link rows, keeps the devices on the person, and booting it
	 * migrates nothing more; until that snapshot is written, booting the old one
	 * again gives the same result, so a crash in between loses nothing.
	 */
	@Test
	void theNextSnapshotCarriesTheDevicesAndNoPrincipals(@TempDir Path dir) throws Exception {
		Kernel.KernelDiskState.Builder old = Kernel.KernelDiskState.newBuilder()
				.addPeople(person(ALICE))
				.addPersonalPrincipals(principal("p1", credential("cred-1", 0)));
		linkDevice(old, "p1", ALICE, 0);

		PrincipalMap migrated = boot(old.build());
		assertEquals(migrated.getPeople(ALICE), boot(old.build()).getPeople(ALICE),
				"replaying the old snapshot is the same migration");

		IdentitySnapshot persistence = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, null,
				() -> {
					try {
						return migrated.proto();
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				});
		persistence.save();
		Kernel.KernelDiskState written = persistence.load();

		assertEquals(0, written.getPersonalPrincipalsCount());
		assertEquals(0, written.getTenantUserLinksCount());
		PrincipalMap afterRestart = new PrincipalMap(new InMemoryManager());
		ClusterServer.restorePeople(written, afterRestart);
		assertEquals(new ClusterServer.PersonalPrincipalMigration(0, 0, 0, 0),
				ClusterServer.migratePersonalPrincipals(written, afterRestart));
		assertEquals(migrated.getPeople(ALICE), afterRestart.getPeople(ALICE),
				"the person and their devices come back field-identical after a restart");
	}

	/** A cold start, and a snapshot from before any device existed, migrate nothing. */
	@Test
	void nothingToMigrateIsANoop() throws Exception {
		PrincipalMap map = new PrincipalMap(new InMemoryManager());
		assertEquals(new ClusterServer.PersonalPrincipalMigration(0, 0, 0, 0),
				ClusterServer.migratePersonalPrincipals(null, map));
		assertEquals(new ClusterServer.PersonalPrincipalMigration(0, 0, 0, 0),
				ClusterServer.migratePersonalPrincipals(
						Kernel.KernelDiskState.newBuilder().addPeople(person(ALICE)).build(), map));
	}

	/**
	 * Fail closed, like the restores around it: a device that cannot be written
	 * onto its person refuses the boot rather than vanish.
	 */
	@Test
	void aMigrationThatCannotBeAppliedRefusesTheBoot() {
		Kernel.KernelDiskState.Builder snapshot = Kernel.KernelDiskState.newBuilder()
				.addPeople(person(ALICE))
				.addPersonalPrincipals(principal("p1",
						credential("cred-1", 0).toBuilder().clearPublicKey().build()));
		linkDevice(snapshot, "p1", ALICE, 0);

		IllegalStateException e = assertThrows(IllegalStateException.class, () -> boot(snapshot.build()));
		assertTrue(e.getMessage().contains("could not be migrated"), e.getMessage());
	}
}
