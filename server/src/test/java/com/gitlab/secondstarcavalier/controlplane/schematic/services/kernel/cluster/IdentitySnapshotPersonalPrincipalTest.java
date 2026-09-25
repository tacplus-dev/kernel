// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Proves a registered person survives a full cluster restart: the row is seeded
 * into the live {@link PrincipalMap}, written to the kernel disk snapshot by
 * {@link IdentitySnapshot#save()}, and restored — field-identical — into a
 * FRESH, empty {@code PrincipalMap} by
 * {@link ClusterServer#restorePersonalPrincipals}, which is the boot path
 * {@code ClusterServer}'s constructor calls.
 *
 * <p>Same shape as {@code IdentitySnapshotGrantTest} plus the restart half of
 * {@code MintDelegatedTokenTest.revocationSurvivesARestart} — the real
 * IdentitySnapshot over a temp dir and the real static restore entry point, not
 * a copy of either.
 */
class IdentitySnapshotPersonalPrincipalTest {

	private static Kernel.PersonalPrincipal principal(String principalId) {
		return Kernel.PersonalPrincipal.newBuilder()
				.setPrincipalId(principalId)
				.addCredentials(Kernel.PersonalCredential.newBuilder()
						.setCredentialId("cred-1")
						.setPublicKey(JwkOuterClass.Jwk.newBuilder()
								.setKid("cred-1")
								.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
								.setAlg("EdDSA")
								.setCreated(1_770_000_000L)
								.build())
						.setLabel("iPhone")
						.setPlatformSynced(true)
						.setCreatedAtMs(1_700_000_000_000L)
						.build())
				.addMemberships(Kernel.TenantMembership.newBuilder()
						.setTenantNamespace("/tenants/acme")
						.setProofKind(Kernel.MembershipProofKind.MEMBERSHIP_PROOF_KIND_TENANT_IDP)
						.setCustomer(true)
						.setProofReference("idp-subject-opaque")
						.setCreatedAtMs(1_700_000_000_000L)
						.build())
				.setCreatedAtMs(1_700_000_000_000L)
				.build();
	}

	/** save() writes personal_principals; load() returns them intact. */
	@Test
	void personalPrincipalSurvivesSaveAndLoad(@TempDir Path dir) {
		Kernel.PersonalPrincipal expected = principal("p-alice");

		IdentitySnapshot p = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, null,
				() -> Kernel.PrincipalState.newBuilder().addPersonalPrincipals(expected).build());
		p.save();

		Kernel.KernelDiskState loaded = p.load();
		assertNotNull(loaded, "snapshot should load back");
		assertEquals(1, loaded.getPersonalPrincipalsCount());
		assertEquals(expected, loaded.getPersonalPrincipals(0));
	}

	/**
	 * The whole round trip through the real boundary: live map -> snapshot ->
	 * restart -> fresh empty map. Without the KernelDiskState field or the
	 * restore call, the fresh map comes back empty and the person is gone.
	 */
	@Test
	void aRegisteredPersonSurvivesARestart(@TempDir Path dir) throws Exception {
		PrincipalMap before = new PrincipalMap(new InMemoryManager());
		Kernel.PersonalPrincipal alice = principal("p-alice");
		Kernel.PersonalPrincipal bob = principal("p-bob");
		before.putPersonalPrincipals("p-alice", alice);
		before.putPersonalPrincipals("p-bob", bob);

		IdentitySnapshot persistence = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, null,
				() -> {
					try {
						return before.proto();
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				});
		persistence.save();

		// --- restart: a brand-new, empty PrincipalMap, as a fresh node has ---
		Kernel.KernelDiskState snapshot = persistence.load();
		assertNotNull(snapshot);
		PrincipalMap after = new PrincipalMap(new InMemoryManager());
		assertEquals(0, after.proto().getPersonalPrincipalsCount(), "fresh map starts empty");

		ClusterServer.restorePersonalPrincipals(snapshot, after);

		assertEquals(2, after.proto().getPersonalPrincipalsCount());
		assertEquals(alice, after.getPersonalPrincipals("p-alice"));
		assertEquals(bob, after.getPersonalPrincipals("p-bob"));
	}

	/** A cold start has nothing to restore and must not throw. */
	@Test
	void restoreFromNoSnapshotIsANoop() throws Exception {
		PrincipalMap after = new PrincipalMap(new InMemoryManager());
		ClusterServer.restorePersonalPrincipals(null, after);
		ClusterServer.restorePersonalPrincipals(Kernel.KernelDiskState.getDefaultInstance(), after);
		assertEquals(0, after.proto().getPersonalPrincipalsCount());
	}

	/** An existing snapshot written before this field existed still loads. */
	@Test
	void snapshotWithoutPersonalPrincipalsStillLoads(@TempDir Path dir) {
		IdentitySnapshot p = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, List::of, null);
		p.save();

		Kernel.KernelDiskState loaded = p.load();
		assertNotNull(loaded);
		assertEquals(0, loaded.getPersonalPrincipalsCount());
	}
}
