// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.collection.CollectionRuntime;
import com.github.tacplusdev.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.CaMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.IdentityMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tenant ids (kernel#3): every tenant carries a tid of exactly 8 of
 * {@code [0-9a-z]}, minted once, immutable, never reused. All-digit tids are
 * the platform's: {@code people} is 00000001 and {@code restore} 00000002.
 * A minted tid starts with a letter. A tenant the deployment's bootstrap
 * config lists is seeded under the tid it carries.
 */
class TenantIdTest {

	private static final String ACME = "/tenants/acme";
	private static final String BETA = "/tenants/beta";
	private static final String MINTED = "^[a-z][0-9a-z]{7}$";

	private ConfigMap configMap;
	private TenantAdminServiceImpl admin;

	@BeforeEach
	void setUp() {
		configMap = new ConfigMap(new InMemoryManager());
		admin = new TenantAdminServiceImpl(configMap, () -> "test.schematic.io", () -> { });
	}

	private Kernel.Tenant create(String ns) throws ProtoException {
		return admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ns).build());
	}

	private void delete(String ns) throws ProtoException {
		admin.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder().setTenantNamespace(ns).build());
	}

	private static Kernel.BootstrapTenant bootstrap(String name, String tid) {
		return Kernel.BootstrapTenant.newBuilder().setName(name).setTid(tid).build();
	}

	/** The real boot path: snapshot the live maps, then restore into fresh ones. */
	private static ConfigMap restart(ConfigMap before, Path dir) throws Exception {
		IdentitySnapshot persistence = new IdentitySnapshot(
				dir.toString(), null, null, null,
				() -> {
					try {
						return ClusterServer.snapshotConfigState(before);
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				},
				null, null, null);
		persistence.save();
		Kernel.KernelDiskState snapshot = persistence.load();
		assertNotNull(snapshot, "snapshot should load back");
		InMemoryManager manager = new InMemoryManager();
		ConfigMap after = new ConfigMap(manager);
		ClusterServer.rehydrateFromSnapshot(snapshot, new IdentityMap(manager), new CaMap(manager),
				new WorkloadMap(manager), after);
		return after;
	}

	// ---- Format ------------------------------------------------------------

	@Test
	void aMintedTidIsALetterThenSevenOfTheAlphabetAndNeverAllDigits() {
		for (int i = 0; i < 10_000; i++) {
			String tid = TenantIds.newTid();
			assertTrue(tid.matches(MINTED), "minted " + tid);
			assertTrue(TenantIds.isWellFormed(tid));
			assertFalse(TenantIds.isReserved(tid), "a minted tid fell in the reserved range: " + tid);
		}
	}

	@Test
	void wellFormedIsExactlyEightOfTheAlphabet() {
		assertTrue(TenantIds.isWellFormed("a1b2c3d4"));
		assertTrue(TenantIds.isWellFormed("00000001"));
		assertFalse(TenantIds.isWellFormed("a1b2c3d"));
		assertFalse(TenantIds.isWellFormed("a1b2c3d4e"));
		assertFalse(TenantIds.isWellFormed("A1B2C3D4"));
		assertFalse(TenantIds.isWellFormed("a1b2-3d4"));
		assertFalse(TenantIds.isWellFormed(""));
	}

	@Test
	void theReservedRangeIsEveryAllDigitTid() {
		assertTrue(TenantIds.isReserved("00000001"));
		assertTrue(TenantIds.isReserved("99999999"));
		assertFalse(TenantIds.isReserved("0000000a"));
		assertFalse(TenantIds.isReserved("a0000000"));
	}

	@Test
	void createTenantMintsATidAndReturnsIt() throws Exception {
		Kernel.Tenant acme = create(ACME);

		assertTrue(acme.getTid().matches(MINTED), "tid " + acme.getTid());
		assertEquals(acme.getTid(), configMap.getTenants(ACME).getTid(), "the record carries the tid");
		assertEquals(ACME, configMap.getTenantIds(acme.getTid()).getTenantNamespace());
	}

	@Test
	void listTenantsShowsEachTenantsTid() throws Exception {
		Kernel.Tenant acme = create(ACME);
		Kernel.Tenant beta = create(BETA);

		CollectionRuntime.Page<Kernel.Tenant> page = admin.listTenants(null,
				Kernel.ListTenantsRequest.newBuilder().setParentNamespace("/tenants").build(),
				new CollectionRuntime.PageParams(0, null));

		assertEquals(List.of(acme.getTid(), beta.getTid()),
				page.items.stream().map(Kernel.Tenant::getTid).toList());
	}

	@Test
	void aSubTenantGetsItsOwnTid() throws Exception {
		Kernel.Tenant acme = create(ACME);
		Kernel.Tenant sub = create(ACME + "/sub");

		assertTrue(sub.getTid().matches(MINTED));
		assertNotEquals(acme.getTid(), sub.getTid());
	}

	// ---- Uniqueness --------------------------------------------------------

	@Test
	void everyTenantGetsADifferentTid() throws Exception {
		Set<String> tids = new HashSet<>();
		for (int i = 0; i < 200; i++) {
			assertTrue(tids.add(create("/tenants/t" + i).getTid()), "a tid was issued twice");
		}
	}

	/** Insert-if-absent: a drawn tid somebody holds is not handed out again. */
	@Test
	void mintDrawsAgainWhenTheTidIsTaken() throws Exception {
		TenantIds.claim(configMap, "abcdefgh", ACME);
		Iterator<String> draws = List.of("abcdefgh", "ijklmnop").iterator();

		assertEquals("ijklmnop", TenantIds.mint(configMap, BETA, draws::next));
		assertEquals(ACME, configMap.getTenantIds("abcdefgh").getTenantNamespace(),
				"the holder keeps its tid");
		assertEquals(BETA, configMap.getTenantIds("ijklmnop").getTenantNamespace());
	}

	@Test
	void aTidAnotherTenantHoldsCannotBeClaimed() throws Exception {
		TenantIds.claim(configMap, "abcdefgh", ACME);

		ProtoException e = assertThrows(ProtoException.class,
				() -> TenantIds.claim(configMap, "abcdefgh", BETA));
		assertEquals(ProtoException.ALREADY_EXISTS, e.getCode());
		// Claiming its own again is what a reseed at every boot does.
		TenantIds.claim(configMap, "abcdefgh", ACME);
	}

	// ---- Immutability and tombstones ----------------------------------------

	@Test
	void aDeletedTenantsTidIsTombstonedAndNeverReused() throws Exception {
		String first = create(ACME).getTid();
		delete(ACME);

		Kernel.TenantIdRow row = configMap.getTenantIds(first);
		assertEquals(ACME, row.getTenantNamespace(), "the row is kept, not freed");
		assertTrue(row.getTombstonedAtMs() > 0, "the row is tombstoned");

		String second = create(ACME).getTid();
		assertNotEquals(first, second, "a recreated tenant gets a new tid");
		assertEquals(0, configMap.getTenantIds(second).getTombstonedAtMs());

		// Not by a draw, and not by a bootstrap entry naming it.
		Iterator<String> draws = List.of(first, "zzzzzzzz").iterator();
		assertEquals("zzzzzzzz", TenantIds.mint(configMap, BETA, draws::next));
		ProtoException e = assertThrows(ProtoException.class,
				() -> TenantIds.claim(configMap, first, ACME));
		assertEquals(ProtoException.ALREADY_EXISTS, e.getCode());
	}

	@Test
	void aBootstrapEntryCannotChangeATenantsTid() throws Exception {
		String tid = create(ACME).getTid();

		ProtoException e = assertThrows(ProtoException.class,
				() -> TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4"))));
		assertTrue(e.getMessage().contains("immutable"), e.getMessage());
		assertEquals(tid, configMap.getTenants(ACME).getTid());
		assertTrue(configMap.getTenantIds("q1w2e3r4").getTid().isEmpty(), "the refused tid was not claimed");
	}

	@Test
	void theTidAndItsTombstonesSurviveARestart(@TempDir Path dir) throws Exception {
		String gone = create(BETA).getTid();
		delete(BETA);
		String tid = create(ACME).getTid();

		ConfigMap after = restart(configMap, dir);

		assertEquals(tid, after.getTenants(ACME).getTid());
		assertEquals(configMap.getTenantIds(tid), after.getTenantIds(tid));
		assertTrue(after.getTenantIds(gone).getTombstonedAtMs() > 0,
				"a restart must not free a tombstoned tid");
	}

	/** A record from a kernel before tids gets one at boot, once. */
	@Test
	void aTenantWrittenWithoutATidIsGivenOneAtBootAndKeepsIt() throws Exception {
		configMap.putTenants(ACME, Kernel.Tenant.newBuilder()
				.setName("acme").setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE).build());
		configMap.putTenantConfigs(ACME, Kernel.TenantConfigEntry.newBuilder().setTenantName(ACME).build());

		TenantIds.backfill(configMap);
		String tid = configMap.getTenants(ACME).getTid();
		assertTrue(tid.matches(MINTED), "tid " + tid);
		assertEquals(ACME, configMap.getTenantIds(tid).getTenantNamespace());

		TenantIds.backfill(configMap);
		assertEquals(tid, configMap.getTenants(ACME).getTid());
	}

	// ---- Reserved tenants ---------------------------------------------------

	@Test
	void peopleIs00000001() throws Exception {
		PeopleTenant.seed(configMap, List.of());

		assertEquals("00000001", configMap.getTenants(PeopleTenant.NAMESPACE).getTid());
		assertEquals(PeopleTenant.NAMESPACE, configMap.getTenantIds("00000001").getTenantNamespace());
		PeopleTenant.seed(configMap, List.of());
		assertEquals("00000001", configMap.getTenants(PeopleTenant.NAMESPACE).getTid());
	}

	@Test
	void restoreIs00000002AndExistsAfterTheSeed() throws Exception {
		RestoreTenant.seed(configMap);
		var created = configMap.getTenants(RestoreTenant.NAMESPACE).getCreatedAt();
		RestoreTenant.seed(configMap);

		Kernel.Tenant restore = configMap.getTenants(RestoreTenant.NAMESPACE);
		assertEquals("restore", restore.getName());
		assertEquals("00000002", restore.getTid());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE, restore.getStatus());
		assertEquals(created, restore.getCreatedAt(), "a reseed keeps created_at");
		assertEquals(RestoreTenant.NAMESPACE, configMap.getTenantIds("00000002").getTenantNamespace());

		CollectionRuntime.Page<Kernel.Tenant> page = admin.listTenants(null,
				Kernel.ListTenantsRequest.newBuilder().setParentNamespace("/tenants").build(),
				new CollectionRuntime.PageParams(0, null));
		assertEquals(List.of("00000002"), page.items.stream().map(Kernel.Tenant::getTid).toList());
	}

	@Test
	void restoreCannotBeDeletedCreatedOrReconfigured() throws Exception {
		RestoreTenant.seed(configMap);

		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> delete(RestoreTenant.NAMESPACE)).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> create(RestoreTenant.NAMESPACE)).getCode());
		assertEquals(ProtoException.PERMISSION_DENIED, assertThrows(ProtoException.class,
				() -> admin.updateTenantConfig(null, Kernel.SetTenantConfigRequest.newBuilder()
						.setTenantNamespace(RestoreTenant.NAMESPACE)
						.setConfig(TenantConfigOuterClass.TenantConfig.getDefaultInstance())
						.build())).getCode());
		assertEquals("00000002", configMap.getTenants(RestoreTenant.NAMESPACE).getTid(), "it is still there");
	}

	@Test
	void theReservedTidsSurviveARestart(@TempDir Path dir) throws Exception {
		PeopleTenant.seed(configMap, List.of());
		RestoreTenant.seed(configMap);

		ConfigMap after = restart(configMap, dir);
		PeopleTenant.seed(after, List.of());
		RestoreTenant.seed(after);

		assertEquals("00000001", after.getTenants(PeopleTenant.NAMESPACE).getTid());
		assertEquals("00000002", after.getTenants(RestoreTenant.NAMESPACE).getTid());
	}

	// ---- The bootstrap seed -------------------------------------------------

	@Test
	void aBootstrapTenantIsSeededUnderTheTidItCarries() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4")));

		Kernel.Tenant acme = configMap.getTenants(ACME);
		assertEquals("acme", acme.getName());
		assertEquals("q1w2e3r4", acme.getTid());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE, acme.getStatus());
		assertEquals(ACME, configMap.getTenantIds("q1w2e3r4").getTenantNamespace());
		assertFalse(configMap.getProjectConfigs(ACME + "/default").getProjectNamespace().isEmpty(),
				"it is created as CreateTenant creates one, default project included");
	}

	@Test
	void aBootstrapTenantKeepsItsTidOnEveryBoot(@TempDir Path dir) throws Exception {
		List<Kernel.BootstrapTenant> bundle = List.of(bootstrap("acme", "q1w2e3r4"), bootstrap("beta", ""));
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, bundle);
		String betaTid = configMap.getTenants(BETA).getTid();
		assertTrue(betaTid.matches(MINTED), "a bootstrap tenant without a tid gets a minted one: " + betaTid);

		ConfigMap after = restart(configMap, dir);
		TenantAdminServiceImpl.seedBootstrapTenants(after, bundle);
		TenantIds.backfill(after);

		assertEquals("q1w2e3r4", after.getTenants(ACME).getTid());
		assertEquals(betaTid, after.getTenants(BETA).getTid());
	}

	@Test
	void aBootstrapTidInTheReservedRangeIsRefused() {
		ProtoException e = assertThrows(ProtoException.class,
				() -> TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "00000003"))));
		assertTrue(e.getMessage().contains(ACME), e.getMessage());
		assertTrue(configMap.getTenants(ACME).getName().isEmpty());
	}

	@Test
	void aMalformedBootstrapTidIsRefusedAndTheRestAreSeeded() {
		assertThrows(ProtoException.class, () -> TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(bootstrap("acme", "Q1W2E3R4"), bootstrap("beta", "q1w2e3r5"))));
		assertTrue(configMap.getTenants(ACME).getName().isEmpty());
		assertEquals("q1w2e3r5", configMap.getTenants(BETA).getTid());
	}

	@Test
	void aBootstrapEntryCannotTakeAnotherTenantsTid() throws Exception {
		String acmeTid = create(ACME).getTid();

		assertThrows(ProtoException.class,
				() -> TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("beta", acmeTid))));
		assertTrue(configMap.getTenants(BETA).getName().isEmpty());
		assertEquals(ACME, configMap.getTenantIds(acmeTid).getTenantNamespace());
	}

	@Test
	void aBootstrapEntryCannotNameAReservedTenant() {
		assertThrows(ProtoException.class, () -> TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(bootstrap("people", "q1w2e3r4"), bootstrap("restore", ""))));
		assertTrue(configMap.getTenants(PeopleTenant.NAMESPACE).getName().isEmpty());
		assertTrue(configMap.getTenants(RestoreTenant.NAMESPACE).getName().isEmpty());
	}

	/** A record from before tids takes the tid the bootstrap entry carries. */
	@Test
	void aBootstrapTidLandsOnARecordWrittenWithoutOne() throws Exception {
		configMap.putTenants(ACME, Kernel.Tenant.newBuilder()
				.setName("acme").setStatus(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED).build());

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4")));

		assertEquals("q1w2e3r4", configMap.getTenants(ACME).getTid());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, configMap.getTenants(ACME).getStatus(),
				"the rest of the record is kept");
	}
}
