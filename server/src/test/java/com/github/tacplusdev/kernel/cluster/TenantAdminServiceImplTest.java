// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.collection.CollectionRuntime;
import com.github.tacplusdev.kernel.model.types.generated.entitlements.Entitlements;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CreateTenant's ceiling check ({@code constraints.entitlements_ceiling} must be
 * a subset of the parent's) resolved the parent by string-chopping the last
 * namespace segment, and treated a missing tenant record there as an UNBOUNDED
 * ceiling.
 *
 * <p>That let a tenant admin scoped to {@code /tenants/acme} skip a level:
 * creating {@code /tenants/acme/ghost/evil} in one call resolved the parent to
 * the never-created {@code /tenants/acme/ghost}, found no record, skipped the
 * check entirely, and produced a sub-tenant holding entitlements acme itself was
 * never allowed to hold — plus a phantom {@code /tenants/acme/ghost} segment
 * that had never passed a ceiling check of its own.
 *
 * <p>The fix requires the immediate parent to exist (only {@code /tenants}, the
 * parent of a top-level tenant, is unbounded). Because every existing tenant was
 * validated against ITS parent at creation, the immediate parent's ceiling is
 * already the tightest one on the whole ancestor chain.
 */
class TenantAdminServiceImplTest {

	private static final String ACME = "/tenants/acme";
	private static final String GRANDCHILD = "/tenants/acme/ghost/evil";

	private ConfigMap configMap;
	private TenantAdminServiceImpl impl;

	@BeforeEach
	void setUp() throws Exception {
		configMap = new ConfigMap(new InMemoryManager());
		impl = new TenantAdminServiceImpl(configMap, () -> "test.schematic.io", () -> {});
		// /tenants/acme exists with a real, bounded ceiling: read-only config access.
		configMap.putTenants(ACME, Kernel.Tenant.newBuilder()
				.setName("acme")
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.setConstraints(ceiling("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.build());
	}

	/**
	 * The exploit. Against the unfixed {@code parentCeiling} this call SUCCEEDS
	 * and returns a tenant holding KERNEL_ANY — strictly wider than acme's
	 * ceiling two levels up.
	 */
	@Test
	void createTenantRejectsAGrandchildWhoseIntermediateParentDoesNotExist() {
		ProtoException e = assertThrows(ProtoException.class,
				() -> impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
						.setTenantNamespace(GRANDCHILD)
						.setConstraints(ceiling("KERNEL_ANY"))
						.build()));

		assertEquals(ProtoException.NOT_FOUND, e.getCode(), "message was: " + e.getMessage());
		assertTrue(e.getMessage().contains("/tenants/acme/ghost"),
				"error should name the missing parent, got: " + e.getMessage());

		// Negative control on the side-effects: nothing landed, and in
		// particular no phantom intermediate segment was materialised.
		assertTrue(configMap.getTenants(GRANDCHILD).getName().isEmpty(), "tenant must not have been created");
		assertTrue(configMap.getProjectConfigs(GRANDCHILD + "/default").getProjectNamespace().isEmpty(),
				"default project must not have been created");
		assertFalse(configMap.proto().getProjectConfigsList().stream()
						.anyMatch(p -> p.getProjectNamespace().startsWith("/tenants/acme/ghost")),
				"no project key may exist under the phantom segment");
	}

	/**
	 * Negative control for the check itself: with the intermediate parent really
	 * present (and itself bounded by acme), the same over-wide ceiling is caught
	 * by the ordinary subset check — proving the NOT_FOUND above is a genuine
	 * extra guard and not the only thing standing in the way.
	 */
	@Test
	void createTenantRejectsAnOverWideCeilingWhenTheParentDoesExist() throws Exception {
		impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
				.setTenantNamespace("/tenants/acme/ghost")
				.setConstraints(ceiling("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.build());

		ProtoException e = assertThrows(ProtoException.class,
				() -> impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
						.setTenantNamespace(GRANDCHILD)
						.setConstraints(ceiling("KERNEL_ANY"))
						.build()));

		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
		assertTrue(e.getMessage().contains("exceeds the parent tenant's ceiling"), e.getMessage());
	}

	/** A sub-tenant within its parent's ceiling is still created normally. */
	@Test
	void createTenantAllowsASubTenantWithinTheParentCeiling() throws Exception {
		Kernel.Tenant created = impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
				.setTenantNamespace(ACME + "/sub")
				.setConstraints(ceiling("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.build());

		assertEquals("sub", created.getName());
		assertEquals("sub", configMap.getTenants(ACME + "/sub").getName());
		assertEquals(ACME + "/sub/default",
				configMap.getProjectConfigs(ACME + "/sub/default").getProjectNamespace());
	}

	/** A top-level tenant's parent is the "/tenants" root: still unbounded. */
	@Test
	void createTenantAllowsATopLevelTenantWithAnyCeiling() throws Exception {
		Kernel.Tenant created = impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
				.setTenantNamespace("/tenants/globex")
				.setConstraints(ceiling("KERNEL_ANY"))
				.build());

		assertEquals("globex", created.getName());
		assertEquals("globex", configMap.getTenants("/tenants/globex").getName());
	}

	/**
	 * The ceiling exploit. {@code entitlementsSubsetOf} compared only the
	 * {@code grants} list, so a sub-tenant could stay within its parent's RPC
	 * grants while requesting {@code data_grants} the parent does not hold and
	 * {@code principal_scope: ANY} — authority over every principal — neither of
	 * which the ceiling ever looked at. Against the unfixed check both of these
	 * calls SUCCEED.
	 */
	@Test
	void createTenantRejectsDataGrantsAndPrincipalScopeBeyondTheParentCeiling() {
		ProtoException dataGrants = assertThrows(ProtoException.class,
				() -> impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
						.setTenantNamespace(ACME + "/sub")
						.setConstraints(fullCeiling(
								List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"),
								List.of("KERNEL_TENANT_CONSTRAINTS"),
								""))
						.build()));
		assertEquals(ProtoException.INVALID_ARGUMENT, dataGrants.getCode(), dataGrants.getMessage());
		assertTrue(dataGrants.getMessage().contains("exceeds the parent tenant's ceiling"),
				dataGrants.getMessage());

		ProtoException scope = assertThrows(ProtoException.class,
				() -> impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
						.setTenantNamespace(ACME + "/sub")
						.setConstraints(fullCeiling(
								List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"),
								List.of(),
								"PRINCIPAL_SCOPE_ANY"))
						.build()));
		assertEquals(ProtoException.INVALID_ARGUMENT, scope.getCode(), scope.getMessage());
		assertTrue(scope.getMessage().contains("exceeds the parent tenant's ceiling"), scope.getMessage());

		assertTrue(configMap.getTenants(ACME + "/sub").getName().isEmpty(),
				"tenant must not have been created");
	}

	/**
	 * Negative control for the widened check: data_grants and principal_scope no
	 * wider than the parent's still pass.
	 */
	@Test
	void createTenantAllowsDataGrantsAndPrincipalScopeWithinTheParentCeiling() throws Exception {
		configMap.putTenants(ACME, Kernel.Tenant.newBuilder()
				.setName("acme")
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.setConstraints(fullCeiling(
						List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"),
						List.of("KERNEL_TENANT_CONSTRAINTS"),
						"PRINCIPAL_SCOPE_SUBTREE"))
				.build());

		Kernel.Tenant created = impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
				.setTenantNamespace(ACME + "/sub")
				.setConstraints(fullCeiling(
						List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"),
						List.of("KERNEL_TENANT_CONSTRAINTS"),
						"PRINCIPAL_SCOPE_SELF_ONLY"))
				.build());

		assertEquals("sub", created.getName());
	}

	/**
	 * The orphaning exploit. DeleteTenant removed only the named tenant's record
	 * and config, leaving every nested tenant beneath it live — its cred_pairs
	 * kept minting tokens under a parent that no longer existed. Against the
	 * unfixed handler this call SUCCEEDS and /tenants/acme/sub survives, with no
	 * tenant above it to ever narrow or revoke it.
	 */
	@Test
	void deleteTenantRefusesToOrphanNestedTenants() throws Exception {
		impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
				.setTenantNamespace(ACME + "/sub")
				.setConstraints(ceiling("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.build());

		ProtoException e = assertThrows(ProtoException.class,
				() -> impl.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder()
						.setTenantNamespace(ACME)
						.build()));

		assertEquals(ProtoException.FAILED_PRECONDITION, e.getCode(), e.getMessage());
		assertTrue(e.getMessage().contains(ACME + "/sub"),
				"error should name the nested tenant, got: " + e.getMessage());

		// Nothing was partially removed.
		assertEquals("acme", configMap.getTenants(ACME).getName());
		assertEquals("sub", configMap.getTenants(ACME + "/sub").getName());
		assertEquals(ACME + "/sub/default",
				configMap.getProjectConfigs(ACME + "/sub/default").getProjectNamespace());
	}

	/** Negative control: leaf-first deletion of the whole subtree still works. */
	@Test
	void deleteTenantDeletesALeafTenantAndThenItsParent() throws Exception {
		impl.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
				.setTenantNamespace(ACME + "/sub")
				.setConstraints(ceiling("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"))
				.build());

		impl.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder()
				.setTenantNamespace(ACME + "/sub")
				.build());
		assertTrue(configMap.getTenants(ACME + "/sub").getName().isEmpty());

		impl.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder()
				.setTenantNamespace(ACME)
				.build());
		assertTrue(configMap.getTenants(ACME).getName().isEmpty());
	}

	/**
	 * A project config row must have a live tenant above it. Without this check a
	 * SetProjectConfig under a namespace with no tenant record creates an orphan:
	 * ListProjects returns it (it filters on immediate-child shape, not on tenant
	 * existence) and DeleteTenant, which refuses on nested tenants, says nothing
	 * about nested projects.
	 */
	@Test
	void setProjectConfigRefusesAProjectWithNoTenantAboveIt() {
		ProtoException e = assertThrows(ProtoException.class,
				() -> impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
						.setProjectNamespace("/tenants/ghost/prod")
						.setConfig(Kernel.ProjectConfig.getDefaultInstance())
						.build()));

		assertEquals(ProtoException.NOT_FOUND, e.getCode(), e.getMessage());
		assertTrue(e.getMessage().contains("/tenants/ghost"),
				"error should name the missing tenant, got: " + e.getMessage());
		assertTrue(configMap.getProjectConfigs("/tenants/ghost/prod").getProjectNamespace().isEmpty(),
				"the orphan project row must not have been written");
	}

	/** A suspended tenant is no more a home for new project config than a missing one. */
	@Test
	void setProjectConfigRefusesAProjectUnderASuspendedTenant() throws Exception {
		configMap.putTenants(ACME, configMap.getTenants(ACME).toBuilder()
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED)
				.build());

		ProtoException e = assertThrows(ProtoException.class,
				() -> impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
						.setProjectNamespace(ACME + "/prod")
						.setConfig(Kernel.ProjectConfig.getDefaultInstance())
						.build()));

		assertEquals(ProtoException.NOT_FOUND, e.getCode(), e.getMessage());
	}

	/** Negative control: an active tenant still takes project config normally. */
	@Test
	void setProjectConfigWritesUnderALiveTenant() throws Exception {
		impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
				.setProjectNamespace(ACME + "/prod")
				.setConfig(Kernel.ProjectConfig.getDefaultInstance())
				.build());

		assertEquals(ACME + "/prod",
				configMap.getProjectConfigs(ACME + "/prod").getProjectNamespace());
	}

	/**
	 * A zero limit is what a caller sends when it omits page_size — the ordinary
	 * "give me the default page" wiring. Returning an empty item list alongside
	 * the real total hands back a page nobody can act on and no cursor to resume
	 * from.
	 */
	@Test
	void listProjectsWithNoLimitReturnsTheDefaultPageRatherThanNothing() throws Exception {
		impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
				.setProjectNamespace(ACME + "/prod")
				.setConfig(Kernel.ProjectConfig.getDefaultInstance())
				.build());
		impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
				.setProjectNamespace(ACME + "/staging")
				.setConfig(Kernel.ProjectConfig.getDefaultInstance())
				.build());

		CollectionRuntime.Page<Kernel.ProjectNamespace> page = impl.listProjects(
				null,
				Kernel.ListProjectsRequest.newBuilder().setTenantNamespace(ACME).build(),
				new CollectionRuntime.PageParams(0, null));

		assertEquals(2, page.total);
		assertEquals(2, page.items.size(), "a zero limit must page, not return nothing");
		assertEquals(ACME + "/prod", page.items.get(0).getProjectNamespace());
		assertEquals(ACME + "/staging", page.items.get(1).getProjectNamespace());
	}

	/** And an explicit limit still bounds the page and hands back a cursor. */
	@Test
	void listProjectsHonoursAnExplicitLimit() throws Exception {
		impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
				.setProjectNamespace(ACME + "/prod")
				.setConfig(Kernel.ProjectConfig.getDefaultInstance())
				.build());
		impl.updateProjectConfig(null, Kernel.SetProjectConfigRequest.newBuilder()
				.setProjectNamespace(ACME + "/staging")
				.setConfig(Kernel.ProjectConfig.getDefaultInstance())
				.build());

		CollectionRuntime.Page<Kernel.ProjectNamespace> page = impl.listProjects(
				null,
				Kernel.ListProjectsRequest.newBuilder().setTenantNamespace(ACME).build(),
				new CollectionRuntime.PageParams(1, null));

		assertEquals(1, page.items.size());
		assertEquals(2, page.total);
		assertEquals(List.of(ACME + "/prod"), page.nextAfter.keys);
	}

	private static Kernel.Constraints fullCeiling(
			List<String> grants, List<String> dataGrants, String principalScope) {
		return Kernel.Constraints.newBuilder()
				.setEntitlementsCeiling(Entitlements.TokenEntitlements.newBuilder()
						.addAllGrants(grants)
						.addAllDataGrants(dataGrants)
						.setPrincipalScope(principalScope))
				.build();
	}

	private static Kernel.Constraints ceiling(String... grants) {
		Entitlements.TokenEntitlements.Builder entitlements = Entitlements.TokenEntitlements.newBuilder();
		for (String g : grants) {
			entitlements.addGrants(g);
		}
		return Kernel.Constraints.newBuilder().setEntitlementsCeiling(entitlements).build();
	}
}
