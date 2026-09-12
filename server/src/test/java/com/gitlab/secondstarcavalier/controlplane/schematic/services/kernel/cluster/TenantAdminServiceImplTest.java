// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

	private static Kernel.Constraints ceiling(String... grants) {
		Entitlements.TokenEntitlements.Builder entitlements = Entitlements.TokenEntitlements.newBuilder();
		for (String g : grants) {
			entitlements.addGrants(g);
		}
		return Kernel.Constraints.newBuilder().setEntitlementsCeiling(entitlements).build();
	}
}
