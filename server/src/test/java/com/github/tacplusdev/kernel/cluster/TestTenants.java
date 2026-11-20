// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;

/**
 * Makes a test's tenants the way kernel makes them: a top-level tenant as the
 * tenant registry and the boot seed do (CreateTenant refuses one, kernel#69),
 * with a minted tid, and a sub-tenant through CreateTenant.
 */
final class TestTenants {

	private static final String TENANTS_PREFIX = "/tenants/";

	private TestTenants() {
	}

	/** The tenant at {@code ns}, made as kernel makes it. */
	static Kernel.Tenant create(TenantAdminServiceImpl admin, ConfigMap configMap, String ns) throws ProtoException {
		return create(admin, configMap, ns, Kernel.Constraints.getDefaultInstance());
	}

	/** The tenant at {@code ns} under {@code constraints}, made as kernel makes it. */
	static Kernel.Tenant create(TenantAdminServiceImpl admin, ConfigMap configMap, String ns,
			Kernel.Constraints constraints) throws ProtoException {
		String rest = ns.startsWith(TENANTS_PREFIX) ? ns.substring(TENANTS_PREFIX.length()) : "";
		if (rest.isEmpty() || rest.indexOf('/') >= 0) {
			return admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder()
					.setTenantNamespace(ns).setConstraints(constraints).build());
		}
		Kernel.Tenant existing = configMap.getTenants(ns);
		if (!existing.getName().isEmpty()) {
			throw new ProtoException(ProtoException.ALREADY_EXISTS, "tenant already exists at " + ns);
		}
		TenantAdminServiceImpl.seedBootstrapTenant(configMap, ns,
				Kernel.BootstrapTenant.newBuilder().setName(rest).build());
		Kernel.Tenant seeded = configMap.getTenants(ns).toBuilder().setConstraints(constraints).build();
		configMap.putTenants(ns, seeded);
		return seeded;
	}
}
