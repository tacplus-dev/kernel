// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import java.util.List;

/** The boot seed of Config.tenants, for tests outside this package (authz's served reads). */
public final class TenantBootstrapSeeds {

	private TenantBootstrapSeeds() {
	}

	/** Seeds {@code tenants} into {@code configMap} as kernel does at boot. */
	public static void seed(ConfigMap configMap, List<Kernel.BootstrapTenant> tenants) throws ProtoException {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, tenants);
	}
}
