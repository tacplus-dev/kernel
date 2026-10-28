// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;

/**
 * Test fixtures' tenant-owned service subjects, as kernel mints them
 * (kernel#23): {@code spiffe://<td>/tenants/<tid>/services/<svc>}, rooted at
 * the tenant's tid. A fixture that holds no tid for the tenant gets one
 * claimed: {@code people}'s reserved one, or a fresh one.
 */
final class TenantServiceSubjects {

	private TenantServiceSubjects() {
	}

	/** The subject of the service {@code name} owned by {@code tenantNamespace}. */
	static String of(ConfigMap configMap, String trustDomain, String tenantNamespace, String name) {
		return SpiffeIds.build(trustDomain, SpiffeIds.tenantRoot(tidOf(configMap, tenantNamespace)), name);
	}

	/** The live tid {@code tenantNamespace} holds, claimed now if it holds none. */
	static String tidOf(ConfigMap configMap, String tenantNamespace) {
		try {
			for (Kernel.TenantIdRow row : configMap.proto().getTenantIdsList()) {
				if (row.getTombstonedAtMs() == 0 && row.getTenantNamespace().equals(tenantNamespace)) {
					return row.getTid();
				}
			}
			if (PeopleTenant.NAMESPACE.equals(tenantNamespace)) {
				TenantIds.claim(configMap, TenantIds.PEOPLE, tenantNamespace);
				return TenantIds.PEOPLE;
			}
			return TenantIds.mint(configMap, tenantNamespace);
		} catch (ProtoException e) {
			throw new IllegalStateException(e);
		}
	}
}
