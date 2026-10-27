// Copyright (c) 2026 Seabeam LLC. All rights reserved.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The reserved {@code restore} tenant, tid {@value TenantIds#RESTORE} in every
 * deployment. It hosts the redo service (tacplus-dev/redo#1) and has no human
 * members.
 *
 * <p>Reserved as {@link PeopleTenant} is: kernel creates it at every boot
 * ({@link #seed}), and {@code TenantAdmin} refuses to create, reconfigure or
 * delete it. Unlike {@code people} it has no IdPs, so its config is empty.
 */
final class RestoreTenant {

	private static final Logger logger = LoggerFactory.getLogger(RestoreTenant.class);

	/** The tenant's leaf name — reserved fleet-wide. */
	static final String NAME = "restore";

	/** The tenant's canonical namespace. */
	static final String NAMESPACE = "/" + Spiffe.TENANTS_SEGMENT + "/" + NAME;

	private RestoreTenant() {
	}

	/**
	 * Creates the tenant record under its fixed tid, keeping {@code created_at}
	 * across restarts, and an empty config entry if it has none (the entry is
	 * what lists the tenant and carries it into the disk snapshot).
	 *
	 * @param configMap kernel ConfigState accessor
	 */
	static void seed(ConfigMap configMap) throws ProtoException {
		TenantIds.claim(configMap, TenantIds.RESTORE, NAMESPACE);
		Kernel.Tenant existing = configMap.getTenants(NAMESPACE);
		Timestamp now = Timestamp.newBuilder()
				.setSeconds(Instant.now().getEpochSecond()).build();
		configMap.putTenants(NAMESPACE, Kernel.Tenant.newBuilder()
				.setName(NAME)
				.setTid(TenantIds.RESTORE)
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.setCreatedAt(existing.getName().isEmpty() ? now : existing.getCreatedAt())
				.setUpdatedAt(now)
				.build());
		configMap.putIfAbsentTenantConfigs(NAMESPACE, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(NAMESPACE)
				.build());
		logger.info("Seeded reserved tenant {} (tid {})", NAMESPACE, TenantIds.RESTORE);
	}
}
