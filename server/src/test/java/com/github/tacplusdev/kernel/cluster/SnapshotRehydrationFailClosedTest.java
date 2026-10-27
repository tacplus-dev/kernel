// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.CaMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.IdentityMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Rehydration fails closed, at the severity {@code IdentitySnapshot.load()}
 * already uses for an unreadable snapshot.
 *
 * <p>{@code load()} refuses to boot when a snapshot exists but cannot be read.
 * The rehydration that CONSUMES that snapshot did not get the same treatment:
 * one try/catch logged "Failed to fully rehydrate kernel snapshot (continuing)"
 * and let the node come up. One malformed tenant, CA or revocation row aborted
 * the rest of the loop, so the kernel booted SERVING with an arbitrary prefix of
 * the snapshot applied — revocations restored but tenants not, or the reverse.
 */
class SnapshotRehydrationFailClosedTest {

	private record Maps(IdentityMap identity, CaMap ca, WorkloadMap workload, ConfigMap config) {
		static Maps fresh() {
			InMemoryManager m = new InMemoryManager();
			return new Maps(new IdentityMap(m), new CaMap(m), new WorkloadMap(m), new ConfigMap(m));
		}
	}

	private static void rehydrate(Kernel.KernelDiskState snapshot, Maps maps) {
		ClusterServer.rehydrateFromSnapshot(
				snapshot, maps.identity(), maps.ca(), maps.workload(), maps.config());
	}

	/** A revocation with no revoked_by fails the boundary's own validation. */
	private static Kernel.WorkloadRevocation malformedRevocation() {
		return Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId("spiffe://local.dev/system/services/example")
				.build();
	}

	private static Kernel.WorkloadRevocation revocation(String spiffeId) {
		return Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(spiffeId)
				.setRevokedBy("/tenants/acme")
				.setRevokedAtMs(1_700_000_000_000L)
				.build();
	}

	/**
	 * The regression: a row the boundary rejects must refuse the boot rather than
	 * leaving the node SERVING with the rest of the snapshot missing.
	 */
	@Test
	void aMalformedRowRefusesTheBootInsteadOfLoggingAndContinuing() {
		Kernel.KernelDiskState snapshot = Kernel.KernelDiskState.newBuilder()
				.addWorkloadRevocations(malformedRevocation())
				.build();

		IllegalStateException e = assertThrows(IllegalStateException.class,
				() -> rehydrate(snapshot, Maps.fresh()));
		assertEquals("kernel refuses to start: disk snapshot could not be fully rehydrated",
				e.getMessage());
	}

	/**
	 * The harm the old behaviour hid: the loop aborted mid-way, so the rows after
	 * the bad one were silently dropped and a revoked workload came back live.
	 */
	@Test
	void aBadRowDoesNotLetLaterRevocationsBeSilentlyDropped() {
		Kernel.KernelDiskState snapshot = Kernel.KernelDiskState.newBuilder()
				.addWorkloadRevocations(malformedRevocation())
				.addWorkloadRevocations(revocation("spiffe://local.dev/workloads/still-revoked"))
				.build();

		Maps maps = Maps.fresh();
		assertThrows(IllegalStateException.class, () -> rehydrate(snapshot, maps));
		assertEquals(0, maps.workload().proto().getRevocationsCount(),
				"the partial restore must not be accepted as the node's state");
	}

	/** A well-formed snapshot still restores, and a cold start is still a no-op. */
	@Test
	void aCleanSnapshotAndAColdStartAreUnaffected() throws Exception {
		Maps maps = Maps.fresh();
		Kernel.KernelDiskState snapshot = Kernel.KernelDiskState.newBuilder()
				.addWorkloadRevocations(revocation("spiffe://local.dev/workloads/gone"))
				.addTenantConfigs(Kernel.TenantConfigEntry.newBuilder()
						.setTenantName("/tenants/acme")
						.build())
				.addTenants(Kernel.Tenant.newBuilder()
						.setName("/tenants/acme")
						.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
						.build())
				.build();

		assertDoesNotThrow(() -> rehydrate(snapshot, maps));
		assertEquals(1, maps.workload().proto().getRevocationsCount());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE,
				maps.config().getTenants("/tenants/acme").getStatus());

		assertDoesNotThrow(() -> rehydrate(null, Maps.fresh()));
	}
}
