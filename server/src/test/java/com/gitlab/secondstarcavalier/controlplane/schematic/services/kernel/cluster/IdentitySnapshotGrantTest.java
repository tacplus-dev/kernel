// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Round-trips standing delegation grants through the kernel disk snapshot:
 * {@link IdentitySnapshot#save()} must write {@code KernelDiskState.grants}
 * and {@link IdentitySnapshot#load()} must return them intact.
 */
class IdentitySnapshotGrantTest {

	private static Kernel.Grant grant() {
		return Kernel.Grant.newBuilder()
				.setId("grant-abc123")
				.setDelegateName("argus")
				.setSubject("user@example.com")
				.setAuthorizedScope(Entitlements.TokenEntitlements.newBuilder()
						.addGrants("KERNEL_IDENTITY_MINT")
						.addDataGrants("KERNEL_TENANT_NAME")
						.addAzp("argus")
						.build())
				.setClaims(Struct.newBuilder()
						.putFields("email", Value.newBuilder().setStringValue("user@example.com").build())
						.putFields("groups", Value.newBuilder().setStringValue("[\"eng\"]").build())
						.build())
				.setCreatedAtMs(1_700_000_000_000L)
				.setExpiresAtMs(1_700_086_400_000L)
				.build();
	}

	@Test
	void grantSurvivesSaveAndLoad(@TempDir Path dir) {
		Kernel.Grant expected = grant();

		IdentitySnapshot p = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, () -> List.of(expected), null);
		p.save();

		Kernel.KernelDiskState loaded = p.load();
		assertNotNull(loaded, "snapshot should load back");
		assertEquals(1, loaded.getGrantsCount());
		assertEquals(expected, loaded.getGrants(0));
	}

	@Test
	void coldStartHasNoGrants(@TempDir Path dir) {
		assertNull(new IdentitySnapshot(dir.toString(), null, null, null, null, null, List::of, null).load());
	}

	@Test
	void snapshotWithoutGrantsStillLoads(@TempDir Path dir) {
		IdentitySnapshot p = new IdentitySnapshot(
				dir.toString(), null, null, null, null, null, List::of, null);
		p.save();

		Kernel.KernelDiskState loaded = p.load();
		assertNotNull(loaded);
		assertEquals(0, loaded.getGrantsCount());
	}
}
