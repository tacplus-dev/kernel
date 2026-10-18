// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.diskstore.DiskStoreException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Failure-path contract for {@link IdentitySnapshot}: a write that does not
 * land must throw (so the mutating RPC that triggered it reports failure rather
 * than acking a revocation only held in memory), and a snapshot that exists but
 * cannot be read must throw rather than being mistaken for a cold start.
 */
class IdentitySnapshotFailureTest {

	/** {@code <base>/_root/kernel_disk_state.snapshot} — the UC1 root-namespace store file. */
	private static Path snapshotFile(Path base) {
		return base.resolve("_root").resolve("kernel_disk_state.snapshot");
	}

	private static Kernel.WorkloadRevocation revocation() {
		return Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId("spiffe://schematic/ns/default/sa/argus")
				.setRevokedBy("admin@example.com")
				.setRevokedAtMs(Instant.parse("2026-09-12T00:00:00Z").toEpochMilli())
				.build();
	}

	private static IdentitySnapshot persistence(Path dir) {
		return new IdentitySnapshot(
				dir.toString(), null, null, null, null, () -> List.of(revocation()), null, null);
	}

	/**
	 * A storage-layer write failure propagates. The RPC handlers call this
	 * through a {@code Runnable} hook, so the throw is what turns an unpersisted
	 * revocation into a non-OK status instead of a success the caller trusts.
	 */
	@Test
	void saveThrowsWhenTheUnderlyingWriteFails(@TempDir Path dir) throws IOException {
		// A regular file where the namespace directory has to go: createDirectories
		// fails, so nothing is ever written.
		Files.writeString(dir.resolve("_root"), "not a directory");

		assertThrows(DiskStoreException.class, () -> persistence(dir).save());
	}

	/** A genuinely absent snapshot is still a clean cold start. */
	@Test
	void absentSnapshotColdStarts(@TempDir Path dir) {
		assertNull(persistence(dir).load(), "no snapshot on disk is a cold start");
	}

	/** Sanity: the happy path still round-trips, so the failure tests mean something. */
	@Test
	void writtenSnapshotLoadsBack(@TempDir Path dir) {
		IdentitySnapshot p = persistence(dir);
		p.save();

		Kernel.KernelDiskState loaded = p.load();
		assertNotNull(loaded);
		assertEquals(1, loaded.getWorkloadRevocationsCount());
		assertEquals(revocation(), loaded.getWorkloadRevocations(0));
	}

	/** A corrupt snapshot fails loudly rather than silently un-revoking everything. */
	@Test
	void corruptSnapshotThrowsInsteadOfColdStarting(@TempDir Path dir) throws IOException {
		IdentitySnapshot p = persistence(dir);
		p.save();
		Files.write(snapshotFile(dir), "}{ not json".getBytes(StandardCharsets.UTF_8));

		assertThrows(DiskStoreException.class, p::load);
	}

	/** Same for a half-written snapshot (interrupted write / torn file). */
	@Test
	void truncatedSnapshotThrowsInsteadOfColdStarting(@TempDir Path dir) throws IOException {
		IdentitySnapshot p = persistence(dir);
		p.save();

		Path file = snapshotFile(dir);
		String whole = Files.readString(file, StandardCharsets.UTF_8);
		Files.writeString(file, whole.substring(0, whole.length() / 2), StandardCharsets.UTF_8);

		assertThrows(DiskStoreException.class, p::load);
	}
}
