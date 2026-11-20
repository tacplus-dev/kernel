// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.vservices.query.Query;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import io.grpc.Status;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Kernel follows the tenant registry's change feed (kernel#69): the snapshot,
 * then the changes, resuming after the last revision it saw.
 */
class TenantRegistryWatchTest {

	private final ConfigMap configMap = new ConfigMap(new InMemoryManager());
	private final TenantRegistry registry = new TenantRegistry(configMap, () -> { });
	/** The revision each opened stream asked for. */
	private final List<Long> opened = new ArrayList<>();
	/** The streams the feed serves, in order. */
	private final Deque<List<TenantRegistryWatch.Event>> streams = new ArrayDeque<>();
	private RuntimeException failure;
	private int closed;

	private final TenantRegistryWatch watch = new TenantRegistryWatch(registry, from -> {
		opened.add(from);
		if (failure != null) {
			RuntimeException f = failure;
			failure = null;
			throw f;
		}
		Iterator<TenantRegistryWatch.Event> events = streams.removeFirst().iterator();
		return new TenantRegistryWatch.Stream() {
			@Override
			public boolean hasNext() {
				return events.hasNext();
			}

			@Override
			public TenantRegistryWatch.Event next() {
				return events.next();
			}

			@Override
			public void close() {
				closed++;
			}
		};
	}, 0);

	private static Kernel.TenantRegistryEntry entry(String tid, String name, long version) {
		return Kernel.TenantRegistryEntry.newBuilder()
				.setTid(tid)
				.setName(name)
				.setKubernetesNamespace("tac-dev-" + tid)
				.addServices(Kernel.TenantRegistryService.newBuilder()
						.setName("docmanager")
						.setKubernetesServiceAccount("docmanager-" + name))
				.setVersion(version)
				.build();
	}

	private static TenantRegistryWatch.Event item(Kernel.TenantRegistryEntry e) {
		return new TenantRegistryWatch.Event(TenantRegistryWatch.Kind.SNAPSHOT_ITEM, e, 0);
	}

	private static TenantRegistryWatch.Event done(long revision) {
		return new TenantRegistryWatch.Event(TenantRegistryWatch.Kind.SNAPSHOT_DONE, null, revision);
	}

	private static TenantRegistryWatch.Event put(Kernel.TenantRegistryEntry e, long revision) {
		return new TenantRegistryWatch.Event(TenantRegistryWatch.Kind.PUT, e, revision);
	}

	private static TenantRegistryWatch.Event delete(Kernel.TenantRegistryEntry e, long revision) {
		return new TenantRegistryWatch.Event(TenantRegistryWatch.Kind.DELETE, e, revision);
	}

	private List<String> heldTids() {
		List<String> tids = new ArrayList<>();
		registry.entries().forEach(e -> tids.add(e.getTid()));
		return tids;
	}

	@Test
	void theSnapshotThenTheChangesAreApplied() throws Exception {
		streams.add(List.of(
				item(entry("acmetid1", "acme", 1)),
				done(7),
				put(entry("globex01", "globex", 1), 8),
				put(entry("acmetid1", "acme", 2).toBuilder()
						.setStatus(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED).build(), 9)));

		watch.followOnce();

		assertEquals(List.of(0L), opened, "the first stream reads the snapshot");
		assertEquals(List.of("acmetid1", "globex01"), heldTids());
		assertEquals("acmetid1", configMap.getTenants("/tenants/acme").getTid());
		assertEquals("globex01", configMap.getTenants("/tenants/globex").getTid());
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, configMap.getTenants("/tenants/acme").getStatus());
		assertEquals(9, watch.revision());
		assertEquals(1, closed);
	}

	@Test
	void aStreamThatEndsResumesAfterTheLastRevision() {
		streams.add(List.of(item(entry("acmetid1", "acme", 1)), done(3)));
		streams.add(List.of(delete(entry("acmetid1", "acme", 1), 4)));

		watch.followOnce();
		watch.followOnce();

		assertEquals(List.of(0L, 3L), opened);
		assertTrue(registry.entries().isEmpty(), "the deleted entry is dropped");
		assertTrue(registry.delegates().isEmpty());
	}

	@Test
	void anEntryTheSnapshotNoLongerListsIsDropped() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				Kernel.BootstrapTenant.newBuilder().setName("acme").setTid("acmetid1").build(),
				Kernel.BootstrapTenant.newBuilder().setName("gone").setTid("gonetid1").build()));
		registry.restore(List.of(entry("acmetid1", "acme", 1), entry("gonetid1", "gone", 1)));
		streams.add(List.of(item(entry("acmetid1", "acme", 1)), done(2)));

		watch.followOnce();

		assertEquals(List.of("acmetid1"), heldTids());
		assertEquals(1, registry.delegates().size());
	}

	@Test
	void aRefusedEntryDoesNotStopTheFeed() {
		streams.add(List.of(
				item(entry("acmetid1", "acme", 1)),
				done(1),
				put(entry("acmetid1", "renamed", 2), 2),
				put(entry("globex01", "globex", 1), 3)));

		watch.followOnce();

		assertEquals(List.of("acmetid1", "globex01"), heldTids());
		assertEquals("acme", registry.entries().get(0).getName());
		assertEquals(3, watch.revision());
	}

	@Test
	void aResumePointTheStoreNoLongerHoldsStartsOverFromZero() {
		streams.add(List.of(item(entry("acmetid1", "acme", 1)), done(5)));
		watch.followOnce();
		failure = new ProtoException(Status.Code.OUT_OF_RANGE.value(), "revision 5 is compacted");

		watch.followOnce();

		assertEquals(0, watch.revision());
		streams.add(List.of(item(entry("acmetid1", "acme", 1)), done(12)));
		watch.followOnce();
		assertEquals(List.of(0L, 5L, 0L), opened);
		assertEquals(12, watch.revision());
	}

	@Test
	void anotherFailureIsThrownAndTheRevisionKept() {
		streams.add(List.of(item(entry("acmetid1", "acme", 1)), done(5)));
		watch.followOnce();
		failure = new ProtoException(Status.Code.UNAVAILABLE.value(), "no stratum");

		assertThrows(ProtoException.class, watch::followOnce);
		assertEquals(5, watch.revision());
	}

	// ---- The generated plane's events ----------------------------------------

	@Test
	void thePlanesWatchEventsMapOntoTheRegistrys() {
		Kernel.TenantRegistryEntry e = entry("acmetid1", "acme", 1);

		TenantRegistryWatch.Event snapshotItem = StratumTenantRegistryFeed.event(
				Query.TenantRegistryEntryWatchEvent.newBuilder().setSnapshotItem(e).build());
		assertEquals(TenantRegistryWatch.Kind.SNAPSHOT_ITEM, snapshotItem.kind());
		assertEquals(e, snapshotItem.entry());

		TenantRegistryWatch.Event snapshotDone = StratumTenantRegistryFeed.event(
				Query.TenantRegistryEntryWatchEvent.newBuilder().setSnapshotDone(7).build());
		assertEquals(TenantRegistryWatch.Kind.SNAPSHOT_DONE, snapshotDone.kind());
		assertNull(snapshotDone.entry());
		assertEquals(7, snapshotDone.revision());

		TenantRegistryWatch.Event modify = StratumTenantRegistryFeed.event(
				Query.TenantRegistryEntryWatchEvent.newBuilder().setDelta(Query.TenantRegistryEntryWatchChange.newBuilder()
						.setType(Query.RecordChangeType.RECORD_CHANGE_TYPE_MODIFY).setItem(e).setRevision(8)).build());
		assertEquals(TenantRegistryWatch.Kind.PUT, modify.kind());
		assertEquals(8, modify.revision());

		TenantRegistryWatch.Event deleted = StratumTenantRegistryFeed.event(
				Query.TenantRegistryEntryWatchEvent.newBuilder().setDelta(Query.TenantRegistryEntryWatchChange.newBuilder()
						.setType(Query.RecordChangeType.RECORD_CHANGE_TYPE_DELETE).setItem(e).setRevision(9)).build());
		assertEquals(TenantRegistryWatch.Kind.DELETE, deleted.kind());
		assertEquals(e, deleted.entry());
	}

	@Test
	void theWatchRequestIsRoutedToTheRegistrysStratum() {
		Query.WatchTenantRegistryEntryChangesRequest req = StratumTenantRegistryFeed.request("sysreg01", 42);

		assertEquals("sysreg01", req.getTargetTenant());
		assertEquals(42, req.getFromRevision());
	}
}
