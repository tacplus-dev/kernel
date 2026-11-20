// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.vservices.query.Query;

import java.util.Iterator;

/**
 * The tenant registry's change feed as the generated record plane serves it:
 * {@code RecordMap.WatchTenantRegistryEntryChanges} on the system tenant's
 * Stratum, routed by its tid (kernel#69). It maps the plane's watch events onto
 * {@link TenantRegistryWatch.Event}, and is the only class that knows their
 * generated shape.
 */
final class StratumTenantRegistryFeed {

	private StratumTenantRegistryFeed() {
	}

	/**
	 * The request that opens the feed after {@code fromRevision} on the Stratum of
	 * tenant {@code tid}.
	 */
	static Query.WatchTenantRegistryEntryChangesRequest request(String tid, long fromRevision) {
		// trace: unrelated: kernel follows the registry from boot, for no inbound request.
		return Query.WatchTenantRegistryEntryChangesRequest.newBuilder()
				.setFromRevision(fromRevision)
				.setTargetTenant(tid)
				.build();
	}

	/** The plane's stream as a {@link TenantRegistryWatch.Stream}; closing it cancels the call. */
	static <I extends Iterator<Query.TenantRegistryEntryWatchEvent> & AutoCloseable> TenantRegistryWatch.Stream stream(
			I events) {
		return new TenantRegistryWatch.Stream() {
			@Override
			public boolean hasNext() {
				return events.hasNext();
			}

			@Override
			public TenantRegistryWatch.Event next() {
				return event(events.next());
			}

			@Override
			public void close() {
				try {
					events.close();
				} catch (Exception e) {
					throw new IllegalStateException("closing the tenant registry watch: " + e.getMessage(), e);
				}
			}
		};
	}

	/** One watch event of the plane as the registry's. */
	static TenantRegistryWatch.Event event(Query.TenantRegistryEntryWatchEvent event) {
		switch (event.getEventCase()) {
			case SNAPSHOT_ITEM:
				return new TenantRegistryWatch.Event(TenantRegistryWatch.Kind.SNAPSHOT_ITEM,
						event.getSnapshotItem(), 0);
			case SNAPSHOT_DONE:
				return new TenantRegistryWatch.Event(TenantRegistryWatch.Kind.SNAPSHOT_DONE,
						null, event.getSnapshotDone());
			case DELTA:
				Query.TenantRegistryEntryWatchChange delta = event.getDelta();
				TenantRegistryWatch.Kind kind = delta.getType() == Query.RecordChangeType.RECORD_CHANGE_TYPE_DELETE
						? TenantRegistryWatch.Kind.DELETE : TenantRegistryWatch.Kind.PUT;
				return new TenantRegistryWatch.Event(kind, delta.getItem(), delta.getRevision());
			default:
				throw new IllegalStateException("tenant registry watch event carries nothing: " + event);
		}
	}
}
