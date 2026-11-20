// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Follows the tenant registry's change feed ({@code WatchTenantRegistryEntryChanges}
 * on the system tenant's Stratum) into the {@link TenantRegistry} (kernel#69).
 *
 * <p>The first stream starts at revision 0: the registry's snapshot, then its
 * changes. Once the snapshot is done, an entry kernel held (from its disk
 * snapshot) that the registry no longer lists is dropped. A stream that ends or
 * fails is opened again after a pause, from the last revision seen, so only
 * the changes since arrive; a resume point the store no longer holds
 * (OUT_OF_RANGE) starts over from 0. An entry the registry refuses to apply
 * (a changed tid or name, a malformed one) is logged and skipped: one bad entry
 * never stops the feed.
 *
 * <p>The feed is the {@link Source}, so the stream's shape is all this class
 * knows of the generated record plane.
 */
final class TenantRegistryWatch implements Runnable {

	private static final Logger logger = LoggerFactory.getLogger(TenantRegistryWatch.class);

	/** gRPC's OUT_OF_RANGE: the resume point is older than the store retains. */
	private static final int OUT_OF_RANGE = io.grpc.Status.Code.OUT_OF_RANGE.value();

	/** What an event of the feed is. */
	enum Kind {
		/** One entry of the snapshot. */
		SNAPSHOT_ITEM,
		/** The snapshot is complete; its revision is the one it was taken at. */
		SNAPSHOT_DONE,
		/** An entry was written. */
		PUT,
		/** An entry was deleted. */
		DELETE
	}

	/** One event of the feed: the entry (none for SNAPSHOT_DONE) and its revision. */
	record Event(Kind kind, Kernel.TenantRegistryEntry entry, long revision) {
	}

	/** One open stream of the feed. */
	interface Stream extends Iterator<Event>, AutoCloseable {
		@Override
		void close();
	}

	/** Opens the feed after {@code fromRevision} (0: the snapshot, then the changes). */
	@FunctionalInterface
	interface Source {
		Stream open(long fromRevision);
	}

	private final TenantRegistry registry;
	private final Source source;
	private final long retryMillis;
	private long revision;

	/**
	 * @param registry    where the entries are applied
	 * @param source      the registry's change feed
	 * @param retryMillis the pause before a stream that ended is opened again
	 */
	TenantRegistryWatch(TenantRegistry registry, Source source, long retryMillis) {
		this.registry = registry;
		this.source = source;
		this.retryMillis = retryMillis;
	}

	/** The revision the next stream resumes after. */
	long revision() {
		return revision;
	}

	@Override
	public void run() {
		while (!Thread.currentThread().isInterrupted()) {
			try {
				followOnce();
				logger.info("Tenant registry watch ended at revision {}; resuming", revision);
			} catch (RuntimeException e) {
				logger.warn("Tenant registry watch failed at revision {}: {}", revision, e.getMessage());
			}
			try {
				Thread.sleep(retryMillis);
			} catch (InterruptedException ie) {
				Thread.currentThread().interrupt();
			}
		}
	}

	/**
	 * Opens one stream from the last revision seen and applies its events until
	 * it ends. A failure other than OUT_OF_RANGE is thrown to the caller.
	 */
	void followOnce() {
		Set<String> snapshot = revision == 0 ? new HashSet<>() : null;
		try (Stream stream = source.open(revision)) {
			while (stream.hasNext()) {
				Event event = stream.next();
				switch (event.kind()) {
					case SNAPSHOT_ITEM -> {
						if (snapshot != null) {
							snapshot.add(event.entry().getTid());
						}
						apply(event.entry());
					}
					case SNAPSHOT_DONE -> {
						if (snapshot != null) {
							registry.retainOnly(snapshot);
							snapshot = null;
						}
						revision = Math.max(revision, event.revision());
					}
					case PUT -> {
						apply(event.entry());
						revision = Math.max(revision, event.revision());
					}
					case DELETE -> {
						registry.remove(event.entry().getTid());
						revision = Math.max(revision, event.revision());
					}
				}
			}
		} catch (ProtoException e) {
			if (e.getCode() != OUT_OF_RANGE) {
				throw e;
			}
			logger.warn("Tenant registry: revision {} is no longer held by the store; re-reading from 0", revision);
			revision = 0;
		}
	}

	private void apply(Kernel.TenantRegistryEntry entry) {
		try {
			registry.apply(entry);
		} catch (ProtoException e) {
			logger.error("Tenant registry entry {} (/tenants/{}) at version {} refused: {}",
					entry.getTid(), entry.getName(), entry.getVersion(), e.getMessage());
		}
	}
}
