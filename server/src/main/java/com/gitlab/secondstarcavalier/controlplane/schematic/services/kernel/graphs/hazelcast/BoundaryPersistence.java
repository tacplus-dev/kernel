// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.DiskStoreException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.Snapshot;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.StorePath;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.OpType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.PersistenceEntry;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import com.hazelcast.core.EntryEvent;
import com.hazelcast.map.MapEvent;
import com.hazelcast.map.listener.EntryAddedListener;
import com.hazelcast.map.listener.EntryEvictedListener;
import com.hazelcast.map.listener.EntryExpiredListener;
import com.hazelcast.map.listener.EntryRemovedListener;
import com.hazelcast.map.listener.EntryUpdatedListener;
import com.hazelcast.map.listener.MapClearedListener;
import com.hazelcast.map.listener.MapEvictedListener;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The durable store behind {@code (spec.persistence) = true}.
 *
 * <p>Kernel is the cluster's durable store for state boundaries. Every boundary
 * any service's proto flags persistent — not just kernel's own — is snapshotted
 * to kernel's {@code data} volume and rehydrated at boot. Boundaries that are
 * not flagged stay ephemeral: they live in Hazelcast memory, survive a single
 * pod restart through partition backups, and are gone after a cold start. That
 * is the whole contract of the annotation, and until this class existed it was
 * a no-op outside {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.KernelPersistence
 * KernelPersistence}'s own whole-kernel snapshot.
 *
 * <p><b>One file per boundary.</b> The flagged set includes collections whose
 * declared maxima run to the millions, so a single all-boundaries blob would
 * rewrite every service's state on every write. Each boundary instead owns
 * {@code <persistenceDir>/_root/boundaries/<map name>.snapshot}, written
 * through the same atomic {@link Snapshot} helper (fresh temp, fsync, rename,
 * numbered archives) that kernel's own snapshot uses. The payload is a stream
 * of length-delimited {@link PersistenceEntry} records, one per live map entry,
 * each carrying its value in an {@link Any} so the file names the proto type it
 * holds and a type change is caught on read rather than mis-parsed.
 *
 * <p><b>Written on change, synchronously, on the writing member.</b> {@link
 * PersistentMap} calls {@link #snapshot} after each mutation and lets the
 * exception out, so a state-plane write whose snapshot did not land fails the
 * RPC instead of acking data that exists only in memory — the same rule kernel
 * already applies to its own state. The other members keep their own copies
 * current from the map's entry listener (see {@link #register}), coalesced by
 * the writer below: every member holds a complete boundary file, so a cold
 * start is safe whichever pod happens to form the cluster first.
 *
 * <p><b>Rehydration is cold-start only.</b> {@link #rehydrate} is called by
 * {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.ClusterServer
 * ClusterServer} only when this pod booted alone. A pod joining peers takes its
 * state from them; replaying a snapshot over a live cluster would resurrect
 * whatever that pod last wrote before it went down. Rehydration also writes
 * with put-if-absent, so even if it were ever reached with entries present it
 * cannot overwrite them.
 *
 * <p><b>Fail closed.</b> A boundary file that exists but cannot be read or
 * parsed throws, so kernel refuses to boot rather than coming up with a
 * service's state silently emptied — the rule {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.KernelPersistence#load()}
 * already states for kernel's own snapshot.
 */
public final class BoundaryPersistence implements AutoCloseable {

	private static final Logger logger = LoggerFactory.getLogger(BoundaryPersistence.class);

	/** UC1 diskstore namespace. Boundaries are cluster-wide, so root. */
	private static final String NS = "/";
	/** Store-name prefix, so boundary files sit beside — not among — kernel's own snapshot. */
	private static final String STORE_PREFIX = "boundaries/";
	private static final String SUFFIX = ".snapshot";
	private static final String TYPE_URL_PREFIX = "type.googleapis.com/";

	/** How often the coalescing writer drains boundaries dirtied by a remote write. */
	private static final long FLUSH_INTERVAL_MS = 250;

	/** One registered persistent boundary. */
	private record Boundary(
			String mapName,
			com.hazelcast.map.IMap<String, Message> hzMap,
			Message defaultInstance,
			Path file) {}

	private final Path base;
	private final boolean enabled;
	private final MapRegistry registry = new MapRegistry();
	private final Map<String, Boundary> boundaries = new ConcurrentHashMap<>();
	private final Set<String> dirty = new CopyOnWriteArraySet<>();
	private final AtomicLong lastSnapshotMs = new AtomicLong(0);
	private final ScheduledExecutorService flusher;

	private BoundaryPersistence(Path base) {
		this.base = base;
		this.enabled = base != null;
		if (!enabled) {
			this.flusher = null;
			return;
		}
		this.flusher = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "boundary-persistence-flusher");
			t.setDaemon(true);
			return t;
		});
		flusher.scheduleWithFixedDelay(
				this::flushDirty, FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);
	}

	/**
	 * A persistence store rooted at {@code persistenceDir} — kernel's {@code
	 * data} volume, the same directory {@code KernelPersistence} writes to.
	 */
	public static BoundaryPersistence at(String persistenceDir) {
		if (persistenceDir == null || persistenceDir.isEmpty()) {
			throw new IllegalArgumentException("persistenceDir is required");
		}
		return new BoundaryPersistence(Path.of(persistenceDir));
	}

	/**
	 * A store that persists nothing and registers boundaries for cluster stats
	 * only. For a node configured without a persistence directory, and for tests
	 * that stand up a manager without a volume.
	 */
	public static BoundaryPersistence disabled() {
		return new BoundaryPersistence(null);
	}

	public boolean isEnabled() {
		return enabled;
	}

	/** The registry of persistent boundaries, read by the cluster-stats publisher. */
	public MapRegistry getRegistry() {
		return registry;
	}

	/** Epoch millis of the last boundary file written, or 0 if none has been. */
	public long getLastSnapshotTimestamp() {
		return lastSnapshotMs.get();
	}

	/** Total bytes the boundary snapshots currently occupy, archives included. */
	public long getSnapshotSizeBytes() {
		if (!enabled) {
			return 0;
		}
		long total = 0;
		for (Boundary b : boundaries.values()) {
			total += sizeOf(b.file());
			for (int i = 1; i <= Snapshot.Opts.defaults().archiveCount; i++) {
				total += sizeOf(Path.of(b.file().toString() + ".bak." + i));
			}
		}
		return total;
	}

	private static long sizeOf(Path p) {
		try {
			return java.nio.file.Files.size(p);
		} catch (IOException e) {
			return 0;
		}
	}

	/**
	 * Registers a boundary the codegen flagged {@code (spec.persistence) = true}.
	 * Idempotent: a boundary is reached through both its generated {@code
	 * <Backend>Map} and its generated state-service server, which resolve to one
	 * Hazelcast map and must register once.
	 *
	 * <p>The entry listener attached here is what keeps the members that did NOT
	 * serve a write up to date. It only marks the boundary dirty; the coalescing
	 * writer does the I/O, so a burst of writes costs one file rewrite rather
	 * than one per entry, and a member that served the write itself has usually
	 * already written the file synchronously and finds nothing to do.
	 *
	 * @param mapName         the Hazelcast map name (class-qualified boundary path)
	 * @param hzMap           the backing Hazelcast map
	 * @param imap            the wrapper handed to generated code, for the stats registry
	 * @param defaultInstance the boundary's value type — its parser on read, and
	 *                        the proto type name stamped into each record
	 * @param consistency     the boundary's declared consistency, for the stats registry
	 */
	@SuppressWarnings("unchecked")
	public <K, V> void register(
			String mapName,
			com.hazelcast.map.IMap<K, V> hzMap,
			IMap<K, V> imap,
			Message defaultInstance,
			ConsistencyType consistency) {
		Objects.requireNonNull(mapName, "mapName");
		registry.register(mapName, imap, defaultInstance == null ? null : defaultInstance.getParserForType(),
				consistency);
		if (!enabled || defaultInstance == null) {
			return;
		}
		if (boundaries.containsKey(mapName)) {
			return;
		}
		Path file = StorePath.storePath(base, NS, STORE_PREFIX + fileNameFor(mapName), SUFFIX);
		boundaries.put(
				mapName,
				new Boundary(mapName, (com.hazelcast.map.IMap<String, Message>) hzMap, defaultInstance, file));
		hzMap.addEntryListener(new DirtyMarker(mapName), false);
	}

	/**
	 * A boundary's map name as a file name. Map names are class-qualified
	 * ({@code <generated map class>:<package>.<Backend>.<Boundary>}) and so are
	 * already unique and stable; the substitution below only makes them legal
	 * path segments, and is injective for the characters map names actually use.
	 */
	static String fileNameFor(String mapName) {
		StringBuilder sb = new StringBuilder(mapName.length());
		for (int i = 0; i < mapName.length(); i++) {
			char c = mapName.charAt(i);
			boolean safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
					|| c == '.' || c == '-' || c == '_';
			sb.append(safe ? c : '_');
		}
		return sb.toString();
	}

	/**
	 * Writes {@code mapName}'s boundary file from the live map, atomically.
	 *
	 * <p>Throws on any failure to build or write the file. {@link PersistentMap}
	 * calls this on the mutating path and does not catch, so the caller is never
	 * told its write is durable when the file it depends on did not land.
	 *
	 * @throws DiskStoreException if the boundary file could not be built or written
	 */
	public void snapshot(String mapName) {
		Boundary b = boundaries.get(mapName);
		if (b == null) {
			return;
		}
		// One writer per boundary. Two concurrent state-plane writes — or a
		// write racing the flusher thread — otherwise build and rename through
		// the same process-scoped temp file name and one of them fails on a
		// file the other has already moved away.
		synchronized (b) {
			writeBoundary(b, mapName);
		}
	}

	private void writeBoundary(Boundary b, String mapName) {
		// Cleared BEFORE the read below, not after the write: a concurrent
		// mutation that lands between the two re-dirties the boundary and gets
		// its own flush, where clearing afterwards could swallow it.
		dirty.remove(mapName);
		byte[] payload;
		int count;
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			String typeUrl = TYPE_URL_PREFIX + b.defaultInstance().getDescriptorForType().getFullName();
			long now = System.currentTimeMillis();
			count = 0;
			for (Map.Entry<String, Message> e : b.hzMap().entrySet()) {
				PersistenceEntry.newBuilder()
						.setMapName(mapName)
						.setKey(e.getKey())
						.setPayload(Any.newBuilder()
								.setTypeUrl(typeUrl)
								.setValue(ByteString.copyFrom(e.getValue().toByteArray()))
								.build())
						.setOp(OpType.OP_TYPE_PUT)
						.setTimestampMs(now)
						.build()
						.writeDelimitedTo(out);
				count++;
			}
			payload = out.toByteArray();
		} catch (IOException | RuntimeException e) {
			logger.error("Failed to build the boundary snapshot for {}: {}", mapName, e.getMessage(), e);
			throw DiskStoreException.codec("boundary snapshot " + mapName + ": " + e.getMessage(), e);
		}
		Snapshot.writeSnapshot(b.file(), payload, Snapshot.Opts.defaults());
		lastSnapshotMs.set(System.currentTimeMillis());
		logger.debug("Persisted boundary {} ({} entries, {} bytes)", mapName, count, payload.length);
	}

	/**
	 * Loads every registered boundary from disk into its Hazelcast map.
	 *
	 * <p>COLD START ONLY. The caller must have established that this pod booted
	 * with no reachable peers; see {@code ClusterServer}. Entries are written
	 * with put-if-absent so that even a mistaken call cannot overwrite live
	 * cluster state with this pod's last snapshot — the one way this feature
	 * could silently destroy data.
	 *
	 * @return the number of entries rehydrated across all boundaries
	 * @throws DiskStoreException if a boundary file exists but cannot be read
	 */
	public int rehydrate() {
		if (!enabled) {
			return 0;
		}
		int total = 0;
		for (Boundary b : boundaries.values()) {
			total += rehydrateOne(b);
		}
		if (total > 0) {
			logger.info("Rehydrated {} entries across {} persistent boundaries from {}",
					total, boundaries.size(), base);
		} else {
			logger.info("No persisted boundary state under {} — cold start with {} boundaries empty",
					base, boundaries.size());
		}
		return total;
	}

	private int rehydrateOne(Boundary b) {
		byte[] payload;
		try {
			payload = Snapshot.readSnapshot(b.file());
		} catch (RuntimeException e) {
			logger.error("Boundary snapshot {} exists but could not be read — refusing to start: {}",
					b.file(), e.getMessage(), e);
			throw e;
		}
		if (payload == null) {
			return 0;
		}
		String expectedType = b.defaultInstance().getDescriptorForType().getFullName();
		int applied = 0;
		ByteArrayInputStream in = new ByteArrayInputStream(payload);
		while (true) {
			PersistenceEntry entry;
			try {
				entry = PersistenceEntry.parseDelimitedFrom(in);
			} catch (IOException e) {
				throw DiskStoreException.invalidData(
						"boundary snapshot " + b.file() + " is truncated or corrupt: " + e.getMessage());
			}
			if (entry == null) {
				break;
			}
			String typeUrl = entry.getPayload().getTypeUrl();
			String recordedType = typeUrl.substring(typeUrl.lastIndexOf('/') + 1);
			if (!expectedType.equals(recordedType)) {
				// The boundary's value type changed under a file written by an
				// older build. Parsing it as the new type would quietly produce
				// garbage rows, so this is a startup failure, not a warning.
				throw DiskStoreException.invalidData("boundary snapshot " + b.file() + " holds "
						+ recordedType + " but boundary " + b.mapName() + " is " + expectedType);
			}
			Message value;
			try {
				value = b.defaultInstance().getParserForType().parseFrom(entry.getPayload().getValue());
			} catch (Exception e) {
				throw DiskStoreException.invalidData(
						"boundary snapshot " + b.file() + " has an unparseable " + expectedType
								+ " at key " + entry.getKey() + ": " + e.getMessage());
			}
			if (b.hzMap().putIfAbsent(entry.getKey(), value) == null) {
				applied++;
			}
		}
		logger.info("Rehydrated boundary {}: {} entries from {}", b.mapName(), applied, b.file());
		return applied;
	}

	/** Writes any boundary a remote member's write has dirtied on this node. */
	private void flushDirty() {
		for (String mapName : dirty) {
			try {
				snapshot(mapName);
			} catch (RuntimeException e) {
				// This node did not serve the write, so there is no RPC to fail:
				// the writing member has already persisted its own copy. Log
				// loudly — this node's copy is now behind, which matters only if
				// it is the one that forms the cluster after a cold start.
				logger.error("Failed to persist boundary {} replicated from another member: {}",
						mapName, e.getMessage(), e);
			}
		}
	}

	/** Marks a boundary dirty on every member that observes a change to it. */
	private final class DirtyMarker
			implements EntryAddedListener<String, Message>, EntryUpdatedListener<String, Message>,
			EntryRemovedListener<String, Message>, EntryEvictedListener<String, Message>,
			EntryExpiredListener<String, Message>, MapClearedListener, MapEvictedListener {

		private final String mapName;

		private DirtyMarker(String mapName) {
			this.mapName = mapName;
		}

		@Override
		public void entryAdded(EntryEvent<String, Message> event) {
			dirty.add(mapName);
		}

		@Override
		public void entryUpdated(EntryEvent<String, Message> event) {
			dirty.add(mapName);
		}

		@Override
		public void entryRemoved(EntryEvent<String, Message> event) {
			dirty.add(mapName);
		}

		@Override
		public void entryEvicted(EntryEvent<String, Message> event) {
			dirty.add(mapName);
		}

		@Override
		public void entryExpired(EntryEvent<String, Message> event) {
			dirty.add(mapName);
		}

		@Override
		public void mapCleared(MapEvent event) {
			dirty.add(mapName);
		}

		@Override
		public void mapEvicted(MapEvent event) {
			dirty.add(mapName);
		}
	}

	/** The registered boundaries and their files, for tests and diagnostics. */
	public Map<String, Path> files() {
		Map<String, Path> out = new LinkedHashMap<>();
		for (Boundary b : boundaries.values()) {
			out.put(b.mapName(), b.file());
		}
		return Collections.unmodifiableMap(out);
	}

	@Override
	public void close() {
		if (flusher != null) {
			flusher.shutdownNow();
		}
	}
}
