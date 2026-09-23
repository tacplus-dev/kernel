// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.Codec;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.DiskStoreException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.FsUtil;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.RedoLog;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.Snapshot;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.diskstore.StorePath;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.OpType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.PersistenceEntry;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
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

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.BooleanSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The durable store behind {@code (spec.persistence) = true}.
 *
 * <p>Kernel is the cluster's durable store for state boundaries. Every boundary
 * any service's proto flags persistent — not just kernel's own — is written to
 * kernel's {@code data} volume and replayed at boot. Boundaries that are not
 * flagged stay ephemeral: they live in Hazelcast memory, survive a single pod
 * restart through partition backups, and are gone after a cold start. That is
 * the whole contract of the annotation, and until this class existed it was a
 * no-op outside {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.KernelPersistence
 * KernelPersistence}'s own whole-kernel snapshot.
 *
 * <p><b>Redo log plus periodic checkpoint.</b> Each boundary owns one
 * append-only log, {@code <persistenceDir>/_root/boundaries/<map name>.log},
 * opened through the chassis's UC2 {@link RedoLog}. A mutation appends ONE
 * record for the one key it touched and fsyncs it — O(1) in the boundary's row
 * count, whatever its size. Periodically ({@link #maybeCheckpoint}) the log is
 * CHECKPOINTED: {@link RedoLog#roll} rebuilds it as the boundary's current
 * state, folds in anything appended meanwhile and swaps the new file in with
 * one atomic rename, which both coalesces the history and truncates it. The
 * steady-state write path never rewrites the file; a checkpoint does, and that
 * is its whole job.
 *
 * <p>This replaces a first implementation that rewrote the entire boundary file
 * inside every mutation. That is O(rows) per write, and the flagged set
 * includes collections whose declared maxima run to the millions — see
 * {@code decisions/2026-09-23-boundary-persistence-honored.md}.
 *
 * <p><b>The checkpoint trigger is size-based.</b> A boundary is checkpointed
 * when its log has grown past {@link #MIN_CHECKPOINT_BYTES} AND past twice the
 * size it had at the end of the last checkpoint. Doubling is what makes the
 * amortized cost per write O(1) — each row is rewritten once per doubling of
 * the log, so the rewriting a boundary does is proportional to the writes it
 * received, not to the product of its size and its write count. It also bounds
 * the log at twice the live state rather than at a duration's worth of writes,
 * which a wall-clock trigger cannot do across boundaries whose write rates
 * differ by orders of magnitude. The check rides the flusher below, so there is
 * no second timer.
 *
 * <p><b>Written on change, synchronously, on the writing member.</b> {@link
 * PersistentMap} calls {@link #record} after each mutation and lets the
 * exception out, so a state-plane write whose log append did not land fails the
 * RPC instead of acking data that exists only in memory — the same rule kernel
 * already applies to its own state. The other members keep their own logs
 * current from the map's entry listener (see {@link #register}), coalesced by
 * the writer below: every member holds a complete boundary log, so a cold start
 * is safe whichever pod happens to form the cluster first.
 *
 * <p><b>Replay is cold-start only.</b> {@link #rehydrate} is called by {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.ClusterServer
 * ClusterServer} only when this pod is its boot cohort's STATE ORIGIN — no peer
 * has declared itself state-bearing and this pod won the election in {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.StateBearingLedger
 * StateBearingLedger}. A pod joining peers that hold state takes it from them;
 * replaying a log over a live cluster would resurrect whatever that pod last
 * wrote before it went down. Replay also writes with put-if-absent, so even if
 * it were ever reached with entries present it cannot overwrite them.
 *
 * <p><b>A pod that joined peers still writes its own full copy.</b> Taking
 * state from peers puts nothing on THIS pod's disk, so a row that never
 * mutates again would never reach it and the next simultaneous cold restart
 * would lose the row on every pod at once. {@link #checkpointAll} is called
 * after the join — in the background, off the readiness path — and logs one
 * line per boundary with the row count it wrote, so a rolling restart can be
 * verified to have left every pod holding every boundary.
 *
 * <p><b>Fail closed.</b> A boundary log that exists but cannot be parsed
 * throws, so kernel refuses to boot rather than coming up with a service's
 * state silently emptied — the rule {@link
 * com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.KernelPersistence#load()}
 * already states for kernel's own snapshot. The one tolerated damage is an
 * unterminated FINAL line, which is a crash between an append's write and its
 * fsync: that record's RPC was never acked, so dropping it loses nothing a
 * caller was told about. See {@link #recoverTornTail}.
 */
public final class BoundaryPersistence implements AutoCloseable {

	private static final Logger logger = LoggerFactory.getLogger(BoundaryPersistence.class);

	/** UC1 diskstore namespace. Boundaries are cluster-wide, so root. */
	private static final String NS = "/";
	/** Store-name prefix, so boundary logs sit beside — not among — kernel's own snapshot. */
	private static final String STORE_PREFIX = "boundaries/";
	private static final String TYPE_URL_PREFIX = "type.googleapis.com/";

	/** How often the coalescing writer drains keys dirtied by a remote write. */
	private static final long FLUSH_INTERVAL_MS = 250;

	/**
	 * A log smaller than this is never checkpointed, however many times it has
	 * doubled. Rolling a 12KB log costs more in fsyncs than the bytes it saves,
	 * and most flagged boundaries — the cert, the config singletons — never
	 * reach this at all.
	 */
	private static final long MIN_CHECKPOINT_BYTES = 4L * 1024 * 1024;

	/** One registered persistent boundary. */
	private record Boundary(
			String mapName,
			com.hazelcast.map.IMap<String, Message> hzMap,
			Message defaultInstance,
			RedoLog log,
			/** Log size the last checkpoint left behind — the doubling baseline. */
			AtomicLong checkpointedBytes,
			/**
			 * Appends take the read lock and run concurrently; a checkpoint takes
			 * the write lock. {@link RedoLog#roll} redirects appends to a temp log
			 * for its own duration, but the CALLER builds the row list it is given,
			 * and a write landing during that read would be in the list for a key
			 * not yet visited and absent for one already passed — lost when the old
			 * log is archived. The lock is what makes the list and the swap one
			 * step.
			 */
			ReadWriteLock lock) {}

	private final Path base;
	private final boolean enabled;
	private final MapRegistry registry = new MapRegistry();
	private final Map<String, Boundary> boundaries = new ConcurrentHashMap<>();
	/** Keys a remote member changed, per boundary, awaiting their log append. */
	private final Map<String, Set<String>> pending = new ConcurrentHashMap<>();
	/** Boundaries a remote clear/evict-all hit: the whole log has to be rebuilt. */
	private final Set<String> pendingCheckpoint = ConcurrentHashMap.newKeySet();
	private final AtomicLong lastWriteMs = new AtomicLong(0);
	private final ScheduledExecutorService flusher;
	/**
	 * Whether the cluster is PROVABLY holding boundary state, which is the one
	 * condition under which the join-time checkpoint may write a file smaller
	 * than the one already on disk. Wired by {@code ClusterServer} to {@code
	 * StateBearingLedger.clusterBearsState}.
	 *
	 * <p>Defaults to "no". A store standing on its own — a test, a node with no
	 * cluster — has nothing that could prove the claim, and the whole point of
	 * the guard is that the unproven case does not shrink the file.
	 */
	private volatile BooleanSupplier stateBearing = () -> false;

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
				this::flushPending, FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);
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

	/**
	 * Tells this store how to find out whether the cluster is provably holding
	 * boundary state. See {@link #checkpointAll} for what turns on it.
	 */
	public void setStateBearingGate(BooleanSupplier gate) {
		this.stateBearing = Objects.requireNonNull(gate, "gate");
	}

	/**
	 * Live rows this pod's own boundary logs hold on disk, across every
	 * registered boundary.
	 *
	 * <p>Read from the FILES, not from the maps: this is what the cold-start
	 * election asks of each pod's volume, and the maps are precisely what is in
	 * question at that moment. Deduplicated to the latest record per key and
	 * tombstones excluded, so it is the recoverable row count rather than the
	 * log's length — a boundary written a thousand times holds one row.
	 */
	public long diskRowCount() {
		if (!enabled) {
			return 0;
		}
		long total = 0;
		for (Boundary b : boundaries.values()) {
			total += diskRows(b);
		}
		return total;
	}

	/** Live rows on disk for one registered boundary; 0 if it has no log yet. */
	public long diskRowCount(String mapName) {
		Boundary b = boundaries.get(mapName);
		return b == null ? 0 : diskRows(b);
	}

	private static long diskRows(Boundary b) {
		long rows = 0;
		for (RedoLog.Record rec : RedoLog.dedupFile(b.log().activePath())) {
			if (!rec.deleted) {
				rows++;
			}
		}
		return rows;
	}

	/** The registry of persistent boundaries, read by the cluster-stats publisher. */
	public MapRegistry getRegistry() {
		return registry;
	}

	/** Epoch millis of the last boundary record written, or 0 if none has been. */
	public long getLastSnapshotTimestamp() {
		return lastWriteMs.get();
	}

	/** Total bytes the boundary logs currently occupy, archives included. */
	public long getSnapshotSizeBytes() {
		if (!enabled) {
			return 0;
		}
		long total = 0;
		for (Boundary b : boundaries.values()) {
			Path active = b.log().activePath();
			total += sizeOf(active);
			for (int i = 1; i <= Snapshot.Opts.defaults().archiveCount; i++) {
				total += sizeOf(FsUtil.archiveName(active, i));
			}
		}
		return total;
	}

	private static long sizeOf(Path p) {
		try {
			return Files.size(p);
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
	 * serve a write up to date. It only records which KEYS changed; the
	 * coalescing writer appends them, so a burst of writes to one key costs one
	 * log record rather than one per event, and the Hazelcast event thread never
	 * waits on an fsync. Events this member caused are skipped: {@link
	 * PersistentMap} is the only local write path to a registered boundary and
	 * it has already appended them synchronously.
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
		String store = STORE_PREFIX + fileNameFor(mapName);
		// Before anything opens the log for append: a crash between an append's
		// write and its fsync can leave a half-written final line, and the
		// parser would refuse the whole log over a record nobody was acked for.
		recoverTornTail(store);
		RedoLog log = RedoLog.open(base, NS, store, Snapshot.Opts.defaults().archiveCount, Codec.NONE);
		boundaries.put(
				mapName,
				new Boundary(
						mapName,
						(com.hazelcast.map.IMap<String, Message>) hzMap,
						defaultInstance,
						log,
						new AtomicLong(sizeOf(log.activePath())),
						new ReentrantReadWriteLock()));
		hzMap.addEntryListener(new RemoteChangeListener(mapName), false);
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
	 * Appends {@code key}'s current state to its boundary's redo log, and fsyncs.
	 *
	 * <p>The value is read back from the live map rather than taken from the
	 * caller, so one call is correct for every mutation shape {@link
	 * PersistentMap} wraps: present means an upsert of what the map now holds,
	 * absent means a tombstone, and a conditional write that did not take effect
	 * re-records the value that is still there. Cost is O(1) in the boundary's
	 * size either way.
	 *
	 * <p>Throws on any failure to append. {@link PersistentMap} calls this on
	 * the mutating path and does not catch, so the caller is never told its
	 * write is durable when the record it depends on did not land.
	 *
	 * @throws DiskStoreException if the record could not be built or appended
	 */
	public void record(String mapName, Object key) {
		Boundary b = boundaries.get(mapName);
		if (b == null) {
			return;
		}
		String k = String.valueOf(key);
		b.lock().readLock().lock();
		try {
			append(b, k);
		} finally {
			b.lock().readLock().unlock();
		}
		lastWriteMs.set(System.currentTimeMillis());
	}

	/**
	 * Checkpoints {@code mapName}: coalesces its log down to the boundary's
	 * current state and truncates the history behind it, committed by one atomic
	 * rename.
	 *
	 * <p>For the mutations that are not one key — {@code putAll}, {@code clear},
	 * {@code evictAll} — and for the size-based trigger and the post-join full
	 * write. Everything else appends.
	 *
	 * <p>UNGUARDED: this is the path behind an observed mutation — a {@code
	 * clear}, an {@code evictAll}, the size-based trigger — where a row count
	 * smaller than the file's is the correct result of what the caller did.
	 * {@link #checkpointAll} is the path that cannot tell, and it is guarded.
	 *
	 * @return the number of rows written
	 * @throws DiskStoreException if the checkpoint could not be built or written
	 */
	public int checkpoint(String mapName) {
		Boundary b = boundaries.get(mapName);
		if (b == null) {
			return 0;
		}
		return checkpoint(b, false);
	}

	/**
	 * @param guardShrink refuse the write if it would leave FEWER rows on disk
	 *                    than the file already holds and nothing in the cluster
	 *                    is provably state-bearing — see {@link #checkpointAll}
	 * @return rows written, or {@code -1} if the guard refused and the file was
	 *         left exactly as it was
	 */
	private int checkpoint(Boundary b, boolean guardShrink) {
		b.lock().writeLock().lock();
		try {
			List<RedoLog.Record> rows = new ArrayList<>();
			for (Map.Entry<String, Message> e : b.hzMap().entrySet()) {
				rows.add(RedoLog.Record.upsert(e.getKey(), encode(b, e.getKey(), e.getValue())));
			}
			if (guardShrink) {
				long onDisk = diskRows(b);
				if (rows.size() < onDisk && !stateBearing.getAsBoolean()) {
					logger.error("REFUSING to checkpoint boundary {}: this pod's memory holds {} row(s)"
							+ " and its log already holds {}, and no member of this cluster has declared"
							+ " itself state-bearing. Writing would truncate durable state to what an"
							+ " empty member happens to hold — the simultaneous-restart data loss this"
							+ " guard exists to stop. The log at {} is left untouched.",
							b.mapName(), rows.size(), onDisk, b.log().activePath());
					return -1;
				}
			}
			b.log().roll(rows);
			b.checkpointedBytes().set(sizeOf(b.log().activePath()));
			pendingCheckpoint.remove(b.mapName());
			pending.remove(b.mapName());
			lastWriteMs.set(System.currentTimeMillis());
			logger.debug("Checkpointed boundary {}: {} rows, log now {} bytes",
					b.mapName(), rows.size(), b.checkpointedBytes().get());
			return rows.size();
		} finally {
			b.lock().writeLock().unlock();
		}
	}

	/**
	 * Writes the COMPLETE current contents of every registered boundary to this
	 * pod's own disk, one checkpoint each, and logs the row count per boundary.
	 *
	 * <p>Called after this pod joined a live cluster. It took its state from its
	 * peers, which puts nothing on its local volume: without this, only the rows
	 * that happen to be written again while this pod is up ever reach its disk,
	 * and a row that never mutates again is absent from it forever. The next
	 * simultaneous cold restart would then lose exactly the quiet rows, on every
	 * pod at once.
	 *
	 * <p>Runs off the caller's thread. Cluster join and readiness must not wait
	 * on serializing every boundary, and nothing depends on the result — the
	 * live cluster is still the source of truth until the pod goes down.
	 *
	 * <p><b>It never shrinks a boundary file on an unproven cluster.</b> This is
	 * the write that destroyed state in the simultaneous-restart incident: every
	 * pod of a {@code Parallel} StatefulSet came up at once, each concluded from
	 * the member count that it had joined peers holding state, each took "state"
	 * from peers that were equally empty, and each then rewrote its own log from
	 * an empty map. The rewrite had no opinion about what it was replacing. It
	 * has one now: a checkpoint that would leave FEWER rows on disk than the file
	 * already holds is REFUSED and logged at error, unless {@code
	 * StateBearingLedger} says some member of this cluster is provably bearing
	 * state — in which case the in-memory view IS the cluster's state and a
	 * smaller file is the legitimate result of rows having been deleted.
	 *
	 * <p>The residual it does not cover, named: when a peer is state-bearing the
	 * rows on this pod's volume and the ones the cluster holds need not be the
	 * same set, and the shrink is then allowed on the cluster's authority.
	 * Merging logs across pods is a different feature; what this guarantees is
	 * that an UNPROVEN cluster cannot empty a volume.
	 *
	 * @param reason what put this pod in this position, for the log line
	 */
	public void checkpointAll(String reason) {
		if (!enabled || flusher == null) {
			return;
		}
		flusher.execute(() -> {
			long rows = 0;
			int failed = 0;
			int refused = 0;
			for (Boundary b : boundaries.values()) {
				try {
					int n = checkpoint(b, true);
					if (n < 0) {
						refused++;
						continue;
					}
					rows += n;
					logger.info("Boundary {}: wrote {} rows to {} ({})",
							b.mapName(), n, b.log().activePath(), reason);
				} catch (RuntimeException e) {
					failed++;
					logger.error("Boundary {}: failed to write this pod's own copy ({}): {}",
							b.mapName(), reason, e.getMessage(), e);
				}
			}
			logger.info("Wrote this pod's own copy of {} boundaries ({} rows, {} failed,"
					+ " {} refused as shrinking) — {}",
					boundaries.size(), rows, failed, refused, reason);
		});
	}

	/**
	 * Replays every registered boundary's redo log into its Hazelcast map.
	 *
	 * <p>COLD START ONLY. The caller must have established that this pod booted
	 * with no reachable peers; see {@code ClusterServer}. Entries are written
	 * with put-if-absent so that even a mistaken call cannot overwrite live
	 * cluster state with this pod's last log — the one way this feature could
	 * silently destroy data. The log is deduplicated to the latest record per
	 * key BEFORE anything is applied, so a key's final tombstone wins over its
	 * earlier writes rather than racing them through put-if-absent.
	 *
	 * @return the number of entries replayed across all boundaries
	 * @throws DiskStoreException if a boundary log exists but cannot be read
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
			logger.info("Replayed {} entries across {} persistent boundaries from {}",
					total, boundaries.size(), base);
		} else {
			logger.info("No persisted boundary state under {} — cold start with {} boundaries empty",
					base, boundaries.size());
		}
		return total;
	}

	private int rehydrateOne(Boundary b) {
		String expectedType = b.defaultInstance().getDescriptorForType().getFullName();
		Map<String, Message> state = new LinkedHashMap<>();
		int records;
		try {
			records = b.log().restore(rec -> {
				if (rec.deleted) {
					state.remove(rec.key);
					return;
				}
				state.put(rec.key, decode(b, expectedType, rec));
			});
		} catch (RuntimeException e) {
			logger.error("Boundary log {} exists but could not be read — refusing to start: {}",
					b.log().activePath(), e.getMessage(), e);
			throw e;
		}
		int applied = 0;
		for (Map.Entry<String, Message> e : state.entrySet()) {
			if (b.hzMap().putIfAbsent(e.getKey(), e.getValue()) == null) {
				applied++;
			}
		}
		if (records > 0) {
			logger.info("Replayed boundary {}: {} entries from {} records in {}",
					b.mapName(), applied, records, b.log().activePath());
		}
		return applied;
	}

	// ==================== The log record ====================

	/**
	 * One key's current state as a redo-log payload: a {@link PersistenceEntry},
	 * base64 inside the log envelope's JSON payload slot.
	 *
	 * <p>{@code PersistenceEntry} is the platform's own persistence record and
	 * carries the value in an {@link Any}, so the log names the proto type it
	 * holds and a type change is caught on read rather than mis-parsed. The
	 * base64 wrapper is what makes a protobuf record a JSON value the chassis
	 * log can frame; its alphabet needs no escaping, but it is written through
	 * Gson so the framing is not a hand-rolled assumption.
	 */
	private static String encode(Boundary b, String key, Message value) {
		PersistenceEntry entry = PersistenceEntry.newBuilder()
				.setMapName(b.mapName())
				.setKey(key)
				.setPayload(Any.newBuilder()
						.setTypeUrl(TYPE_URL_PREFIX + b.defaultInstance().getDescriptorForType().getFullName())
						.setValue(ByteString.copyFrom(value.toByteArray()))
						.build())
				.setOp(OpType.OP_TYPE_PUT)
				.setTimestampMs(System.currentTimeMillis())
				.build();
		return new JsonPrimitive(Base64.getEncoder().encodeToString(entry.toByteArray())).toString();
	}

	private static Message decode(Boundary b, String expectedType, RedoLog.Record rec) {
		PersistenceEntry entry;
		try {
			entry = PersistenceEntry.parseFrom(
					Base64.getDecoder().decode(JsonParser.parseString(rec.payload).getAsString()));
		} catch (RuntimeException | com.google.protobuf.InvalidProtocolBufferException e) {
			throw DiskStoreException.invalidData("boundary log " + b.log().activePath()
					+ " has an unreadable record at key " + rec.key + ": " + e.getMessage());
		}
		String typeUrl = entry.getPayload().getTypeUrl();
		String recordedType = typeUrl.substring(typeUrl.lastIndexOf('/') + 1);
		if (!expectedType.equals(recordedType)) {
			// The boundary's value type changed under a log written by an older
			// build. Parsing it as the new type would quietly produce garbage
			// rows, so this is a startup failure, not a warning.
			throw DiskStoreException.invalidData("boundary log " + b.log().activePath() + " holds "
					+ recordedType + " but boundary " + b.mapName() + " is " + expectedType);
		}
		try {
			return b.defaultInstance().getParserForType().parseFrom(entry.getPayload().getValue());
		} catch (Exception e) {
			throw DiskStoreException.invalidData("boundary log " + b.log().activePath()
					+ " has an unparseable " + expectedType + " at key " + rec.key + ": " + e.getMessage());
		}
	}

	private static void append(Boundary b, String key) {
		Message value = b.hzMap().get(key);
		b.log().append(value == null
				? RedoLog.Record.tombstone(key)
				: RedoLog.Record.upsert(key, encode(b, key, value)));
	}

	/**
	 * Drops an unterminated final line from a boundary's log before it is opened.
	 *
	 * <p>{@link RedoLog#append} writes one newline-framed line and fsyncs it, so
	 * a log whose last byte is not a newline was cut by a crash partway through
	 * exactly one append — and that append's RPC threw, so nothing was acked for
	 * it. Every OTHER damage stays fatal: a malformed line with a newline after
	 * it is real corruption, and {@link RedoLog#dedupBytes} refuses the whole
	 * log over it, which is the fail-closed rule this store shares with kernel's
	 * own snapshot.
	 */
	private void recoverTornTail(String store) {
		Path active = StorePath.storePath(base, NS, store, ".log");
		try {
			if (!Files.exists(active)) {
				return;
			}
			long size = Files.size(active);
			if (size == 0) {
				return;
			}
			byte[] bytes = Files.readAllBytes(active);
			if (bytes[bytes.length - 1] == '\n') {
				return;
			}
			int lastNewline = -1;
			for (int i = bytes.length - 1; i >= 0; i--) {
				if (bytes[i] == '\n') {
					lastNewline = i;
					break;
				}
			}
			long keep = lastNewline + 1L;
			try (FileChannel ch = FileChannel.open(active, StandardOpenOption.WRITE)) {
				ch.truncate(keep);
				ch.force(true);
			}
			logger.warn("Boundary log {} ended mid-record — dropped the last {} bytes. That append's"
					+ " RPC failed, so no caller was told the write was durable.", active, size - keep);
		} catch (IOException e) {
			throw DiskStoreException.io("boundary log " + active + ": " + e.getMessage(), e);
		}
	}

	// ==================== The coalescing writer ====================

	/**
	 * Appends the keys remote members changed, and checkpoints any boundary
	 * whose log has outgrown its last checkpoint.
	 */
	private void flushPending() {
		for (Boundary b : boundaries.values()) {
			try {
				drain(b);
				maybeCheckpoint(b);
			} catch (RuntimeException e) {
				// This node did not serve the write, so there is no RPC to fail:
				// the writing member has already appended its own record. Log
				// loudly — this node's log is now behind, which matters only if
				// it is the one that forms the cluster after a cold start.
				logger.error("Failed to persist boundary {} replicated from another member: {}",
						b.mapName(), e.getMessage(), e);
			}
		}
	}

	private void drain(Boundary b) {
		if (pendingCheckpoint.remove(b.mapName())) {
			// A remote clear or evict-all: the surviving state is what the map
			// now holds, and no per-key record describes "everything else went".
			pending.remove(b.mapName());
			checkpoint(b, false);
			return;
		}
		Set<String> keys = pending.remove(b.mapName());
		if (keys == null || keys.isEmpty()) {
			return;
		}
		b.lock().readLock().lock();
		try {
			for (String key : keys) {
				append(b, key);
			}
		} finally {
			b.lock().readLock().unlock();
		}
		lastWriteMs.set(System.currentTimeMillis());
	}

	/**
	 * Checkpoints {@code b} once its log has passed both the floor and twice its
	 * size at the last checkpoint — see the doubling argument in this class's
	 * documentation.
	 */
	private void maybeCheckpoint(Boundary b) {
		long size = sizeOf(b.log().activePath());
		if (size < MIN_CHECKPOINT_BYTES || size < 2 * b.checkpointedBytes().get()) {
			return;
		}
		int rows = checkpoint(b, false);
		logger.info("Checkpointed boundary {}: log had grown to {} bytes, coalesced to {} rows in {} bytes",
				b.mapName(), size, rows, b.checkpointedBytes().get());
	}

	/** Records which keys a remote member changed, for the writer above. */
	private final class RemoteChangeListener
			implements EntryAddedListener<String, Message>, EntryUpdatedListener<String, Message>,
			EntryRemovedListener<String, Message>, EntryEvictedListener<String, Message>,
			EntryExpiredListener<String, Message>, MapClearedListener, MapEvictedListener {

		private final String mapName;

		private RemoteChangeListener(String mapName) {
			this.mapName = mapName;
		}

		private void changed(EntryEvent<String, Message> event) {
			if (event.getMember() != null && event.getMember().localMember()) {
				// PersistentMap is the only local write path to a registered
				// boundary and has already appended this key synchronously.
				// Queueing it again would double every log's growth rate.
				return;
			}
			pending.computeIfAbsent(mapName, n -> ConcurrentHashMap.newKeySet()).add(event.getKey());
		}

		@Override
		public void entryAdded(EntryEvent<String, Message> event) {
			changed(event);
		}

		@Override
		public void entryUpdated(EntryEvent<String, Message> event) {
			changed(event);
		}

		@Override
		public void entryRemoved(EntryEvent<String, Message> event) {
			changed(event);
		}

		@Override
		public void entryEvicted(EntryEvent<String, Message> event) {
			changed(event);
		}

		@Override
		public void entryExpired(EntryEvent<String, Message> event) {
			changed(event);
		}

		@Override
		public void mapCleared(MapEvent event) {
			wholeMapChanged(event);
		}

		@Override
		public void mapEvicted(MapEvent event) {
			wholeMapChanged(event);
		}

		private void wholeMapChanged(MapEvent event) {
			if (event.getMember() != null && event.getMember().localMember()) {
				return;
			}
			pendingCheckpoint.add(mapName);
		}
	}

	/** The registered boundaries and their logs, for tests and diagnostics. */
	public Map<String, Path> files() {
		Map<String, Path> out = new LinkedHashMap<>();
		for (Boundary b : boundaries.values()) {
			out.put(b.mapName(), b.log().activePath());
		}
		return Collections.unmodifiableMap(out);
	}

	@Override
	public void close() {
		if (flusher != null) {
			// Wait for an in-flight flush: closing a log out from under it would
			// turn a benign "this node is behind" into a stream-closed error on
			// the way down.
			flusher.shutdownNow();
			try {
				flusher.awaitTermination(5, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
		for (Boundary b : boundaries.values()) {
			b.log().close();
		}
	}
}
