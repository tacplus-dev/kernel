// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.persistence;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.hazelcast.MapRegistry;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.hazelcast.PersistenceProvider;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.IMap;
import com.hazelcast.core.HazelcastInstance;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinator for the persistence subsystem. Owns the {@link RedoLog},
 * {@link FullDumper}, {@link StateRestorer}, and {@link MapRegistry}.
 *
 * <p>
 * At startup, runs the negotiation protocol to determine which node restores
 * state (winner). At runtime, provides {@link #registerMap} to attach a
 * cluster-wide {@link PersistenceMapListener} to Hazelcast maps, and schedules
 * periodic dumps.
 */
public class PersistenceManager implements PersistenceProvider {

	private static final Logger logger = LoggerFactory.getLogger(PersistenceManager.class);

	private static final long DEFAULT_QUORUM_TIMEOUT_MS = 30_000;
	private static final long DEFAULT_RESTORE_TIMEOUT_MS = 60_000;

	/**
	 * Internal Hazelcast map name for persistence timestamps.
	 */
	static final String TIMESTAMPS_MAP = "__persistence_timestamps";
	/**
	 * Internal Hazelcast map name for entry timestamps (used in convergent
	 * merge).
	 */
	static final String ENTRY_TIMESTAMPS_MAP = "__persistence_entry_timestamps";
	/**
	 * Internal Hazelcast map name for the ready sentinel.
	 */
	static final String READY_MAP = "__persistence_ready";
	/**
	 * Key used in the ready map.
	 */
	static final String READY_KEY = "ready";

	private final Path dataDir;
	private final String nodeId;
	private volatile boolean enabled;
	private final long dumpIntervalHours;
	private final long dumpJitterSeconds;
	private final long redoFlushIntervalMs;
	private final int retentionDays;

	private final MapRegistry registry;
	private final RedoLog redoLog;
	private final FullDumper dumper;
	private final StateRestorer restorer;

	private final ScheduledExecutorService dumpScheduler;
	private ScheduledFuture<?> dumpTask;

	private volatile String nodeRole = "UNKNOWN";

	public PersistenceManager(Path dataDir, String nodeId, PersistenceConfig config) {
		this.dataDir = Objects.requireNonNull(dataDir, "dataDir");
		Objects.requireNonNull(config, "config");
		this.nodeId = Objects.requireNonNullElse(nodeId, "");
		this.enabled = config.enabled();
		this.dumpIntervalHours = config.dumpIntervalHours();
		this.dumpJitterSeconds = config.dumpJitterSeconds();
		this.redoFlushIntervalMs = config.redoFlushIntervalMs();
		this.retentionDays = config.retentionDays();

		this.registry = new MapRegistry();
		this.redoLog = new RedoLog(this.dataDir, this.nodeId, redoFlushIntervalMs);
		this.dumper = new FullDumper(this.dataDir, this.nodeId, registry, redoLog, retentionDays);
		this.restorer = new StateRestorer(this.dataDir, this.nodeId, registry);

		this.dumpScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "full-dump-scheduler");
			t.setDaemon(true);
			return t;
		});
	}

	/**
	 * Runs the startup negotiation protocol:
	 * <ol>
	 * <li>Each node publishes its latest persistence timestamp</li>
	 * <li>Wait for quorum (with timeout)</li>
	 * <li>If quorum reached: winner negotiation → full restore</li>
	 * <li>If quorum NOT reached: restore from local files</li>
	 * </ol>
	 */
	@Override
	public void initialize(HazelcastInstance hazelcast, int quorum) throws IOException {
		if (!enabled) {
			logger.info("Persistence disabled, skipping initialization");
			return;
		}

		Files.createDirectories(dataDir);

		// Open the redo log for this session
		redoLog.open();

		// 1. Publish local timestamp
		com.hazelcast.map.IMap<String, Long> timestampsMap = hazelcast.getMap(Objects.requireNonNull(TIMESTAMPS_MAP));
		long localTimestamp = restorer.getLatestTimestamp();
		timestampsMap.put(Objects.requireNonNull(nodeId), localTimestamp);
		logger.info("Published persistence timestamp: {} for node {}", localTimestamp, nodeId);

		// 2. Wait for quorum (with timeout to avoid catch-22)
		long quorumTimeoutMs = DEFAULT_QUORUM_TIMEOUT_MS;
		long deadline = System.currentTimeMillis() + quorumTimeoutMs;
		logger.info("Waiting for {} nodes to publish timestamps (timeout={}s)...", quorum, quorumTimeoutMs / 1000);
		while (timestampsMap.size() < quorum) {
			if (System.currentTimeMillis() >= deadline) {
				break;
			}
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IOException("Interrupted waiting for quorum", e);
			}
		}
		boolean hasQuorum = timestampsMap.size() >= quorum;

		if (!hasQuorum) {
			logger.warn(
					"Quorum not reached ({}/{} nodes) — restoring from local data.",
					timestampsMap.size(),
					quorum);
			nodeRole = "DEGRADED";
			restorer.restoreConvergentOnly();
			scheduleDumps();
			logger.info("Persistence initialization complete (role=DEGRADED)");
			return;
		}

		logger.info("Quorum reached: {} nodes have published timestamps", timestampsMap.size());

		// 3. Determine winner: highest timestamp, then lexicographic nodeId for ties
		String winnerId = null;
		long winnerTimestamp = -1;
		for (Map.Entry<String, Long> entry : timestampsMap.entrySet()) {
			String entryNodeId = Objects.requireNonNull(entry.getKey(), "timestamp map key");
			long entryTimestamp = Objects.requireNonNull(entry.getValue(), "timestamp map value");

			if (entryTimestamp > winnerTimestamp
					|| (entryTimestamp == winnerTimestamp
							&& (winnerId == null || entryNodeId.compareTo(winnerId) < 0))) {
				winnerId = entryNodeId;
				winnerTimestamp = entryTimestamp;
			}
		}

		boolean isWinner = nodeId.equals(winnerId);
		nodeRole = isWinner ? "WINNER" : "FOLLOWER";
		logger.info("Persistence winner: {} (timestamp={}), this node is {}", winnerId, winnerTimestamp, nodeRole);

		// 4. Winner restores, others wait
		com.hazelcast.map.IMap<String, Long> entryTimestampsMap = hazelcast
				.getMap(Objects.requireNonNull(ENTRY_TIMESTAMPS_MAP));
		com.hazelcast.map.IMap<String, String> readyMap = hazelcast.getMap(Objects.requireNonNull(READY_MAP));

		if (isWinner) {
			if (winnerTimestamp > 0) {
				Map<String, Long> entryTimestamps = restorer.restore();
				if (entryTimestamps != null) {
					entryTimestampsMap.putAll(entryTimestamps);
					logger.info("Winner restore complete: {} entry timestamps published", entryTimestamps.size());
				}
			} else {
				logger.info("No persistence data found, starting fresh");
			}

			readyMap.put(Objects.requireNonNull(READY_KEY), Objects.requireNonNull(nodeId));
			logger.info("Persistence ready sentinel set");
		} else {
			long restoreTimeoutMs = DEFAULT_RESTORE_TIMEOUT_MS;
			long restoreDeadline = System.currentTimeMillis() + restoreTimeoutMs;
			logger.info("Waiting for winner to complete restore (timeout={}s)...", restoreTimeoutMs / 1000);
			while (!readyMap.containsKey(Objects.requireNonNull(READY_KEY))) {
				if (System.currentTimeMillis() >= restoreDeadline) {
					logger.warn("Timed out waiting for persistence winner — falling back to local restore.");
					nodeRole = "DEGRADED";
					restorer.restoreConvergentOnly();
					scheduleDumps();
					logger.info("Persistence initialization complete (role=DEGRADED)");
					return;
				}
				try {
					Thread.sleep(500);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					throw new IOException("Interrupted waiting for persistence ready", e);
				}
			}
			logger.info("Winner ready, performing convergent merge...");
			IMap<String, Long> entryTsIMap = new SimpleHazelcastIMap<>(entryTimestampsMap);
			restorer.mergeConvergent(entryTsIMap);
		}

		scheduleDumps();

		logger.info("Persistence initialization complete (role={})", nodeRole);
	}

	/**
	 * Registers a Hazelcast map for persistence by attaching a cluster-wide
	 * {@link PersistenceMapListener} and recording the map in the
	 * {@link MapRegistry}. The protobuf parser is detected lazily from the
	 * first value written.
	 *
	 * @param name         the map name
	 * @param hazelcastMap the raw Hazelcast IMap (listener is attached here)
	 * @param imap         the IMap interface wrapper (stored in MapRegistry for
	 *                     restore)
	 * @param consistency  the consistency model
	 */
	// Maps that should NOT be persisted — transient data with TTL eviction.
	// These are high-frequency health/subscription updates that bloat the redo log.
	// TODO: Replace with proper (spec.persistence) annotation filtering from proto.
	private static final java.util.Set<String> TRANSIENT_MAPS = java.util.Set.of(
			"services.kernel.ServiceHealth.Instances",
			"services.kernel.Cluster.MapStats",
			"services.kernel.WorkloadState.Localities",
			"services.kernel.WorkloadState.Revocations"
	);

	private static boolean isTransient(String mapName) {
		for (String t : TRANSIENT_MAPS) {
			if (mapName.contains(t)) return true;
		}
		return false;
	}

	@Override
	public <K, V> void registerMap(
			String name, com.hazelcast.map.IMap<K, V> hazelcastMap, IMap<K, V> imap, ConsistencyType consistency) {
		if (!enabled) {
			return;
		}
		registry.register(name, imap, consistency);
		if (isTransient(name)) {
			logger.info("Skipping persistence listener for transient map: {}", name);
			return;
		}
		var listener = new PersistenceMapListener(redoLog, name, consistency, registry);
		hazelcastMap.addEntryListener(listener, true);
		logger.info("Registered persistence listener for map: {} ({})", name, consistency);
	}

	/**
	 * Triggers an on-demand full dump.
	 */
	public FullDumper.DumpResult triggerDump() throws IOException {
		return dumper.dump();
	}

	/**
	 * Returns the node role from the last initialization ("WINNER", "FOLLOWER",
	 * or "UNKNOWN").
	 */
	public String getNodeRole() {
		return nodeRole;
	}

	/**
	 * Returns the last dump timestamp.
	 */
	@Override
	public long getLastDumpTimestamp() {
		return dumper.getLastDumpTimestamp();
	}

	/**
	 * Returns the current redo log file size in bytes, or -1 if unavailable.
	 */
	@Override
	public long getRedoLogSizeBytes() {
		Path currentFile = redoLog.getCurrentFile();
		if (currentFile != null) {
			try {
				return Files.size(currentFile);
			} catch (IOException e) {
				logger.warn("Failed to get redo log size for {}", currentFile, e);
				return -1;
			}
		}
		return 0;
	}

	/**
	 * Disables persistence. Called when initialization fails so that
	 * subsequent registerMap calls skip attaching listeners.
	 */
	public void disable() {
		this.enabled = false;
	}

	/**
	 * Returns whether persistence is enabled.
	 */
	@Override
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Returns the map registry.
	 */
	@Override
	public MapRegistry getRegistry() {
		return registry;
	}

	/**
	 * Flushes the redo log and shuts down the dump scheduler.
	 */
	@Override
	public void close() {
		if (dumpTask != null) {
			dumpTask.cancel(false);
		}
		dumpScheduler.shutdown();
		redoLog.close();

		try {
			dumper.dump();
		} catch (IOException e) {
			logger.error("dump on close failed", e);
		}

		logger.info("Persistence manager closed");
	}

	private void scheduleDumps() {
		long jitterMs = FullDumper.calculateJitterMs(nodeId, dumpJitterSeconds);
		long intervalMs = TimeUnit.HOURS.toMillis(dumpIntervalHours);
		long initialDelayMs = intervalMs + jitterMs;

		dumpTask = dumpScheduler.scheduleAtFixedRate(
				() -> {
					try {
						logger.info("Scheduled dump triggered");
						dumper.dump();
					} catch (IOException e) {
						logger.error("Scheduled dump failed", e);
					}
				},
				initialDelayMs,
				intervalMs,
				TimeUnit.MILLISECONDS);

		logger.info(
				"Dump scheduled: interval={}h, jitter={}s, initial delay={}ms",
				dumpIntervalHours,
				jitterMs / 1000,
				initialDelayMs);
	}

	/**
	 * Configuration for the persistence subsystem.
	 */
	public record PersistenceConfig(
			boolean enabled,
			long dumpIntervalHours,
			long dumpJitterSeconds,
			long redoFlushIntervalMs,
			int retentionDays,
			String persistenceFormat) {

		/**
		 * Creates a config from environment variables with defaults.
		 */
		public static PersistenceConfig fromEnv() {
			return new PersistenceConfig(
					getBoolEnv("BACKENDDB_PERSISTENCE_ENABLED", true),
					getLongEnv("BACKENDDB_DUMP_INTERVAL_HOURS", 24),
					getLongEnv("BACKENDDB_DUMP_JITTER_SECONDS", 3600),
					getLongEnv("BACKENDDB_REDO_FLUSH_INTERVAL_MS", 100),
					getIntEnv("BACKENDDB_RETENTION_DAYS", 7),
					getStringEnv("BACKENDDB_PERSISTENCE_FORMAT", "PROTO_WIRE"));
		}

		/**
		 * Creates a disabled config (for testing or when persistence is not
		 * wanted).
		 */
		public static PersistenceConfig disabled() {
			return new PersistenceConfig(false, 24, 3600, 100, 7, "PROTO_WIRE");
		}

		private static String getStringEnv(String name, String defaultVal) {
			String val = System.getenv(name);
			return val != null ? val : defaultVal;
		}

		private static boolean getBoolEnv(String name, boolean defaultVal) {
			String val = System.getenv(name);
			return val != null ? Boolean.parseBoolean(val) : defaultVal;
		}

		private static long getLongEnv(String name, long defaultVal) {
			String val = System.getenv(name);
			if (val != null) {
				try {
					return Long.parseLong(val);
				} catch (NumberFormatException e) {
					logger.warn(
							"Invalid value for environment variable {}: {}. Using default: {}", name, val, defaultVal);
					return defaultVal;
				}
			}
			return defaultVal;
		}

		private static int getIntEnv(String name, int defaultVal) {
			String val = System.getenv(name);
			if (val != null) {
				try {
					return Integer.parseInt(val);
				} catch (NumberFormatException e) {
					logger.warn(
							"Invalid value for environment variable {}: {}. Using default: {}", name, val, defaultVal);
					return defaultVal;
				}
			}
			return defaultVal;
		}
	}

	/**
	 * Minimal IMap adapter for Hazelcast maps used internally by the
	 * persistence subsystem (e.g., __persistence_entry_timestamps). Only
	 * implements the methods needed by StateRestorer.mergeConvergent().
	 */
	private static class SimpleHazelcastIMap<K, V> implements IMap<K, V> {

		private final com.hazelcast.map.IMap<K, V> delegate;

		SimpleHazelcastIMap(com.hazelcast.map.IMap<K, V> delegate) {
			this.delegate = Objects.requireNonNull(delegate, "delegate");
		}

		@Override
		public V get(K key) {
			return delegate.get(Objects.requireNonNull(key, "key"));
		}

		@Override
		public V put(K key, V value) {
			return delegate.put(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public V put(K key, V value, long ttl, TimeUnit u) {
			return delegate.put(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(value, "value"),
					ttl,
					Objects.requireNonNull(u, "u"));
		}

		@Override
		public void set(K key, V value) {
			delegate.set(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public void set(K key, V value, long ttl, TimeUnit u) {
			delegate.set(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(value, "value"),
					ttl,
					Objects.requireNonNull(u, "u"));
		}

		@Override
		public V putIfAbsent(K key, V value) {
			return delegate.putIfAbsent(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public V putIfAbsent(K key, V value, long ttl, TimeUnit u) {
			return delegate.putIfAbsent(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(value, "value"),
					ttl,
					Objects.requireNonNull(u, "u"));
		}

		@Override
		public void putAll(java.util.Map<? extends K, ? extends V> map) {
			delegate.putAll(Objects.requireNonNull(map, "map"));
		}

		@Override
		public V remove(K key) {
			return delegate.remove(Objects.requireNonNull(key, "key"));
		}

		@Override
		public boolean remove(K key, V value) {
			return delegate.remove(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public void delete(K key) {
			delegate.delete(Objects.requireNonNull(key, "key"));
		}

		@Override
		public V replace(K key, V value) {
			return delegate.replace(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public boolean replace(K key, V o, V n) {
			return delegate.replace(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(o, "o"),
					Objects.requireNonNull(n, "n"));
		}

		@Override
		public boolean containsKey(K key) {
			return delegate.containsKey(Objects.requireNonNull(key, "key"));
		}

		@Override
		public boolean containsValue(V value) {
			return delegate.containsValue(Objects.requireNonNull(value, "value"));
		}

		@Override
		public java.util.Map<K, V> getAll(java.util.Set<K> keys) {
			return delegate.getAll(Objects.requireNonNull(keys, "keys"));
		}

		@Override
		public java.util.Set<K> keySet() {
			return delegate.keySet();
		}

		@Override
		public java.util.Collection<V> values() {
			return delegate.values();
		}

		@Override
		public java.util.Set<java.util.Map.Entry<K, V>> entrySet() {
			return delegate.entrySet();
		}

		@Override
		public int size() {
			return delegate.size();
		}

		@Override
		public boolean isEmpty() {
			return delegate.isEmpty();
		}

		@Override
		public void clear() {
			delegate.clear();
		}

		@Override
		public boolean evict(K key) {
			return delegate.evict(Objects.requireNonNull(key, "key"));
		}

		@Override
		public void evictAll() {
			delegate.evictAll();
		}

		@Override
		public boolean tryPut(K key, V value, long t, TimeUnit u) {
			return delegate.tryPut(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(value, "value"),
					t,
					Objects.requireNonNull(u, "u"));
		}

		@Override
		public boolean tryRemove(K key, long t, TimeUnit u) {
			return delegate.tryRemove(Objects.requireNonNull(key, "key"), t, Objects.requireNonNull(u, "u"));
		}

		@Override
		public void lock(K key) {
			delegate.lock(Objects.requireNonNull(key, "key"));
		}

		@Override
		public void lock(K key, long l, TimeUnit u) {
			delegate.lock(Objects.requireNonNull(key, "key"), l, Objects.requireNonNull(u, "u"));
		}

		@Override
		public void unlock(K key) {
			delegate.unlock(Objects.requireNonNull(key, "key"));
		}

		@Override
		public boolean tryLock(K key) {
			return delegate.tryLock(Objects.requireNonNull(key, "key"));
		}

		@Override
		public boolean tryLock(K key, long t, TimeUnit u) throws InterruptedException {
			return delegate.tryLock(Objects.requireNonNull(key, "key"), t, Objects.requireNonNull(u, "u"));
		}

		@Override
		public boolean tryLock(K key, long t, TimeUnit u, long l, TimeUnit lu) throws InterruptedException {
			return delegate.tryLock(
					Objects.requireNonNull(key, "key"),
					t,
					Objects.requireNonNull(u, "u"),
					l,
					Objects.requireNonNull(lu, "lu"));
		}

		@Override
		public boolean isLocked(K key) {
			return delegate.isLocked(Objects.requireNonNull(key, "key"));
		}

		@Override
		public void forceUnlock(K key) {
			delegate.forceUnlock(Objects.requireNonNull(key, "key"));
		}

		@Override
		public java.util.concurrent.CompletionStage<V> getAsync(K key) {
			return delegate.getAsync(Objects.requireNonNull(key, "key"));
		}

		@Override
		public java.util.concurrent.CompletionStage<V> putAsync(K key, V value) {
			return delegate.putAsync(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public java.util.concurrent.CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit u) {
			return delegate.putAsync(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(value, "value"),
					ttl,
					Objects.requireNonNull(u, "u"));
		}

		@Override
		public java.util.concurrent.CompletionStage<Void> setAsync(K key, V value) {
			return delegate.setAsync(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
		}

		@Override
		public java.util.concurrent.CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit u) {
			return delegate.setAsync(
					Objects.requireNonNull(key, "key"),
					Objects.requireNonNull(value, "value"),
					ttl,
					Objects.requireNonNull(u, "u"));
		}

		@Override
		public java.util.concurrent.CompletionStage<V> removeAsync(K key) {
			return delegate.removeAsync(Objects.requireNonNull(key, "key"));
		}

		@Override
		public java.util.concurrent.CompletionStage<Boolean> deleteAsync(K key) {
			return delegate.deleteAsync(Objects.requireNonNull(key, "key"));
		}
	}
}
