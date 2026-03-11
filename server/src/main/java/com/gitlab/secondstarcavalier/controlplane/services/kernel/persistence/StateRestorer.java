// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.MapRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.EpochExpirationHelper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.FullDumpHeader;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.RedoLogEntry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.DbDump;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.KitchenSink;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IMap;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast;

/**
 * Restores Hazelcast IMap state from dump files and redo logs at startup.
 *
 * <p>
 * The winner node loads the latest dump and replays redo logs. Non-winner
 * nodes perform a convergent merge: they scan their own redo logs for entries
 * with {@code CONSISTENCY_CONVERGENT} and push any entries with a newer
 * timestamp than what the winner installed (last-writer-wins).
 */
public class StateRestorer {

	private static final Logger logger = LoggerFactory.getLogger(StateRestorer.class);

	private final Path dataDir;
	private final String nodeId;
	private final MapRegistry registry;

	public StateRestorer(Path dataDir, String nodeId, MapRegistry registry) {
		this.dataDir = dataDir;
		this.nodeId = nodeId;
		this.registry = registry;
	}

	/**
	 * Scans dump and redo files to find the latest timestamp across all
	 * persistence data for this node.
	 */
	public long getLatestTimestamp() throws IOException {
		long maxTs = 0;

		// Check dump files
		List<Path> dumps = FullDumper.listDumpFiles(dataDir, nodeId);
		if (!dumps.isEmpty()) {
			maxTs = FullDumper.extractTimestamp(dumps.getLast());
		}

		// Check redo logs
		List<Path> redos = RedoLog.listSegments(dataDir, nodeId);
		for (Path redo : redos) {
			// Scan each redo log for the max entry timestamp
			long fileTs = RedoLog.extractTimestamp(redo, "redo-" + nodeId + "-", ".log");
			if (fileTs > maxTs) {
				maxTs = fileTs;
			}
			// Also check actual entries for the latest timestamp
			try {
				List<RedoLogEntry> entries = readRedoLog(redo);
				for (RedoLogEntry entry : entries) {
					if (entry.getTimestampMs() > maxTs) {
						maxTs = entry.getTimestampMs();
					}
				}
			} catch (IOException e) {
				logger.warn("Error reading redo log {} for timestamp scan", redo.getFileName(), e);
			}
		}

		return maxTs;
	}

	/**
	 * Restores state from the latest dump and redo logs (winner path).
	 * Returns a map of {@code mapName:key → timestamp_ms} for all restored
	 * entries, used by non-winners for convergent merge comparison.
	 *
	 * <p>
	 * Supports both new KitchenSink format and legacy RedoLogEntry format.
	 * New dumps use DbDump wrapper; legacy dumps use FullDumpHeader + RedoLogEntry.
	 */
	public Map<String, Long> restore() throws IOException {
		Map<String, Long> entryTimestamps = new HashMap<>();
		long dumpTimestamp = 0;

		// 1. Find and load latest dump
		List<Path> dumps = FullDumper.listDumpFiles(dataDir, nodeId);
		if (!dumps.isEmpty()) {
			Path latestDump = dumps.getLast();
			dumpTimestamp = FullDumper.extractTimestamp(latestDump);
			logger.info("Loading dump: {}", latestDump.getFileName());

			try (InputStream is = new GZIPInputStream(new BufferedInputStream(Files.newInputStream(latestDump)))) {
				// Peek at first record to determine format
				byte[] firstRecord = readRecord(is);

				// Try parsing as DbDump (new format — single message)
				try {
					DbDump dbDump = DbDump.parseFrom(firstRecord);
					if (dbDump.getEntriesCount() > 0 || dbDump.getTimestampMs() > 0) {
						logger.info(
								"Dump format: DbDump ({} entries, node={}, timestamp={})",
								dbDump.getEntryCount(),
								dbDump.getNodeId(),
								dbDump.getTimestampMs());
						for (KitchenSink ks : dbDump.getEntriesList()) {
							applyKitchenSink(ks);
							entryTimestamps.put(ks.getMapName() + ":" + ks.getKey(), ks.getTimestampMs());
						}
						logger.info("Loaded {} entries from DbDump", dbDump.getEntriesCount());
					}
				} catch (InvalidProtocolBufferException e) {
					// Not a DbDump — fall back to legacy format
					FullDumpHeader header = FullDumpHeader.parseFrom(firstRecord);
					logger.info(
							"Dump format: legacy ({} entries, node={}, timestamp={})",
							header.getEntryCount(),
							header.getNodeId(),
							header.getTimestampMs());

					int count = 0;
					byte[] recordData;
					while ((recordData = readRecordOrNull(is)) != null) {
						RedoLogEntry entry = RedoLogEntry.parseFrom(recordData);
						applyEntry(entry);
						entryTimestamps.put(entry.getMapName() + ":" + entry.getKey(), entry.getTimestampMs());
						count++;
					}
					logger.info("Loaded {} entries from legacy dump", count);
				}
			}
		} else {
			logger.info("No dump files found for node {}", nodeId);
		}

		// 2. Replay redo logs newer than the dump timestamp
		List<Path> redos = RedoLog.listSegments(dataDir, nodeId);
		int replayCount = 0;
		for (Path redo : redos) {
			long fileTs = RedoLog.extractTimestamp(redo, "redo-" + nodeId + "-", ".log");
			if (fileTs >= dumpTimestamp) {
				List<KitchenSink> entries = readRedoLogKitchenSink(redo);
				entries.sort(Comparator.comparingLong(KitchenSink::getTimestampMs));
				for (KitchenSink ks : entries) {
					if (ks.getTimestampMs() > dumpTimestamp) {
						applyKitchenSink(ks);
						entryTimestamps.put(ks.getMapName() + ":" + ks.getKey(), ks.getTimestampMs());
						replayCount++;
					}
				}
			}
		}
		logger.info("Replayed {} entries from redo logs", replayCount);

		return entryTimestamps;
	}

	/**
	 * Restores all data from local dump and redo logs.
	 * All boundaries are convergent.
	 */
	public void restoreConvergentOnly() throws IOException {
		long dumpTimestamp = 0;

		// 1. Load entries from latest dump
		List<Path> dumps = FullDumper.listDumpFiles(dataDir, nodeId);
		int loadedCount = 0;
		if (!dumps.isEmpty()) {
			Path latestDump = dumps.getLast();
			dumpTimestamp = FullDumper.extractTimestamp(latestDump);
			logger.info("Loading data from dump: {}", latestDump.getFileName());

			try (InputStream is = new GZIPInputStream(new BufferedInputStream(Files.newInputStream(latestDump)))) {
				byte[] firstRecord = readRecord(is);
				try {
					DbDump dbDump = DbDump.parseFrom(firstRecord);
					if (dbDump.getEntriesCount() > 0 || dbDump.getTimestampMs() > 0) {
						for (KitchenSink ks : dbDump.getEntriesList()) {
							applyKitchenSink(ks);
							loadedCount++;
						}
					}
				} catch (InvalidProtocolBufferException e) {
					// Legacy format
					byte[] recordData;
					while ((recordData = readRecordOrNull(is)) != null) {
						RedoLogEntry entry = RedoLogEntry.parseFrom(recordData);
						applyEntry(entry);
						loadedCount++;
					}
				}
			}
		}

		// 2. Replay entries from redo logs newer than dump
		List<Path> redos = RedoLog.listSegments(dataDir, nodeId);
		for (Path redo : redos) {
			long fileTs = RedoLog.extractTimestamp(redo, "redo-" + nodeId + "-", ".log");
			if (fileTs >= dumpTimestamp) {
				List<KitchenSink> entries = readRedoLogKitchenSink(redo);
				entries.sort(Comparator.comparingLong(KitchenSink::getTimestampMs));
				for (KitchenSink ks : entries) {
					if (ks.getTimestampMs() > dumpTimestamp) {
						applyKitchenSink(ks);
						loadedCount++;
					}
				}
			}
		}

		logger.info("Restore complete: {} entries loaded", loadedCount);
	}

	/**
	 * Performs convergent merge for non-winner nodes. Scans local redo logs
	 * for entries where {@code consistency = CONVERGENT} and pushes any that
	 * are newer than the corresponding entry in the winner's data.
	 *
	 * @param winnerTimestamps map of {@code mapName:key → timestamp_ms} from
	 *                         the winner's restore, stored in
	 *                         {@code __persistence_entry_timestamps}
	 */
	public void mergeConvergent(IMap<String, Long> winnerTimestamps) throws IOException {
		List<Path> redos = RedoLog.listSegments(dataDir, nodeId);
		int mergedCount = 0;

		// Collect all convergent entries, keeping only the latest per key
		Map<String, KitchenSink> latestByKey = new HashMap<>();
		for (Path redo : redos) {
			List<KitchenSink> entries = readRedoLogKitchenSink(redo);
			for (KitchenSink entry : entries) {
				if (entry.getConsistency() != KitchenSinkOuterClass.ConsistencyType.CONSISTENCY_CONVERGENT) {
					continue;
				}
				String compositeKey = entry.getMapName() + ":" + entry.getKey();
				KitchenSink existing = latestByKey.get(compositeKey);
				if (existing == null || entry.getTimestampMs() > existing.getTimestampMs()) {
					latestByKey.put(compositeKey, entry);
				}
			}
		}

		// Compare with winner timestamps and push newer entries
		for (Map.Entry<String, KitchenSink> entry : latestByKey.entrySet()) {
			String compositeKey = entry.getKey();
			KitchenSink ksEntry = entry.getValue();

			Long winnerTs = winnerTimestamps.get(compositeKey);
			if (winnerTs == null || ksEntry.getTimestampMs() > winnerTs) {
				applyKitchenSink(ksEntry);
				// Update the timestamp in the shared map
				winnerTimestamps.put(compositeKey, ksEntry.getTimestampMs());
				mergedCount++;
			}
		}

		logger.info("Convergent merge: pushed {} entries from local redo logs", mergedCount);
	}

	/** Applies a single KitchenSink entry to the appropriate IMap.
	 *  Skips entries with epoch_expiration that have already expired.
	 *  Uses TTL-aware put for entries with a future epoch_expiration. */
	@SuppressWarnings("unchecked")
	private void applyKitchenSink(KitchenSink entry) {
		MapRegistry.MapInfo info = registry.get(entry.getMapName());
		if (info == null) {
			logger.warn("Skipping entry for unknown map: {}", entry.getMapName());
			return;
		}

		IMap<String, Object> map = (IMap<String, Object>) info.map();
		if (entry.getOp() == KitchenSinkOuterClass.OpType.OP_TYPE_DELETE) {
			map.delete(entry.getKey());
		} else {
			// Extract the typed payload from the oneof
			MessageLite value = KitchenSinkHelper.getPayload(entry);
			if (value != null) {
				// Skip expired entries; apply TTL for entries with future expiration
				if (EpochExpirationHelper.isExpired(entry.getMapName(), value)) {
					logger.debug("Skipping expired entry: map={} key={}", entry.getMapName(), entry.getKey());
					return;
				}
				long ttl = EpochExpirationHelper.computeTtlSeconds(entry.getMapName(), value);
				if (ttl > 0) {
					map.put(entry.getKey(), value, ttl, java.util.concurrent.TimeUnit.SECONDS);
				} else {
					map.put(entry.getKey(), value);
				}
			} else {
				logger.error("No payload in KitchenSink entry for map={} key={}", entry.getMapName(), entry.getKey());
			}
		}
	}

	/** Applies a legacy RedoLogEntry to the appropriate IMap. */
	@SuppressWarnings("unchecked")
	private void applyEntry(RedoLogEntry entry) {
		MapRegistry.MapInfo info = registry.get(entry.getMapName());
		if (info == null) {
			logger.warn("Skipping entry for unknown map: {}", entry.getMapName());
			return;
		}

		IMap<String, Object> map = (IMap<String, Object>) info.map();
		if (entry.getOp() == Hazelcast.OpType.OP_TYPE_DELETE) {
			map.delete(entry.getKey());
		} else {
			try {
				if (info.parser() == null) {
					logger.error("No parser available for map={} key={}", entry.getMapName(), entry.getKey());
					return;
				}
				MessageLite value = info.parser().parseFrom(entry.getValue());
				map.put(entry.getKey(), value);
			} catch (InvalidProtocolBufferException e) {
				logger.error("Failed to parse value for map={} key={}", entry.getMapName(), entry.getKey(), e);
			}
		}
	}

	/** Reads all entries from a redo log file as KitchenSink messages. */
	static List<KitchenSink> readRedoLogKitchenSink(Path file) throws IOException {
		List<KitchenSink> entries = new ArrayList<>();
		try (InputStream is = new BufferedInputStream(Files.newInputStream(file))) {
			byte[] recordData;
			while ((recordData = readRecordOrNull(is)) != null) {
				try {
					entries.add(KitchenSink.parseFrom(recordData));
				} catch (InvalidProtocolBufferException e) {
					// Try legacy format
					entries.add(convertLegacyEntry(RedoLogEntry.parseFrom(recordData)));
				}
			}
		}
		return entries;
	}

	/** Reads all entries from a redo log file as legacy RedoLogEntry messages. */
	static List<RedoLogEntry> readRedoLog(Path file) throws IOException {
		List<RedoLogEntry> entries = new ArrayList<>();
		try (InputStream is = new BufferedInputStream(Files.newInputStream(file))) {
			byte[] recordData;
			while ((recordData = readRecordOrNull(is)) != null) {
				entries.add(RedoLogEntry.parseFrom(recordData));
			}
		}
		return entries;
	}

	/** Converts a legacy RedoLogEntry to a KitchenSink message. */
	private static KitchenSink convertLegacyEntry(RedoLogEntry entry) {
		KitchenSink.Builder builder = KitchenSink.newBuilder()
				.setMapName(entry.getMapName())
				.setKey(entry.getKey())
				.setTimestampMs(entry.getTimestampMs());

		// Map OpType
		if (entry.getOp() == Hazelcast.OpType.OP_TYPE_DELETE) {
			builder.setOp(KitchenSinkOuterClass.OpType.OP_TYPE_DELETE);
		} else {
			builder.setOp(KitchenSinkOuterClass.OpType.OP_TYPE_PUT);
		}

		// All boundaries are convergent
		builder.setConsistency(KitchenSinkOuterClass.ConsistencyType.CONSISTENCY_CONVERGENT);

		// Note: legacy entries have opaque bytes, not typed payload.
		// The caller must use the registry parser to deserialize.
		return builder.build();
	}

	/** Reads a length-prefixed record from the stream. Throws on unexpected EOF. */
	static byte[] readRecord(InputStream is) throws IOException {
		byte[] recordData = readRecordOrNull(is);
		if (recordData == null) {
			throw new IOException("Unexpected end of stream");
		}
		return recordData;
	}

	/** Reads a length-prefixed record, returns null at EOF. */
	static byte[] readRecordOrNull(InputStream is) throws IOException {
		byte[] lenBuf = new byte[4];
		int read = is.readNBytes(lenBuf, 0, 4);
		if (read == 0) {
			return null;
		}
		if (read < 4) {
			throw new IOException("Truncated length prefix: read " + read + " bytes");
		}
		int len = ByteBuffer.wrap(lenBuf).getInt();
		if (len < 0 || len > 64 * 1024 * 1024) {
			throw new IOException("Invalid record length: " + len);
		}
		byte[] data = new byte[len];
		read = is.readNBytes(data, 0, len);
		if (read < len) {
			throw new IOException("Truncated record: expected " + len + " bytes, got " + read);
		}
		return data;
	}
}
