// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.RedoLogEntry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.PersistenceEntry;
import com.google.protobuf.MessageLite;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Append-only redo log writer. Each mutation to a persistent IMap is recorded
 * as a length-prefixed protobuf {@link RedoLogEntry}.
 *
 * <p>
 * Writes are buffered and batch-flushed on a configurable interval (default
 * 100ms). Thread-safe via explicit locking.
 */
public class RedoLog {

	private static final Logger logger = LoggerFactory.getLogger(RedoLog.class);

	private final Path dataDir;
	private final String nodeId;
	private final long flushIntervalMs;
	private final ReentrantLock lock = new ReentrantLock();

	private OutputStream out;
	private Path currentFile;
	private long currentSegmentTimestamp;

	private final ScheduledExecutorService flusher;
	private ScheduledFuture<?> flushTask;

	public RedoLog(Path dataDir, String nodeId, long flushIntervalMs) {
		this.dataDir = dataDir;
		this.nodeId = nodeId;
		this.flushIntervalMs = flushIntervalMs;
		this.flusher = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "redo-log-flusher");
			t.setDaemon(true);
			return t;
		});
	}

	public RedoLog(Path dataDir, String nodeId) {
		this(dataDir, nodeId, 100);
	}

	/**
	 * Opens a new redo log segment. Must be called before {@link #append}.
	 */
	public void open() throws IOException {
		lock.lock();
		try {
			this.currentSegmentTimestamp = System.currentTimeMillis();
			this.currentFile = dataDir.resolve("redo-" + nodeId + "-" + currentSegmentTimestamp + ".log");
			Files.createDirectories(dataDir);
			this.out = new BufferedOutputStream(
					Files.newOutputStream(currentFile, StandardOpenOption.CREATE, StandardOpenOption.APPEND));
			logger.info("Opened redo log segment: {}", currentFile.getFileName());

			flushTask = flusher.scheduleAtFixedRate(
					this::periodicFlush, flushIntervalMs, flushIntervalMs, TimeUnit.MILLISECONDS);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Appends a typed PersistenceEntry to the current redo log segment.
	 */
	public void append(PersistenceEntry entry) {
		appendMessage(entry);
	}

	/**
	 * Appends a legacy RedoLogEntry to the current redo log segment.
	 * Used as fallback when the value type cannot be packed into Any.
	 */
	public void appendLegacy(RedoLogEntry entry) {
		appendMessage(entry);
	}

	private void appendMessage(MessageLite entry) {
		lock.lock();
		try {
			if (out == null) {
				throw new IllegalStateException("RedoLog not open");
			}
			byte[] data = entry.toByteArray();
			byte[] lenBuf = new byte[4];
			ByteBuffer.wrap(lenBuf).putInt(data.length);
			out.write(lenBuf);
			out.write(data);
		} catch (IOException e) {
			logger.error("Failed to append to redo log", e);
			throw new RuntimeException("Redo log write failed", e);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Closes the current segment and opens a new one. Called after a full dump
	 * so that old redo logs can be cleaned up independently.
	 */
	public void rotate() throws IOException {
		lock.lock();
		try {
			closeCurrentSegment();
			open();
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the timestamp of the current segment.
	 */
	public long getCurrentSegmentTimestamp() {
		lock.lock();
		try {
			return currentSegmentTimestamp;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Returns the path to the current redo log file.
	 */
	public Path getCurrentFile() {
		lock.lock();
		try {
			return currentFile;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Flushes and closes the redo log.
	 */
	public void close() {
		lock.lock();
		try {
			closeCurrentSegment();
			flusher.shutdown();
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Lists all redo log files in the data directory for this node, sorted by
	 * timestamp.
	 */
	public List<Path> listSegments() throws IOException {
		return listSegments(dataDir, nodeId);
	}

	/**
	 * Lists all redo log files in the data directory for a given node, sorted
	 * by timestamp.
	 */
	public static List<Path> listSegments(Path dataDir, String nodeId) throws IOException {
		if (!Files.exists(dataDir)) {
			return List.of();
		}
		List<Path> segments = new ArrayList<>();
		try (var stream = Files.list(dataDir)) {
			stream.filter(p -> {
				String name = p.getFileName().toString();
				return name.startsWith("redo-" + nodeId + "-") && name.endsWith(".log");
			})
					.forEach(segments::add);
		}
		segments.sort((a, b) -> {
			long ta = extractTimestamp(a, "redo-" + nodeId + "-", ".log");
			long tb = extractTimestamp(b, "redo-" + nodeId + "-", ".log");
			return Long.compare(ta, tb);
		});
		return segments;
	}

	/**
	 * Lists all redo log files for any node in the data directory.
	 */
	public static List<Path> listAllSegments(Path dataDir) throws IOException {
		if (!Files.exists(dataDir)) {
			return List.of();
		}
		List<Path> segments = new ArrayList<>();
		try (var stream = Files.list(dataDir)) {
			stream.filter(p -> {
				String name = p.getFileName().toString();
				return name.startsWith("redo-") && name.endsWith(".log");
			})
					.forEach(segments::add);
		}
		segments.sort((a, b) -> {
			long ta = extractTimestampGeneric(a);
			long tb = extractTimestampGeneric(b);
			return Long.compare(ta, tb);
		});
		return segments;
	}

	/**
	 * Extracts timestamp from a redo log filename.
	 */
	static long extractTimestamp(Path file, String prefix, String suffix) {
		String name = file.getFileName().toString();
		String ts = name.substring(prefix.length(), name.length() - suffix.length());
		return Long.parseLong(ts);
	}

	/**
	 * Extracts timestamp from any redo-{nodeId}-{ts}.log filename.
	 */
	static long extractTimestampGeneric(Path file) {
		String name = file.getFileName().toString();
		// redo-{nodeId}-{timestamp}.log
		int lastDash = name.lastIndexOf('-');
		int dotLog = name.lastIndexOf(".log");
		return Long.parseLong(name.substring(lastDash + 1, dotLog));
	}

	private void periodicFlush() {
		lock.lock();
		try {
			if (out != null) {
				out.flush();
			}
		} catch (IOException e) {
			logger.warn("Periodic flush failed", e);
		} finally {
			lock.unlock();
		}
	}

	private void closeCurrentSegment() {
		if (flushTask != null) {
			flushTask.cancel(false);
			flushTask = null;
		}
		if (out != null) {
			try {
				out.flush();
				out.close();
			} catch (IOException e) {
				logger.warn("Error closing redo log segment", e);
			}
			out = null;
			logger.info("Closed redo log segment: {}", currentFile != null ? currentFile.getFileName() : "null");
		}
	}
}
