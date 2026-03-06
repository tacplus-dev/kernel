// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel.FullDumpHeader;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel.RedoLogEntry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.DbDump;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.KitchenSink;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kitchen_sink.KitchenSinkOuterClass.OpType;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;

/**
 * Writes periodic full snapshots of all registered IMaps. Each dump is a
 * gzipped sequence of length-prefixed protobuf records: one
 * {@link FullDumpHeader} followed by {@link RedoLogEntry} records (all
 * {@code OP_TYPE_PUT}).
 *
 * <p>
 * After a successful dump, the redo log is rotated and old files are cleaned up
 * according to the retention policy.
 */
public class FullDumper {

    private static final Logger logger = LoggerFactory.getLogger(FullDumper.class);

    private final Path dataDir;
    private final String nodeId;
    private final MapRegistry registry;
    private final RedoLog redoLog;
    private final int retentionDays;

    private volatile long lastDumpTimestamp;

    public FullDumper(Path dataDir, String nodeId, MapRegistry registry,
            RedoLog redoLog, int retentionDays) {
        this.dataDir = dataDir;
        this.nodeId = nodeId;
        this.registry = registry;
        this.redoLog = redoLog;
        this.retentionDays = retentionDays;
    }

    /**
     * Performs a full dump of all registered IMaps.
     * Writes a single {@link DbDump} protobuf message containing all entries
     * as typed {@link KitchenSink} records.
     *
     * @return a {@link DumpResult} with the timestamp, entry count, and
     * duration
     */
    public DumpResult dump() throws IOException {
        long startTime = System.currentTimeMillis();
        long dumpTimestamp = startTime;
        int totalEntries = 0;

        // Count entries first for the header
        Map<String, MapRegistry.MapInfo> allMaps = registry.all();
        for (MapRegistry.MapInfo info : allMaps.values()) {
            totalEntries += info.map().size();
        }

        // Build the DbDump message with all entries
        DbDump.Builder dumpBuilder = DbDump.newBuilder()
                .setTimestampMs(dumpTimestamp)
                .setEntryCount(totalEntries)
                .setNodeId(nodeId);

        for (Map.Entry<String, MapRegistry.MapInfo> mapEntry : allMaps.entrySet()) {
            String mapName = mapEntry.getKey();
            MapRegistry.MapInfo info = mapEntry.getValue();
            ConsistencyType ksConsistency =
                    info.consistency() == Kernel.ConsistencyType.CONSISTENCY_ATOMIC
                    ? ConsistencyType.CONSISTENCY_ATOMIC
                    : ConsistencyType.CONSISTENCY_CONVERGENT;

            for (Map.Entry<String, ?> entry : info.map().entrySet()) {
                KitchenSink.Builder ksBuilder = KitchenSink.newBuilder()
                        .setMapName(mapName)
                        .setKey(entry.getKey())
                        .setOp(OpType.OP_TYPE_PUT)
                        .setTimestampMs(dumpTimestamp)
                        .setConsistency(ksConsistency);
                Object value = entry.getValue();
                if (value instanceof MessageLite msg) {
                    KitchenSinkHelper.setPayload(ksBuilder, mapName, msg);
                }
                dumpBuilder.addEntries(ksBuilder.build());
            }
        }

        // Write the DbDump as a single length-prefixed record
        Path rawFile = dataDir.resolve("dump-" + nodeId + "-" + dumpTimestamp + ".dat");
        Files.createDirectories(dataDir);

        try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(rawFile))) {
            writeRecord(os, dumpBuilder.build());
        }

        // Gzip the dump file
        Path gzFile = dataDir.resolve("dump-" + nodeId + "-" + dumpTimestamp + ".dat.gz");
        try (OutputStream gzOut = new GZIPOutputStream(
                new BufferedOutputStream(Files.newOutputStream(gzFile)))) {
            Files.copy(rawFile, gzOut);
        }
        Files.delete(rawFile);

        // Rotate redo log
        redoLog.rotate();

        // Clean up old files
        cleanupOldFiles(dumpTimestamp);

        lastDumpTimestamp = dumpTimestamp;
        long durationMs = System.currentTimeMillis() - startTime;

        logger.info("Full dump complete: {} entries across {} maps in {}ms → {}",
                totalEntries, allMaps.size(), durationMs, gzFile.getFileName());

        return new DumpResult(dumpTimestamp, totalEntries, durationMs);
    }

    /**
     * Returns the timestamp of the last successful dump, or 0 if never dumped.
     */
    public long getLastDumpTimestamp() {
        return lastDumpTimestamp;
    }

    /**
     * Lists all dump files for this node, sorted by timestamp.
     */
    public List<Path> listDumpFiles() throws IOException {
        return listDumpFiles(dataDir, nodeId);
    }

    /**
     * Lists all dump files for a given node, sorted by timestamp.
     */
    public static List<Path> listDumpFiles(Path dataDir, String nodeId) throws IOException {
        if (!Files.exists(dataDir)) {
            return List.of();
        }
        List<Path> dumps = new ArrayList<>();
        try (var stream = Files.list(dataDir)) {
            stream.filter(p -> {
                String name = p.getFileName().toString();
                return name.startsWith("dump-" + nodeId + "-") && name.endsWith(".dat.gz");
            }).forEach(dumps::add);
        }
        dumps.sort((a, b) -> {
            long ta = extractTimestamp(a);
            long tb = extractTimestamp(b);
            return Long.compare(ta, tb);
        });
        return dumps;
    }

    /**
     * Extracts timestamp from a dump filename like
     * dump-node1-1708000000000.dat.gz
     */
    static long extractTimestamp(Path file) {
        String name = file.getFileName().toString();
        // dump-{nodeId}-{timestamp}.dat.gz
        int lastDash = name.lastIndexOf('-');
        int dotDat = name.indexOf(".dat.gz");
        return Long.parseLong(name.substring(lastDash + 1, dotDat));
    }

    /**
     * Calculates the staggered dump interval offset for a node. Uses a hash of
     * the nodeId to distribute dump times across nodes.
     */
    public static long calculateJitterMs(String nodeId, long maxJitterSeconds) {
        long hash = Math.abs((long) nodeId.hashCode());
        return (hash % maxJitterSeconds) * 1000;
    }

    private void cleanupOldFiles(long currentDumpTimestamp) {
        long cutoffMs = currentDumpTimestamp - Duration.ofDays(retentionDays).toMillis();
        try {
            // Clean old dumps
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dataDir, "dump-*.dat.gz")) {
                for (Path file : stream) {
                    long ts = extractTimestamp(file);
                    if (ts < cutoffMs) {
                        Files.delete(file);
                        logger.info("Deleted old dump: {}", file.getFileName());
                    }
                }
            }
            // Clean old redo logs (any node)
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dataDir, "redo-*.log")) {
                for (Path file : stream) {
                    long ts = RedoLog.extractTimestampGeneric(file);
                    if (ts < cutoffMs) {
                        Files.delete(file);
                        logger.info("Deleted old redo log: {}", file.getFileName());
                    }
                }
            }
        } catch (IOException e) {
            logger.warn("Error cleaning up old persistence files", e);
        }
    }

    static void writeRecord(OutputStream os, MessageLite message) throws IOException {
        byte[] data = message.toByteArray();
        byte[] lenBuf = new byte[4];
        ByteBuffer.wrap(lenBuf).putInt(data.length);
        os.write(lenBuf);
        os.write(data);
    }

    /**
     * Result of a full dump.
     */
    public record DumpResult(long timestampMs, int entryCount, long durationMs) {

    }
}
