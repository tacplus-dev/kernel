// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.persistence;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast.MapRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.RedoLogEntry;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast.PersistenceEntry;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import com.hazelcast.core.EntryEvent;
import com.hazelcast.map.MapEvent;
import com.hazelcast.map.listener.EntryAddedListener;
import com.hazelcast.map.listener.EntryEvictedListener;
import com.hazelcast.map.listener.EntryRemovedListener;
import com.hazelcast.map.listener.EntryUpdatedListener;
import com.hazelcast.map.listener.MapClearedListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.hazelcast.Hazelcast;

/**
 * Hazelcast MapListener that logs cluster-wide map mutations to the
 * {@link RedoLog}. Unlike the former PersistentIMap decorator, this listener
 * receives events from all cluster members, not just local writes.
 *
 * <p>
 * Registered via {@code hazelcastMap.addEntryListener(listener, true)} so
 * that entry values are included in events.
 */
public class PersistenceMapListener
		implements EntryAddedListener<String, Object>,
		EntryUpdatedListener<String, Object>,
		EntryRemovedListener<String, Object>,
		EntryEvictedListener<String, Object>,
		MapClearedListener {

	private static final Logger logger = LoggerFactory.getLogger(PersistenceMapListener.class);

	private final RedoLog redoLog;
	private final String mapName;
	private final Hazelcast.ConsistencyType consistency;
	private final MapRegistry registry;
	private volatile boolean parserDetected = false;

	public PersistenceMapListener(
			RedoLog redoLog, String mapName, Hazelcast.ConsistencyType consistency, MapRegistry registry) {
		this.redoLog = redoLog;
		this.mapName = mapName;
		this.consistency = consistency;
		this.registry = registry;
	}

	@Override
	public void entryAdded(EntryEvent<String, Object> event) {
		logPut(event.getKey(), event.getValue());
	}

	@Override
	public void entryUpdated(EntryEvent<String, Object> event) {
		logPut(event.getKey(), event.getValue());
	}

	@Override
	public void entryRemoved(EntryEvent<String, Object> event) {
		logDelete(event.getKey());
	}

	@Override
	public void entryEvicted(EntryEvent<String, Object> event) {
		logDelete(event.getKey());
	}

	@Override
	public void mapCleared(MapEvent event) {
		logger.info("Map {} cleared ({} entries removed)", mapName, event.getNumberOfEntriesAffected());
		// No individual keys available in MapEvent; the entries are already gone.
		// This is acceptable: on restore, the absence of a subsequent PUT for
		// these keys means they won't be present in the restored state.
	}

	private void logPut(String key, Object value) {
		PersistenceEntry.Builder builder = PersistenceEntry.newBuilder()
				.setMapName(mapName)
				.setKey(key)
				.setOp(Hazelcast.OpType.OP_TYPE_PUT)
				.setTimestampMs(System.currentTimeMillis())
				.setConsistency(mapConsistency());
		if (value instanceof MessageLite msg) {
			if (!KitchenSinkHelper.setPayload(builder, mapName, msg)) {
				// Fallback: type not packable (lite-only), use legacy RedoLogEntry
				redoLog.appendLegacy(RedoLogEntry.newBuilder()
						.setMapName(mapName)
						.setKey(key)
						.setOp(Hazelcast.OpType.OP_TYPE_PUT)
						.setTimestampMs(System.currentTimeMillis())
						.setConsistency(consistency)
						.setValue(ByteString.copyFrom(msg.toByteArray()))
						.build());
				detectParser(msg);
				return;
			}
			detectParser(msg);
		}
		redoLog.append(builder.build());
	}

	private Hazelcast.ConsistencyType mapConsistency() {
		return Hazelcast.ConsistencyType.CONSISTENCY_CONVERGENT;
	}

	private void detectParser(MessageLite msg) {
		if (!parserDetected && registry != null) {
			registry.setParserIfAbsent(mapName, msg.getParserForType());
			parserDetected = true;
		}
	}

	private void logDelete(String key) {
		redoLog.append(PersistenceEntry.newBuilder()
				.setMapName(mapName)
				.setKey(key)
				.setOp(Hazelcast.OpType.OP_TYPE_DELETE)
				.setTimestampMs(System.currentTimeMillis())
				.setConsistency(mapConsistency())
				.build());
	}
}
