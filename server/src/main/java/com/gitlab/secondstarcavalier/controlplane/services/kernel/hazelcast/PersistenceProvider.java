// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IMap;
import com.hazelcast.core.HazelcastInstance;

import java.io.IOException;

/**
 * Abstraction over the persistence subsystem so that common code
 * (HazelcastManager, ClusterServer, ClusterStatePublisher) can work
 * with persistence without depending on the concrete implementation
 * which lives in the core module.
 */
public interface PersistenceProvider extends AutoCloseable {

    boolean isEnabled();

    void initialize(HazelcastInstance hz, int quorum) throws IOException;

    <K, V> void registerMap(String name, com.hazelcast.map.IMap<K, V> hzMap,
                            IMap<K, V> imap, ConsistencyType consistency);

    long getRedoLogSizeBytes();

    long getLastDumpTimestamp();

    MapRegistry getRegistry();

    @Override
    void close();

    /**
     * Returns a no-op provider for edge nodes. Maps are still tracked in the
     * registry (for stats) but no persistence listeners are attached.
     */
    static PersistenceProvider disabled() {
        return new PersistenceProvider() {
            private final MapRegistry registry = new MapRegistry();

            @Override
            public boolean isEnabled() { return false; }

            @Override
            public void initialize(HazelcastInstance hz, int quorum) {}

            @Override
            public <K, V> void registerMap(String name, com.hazelcast.map.IMap<K, V> hzMap,
                                           IMap<K, V> imap, ConsistencyType consistency) {
                registry.register(name, imap, consistency);
            }

            @Override
            public long getRedoLogSizeBytes() { return 0; }

            @Override
            public long getLastDumpTimestamp() { return 0; }

            @Override
            public MapRegistry getRegistry() { return registry; }

            @Override
            public void close() {}
        };
    }
}
