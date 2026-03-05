// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.elvis.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.services.elvis.persistence.PersistenceManager;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.raft.RatisLockManager;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.services.elvis.Elvis.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IList;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IMap;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IPriorityQueue;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IQueue;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.ISet;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.ITopic;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IdGenerator;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Lock;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Manager;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.MultiMap;
import com.hazelcast.core.HazelcastInstance;

/**
 * HazelcastManager implements {@link Manager} by delegating to a
 * {@link HazelcastInstance}. Maps are wrapped in {@link HazelcastMap} and locks
 * in {@link HazelcastLock} so that generated code never touches Hazelcast types
 * directly.
 *
 * <p>
 * When a {@link PersistenceManager} is provided, convergent and atomic maps
 * have a cluster-wide persistence listener registered for redo logging.
 */
public class HazelcastManager implements Manager {

    private final HazelcastInstance hazelcast;
    private final PersistenceManager persistence;
    private final RatisLockManager ratisLockManager;

    public HazelcastManager(HazelcastInstance hazelcast) {
        this(hazelcast, null, null);
    }

    public HazelcastManager(HazelcastInstance hazelcast, PersistenceManager persistence) {
        this(hazelcast, persistence, null);
    }

    public HazelcastManager(HazelcastInstance hazelcast, PersistenceManager persistence,
            RatisLockManager ratisLockManager) {
        this.hazelcast = hazelcast;
        this.persistence = persistence;
        this.ratisLockManager = ratisLockManager;
    }

    @Override
    public <K, V> IMap<K, V> getConvergentMap(String name) {
        com.hazelcast.map.IMap<K, V> hzMap = hazelcast.getMap(name);
        IMap<K, V> base = new HazelcastMap<>(hzMap);
        if (persistence != null) {
            persistence.registerMap(name, hzMap, base, ConsistencyType.CONSISTENCY_CONVERGENT);
        }
        return base;
    }

    @Override
    public <K, V> IMap<K, V> getAtomicMap(String name) {
        com.hazelcast.map.IMap<K, V> hzMap = hazelcast.getMap(name);
        IMap<K, V> base = new HazelcastMap<>(hzMap);
        if (persistence != null) {
            persistence.registerMap(name, hzMap, base, ConsistencyType.CONSISTENCY_ATOMIC);
        }
        return base;
    }

    @Override
    public <K, V> IMap<K, V> getVolatileMap(String name) {
        return new HazelcastMap<>(hazelcast.getMap(name));
    }

    @Override
    public <K, V> MultiMap<K, V> getMultiMap(String name) {
        return new HazelcastMultiMap<>(hazelcast.getMultiMap(name));
    }

    @Override
    public <E> IList<E> getList(String name) {
        return new HazelcastList<>(hazelcast.getList(name));
    }

    @Override
    public <E> ISet<E> getSet(String name) {
        return new HazelcastSet<>(hazelcast.getSet(name));
    }

    @Override
    public <E> IQueue<E> getQueue(String name) {
        return new HazelcastQueue<>(hazelcast.getQueue(name));
    }

    @Override
    public <E> ITopic<E> getTopic(String name) {
        return new HazelcastTopic<>(hazelcast.getTopic(name));
    }

    @Override
    public <E> IPriorityQueue<E> getPriorityQueue(String name) {
		// TODO / AGENT : Is this correct?
        throw new UnsupportedOperationException("Hazelcast does not support IPriorityQueue directly");
    }

    @Override
    public IdGenerator getIdGenerator(String name) {
        var flake = hazelcast.getFlakeIdGenerator(name);
        return flake::newId;
    }

    @Override
    public Lock getLock(String name) {
        if (ratisLockManager != null) {
            return ratisLockManager.getLock(name);
        }
        throw new UnsupportedOperationException(
                "Distributed locks require RatisLockManager — CP subsystem is not available in community edition");
    }

}
