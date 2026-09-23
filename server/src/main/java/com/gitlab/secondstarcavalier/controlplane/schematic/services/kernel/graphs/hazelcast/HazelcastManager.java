// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IList;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IPriorityQueue;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IQueue;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.ISet;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.ITopic;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IdGenerator;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.Lock;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.Manager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.MultiMap;
import com.hazelcast.core.HazelcastInstance;
import java.util.Objects;

/**
 * HazelcastManager implements {@link Manager} by delegating to a
 * {@link HazelcastInstance}. Maps are wrapped in {@link HazelcastMap} so that
 * generated code never touches Hazelcast types directly.
 *
 * <p>
 * All boundaries are convergent. Locks are always no-ops.
 *
 * <p>A boundary its proto flags {@code (spec.persistence) = true} is registered
 * with {@link BoundaryPersistence} and handed back wrapped in a {@link
 * PersistentMap}, so every write to it rewrites its snapshot file before the
 * write is acked. An unflagged boundary is handed back unwrapped and stays
 * purely in memory.
 */
public class HazelcastManager implements Manager {

	private final HazelcastInstance hazelcast;
	private final BoundaryPersistence persistence;

	public HazelcastManager(HazelcastInstance hazelcast) {
		this(hazelcast, null);
	}

	public HazelcastManager(HazelcastInstance hazelcast, BoundaryPersistence persistence) {
		this.hazelcast = Objects.requireNonNull(hazelcast, "hazelcast");
		this.persistence = persistence;
	}

	@Override
	public <K, V> IMap<K, V> getConvergentMap(String name) {
		return getConvergentMap(name, false, null);
	}

	@Override
	public <K, V> IMap<K, V> getConvergentMap(String name, boolean persistent) {
		return getConvergentMap(name, persistent, null);
	}

	@Override
	public <K, V> IMap<K, V> getConvergentMap(
			String name, boolean persistent, com.google.protobuf.Message defaultInstance) {
		String mapName = Objects.requireNonNull(name, "name");
		com.hazelcast.map.IMap<K, V> hzMap = hazelcast.getMap(mapName);
		IMap<K, V> base = new HazelcastMap<>(hzMap);
		if (!persistent || persistence == null) {
			return base;
		}
		persistence.register(
				mapName, hzMap, base, defaultInstance, ConsistencyType.CONSISTENCY_CONVERGENT);
		if (!persistence.isEnabled() || defaultInstance == null) {
			// Registered for cluster stats, but there is nothing to write to:
			// no persistence directory, or a caller that did not name the value
			// type (the two-argument overload, kept for hand-written callers).
			return base;
		}
		return new PersistentMap<>(base, persistence, mapName);
	}

	@Override
	public <K, V> IMap<K, V> getReplicatedMap(String name) {
		return new HazelcastReplicatedMap<>(hazelcast.getReplicatedMap(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <K, V> IMap<K, V> getVolatileMap(String name) {
		return new HazelcastMap<>(hazelcast.getMap(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <K, V> MultiMap<K, V> getMultiMap(String name) {
		return new HazelcastMultiMap<>(hazelcast.getMultiMap(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <E> IList<E> getList(String name) {
		return new HazelcastList<>(hazelcast.getList(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <E> ISet<E> getSet(String name) {
		return new HazelcastSet<>(hazelcast.getSet(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <E> IQueue<E> getQueue(String name) {
		return new HazelcastQueue<>(hazelcast.getQueue(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <E> ITopic<E> getTopic(String name) {
		return new HazelcastTopic<>(hazelcast.getTopic(Objects.requireNonNull(name, "name")));
	}

	@Override
	public <E> IPriorityQueue<E> getPriorityQueue(String name) {
		throw new UnsupportedOperationException(
				"Priority queue not yet implemented — no proto uses (spec.priority_queue)");
	}

	@Override
	public IdGenerator getIdGenerator(String name) {
		var flake = hazelcast.getFlakeIdGenerator(Objects.requireNonNull(name, "name"));
		return flake::newId;
	}

	@Override
	public Lock getLock(String name) {
		return NO_OP_LOCK;
	}

	private static final Lock NO_OP_LOCK = new Lock() {
		@Override
		public void lock() {
		}

		@Override
		public void lockInterruptibly() {
		}

		@Override
		public boolean tryLock() {
			return true;
		}

		@Override
		public boolean tryLock(long time, java.util.concurrent.TimeUnit unit) {
			return true;
		}

		@Override
		public void unlock() {
		}

		@Override
		public boolean isLocked() {
			return false;
		}

		@Override
		public boolean isLockedByCurrentThread() {
			return false;
		}

		@Override
		public int getLockCount() {
			return 0;
		}
	};
}
