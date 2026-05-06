// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.hazelcast.Hazelcast.ConsistencyType;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.IList;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.IMap;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.IPriorityQueue;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.IQueue;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.ISet;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.ITopic;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.IdGenerator;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.Lock;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.Manager;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.MultiMap;
import com.hazelcast.core.HazelcastInstance;
import java.util.Objects;

/**
 * HazelcastManager implements {@link Manager} by delegating to a
 * {@link HazelcastInstance}. Maps are wrapped in {@link HazelcastMap} so that
 * generated code never touches Hazelcast types directly.
 *
 * <p>
 * All boundaries are convergent. Locks are always no-ops.
 * When a {@link PersistenceProvider} is provided, maps have a cluster-wide
 * persistence listener registered for redo logging.
 */
public class HazelcastManager implements Manager {

	private final HazelcastInstance hazelcast;
	private final PersistenceProvider persistence;

	public HazelcastManager(HazelcastInstance hazelcast) {
		this(hazelcast, null);
	}

	public HazelcastManager(HazelcastInstance hazelcast, PersistenceProvider persistence) {
		this.hazelcast = Objects.requireNonNull(hazelcast, "hazelcast");
		this.persistence = persistence;
	}

	@Override
	public <K, V> IMap<K, V> getConvergentMap(String name) {
		String mapName = Objects.requireNonNull(name, "name");
		com.hazelcast.map.IMap<K, V> hzMap = hazelcast.getMap(mapName);
		IMap<K, V> base = new HazelcastMap<>(hzMap);
		if (persistence != null) {
			persistence.registerMap(mapName, hzMap, base, ConsistencyType.CONSISTENCY_CONVERGENT);
		}
		return base;
	}

	@Override
	public <K, V> IMap<K, V> getAtomicMap(String name) {
		return getConvergentMap(name);
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
