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
 * <p>Every boundary is memory-only. Kernel does no durability for service
 * state: it is in-memory coordination, rebuilt from config seeding and from
 * peers on every start, and durable data belongs in stratum records. The only
 * thing kernel writes to disk is its own identity snapshot, which is not a map
 * boundary and does not come through here.
 */
public class HazelcastManager implements Manager {

	private final HazelcastInstance hazelcast;
	/** Every convergent boundary this manager has handed out, for cluster map stats. */
	private final MapRegistry mapRegistry = new MapRegistry();

	public HazelcastManager(HazelcastInstance hazelcast) {
		this.hazelcast = Objects.requireNonNull(hazelcast, "hazelcast");
	}

	/** The convergent boundaries handed out so far; read by ClusterStatePublisher. */
	public MapRegistry getMapRegistry() {
		return mapRegistry;
	}

	@Override
	public <K, V> IMap<K, V> getConvergentMap(String name) {
		String mapName = Objects.requireNonNull(name, "name");
		IMap<K, V> map = new HazelcastMap<>(hazelcast.getMap(mapName));
		mapRegistry.register(mapName, map, ConsistencyType.CONSISTENCY_CONVERGENT);
		return map;
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
