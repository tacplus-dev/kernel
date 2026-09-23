// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs;

/**
 * Factory interface for obtaining distributed data structures.
 * Implementations provide maps, lists, sets, queues, topics, and locks
 * backed by a concrete distributed system (e.g. Hazelcast).
 */
public interface Manager {
	<K, V> IMap<K, V> getConvergentMap(String name);
	<K, V> IMap<K, V> getConvergentMap(String name, boolean persistent);

	/**
	 * A convergent map that, when {@code persistent}, is durable: kernel
	 * snapshots it to disk on every write and rehydrates it on a cold start.
	 *
	 * <p>{@code defaultInstance} is the boundary's value type. Persistence needs
	 * it on the read leg — a boundary file is loaded before any value has been
	 * seen, so the type cannot be inferred from the map's contents — and stamps
	 * the proto type name into each record so a type change is caught rather
	 * than mis-parsed. Generated code passes it for every convergent boundary;
	 * it is ignored when {@code persistent} is false.
	 */
	<K, V> IMap<K, V> getConvergentMap(String name, boolean persistent, com.google.protobuf.Message defaultInstance);
	<K, V> IMap<K, V> getReplicatedMap(String name);
	<K, V> IMap<K, V> getVolatileMap(String name);
	<K, V> MultiMap<K, V> getMultiMap(String name);
	<E> IList<E> getList(String name);
	<E> ISet<E> getSet(String name);
	<E> IQueue<E> getQueue(String name);
	<E> ITopic<E> getTopic(String name);
	<E> IPriorityQueue<E> getPriorityQueue(String name);
	IdGenerator getIdGenerator(String name);
	Lock getLock(String name);
}
