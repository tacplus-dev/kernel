// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

/**
 * Factory interface for obtaining distributed data structures.
 * Implementations provide maps, lists, sets, queues, topics, and locks
 * backed by a concrete distributed system (e.g. Hazelcast).
 */
public interface Manager {
	/**
	 * A convergent map boundary. It is in-memory coordination state: kernel does
	 * no durability for service boundaries, and durable data belongs in stratum
	 * records, not here.
	 */
	<K, V> IMap<K, V> getConvergentMap(String name);
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
