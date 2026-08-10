// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * Distributed map interface. Abstracts over concrete distributed map
 * implementations so that generated code never depends on a specific backend.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
public interface IMap<K, V> {

	// Basic Operations
	V get(K key);
	V put(K key, V value);
	V put(K key, V value, long ttl, TimeUnit ttlUnit);
	void set(K key, V value);
	void set(K key, V value, long ttl, TimeUnit ttlUnit);
	V putIfAbsent(K key, V value);
	V putIfAbsent(K key, V value, long ttl, TimeUnit ttlUnit);
	void putAll(Map<? extends K, ? extends V> map);

	// Remove / Delete
	V remove(K key);
	boolean remove(K key, V value);
	void delete(K key);

	// Replace
	V replace(K key, V value);
	boolean replace(K key, V oldValue, V newValue);

	// Query
	boolean containsKey(K key);
	boolean containsValue(V value);
	Map<K, V> getAll(Set<K> keys);

	// Collection Views
	Set<K> keySet();
	Collection<V> values();
	Set<Map.Entry<K, V>> entrySet();

	// Size / Clear
	int size();
	boolean isEmpty();
	void clear();

	// Eviction
	boolean evict(K key);
	void evictAll();

	// Try Operations
	boolean tryPut(K key, V value, long timeout, TimeUnit timeUnit);
	boolean tryRemove(K key, long timeout, TimeUnit timeUnit);

	// Per-Key Locking
	void lock(K key);
	void lock(K key, long leaseTime, TimeUnit timeUnit);
	void unlock(K key);
	boolean tryLock(K key);
	boolean tryLock(K key, long time, TimeUnit timeUnit) throws InterruptedException;
	boolean tryLock(K key, long time, TimeUnit timeUnit, long leaseTime, TimeUnit leaseTimeUnit)
			throws InterruptedException;
	boolean isLocked(K key);
	void forceUnlock(K key);

	// Async Operations
	CompletionStage<V> getAsync(K key);
	CompletionStage<V> putAsync(K key, V value);
	CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit ttlUnit);
	CompletionStage<Void> setAsync(K key, V value);
	CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit ttlUnit);
	CompletionStage<V> removeAsync(K key);
	CompletionStage<Boolean> deleteAsync(K key);
}
