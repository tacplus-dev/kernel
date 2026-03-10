// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IMap;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * HazelcastMap adapts a Hazelcast {@link com.hazelcast.map.IMap} to the
 * {@link IMap} interface, keeping Hazelcast types out of generated code.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
class HazelcastMap<K, V> implements IMap<K, V> {

	private final com.hazelcast.map.IMap<K, V> delegate;

	HazelcastMap(com.hazelcast.map.IMap<K, V> delegate) {
		this.delegate = Objects.requireNonNull(delegate, "delegate");
	}

	// ========================================================================
	// Basic Operations
	// ========================================================================
	@Override
	public V get(K key) {
		return delegate.get(Objects.requireNonNull(key, "key"));
	}

	@Override
	public V put(K key, V value) {
		return delegate.put(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public V put(K key, V value, long ttl, TimeUnit ttlUnit) {
		return delegate.put(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(value, "value"),
				ttl,
				Objects.requireNonNull(ttlUnit, "ttlUnit"));
	}

	@Override
	public void set(K key, V value) {
		delegate.set(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public void set(K key, V value, long ttl, TimeUnit ttlUnit) {
		delegate.set(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(value, "value"),
				ttl,
				Objects.requireNonNull(ttlUnit, "ttlUnit"));
	}

	@Override
	public V putIfAbsent(K key, V value) {
		return delegate.putIfAbsent(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public V putIfAbsent(K key, V value, long ttl, TimeUnit ttlUnit) {
		return delegate.putIfAbsent(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(value, "value"),
				ttl,
				Objects.requireNonNull(ttlUnit, "ttlUnit"));
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> map) {
		delegate.putAll(Objects.requireNonNull(map, "map"));
	}

	// ========================================================================
	// Remove / Delete
	// ========================================================================
	@Override
	public V remove(K key) {
		return delegate.remove(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean remove(K key, V value) {
		return delegate.remove(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public void delete(K key) {
		delegate.delete(Objects.requireNonNull(key, "key"));
	}

	// ========================================================================
	// Replace
	// ========================================================================
	@Override
	public V replace(K key, V value) {
		return delegate.replace(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public boolean replace(K key, V oldValue, V newValue) {
		return delegate.replace(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(oldValue, "oldValue"),
				Objects.requireNonNull(newValue, "newValue"));
	}

	// ========================================================================
	// Query
	// ========================================================================
	@Override
	public boolean containsKey(K key) {
		return delegate.containsKey(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean containsValue(V value) {
		return delegate.containsValue(Objects.requireNonNull(value, "value"));
	}

	@Override
	public Map<K, V> getAll(Set<K> keys) {
		return delegate.getAll(Objects.requireNonNull(keys, "keys"));
	}

	// ========================================================================
	// Collection Views
	// ========================================================================
	@Override
	public Set<K> keySet() {
		return delegate.keySet();
	}

	@Override
	public Collection<V> values() {
		return delegate.values();
	}

	@Override
	public Set<Map.Entry<K, V>> entrySet() {
		return delegate.entrySet();
	}

	// ========================================================================
	// Size / Clear
	// ========================================================================
	@Override
	public int size() {
		return delegate.size();
	}

	@Override
	public boolean isEmpty() {
		return delegate.isEmpty();
	}

	@Override
	public void clear() {
		delegate.clear();
	}

	// ========================================================================
	// Eviction
	// ========================================================================
	@Override
	public boolean evict(K key) {
		return delegate.evict(Objects.requireNonNull(key, "key"));
	}

	@Override
	public void evictAll() {
		delegate.evictAll();
	}

	// ========================================================================
	// Try Operations
	// ========================================================================
	@Override
	public boolean tryPut(K key, V value, long timeout, TimeUnit timeUnit) {
		return delegate.tryPut(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(value, "value"),
				timeout,
				Objects.requireNonNull(timeUnit, "timeUnit"));
	}

	@Override
	public boolean tryRemove(K key, long timeout, TimeUnit timeUnit) {
		return delegate.tryRemove(
				Objects.requireNonNull(key, "key"),
				timeout,
				Objects.requireNonNull(timeUnit, "timeUnit"));
	}

	// ========================================================================
	// Per-Key Locking
	// ========================================================================
	@Override
	public void lock(K key) {
		delegate.lock(Objects.requireNonNull(key, "key"));
	}

	@Override
	public void lock(K key, long leaseTime, TimeUnit timeUnit) {
		delegate.lock(
				Objects.requireNonNull(key, "key"),
				leaseTime,
				Objects.requireNonNull(timeUnit, "timeUnit"));
	}

	@Override
	public void unlock(K key) {
		delegate.unlock(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean tryLock(K key) {
		return delegate.tryLock(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean tryLock(K key, long time, TimeUnit timeUnit) throws InterruptedException {
		return delegate.tryLock(
				Objects.requireNonNull(key, "key"),
				time,
				Objects.requireNonNull(timeUnit, "timeUnit"));
	}

	@Override
	public boolean tryLock(K key, long time, TimeUnit timeUnit, long leaseTime, TimeUnit leaseTimeUnit)
			throws InterruptedException {
		return delegate.tryLock(
				Objects.requireNonNull(key, "key"),
				time,
				Objects.requireNonNull(timeUnit, "timeUnit"),
				leaseTime,
				Objects.requireNonNull(leaseTimeUnit, "leaseTimeUnit"));
	}

	@Override
	public boolean isLocked(K key) {
		return delegate.isLocked(Objects.requireNonNull(key, "key"));
	}

	@Override
	public void forceUnlock(K key) {
		delegate.forceUnlock(Objects.requireNonNull(key, "key"));
	}

	// ========================================================================
	// Async Operations
	// ========================================================================
	@Override
	public CompletionStage<V> getAsync(K key) {
		return delegate.getAsync(Objects.requireNonNull(key, "key"));
	}

	@Override
	public CompletionStage<V> putAsync(K key, V value) {
		return delegate.putAsync(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
		return delegate.putAsync(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(value, "value"),
				ttl,
				Objects.requireNonNull(ttlUnit, "ttlUnit"));
	}

	@Override
	public CompletionStage<Void> setAsync(K key, V value) {
		return delegate.setAsync(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
		return delegate.setAsync(
				Objects.requireNonNull(key, "key"),
				Objects.requireNonNull(value, "value"),
				ttl,
				Objects.requireNonNull(ttlUnit, "ttlUnit"));
	}

	@Override
	public CompletionStage<V> removeAsync(K key) {
		return delegate.removeAsync(Objects.requireNonNull(key, "key"));
	}

	@Override
	public CompletionStage<Boolean> deleteAsync(K key) {
		return delegate.deleteAsync(Objects.requireNonNull(key, "key"));
	}
}
