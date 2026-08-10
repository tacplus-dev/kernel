// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IMap;
import com.hazelcast.replicatedmap.ReplicatedMap;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * HazelcastReplicatedMap adapts a Hazelcast {@link ReplicatedMap} to the
 * {@link IMap} interface. ReplicatedMaps store a full copy on every cluster
 * member, providing always-local reads with async-replicated writes.
 *
 * <p>
 * Operations not supported by ReplicatedMap (locking, async, eviction,
 * tryPut/tryRemove) throw {@link UnsupportedOperationException}.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
class HazelcastReplicatedMap<K, V> implements IMap<K, V> {

	private final ReplicatedMap<K, V> delegate;

	HazelcastReplicatedMap(ReplicatedMap<K, V> delegate) {
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
		delegate.put(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public void set(K key, V value, long ttl, TimeUnit ttlUnit) {
		throw new UnsupportedOperationException("set(K,V,ttl) not supported on ReplicatedMap");
	}

	@Override
	public V putIfAbsent(K key, V value) {
		return delegate.putIfAbsent(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public V putIfAbsent(K key, V value, long ttl, TimeUnit ttlUnit) {
		throw new UnsupportedOperationException("putIfAbsent(K,V,ttl) not supported on ReplicatedMap");
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
		K nonNullKey = Objects.requireNonNull(key, "key");
		V nonNullValue = Objects.requireNonNull(value, "value");
		V current = delegate.get(nonNullKey);
		if (Objects.equals(current, nonNullValue)) {
			delegate.remove(nonNullKey);
			return true;
		}
		return false;
	}

	@Override
	public void delete(K key) {
		delegate.remove(Objects.requireNonNull(key, "key"));
	}

	// ========================================================================
	// Replace
	// ========================================================================
	@Override
	public V replace(K key, V value) {
		K nonNullKey = Objects.requireNonNull(key, "key");
		V nonNullValue = Objects.requireNonNull(value, "value");
		if (delegate.containsKey(nonNullKey)) {
			return delegate.put(nonNullKey, nonNullValue);
		}
		return null;
	}

	@Override
	public boolean replace(K key, V oldValue, V newValue) {
		K nonNullKey = Objects.requireNonNull(key, "key");
		V nonNullOldValue = Objects.requireNonNull(oldValue, "oldValue");
		V nonNullNewValue = Objects.requireNonNull(newValue, "newValue");
		V current = delegate.get(nonNullKey);
		if (Objects.equals(current, nonNullOldValue)) {
			delegate.put(nonNullKey, nonNullNewValue);
			return true;
		}
		return false;
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
		throw new UnsupportedOperationException("getAll not supported on ReplicatedMap");
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
	// Eviction — not supported on ReplicatedMap
	// ========================================================================
	@Override
	public boolean evict(K key) {
		throw new UnsupportedOperationException("evict not supported on ReplicatedMap");
	}

	@Override
	public void evictAll() {
		throw new UnsupportedOperationException("evictAll not supported on ReplicatedMap");
	}

	// ========================================================================
	// Try Operations — not supported on ReplicatedMap
	// ========================================================================
	@Override
	public boolean tryPut(K key, V value, long timeout, TimeUnit timeUnit) {
		throw new UnsupportedOperationException("tryPut not supported on ReplicatedMap");
	}

	@Override
	public boolean tryRemove(K key, long timeout, TimeUnit timeUnit) {
		throw new UnsupportedOperationException("tryRemove not supported on ReplicatedMap");
	}

	// ========================================================================
	// Per-Key Locking — not supported on ReplicatedMap
	// ========================================================================
	@Override
	public void lock(K key) {
		throw new UnsupportedOperationException("lock not supported on ReplicatedMap");
	}

	@Override
	public void lock(K key, long leaseTime, TimeUnit timeUnit) {
		throw new UnsupportedOperationException("lock not supported on ReplicatedMap");
	}

	@Override
	public void unlock(K key) {
		throw new UnsupportedOperationException("unlock not supported on ReplicatedMap");
	}

	@Override
	public boolean tryLock(K key) {
		throw new UnsupportedOperationException("tryLock not supported on ReplicatedMap");
	}

	@Override
	public boolean tryLock(K key, long time, TimeUnit timeUnit) {
		throw new UnsupportedOperationException("tryLock not supported on ReplicatedMap");
	}

	@Override
	public boolean tryLock(K key, long time, TimeUnit timeUnit, long leaseTime, TimeUnit leaseTimeUnit) {
		throw new UnsupportedOperationException("tryLock not supported on ReplicatedMap");
	}

	@Override
	public boolean isLocked(K key) {
		throw new UnsupportedOperationException("isLocked not supported on ReplicatedMap");
	}

	@Override
	public void forceUnlock(K key) {
		throw new UnsupportedOperationException("forceUnlock not supported on ReplicatedMap");
	}

	// ========================================================================
	// Async Operations — not supported on ReplicatedMap
	// ========================================================================
	@Override
	public CompletionStage<V> getAsync(K key) {
		throw new UnsupportedOperationException("getAsync not supported on ReplicatedMap");
	}

	@Override
	public CompletionStage<V> putAsync(K key, V value) {
		throw new UnsupportedOperationException("putAsync not supported on ReplicatedMap");
	}

	@Override
	public CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
		throw new UnsupportedOperationException("putAsync not supported on ReplicatedMap");
	}

	@Override
	public CompletionStage<Void> setAsync(K key, V value) {
		throw new UnsupportedOperationException("setAsync not supported on ReplicatedMap");
	}

	@Override
	public CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
		throw new UnsupportedOperationException("setAsync not supported on ReplicatedMap");
	}

	@Override
	public CompletionStage<V> removeAsync(K key) {
		throw new UnsupportedOperationException("removeAsync not supported on ReplicatedMap");
	}

	@Override
	public CompletionStage<Boolean> deleteAsync(K key) {
		throw new UnsupportedOperationException("deleteAsync not supported on ReplicatedMap");
	}
}
