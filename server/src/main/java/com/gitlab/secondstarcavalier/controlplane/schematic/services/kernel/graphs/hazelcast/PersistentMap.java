// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.IMap;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * The write leg of {@code (spec.persistence) = true}: an {@link IMap} that
 * rewrites its boundary's snapshot file as part of every mutation.
 *
 * <p>The write is synchronous and its failure is not caught, so a state-plane
 * RPC whose snapshot did not land fails rather than acking data that exists
 * only in Hazelcast memory. That is the rule kernel already applies to its own
 * state through {@code KernelPersistence.save()}; this extends it to every
 * flagged boundary, from any service's proto.
 *
 * <p>Reads and the non-mutating surface delegate untouched.
 */
final class PersistentMap<K, V> implements IMap<K, V> {

	private final IMap<K, V> delegate;
	private final BoundaryPersistence persistence;
	private final String mapName;

	PersistentMap(IMap<K, V> delegate, BoundaryPersistence persistence, String mapName) {
		this.delegate = Objects.requireNonNull(delegate, "delegate");
		this.persistence = Objects.requireNonNull(persistence, "persistence");
		this.mapName = Objects.requireNonNull(mapName, "mapName");
	}

	/** Rewrites this boundary's file from the live map; throws if it does not land. */
	private void persist() {
		persistence.snapshot(mapName);
	}

	private <T> T persistAfter(T result) {
		persist();
		return result;
	}

	// ==================== Mutating ====================
	@Override
	public V put(K key, V value) {
		return persistAfter(delegate.put(key, value));
	}

	@Override
	public V put(K key, V value, long ttl, TimeUnit ttlUnit) {
		return persistAfter(delegate.put(key, value, ttl, ttlUnit));
	}

	@Override
	public void set(K key, V value) {
		delegate.set(key, value);
		persist();
	}

	@Override
	public void set(K key, V value, long ttl, TimeUnit ttlUnit) {
		delegate.set(key, value, ttl, ttlUnit);
		persist();
	}

	@Override
	public V putIfAbsent(K key, V value) {
		return persistAfter(delegate.putIfAbsent(key, value));
	}

	@Override
	public V putIfAbsent(K key, V value, long ttl, TimeUnit ttlUnit) {
		return persistAfter(delegate.putIfAbsent(key, value, ttl, ttlUnit));
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> map) {
		delegate.putAll(map);
		persist();
	}

	@Override
	public V remove(K key) {
		return persistAfter(delegate.remove(key));
	}

	@Override
	public boolean remove(K key, V value) {
		return persistAfter(delegate.remove(key, value));
	}

	@Override
	public void delete(K key) {
		delegate.delete(key);
		persist();
	}

	@Override
	public V replace(K key, V value) {
		return persistAfter(delegate.replace(key, value));
	}

	@Override
	public boolean replace(K key, V oldValue, V newValue) {
		return persistAfter(delegate.replace(key, oldValue, newValue));
	}

	@Override
	public void clear() {
		delegate.clear();
		persist();
	}

	@Override
	public boolean evict(K key) {
		return persistAfter(delegate.evict(key));
	}

	@Override
	public void evictAll() {
		delegate.evictAll();
		persist();
	}

	@Override
	public boolean tryPut(K key, V value, long timeout, TimeUnit timeUnit) {
		return persistAfter(delegate.tryPut(key, value, timeout, timeUnit));
	}

	@Override
	public boolean tryRemove(K key, long timeout, TimeUnit timeUnit) {
		return persistAfter(delegate.tryRemove(key, timeout, timeUnit));
	}

	// Async mutations persist when the mutation itself completes. The returned
	// stage is the one the caller awaits, so a caller that waits for the write
	// also waits for the snapshot and sees its failure.
	@Override
	public CompletionStage<V> putAsync(K key, V value) {
		return delegate.putAsync(key, value).thenApply(this::persistAfter);
	}

	@Override
	public CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
		return delegate.putAsync(key, value, ttl, ttlUnit).thenApply(this::persistAfter);
	}

	@Override
	public CompletionStage<Void> setAsync(K key, V value) {
		return delegate.setAsync(key, value).thenApply(this::persistAfter);
	}

	@Override
	public CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
		return delegate.setAsync(key, value, ttl, ttlUnit).thenApply(this::persistAfter);
	}

	@Override
	public CompletionStage<V> removeAsync(K key) {
		return delegate.removeAsync(key).thenApply(this::persistAfter);
	}

	@Override
	public CompletionStage<Boolean> deleteAsync(K key) {
		return delegate.deleteAsync(key).thenApply(this::persistAfter);
	}

	// ==================== Read-only / pass-through ====================
	@Override
	public V get(K key) {
		return delegate.get(key);
	}

	@Override
	public boolean containsKey(K key) {
		return delegate.containsKey(key);
	}

	@Override
	public boolean containsValue(V value) {
		return delegate.containsValue(value);
	}

	@Override
	public Map<K, V> getAll(Set<K> keys) {
		return delegate.getAll(keys);
	}

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

	@Override
	public int size() {
		return delegate.size();
	}

	@Override
	public boolean isEmpty() {
		return delegate.isEmpty();
	}

	@Override
	public void lock(K key) {
		delegate.lock(key);
	}

	@Override
	public void lock(K key, long leaseTime, TimeUnit timeUnit) {
		delegate.lock(key, leaseTime, timeUnit);
	}

	@Override
	public void unlock(K key) {
		delegate.unlock(key);
	}

	@Override
	public boolean tryLock(K key) {
		return delegate.tryLock(key);
	}

	@Override
	public boolean tryLock(K key, long time, TimeUnit timeUnit) throws InterruptedException {
		return delegate.tryLock(key, time, timeUnit);
	}

	@Override
	public boolean tryLock(K key, long time, TimeUnit timeUnit, long leaseTime, TimeUnit leaseTimeUnit)
			throws InterruptedException {
		return delegate.tryLock(key, time, timeUnit, leaseTime, leaseTimeUnit);
	}

	@Override
	public boolean isLocked(K key) {
		return delegate.isLocked(key);
	}

	@Override
	public void forceUnlock(K key) {
		delegate.forceUnlock(key);
	}

	@Override
	public CompletionStage<V> getAsync(K key) {
		return delegate.getAsync(key);
	}
}
