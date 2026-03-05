// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.elvis.hazelcast;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IMap;

/**
 * HazelcastMap adapts a Hazelcast {@link com.hazelcast.map.IMap} to the
 * {@link IMap} interface, keeping Hazelcast types out of generated code.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
class HazelcastMap<K, V> implements IMap<K, V> {

    private final com.hazelcast.map.IMap<K, V> delegate;

    @SuppressWarnings("unused")
    HazelcastMap(com.hazelcast.map.IMap<K, V> delegate) {
        this.delegate = delegate;
    }

    // ========================================================================
    // Basic Operations
    // ========================================================================
    @Override
    public V get(K key) {
        return delegate.get(key);
    }

    @Override
    public V put(K key, V value) {
        return delegate.put(key, value);
    }

    @Override
    public V put(K key, V value, long ttl, TimeUnit ttlUnit) {
        return delegate.put(key, value, ttl, ttlUnit);
    }

    @Override
    public void set(K key, V value) {
        delegate.set(key, value);
    }

    @Override
    public void set(K key, V value, long ttl, TimeUnit ttlUnit) {
        delegate.set(key, value, ttl, ttlUnit);
    }

    @Override
    public V putIfAbsent(K key, V value) {
        return delegate.putIfAbsent(key, value);
    }

    @Override
    public V putIfAbsent(K key, V value, long ttl, TimeUnit ttlUnit) {
        return delegate.putIfAbsent(key, value, ttl, ttlUnit);
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> map) {
        delegate.putAll(map);
    }

    // ========================================================================
    // Remove / Delete
    // ========================================================================
    @Override
    public V remove(K key) {
        return delegate.remove(key);
    }

    @Override
    public boolean remove(K key, V value) {
        return delegate.remove(key, value);
    }

    @Override
    public void delete(K key) {
        delegate.delete(key);
    }

    // ========================================================================
    // Replace
    // ========================================================================
    @Override
    public V replace(K key, V value) {
        return delegate.replace(key, value);
    }

    @Override
    public boolean replace(K key, V oldValue, V newValue) {
        return delegate.replace(key, oldValue, newValue);
    }

    // ========================================================================
    // Query
    // ========================================================================
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
        return delegate.evict(key);
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
        return delegate.tryPut(key, value, timeout, timeUnit);
    }

    @Override
    public boolean tryRemove(K key, long timeout, TimeUnit timeUnit) {
        return delegate.tryRemove(key, timeout, timeUnit);
    }

    // ========================================================================
    // Per-Key Locking
    // ========================================================================
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

    // ========================================================================
    // Async Operations
    // ========================================================================
    @Override
    public CompletionStage<V> getAsync(K key) {
        return delegate.getAsync(key);
    }

    @Override
    public CompletionStage<V> putAsync(K key, V value) {
        return delegate.putAsync(key, value);
    }

    @Override
    public CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
        return delegate.putAsync(key, value, ttl, ttlUnit);
    }

    @Override
    public CompletionStage<Void> setAsync(K key, V value) {
        return delegate.setAsync(key, value);
    }

    @Override
    public CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
        return delegate.setAsync(key, value, ttl, ttlUnit);
    }

    @Override
    public CompletionStage<V> removeAsync(K key) {
        return delegate.removeAsync(key);
    }

    @Override
    public CompletionStage<Boolean> deleteAsync(K key) {
        return delegate.deleteAsync(key);
    }
}
