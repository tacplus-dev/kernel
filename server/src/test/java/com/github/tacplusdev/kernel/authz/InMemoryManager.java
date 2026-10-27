// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.authz;

import com.github.tacplusdev.kernel.graphs.IList;
import com.github.tacplusdev.kernel.graphs.IMap;
import com.github.tacplusdev.kernel.graphs.IPriorityQueue;
import com.github.tacplusdev.kernel.graphs.IQueue;
import com.github.tacplusdev.kernel.graphs.ISet;
import com.github.tacplusdev.kernel.graphs.ITopic;
import com.github.tacplusdev.kernel.graphs.IdGenerator;
import com.github.tacplusdev.kernel.graphs.Lock;
import com.github.tacplusdev.kernel.graphs.Manager;
import com.github.tacplusdev.kernel.graphs.MultiMap;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Single-JVM {@link Manager} backed by {@link ConcurrentHashMap}, so a generated
 * state-service server can be stood up in a test without a Hazelcast cluster.
 * Only the map factories are implemented — the generated state servers use
 * nothing else, and anything they might grow into should fail loudly rather than
 * silently do nothing.
 */
public final class InMemoryManager implements Manager {

	private final Map<String, IMap<?, ?>> maps = new ConcurrentHashMap<>();

	@SuppressWarnings("unchecked")
	private <K, V> IMap<K, V> map(String name) {
		return (IMap<K, V>) maps.computeIfAbsent(name, n -> new InMemoryMap<>());
	}

	@Override
	public <K, V> IMap<K, V> getConvergentMap(String name) {
		return map(name);
	}

	@Override
	public <K, V> IMap<K, V> getReplicatedMap(String name) {
		return map(name);
	}

	@Override
	public <K, V> IMap<K, V> getVolatileMap(String name) {
		return map(name);
	}

	@Override
	public <K, V> MultiMap<K, V> getMultiMap(String name) {
		throw new UnsupportedOperationException("multimaps are not used by state servers");
	}

	@Override
	public <E> IList<E> getList(String name) {
		throw new UnsupportedOperationException("lists are not used by state servers");
	}

	@Override
	public <E> ISet<E> getSet(String name) {
		throw new UnsupportedOperationException("sets are not used by state servers");
	}

	@Override
	public <E> IQueue<E> getQueue(String name) {
		throw new UnsupportedOperationException("queues are not used by this test");
	}

	@Override
	public <E> ITopic<E> getTopic(String name) {
		throw new UnsupportedOperationException("topics are not used by this test");
	}

	@Override
	public <E> IPriorityQueue<E> getPriorityQueue(String name) {
		throw new UnsupportedOperationException("priority queues are not used by this test");
	}

	@Override
	public IdGenerator getIdGenerator(String name) {
		throw new UnsupportedOperationException("id generators are not used by state servers");
	}

	@Override
	public Lock getLock(String name) {
		throw new UnsupportedOperationException("locks are not used by state servers");
	}

	/** TTLs are ignored and per-key locks are no-ops, as they are in HazelcastManager. */
	private static final class InMemoryMap<K, V> implements IMap<K, V> {

		private final ConcurrentHashMap<K, V> delegate = new ConcurrentHashMap<>();

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
			return delegate.put(key, value);
		}

		@Override
		public void set(K key, V value) {
			delegate.put(key, value);
		}

		@Override
		public void set(K key, V value, long ttl, TimeUnit ttlUnit) {
			delegate.put(key, value);
		}

		@Override
		public V putIfAbsent(K key, V value) {
			return delegate.putIfAbsent(key, value);
		}

		@Override
		public V putIfAbsent(K key, V value, long ttl, TimeUnit ttlUnit) {
			return delegate.putIfAbsent(key, value);
		}

		@Override
		public void putAll(Map<? extends K, ? extends V> map) {
			delegate.putAll(map);
		}

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
			delegate.remove(key);
		}

		@Override
		public V replace(K key, V value) {
			return delegate.replace(key, value);
		}

		@Override
		public boolean replace(K key, V oldValue, V newValue) {
			return delegate.replace(key, oldValue, newValue);
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
			Map<K, V> out = new java.util.HashMap<>();
			for (K key : keys) {
				V value = delegate.get(key);
				if (value != null) {
					out.put(key, value);
				}
			}
			return out;
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
		public void clear() {
			delegate.clear();
		}

		@Override
		public boolean evict(K key) {
			return delegate.remove(key) != null;
		}

		@Override
		public void evictAll() {
			delegate.clear();
		}

		@Override
		public boolean tryPut(K key, V value, long timeout, TimeUnit timeUnit) {
			delegate.put(key, value);
			return true;
		}

		@Override
		public boolean tryRemove(K key, long timeout, TimeUnit timeUnit) {
			return delegate.remove(key) != null;
		}

		@Override
		public void lock(K key) {
		}

		@Override
		public void lock(K key, long leaseTime, TimeUnit timeUnit) {
		}

		@Override
		public void unlock(K key) {
		}

		@Override
		public boolean tryLock(K key) {
			return true;
		}

		@Override
		public boolean tryLock(K key, long time, TimeUnit timeUnit) {
			return true;
		}

		@Override
		public boolean tryLock(K key, long time, TimeUnit timeUnit, long leaseTime, TimeUnit leaseTimeUnit) {
			return true;
		}

		@Override
		public boolean isLocked(K key) {
			return false;
		}

		@Override
		public void forceUnlock(K key) {
		}

		@Override
		public CompletionStage<V> getAsync(K key) {
			return CompletableFuture.completedFuture(delegate.get(key));
		}

		@Override
		public CompletionStage<V> putAsync(K key, V value) {
			return CompletableFuture.completedFuture(delegate.put(key, value));
		}

		@Override
		public CompletionStage<V> putAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
			return CompletableFuture.completedFuture(delegate.put(key, value));
		}

		@Override
		public CompletionStage<Void> setAsync(K key, V value) {
			delegate.put(key, value);
			return CompletableFuture.completedFuture(null);
		}

		@Override
		public CompletionStage<Void> setAsync(K key, V value, long ttl, TimeUnit ttlUnit) {
			delegate.put(key, value);
			return CompletableFuture.completedFuture(null);
		}

		@Override
		public CompletionStage<V> removeAsync(K key) {
			return CompletableFuture.completedFuture(delegate.remove(key));
		}

		@Override
		public CompletionStage<Boolean> deleteAsync(K key) {
			return CompletableFuture.completedFuture(delegate.remove(key) != null);
		}
	}
}
