// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.MultiMap;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;

/**
 * HazelcastMultiMap adapts a Hazelcast {@link com.hazelcast.multimap.MultiMap}
 * to the {@link MultiMap} interface, keeping Hazelcast types out of generated
 * code.
 *
 * @param <K> the key type
 * @param <V> the value type
 */
class HazelcastMultiMap<K, V> implements MultiMap<K, V> {

	private final com.hazelcast.multimap.MultiMap<K, V> delegate;

	HazelcastMultiMap(com.hazelcast.multimap.MultiMap<K, V> delegate) {
		this.delegate = Objects.requireNonNull(delegate, "delegate");
	}

	@Override
	public boolean put(K key, V value) {
		return delegate.put(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public Collection<V> get(K key) {
		return delegate.get(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean remove(K key, V value) {
		return delegate.remove(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
	}

	@Override
	public Collection<V> remove(K key) {
		return delegate.remove(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean containsKey(K key) {
		return delegate.containsKey(Objects.requireNonNull(key, "key"));
	}

	@Override
	public boolean containsValue(V value) {
		return delegate.containsValue(Objects.requireNonNull(value, "value"));
	}

	@Override
	public boolean containsEntry(K key, V value) {
		return delegate.containsEntry(Objects.requireNonNull(key, "key"), Objects.requireNonNull(value, "value"));
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
	public int valueCount(K key) {
		return delegate.valueCount(Objects.requireNonNull(key, "key"));
	}

	@Override
	public int size() {
		return delegate.size();
	}

	@Override
	public void clear() {
		delegate.clear();
	}
}
