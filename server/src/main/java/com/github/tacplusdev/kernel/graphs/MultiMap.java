// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

import java.util.Collection;
import java.util.Set;

/**
 * Distributed multi-map interface (one key to many values).
 *
 * @param <K> the key type
 * @param <V> the value type
 */
public interface MultiMap<K, V> {
	boolean put(K key, V value);
	Collection<V> get(K key);
	boolean remove(K key, V value);
	Collection<V> remove(K key);
	boolean containsKey(K key);
	boolean containsValue(V value);
	boolean containsEntry(K key, V value);
	Set<K> keySet();
	Collection<V> values();
	int valueCount(K key);
	int size();
	void clear();
}
