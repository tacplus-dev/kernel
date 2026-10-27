// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

import java.util.Set;

/**
 * Distributed set interface.
 *
 * @param <E> the element type
 */
public interface ISet<E> {
	boolean add(E element);
	boolean remove(E element);
	boolean contains(E element);
	int size();
	boolean isEmpty();
	Set<E> getAll();
	void clear();
}
