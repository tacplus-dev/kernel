// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

/**
 * Distributed priority queue interface.
 *
 * @param <E> the element type
 */
public interface IPriorityQueue<E> {
	boolean offer(E element);
	E poll();
	E peek();
	int size();
	boolean isEmpty();
	void clear();
}
