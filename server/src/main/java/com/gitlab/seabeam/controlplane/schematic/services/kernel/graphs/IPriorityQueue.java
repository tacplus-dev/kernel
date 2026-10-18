// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

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
