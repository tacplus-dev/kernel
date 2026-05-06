// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs;

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
