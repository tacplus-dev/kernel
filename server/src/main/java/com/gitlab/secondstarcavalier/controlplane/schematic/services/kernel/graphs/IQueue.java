// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs;

import java.util.Collection;
import java.util.concurrent.TimeUnit;

/**
 * Distributed queue interface.
 *
 * @param <E> the element type
 */
public interface IQueue<E> {
	boolean offer(E element);
	boolean offer(E element, long timeout, TimeUnit unit) throws InterruptedException;
	E poll();
	E poll(long timeout, TimeUnit unit) throws InterruptedException;
	void put(E element) throws InterruptedException;
	E take() throws InterruptedException;
	E peek();
	int size();
	boolean isEmpty();
	boolean contains(E element);
	int remainingCapacity();
	int drainTo(Collection<? super E> collection);
	int drainTo(Collection<? super E> collection, int maxElements);
	void clear();
}
