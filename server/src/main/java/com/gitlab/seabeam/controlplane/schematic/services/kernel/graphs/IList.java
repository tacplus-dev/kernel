// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

import java.util.List;

/**
 * Distributed list interface.
 *
 * @param <E> the element type
 */
public interface IList<E> {
	boolean add(E element);
	void add(int index, E element);
	E get(int index);
	E set(int index, E element);
	boolean remove(E element);
	E remove(int index);
	boolean contains(E element);
	int indexOf(E element);
	int size();
	boolean isEmpty();
	List<E> getAll();
	void clear();
}
