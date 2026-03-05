// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.elvis.hazelcast;

import java.util.ArrayList;
import java.util.List;

import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IList;

/**
 * HazelcastList adapts a Hazelcast {@link com.hazelcast.collection.IList}
 * to the {@link IList} interface, keeping Hazelcast types out of generated code.
 *
 * @param <E> the element type
 */
class HazelcastList<E> implements IList<E> {

    private final com.hazelcast.collection.IList<E> delegate;

    HazelcastList(com.hazelcast.collection.IList<E> delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean add(E element) {
        return delegate.add(element);
    }

    @Override
    public void add(int index, E element) {
        delegate.add(index, element);
    }

    @Override
    public E get(int index) {
        return delegate.get(index);
    }

    @Override
    public E set(int index, E element) {
        return delegate.set(index, element);
    }

    @Override
    public boolean remove(E element) {
        return delegate.remove(element);
    }

    @Override
    public E remove(int index) {
        return delegate.remove(index);
    }

    @Override
    public boolean contains(E element) {
        return delegate.contains(element);
    }

    @Override
    public int indexOf(E element) {
        return delegate.indexOf(element);
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
    public List<E> getAll() {
        return new ArrayList<>(delegate);
    }

    @Override
    public void clear() {
        delegate.clear();
    }
}
