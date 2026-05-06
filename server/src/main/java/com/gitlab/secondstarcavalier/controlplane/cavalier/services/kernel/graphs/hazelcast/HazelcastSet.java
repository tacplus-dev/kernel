// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs.ISet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * HazelcastSet adapts a Hazelcast {@link com.hazelcast.collection.ISet}
 * to the {@link ISet} interface, keeping Hazelcast types out of generated code.
 *
 * @param <E> the element type
 */
class HazelcastSet<E> implements ISet<E> {

    private final com.hazelcast.collection.ISet<E> delegate;

    HazelcastSet(com.hazelcast.collection.ISet<E> delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean add(E element) {
        return delegate.add(element);
    }

    @Override
    public boolean remove(E element) {
        return delegate.remove(element);
    }

    @Override
    public boolean contains(E element) {
        return delegate.contains(element);
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
    public Set<E> getAll() {
        return new LinkedHashSet<>(delegate);
    }

    @Override
    public void clear() {
        delegate.clear();
    }
}
