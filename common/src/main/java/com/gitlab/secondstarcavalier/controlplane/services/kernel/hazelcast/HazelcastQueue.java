// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast;

import java.util.Collection;
import java.util.concurrent.TimeUnit;

import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.IQueue;

/**
 * HazelcastQueue adapts a Hazelcast {@link com.hazelcast.collection.IQueue}
 * to the {@link IQueue} interface, keeping Hazelcast types out of generated code.
 *
 * @param <E> the element type
 */
class HazelcastQueue<E> implements IQueue<E> {

    private final com.hazelcast.collection.IQueue<E> delegate;

    HazelcastQueue(com.hazelcast.collection.IQueue<E> delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean offer(E element) {
        return delegate.offer(element);
    }

    @Override
    public boolean offer(E element, long timeout, TimeUnit unit) throws InterruptedException {
        return delegate.offer(element, timeout, unit);
    }

    @Override
    public E poll() {
        return delegate.poll();
    }

    @Override
    public E poll(long timeout, TimeUnit unit) throws InterruptedException {
        return delegate.poll(timeout, unit);
    }

    @Override
    public void put(E element) throws InterruptedException {
        delegate.put(element);
    }

    @Override
    public E take() throws InterruptedException {
        return delegate.take();
    }

    @Override
    public E peek() {
        return delegate.peek();
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
    public boolean contains(E element) {
        return delegate.contains(element);
    }

    @Override
    public int remainingCapacity() {
        return delegate.remainingCapacity();
    }

    @Override
    public int drainTo(Collection<? super E> collection) {
        return delegate.drainTo(collection);
    }

    @Override
    public int drainTo(Collection<? super E> collection, int maxElements) {
        return delegate.drainTo(collection, maxElements);
    }

    @Override
    public void clear() {
        delegate.clear();
    }
}
