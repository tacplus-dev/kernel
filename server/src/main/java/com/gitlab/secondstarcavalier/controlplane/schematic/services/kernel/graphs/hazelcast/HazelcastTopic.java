// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.ITopic;
import java.util.function.Consumer;

/**
 * HazelcastTopic adapts a Hazelcast {@link com.hazelcast.topic.ITopic}
 * to the {@link ITopic} interface, keeping Hazelcast types out of generated
 * code.
 *
 * @param <E> the message type
 */
class HazelcastTopic<E> implements ITopic<E> {

	private final com.hazelcast.topic.ITopic<E> delegate;

	HazelcastTopic(com.hazelcast.topic.ITopic<E> delegate) {
		this.delegate = delegate;
	}

	@Override
	public void publish(E message) {
		delegate.publish(java.util.Objects.requireNonNull(message));
	}

	@Override
	public String addMessageListener(Consumer<E> listener) {
		java.util.UUID id = delegate.addMessageListener(message -> listener.accept(message.getMessageObject()));
		return id.toString();
	}

	@Override
	public boolean removeMessageListener(String subscriptionId) {
		java.util.UUID id = java.util.UUID.fromString(subscriptionId);
		return delegate.removeMessageListener(java.util.Objects.requireNonNull(id));
	}
}
