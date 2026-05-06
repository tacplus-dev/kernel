// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.graphs;

import java.util.function.Consumer;

/**
 * Distributed topic (pub/sub) interface.
 *
 * @param <E> the message type
 */
public interface ITopic<E> {
	void publish(E message);
	String addMessageListener(Consumer<E> listener);
	boolean removeMessageListener(String subscriptionId);
}
