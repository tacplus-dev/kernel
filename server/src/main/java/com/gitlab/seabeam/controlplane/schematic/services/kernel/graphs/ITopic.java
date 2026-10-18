// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

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
