// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

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
