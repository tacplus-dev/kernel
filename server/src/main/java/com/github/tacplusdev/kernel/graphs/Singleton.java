// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

/**
 * Marker interface for singleton distributed objects.
 * Singletons are stored in IMaps under a well-known key.
 */
public interface Singleton {
	String SINGLETON_KEY = "SINGLETON";
}
