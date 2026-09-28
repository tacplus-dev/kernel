// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

/**
 * Marker interface for singleton distributed objects.
 * Singletons are stored in IMaps under a well-known key.
 */
public interface Singleton {
	String SINGLETON_KEY = "SINGLETON";
}
