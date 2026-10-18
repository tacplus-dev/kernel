// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

/**
 * Marker interface for singleton distributed objects.
 * Singletons are stored in IMaps under a well-known key.
 */
public interface Singleton {
	String SINGLETON_KEY = "SINGLETON";
}
