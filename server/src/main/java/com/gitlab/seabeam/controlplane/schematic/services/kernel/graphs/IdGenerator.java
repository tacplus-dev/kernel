// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

/**
 * Distributed unique ID generator.
 */
@FunctionalInterface
public interface IdGenerator {
	long newId();
}
