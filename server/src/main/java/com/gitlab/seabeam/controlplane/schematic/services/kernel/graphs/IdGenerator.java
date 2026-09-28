// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs;

/**
 * Distributed unique ID generator.
 */
@FunctionalInterface
public interface IdGenerator {
	long newId();
}
