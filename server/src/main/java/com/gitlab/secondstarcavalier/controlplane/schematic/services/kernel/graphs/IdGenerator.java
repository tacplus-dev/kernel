// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs;

/**
 * Distributed unique ID generator.
 */
@FunctionalInterface
public interface IdGenerator {
	long newId();
}
