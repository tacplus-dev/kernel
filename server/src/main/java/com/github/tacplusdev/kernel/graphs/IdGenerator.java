// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.graphs;

/**
 * Distributed unique ID generator.
 */
@FunctionalInterface
public interface IdGenerator {
	long newId();
}
