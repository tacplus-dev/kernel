// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel;

/**
 * Single entry point for the kernel. Mode (CORE, EDGE, CORE_EDGE) is
 * determined at runtime from the bootstrap config.
 */
public class Main {

	public static void main(String[] args) throws Exception {
		Bootstrap.run(args);
	}
}
