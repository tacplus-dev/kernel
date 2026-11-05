// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.fencedlock;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;

/**
 * Ratis's transport runs on the Netty that ratis-thirdparty shades into its own
 * jar, which mvn dependency:tree does not list and an io.netty pin does not
 * move. Its version is visible only in the pom.properties the shaded jar
 * carries, so this reads every copy on the classpath. 4.1.137.Final is the
 * first without CVE-2026-75595 (CRITICAL, #43).
 */
class ShadedNettyVersionTest {

	private static final int[] FLOOR = {4, 1, 137};

	@Test
	void everyNettyHandlerOnTheClasspathIsAtLeastTheFloor() throws Exception {
		List<URL> copies = Collections.list(getClass().getClassLoader()
				.getResources("META-INF/maven/io.netty/netty-handler/pom.properties"));
		assertFalse(copies.isEmpty(), "no netty-handler pom.properties: ratis-thirdparty-misc no longer says its Netty");
		List<String> below = new ArrayList<>();
		for (URL copy : copies) {
			Properties props = new Properties();
			try (InputStream in = copy.openStream()) {
				props.load(in);
			}
			String version = props.getProperty("version");
			if (!atLeastFloor(version)) {
				below.add(version + " in " + copy);
			}
		}
		assertTrue(below.isEmpty(), "netty-handler below 4.1.137.Final: " + below);
	}

	private static boolean atLeastFloor(String version) {
		String[] parts = version.split("\\.");
		for (int i = 0; i < FLOOR.length; i++) {
			int part = Integer.parseInt(parts[i]);
			if (part != FLOOR[i]) {
				return part > FLOOR[i];
			}
		}
		return true;
	}
}
