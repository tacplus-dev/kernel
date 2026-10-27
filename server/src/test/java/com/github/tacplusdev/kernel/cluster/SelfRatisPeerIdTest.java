// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.types.sys.host.HostOuterClass;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A kernel pod must know which FencedLock Raft peer it is even while DNS for
 * its own member name still points at the pod it replaced. On a rolling
 * restart kube-dns serves the old pod IP for up to its cache TTL; resolving
 * {@code kernel-1.kernel} then finds no local address and the pod exited 1
 * once, every restart. The member hosts below do not resolve to this machine,
 * which is exactly that window.
 */
class SelfRatisPeerIdTest {

	private static final List<HostOuterClass.Host> STATEFULSET_MEMBERS = members(
			"kernel-0.kernel", "kernel-1.kernel", "kernel-2.kernel");

	@Test
	void statefulSetPodIsItsMemberWhileDnsStillNamesTheReplacedPod() {
		assertEquals("kernel-1.kernel:5002",
				ClusterServer.selfRatisPeerId(STATEFULSET_MEMBERS, 5002, "kernel-1").toString());
	}

	@Test
	void hostnameMatchesWholeFirstLabelOnly() {
		assertEquals("kernel-1.kernel:5002",
				ClusterServer.selfRatisPeerId(members("kernel-10.kernel", "kernel-1.kernel"), 5002, "kernel-1")
						.toString());
	}

	@Test
	void withoutAHostnameMatchALocalAddressStillIdentifiesTheNode() {
		assertEquals("127.0.0.1:5002",
				ClusterServer.selfRatisPeerId(members("192.0.2.10", "127.0.0.1"), 5002, "").toString());
	}

	@Test
	void noMatchingNameOrAddressStillRefusesToStart() {
		assertThrows(IllegalStateException.class,
				() -> ClusterServer.selfRatisPeerId(members("192.0.2.10", "192.0.2.11"), 5002, "kernel-1"));
	}

	private static List<HostOuterClass.Host> members(String... hosts) {
		return java.util.Arrays.stream(hosts)
				.map(h -> HostOuterClass.Host.newBuilder().setHost(h).build())
				.toList();
	}
}
