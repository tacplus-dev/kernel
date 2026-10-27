// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.hazelcast.cluster.Member;
import com.hazelcast.config.Config;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.partition.Partition;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Real Hazelcast members on loopback ports, for tests that need more than one. */
final class HazelcastTestMembers {

	private HazelcastTestMembers() {
	}

	static int freePort() throws IOException {
		try (ServerSocket socket = new ServerSocket(0)) {
			return socket.getLocalPort();
		}
	}

	/** A member on {@code port} that joins {@code memberPorts} over TCP, with kernel's serializers. */
	static Config hazelcastConfig(String cluster, int port, int[] memberPorts) {
		Config config = new Config();
		config.setClusterName(cluster);
		config.getNetworkConfig().setPort(port).setPortAutoIncrement(false);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(true);
		for (int p : memberPorts) {
			config.getNetworkConfig().getJoin().getTcpIpConfig().addMember("127.0.0.1:" + p);
		}
		SerializerRegistry.register(config);
		return config;
	}

	/**
	 * Waits until every member owns partitions and no migration is pending. A
	 * member that joins after the partition table exists gets its share by an
	 * asynchronous migration, so without this a test can start while one member
	 * still owns every key.
	 */
	static void awaitPartitionsOnEveryMember(List<HazelcastInstance> members) throws InterruptedException {
		long deadline = System.nanoTime() + 30_000_000_000L;
		while (System.nanoTime() < deadline) {
			Set<Member> owners = new HashSet<>();
			for (Partition partition : members.get(0).getPartitionService().getPartitions()) {
				owners.add(partition.getOwner());
			}
			if (owners.size() == members.size() && members.get(0).getPartitionService().isClusterSafe()) {
				return;
			}
			Thread.sleep(50);
		}
		throw new AssertionError("partitions never spread across all " + members.size() + " members");
	}
}
