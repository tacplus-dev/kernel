// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.hazelcast.HazelcastManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.host.HostOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ClusterMap;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code has_quorum} must compare the reachable member count against a majority of
 * the cluster's <em>configured</em> member count. The node under test is a real
 * single-node Hazelcast instance, so it always sees exactly one live member — the
 * minority-partition case.
 */
class ClusterStateQuorumTest {

	private HazelcastInstance hazelcast;

	@AfterEach
	void tearDown() {
		if (hazelcast != null) {
			hazelcast.shutdown();
		}
	}

	@Test
	void minorityPartitionReportsNoQuorum() {
		assertFalse(publishHealth(3).getHasQuorum(),
				"1 of 3 configured members reachable must not report quorum");
	}

	@Test
	void majorityPartitionReportsQuorum() {
		assertTrue(publishHealth(1).getHasQuorum(),
				"the only configured member being reachable is a majority");
	}

	private com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast.AdminClusterHealth publishHealth(
			int configuredMembers) {
		hazelcast = Hazelcast.newHazelcastInstance(hazelcastConfig());
		ClusterMap clusterMap = new ClusterMap(new HazelcastManager(hazelcast));

		Kernel.Config.Builder config = Kernel.Config.newBuilder();
		for (int i = 0; i < configuredMembers; i++) {
			config.addMembers(HostOuterClass.Host.newBuilder().setHost("node-" + i));
		}

		new ClusterStatePublisher(hazelcast, clusterMap, null, config.build(), 0, null, null, null)
				.publishClusterHealth();

		return clusterMap.getClusterHealth();
	}

	private static Config hazelcastConfig() {
		Config config = new Config();
		config.setClusterName("cluster-state-quorum-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		SerializerRegistry.register(config);
		return config;
	}
}
