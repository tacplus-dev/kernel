// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast.BoundaryPersistence;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast.HazelcastManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.scottyagent.Scottyagent;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.scottyagent.ScottyagentMap;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The invariant a rolling restart depends on: a pod's on-disk snapshot must
 * never overwrite state the live cluster already holds.
 *
 * <p>This is the easiest way for durable boundaries to destroy data, and it has
 * two independent guards, one per test below.
 *
 * <ol>
 *   <li>The cold-start gate. {@code ClusterServer} rehydrates only when the pod
 *       booted alone; a pod that joined peers takes their state and never reads
 *       its own file. This is the guard that matters in production, because a
 *       rejoining pod's file is stale by exactly the writes it missed while it
 *       was down.</li>
 *   <li>Put-if-absent on the rehydration path itself, so that even a mistaken
 *       call — a future caller, a reordered boot — cannot clobber a live entry.
 *       The two guards are deliberately redundant: the first is a decision made
 *       once at boot, the second is a property of the write.</li>
 * </ol>
 */
class BoundaryPersistenceRollingRestartTest {

	private final List<HazelcastInstance> instances = new ArrayList<>();
	private BoundaryPersistence persistence;

	@AfterEach
	void tearDown() {
		if (persistence != null) {
			persistence.close();
			persistence = null;
		}
		for (HazelcastInstance hz : instances) {
			hz.shutdown();
		}
		instances.clear();
	}

	private static Scottyagent.AgentCursor cursor(String user, long cycles) {
		return Scottyagent.AgentCursor.newBuilder().setUser(user).setCyclesCompleted(cycles).build();
	}

	/**
	 * The production guard. A node alone is forming the cluster and may load its
	 * snapshot; a node that found peers must not.
	 */
	@Test
	void coldStartIsOnlyTrueWhenNoPeerWasReachable() {
		String cluster = "rolling-restart-test-" + UUID.randomUUID();
		HazelcastInstance first = start(joinableConfig(cluster));
		assertTrue(ClusterServer.isColdStart(first),
				"the first node of a cluster has no peers — it is a cold start and loads its snapshot");

		HazelcastInstance second = start(joinableConfig(cluster));
		assertFalse(ClusterServer.isColdStart(second),
				"a node that joined a live peer must take state from it, not from its own disk");
		assertFalse(ClusterServer.isColdStart(first),
				"and the same is true read from either side of the cluster");
	}

	/**
	 * The regression this guards against: the node's file holds cycles=1 from
	 * before it went down, the cluster has since advanced to cycles=9, and
	 * rehydration must not roll it back.
	 */
	@Test
	void rehydrationNeverOverwritesALiveEntry(@TempDir Path volume) throws Exception {
		// The node writes its snapshot, then goes down.
		persistence = BoundaryPersistence.at(volume.toString());
		HazelcastInstance hz = start(isolatedConfig());
		new ScottyagentMap(new HazelcastManager(hz, persistence)).putCursors("jody", cursor("jody", 1));
		tearDown();

		// It comes back into a cluster that has moved on. The live value is what
		// its peers replicated to it, not anything it read from disk.
		persistence = BoundaryPersistence.at(volume.toString());
		HazelcastInstance rejoined = start(isolatedConfig());
		ScottyagentMap cursors = new ScottyagentMap(new HazelcastManager(rejoined, persistence));
		cursors.putCursors("jody", cursor("jody", 9));
		cursors.putCursors("scotty", cursor("scotty", 4));

		persistence.rehydrate();

		assertEquals(9, cursors.getCursors("jody").getCyclesCompleted(),
				"the stale snapshot must not roll a live entry back");
		assertEquals(4, cursors.getCursors("scotty").getCyclesCompleted(),
				"and must not disturb an entry it has never heard of");
		assertEquals(2, cursors.proto().getCursorsCount());
	}

	private HazelcastInstance start(Config config) {
		HazelcastInstance hz = Hazelcast.newHazelcastInstance(config);
		instances.add(hz);
		return hz;
	}

	/** Two members of one cluster, joining over loopback. */
	private static Config joinableConfig(String clusterName) {
		Config config = baseConfig(clusterName);
		var join = config.getNetworkConfig().getJoin();
		join.getMulticastConfig().setEnabled(false);
		join.getTcpIpConfig().setEnabled(true).addMember("127.0.0.1");
		config.getNetworkConfig().setPort(5710).setPortAutoIncrement(true);
		return config;
	}

	/** A member that cannot form a cluster with anything. */
	private static Config isolatedConfig() {
		Config config = baseConfig("boundary-rolling-isolated-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		return config;
	}

	private static Config baseConfig(String clusterName) {
		Config config = new Config();
		config.setClusterName(clusterName);
		config.setProperty("hazelcast.phone.home.enabled", "false");
		SerializerRegistry.register(config);
		return config;
	}
}
