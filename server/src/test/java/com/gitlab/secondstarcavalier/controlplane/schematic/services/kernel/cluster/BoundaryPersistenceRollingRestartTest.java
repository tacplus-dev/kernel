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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
 * two independent guards, one per test below. A third test covers the matching
 * WRITE-side obligation: a pod that took its state from peers has to put that
 * state on its own disk, or the rows nobody writes again are durable on no pod
 * at all.
 *
 * <ol>
 *   <li>The cold-start gate. {@code ClusterServer} rehydrates only when no peer
 *       of this cluster BEARS state; a pod that joined a state-bearing peer
 *       takes that peer's state and never reads its own file. This is the guard
 *       that matters in production, because a rejoining pod's file is stale by
 *       exactly the writes it missed while it was down.</li>
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
	 * The production guard, in its staggered form: a node alone is forming the
	 * cluster and may load its snapshot; a node that found a peer BEARING STATE
	 * must not.
	 *
	 * <p>What the second node reads is the peer's entry in {@code
	 * StateBearingLedger}, not the member count — a count could only ever say
	 * "someone else is there", which is a different fact and the one that made
	 * the simultaneous start destroy data. The simultaneous case is
	 * {@link BoundaryPersistenceSimultaneousStartTest}.
	 *
	 * <p>The decision is taken ONCE per boot and each node here takes it once:
	 * re-asking would file a fresh boot entry for a member that has already
	 * settled, which no pod does.
	 */
	@Test
	void coldStartIsOnlyTrueWhenNoPeerBearsState() {
		String cluster = "rolling-restart-test-" + UUID.randomUUID();
		BoundaryPersistence noVolume = BoundaryPersistence.disabled();

		HazelcastInstance first = start(joinableConfig(cluster, 0));
		assertTrue(ClusterServer.isColdStart(first, noVolume),
				"the first node of a cluster has no state-bearing peer — it is a cold start and loads its snapshot");
		// What a pod does next: it replayed real rows, so it says so.
		StateBearingLedger.settle(first, true);

		HazelcastInstance second = start(joinableConfig(cluster, 1));
		assertFalse(ClusterServer.isColdStart(second, noVolume),
				"a node that joined a peer bearing state must take state from it, not from its own disk");
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

	/**
	 * The gap the join snapshot closes. A pod that joined a live cluster holds
	 * every row in memory and NONE of them on its own disk: only a subsequent
	 * mutation writes one. After a rolling restart every pod is in that state,
	 * so the next simultaneous cold start loses exactly the rows that are quiet
	 * — which, for durable state, is most of them.
	 *
	 * <p>The fixture writes into the map directly, the way replication delivers
	 * a row: no mutation goes through the persistent wrapper, so nothing has
	 * appended anything. That is precisely the pod this is about.
	 */
	@Test
	void aPodThatJoinedPeersWritesEveryBoundaryToItsOwnDisk(@TempDir Path volume) throws Exception {
		persistence = BoundaryPersistence.at(volume.toString());
		HazelcastInstance hz = start(isolatedConfig());
		HazelcastManager manager = new HazelcastManager(hz, persistence);
		new ScottyagentMap(manager);

		String mapName = persistence.files().keySet().stream()
				.filter(n -> n.endsWith(":services.scottyagent.Scottyagent.Cursors"))
				.findFirst()
				.orElseThrow();
		Path log = persistence.files().get(mapName);

		// Rows arrive from peers, not through any write this pod served.
		com.hazelcast.map.IMap<String, com.google.protobuf.Message> raw = hz.getMap(mapName);
		for (int i = 0; i < 5; i++) {
			raw.put("user-" + i, cursor("user-" + i, i));
		}
		assertEquals(0, Files.exists(log) ? Files.size(log) : 0,
				"nothing this pod did was a write, so its disk holds nothing yet");

		persistence.checkpointAll("test: joined a live cluster");

		long deadline = System.currentTimeMillis() + 30_000;
		while (System.currentTimeMillis() < deadline && countLines(log) < 5) {
			Thread.sleep(50);
		}
		assertEquals(5, countLines(log), "every row of every boundary, on this pod's own volume");

		// And it is a real recovery set, not just bytes: a cold start off this
		// volume alone brings all five back.
		tearDown();
		persistence = BoundaryPersistence.at(volume.toString());
		HazelcastInstance cold = start(isolatedConfig());
		ScottyagentMap after = new ScottyagentMap(new HazelcastManager(cold, persistence));
		persistence.rehydrate();
		assertEquals(5, after.proto().getCursorsCount());
		assertEquals(3, after.getCursors("user-3").getCyclesCompleted());
	}

	private static long countLines(Path p) throws Exception {
		if (!Files.exists(p)) {
			return 0;
		}
		return Files.readAllLines(p, StandardCharsets.UTF_8).stream().filter(l -> !l.isBlank()).count();
	}

	private HazelcastInstance start(Config config) {
		HazelcastInstance hz = Hazelcast.newHazelcastInstance(config);
		instances.add(hz);
		return hz;
	}

	/** Two members of one cluster, joining over loopback. */
	private static Config joinableConfig(String clusterName, int ordinal) {
		Config config = baseConfig(clusterName);
		StateBearingLedger.publishOrdinal(config, ordinal);
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
		StateBearingLedger.configure(config);
		SerializerRegistry.register(config);
		return config;
	}
}
