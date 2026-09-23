// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast.BoundaryPersistence;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast.HazelcastManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.eventbus.Eventbus;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.scottyagent.Scottyagent;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.host.HostOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.eventbus.EventbusMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.scottyagent.ScottyagentMap;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The contract of {@code (spec.persistence)}, end to end, over a cold restart
 * of the whole cluster.
 *
 * <p>The fixture is two real fleet boundaries rather than a synthetic proto, so
 * the test exercises the generated path a service actually writes through:
 * <ul>
 *   <li>{@code scottyagent.Scottyagent.cursors} is declared
 *       {@code (spec.persistence) = true} — an app boundary, not one of
 *       kernel's own, which is exactly the case that used to be a no-op;</li>
 *   <li>{@code eventbus.Eventbus.nodes} is declared without the flag and must
 *       stay ephemeral, so the test also proves persistence did not quietly
 *       become universal.</li>
 * </ul>
 *
 * <p>A cold restart is modelled the way a node-pool rotation produces one:
 * every Hazelcast member is shut down, taking all in-memory state with it, and
 * a fresh member comes up alone against the same volume.
 */
class BoundaryPersistenceColdRestartTest {

	private HazelcastInstance hazelcast;
	private BoundaryPersistence persistence;

	@AfterEach
	void tearDown() {
		if (persistence != null) {
			persistence.close();
			persistence = null;
		}
		if (hazelcast != null) {
			hazelcast.shutdown();
			hazelcast = null;
		}
	}

	/** One node of a cluster, sharing nothing but the on-disk volume. */
	private HazelcastManager boot(Path volume) {
		persistence = BoundaryPersistence.at(volume.toString());
		hazelcast = Hazelcast.newHazelcastInstance(isolatedConfig());
		return new HazelcastManager(hazelcast, persistence);
	}

	private static Scottyagent.AgentCursor cursor(String user, long cycles) {
		return Scottyagent.AgentCursor.newBuilder()
				.setUser(user)
				.setCyclesCompleted(cycles)
				.build();
	}

	private static Eventbus.EventbusNode node(int id) {
		return Eventbus.EventbusNode.newBuilder()
				.setNodeId(id)
				.setRole(Eventbus.KafkaNodeRole.KAFKA_ROLE_BROKER)
				.setEndpoint(HostOuterClass.Host.newBuilder().setHost("eventbus-" + id + ".svc.cluster.local").setPort(9093))
				.build();
	}

	/**
	 * The whole point of the feature: a flagged boundary from a service OTHER
	 * than kernel survives losing every member at once, and an unflagged one
	 * does not.
	 */
	@Test
	void flaggedBoundarySurvivesAColdRestartAndUnflaggedDoesNot(@TempDir Path volume) throws Exception {
		HazelcastManager first = boot(volume);
		ScottyagentMap cursors = new ScottyagentMap(first);
		EventbusMap nodes = new EventbusMap(first);

		cursors.putCursors("jody", cursor("jody", 7));
		cursors.putCursors("scotty", cursor("scotty", 2));
		nodes.putNodes("0", node(0));

		// Every member gone: the entire cluster's memory is lost, which is what
		// a simultaneous restart of all three kernel pods does.
		tearDown();

		HazelcastManager second = boot(volume);
		ScottyagentMap cursorsAfter = new ScottyagentMap(second);
		EventbusMap nodesAfter = new EventbusMap(second);
		assertEquals(0, cursorsAfter.proto().getCursorsCount(), "a fresh member starts empty before replay");

		persistence.rehydrate();

		assertEquals(2, cursorsAfter.proto().getCursorsCount(), "the flagged boundary is restored");
		assertEquals(7, cursorsAfter.getCursors("jody").getCyclesCompleted());
		assertEquals(2, cursorsAfter.getCursors("scotty").getCyclesCompleted());
		assertEquals(0, nodesAfter.proto().getNodesCount(),
				"an unflagged boundary is ephemeral and must NOT come back");
	}

	/** A delete is persisted too: the restored boundary is the live set, not a union of everything ever written. */
	@Test
	void deletesSurviveAColdRestart(@TempDir Path volume) throws Exception {
		HazelcastManager first = boot(volume);
		ScottyagentMap cursors = new ScottyagentMap(first);
		cursors.putCursors("jody", cursor("jody", 1));
		cursors.putCursors("scotty", cursor("scotty", 1));
		cursors.deleteCursors("scotty");
		tearDown();

		HazelcastManager second = boot(volume);
		ScottyagentMap after = new ScottyagentMap(second);
		persistence.rehydrate();

		assertEquals(1, after.proto().getCursorsCount());
		assertEquals("jody", after.getCursors("jody").getUser());
	}

	/** One log per boundary, on the kernel volume — not one blob for the whole fleet. */
	@Test
	void eachFlaggedBoundaryGetsItsOwnFile(@TempDir Path volume) throws Exception {
		HazelcastManager manager = boot(volume);
		new ScottyagentMap(manager).putCursors("jody", cursor("jody", 1));
		new EventbusMap(manager).putNodes("0", node(0));

		Path dir = volume.resolve("_root").resolve("boundaries");
		assertTrue(Files.isDirectory(dir), "boundary logs live under <volume>/_root/boundaries");
		try (var files = Files.list(dir)) {
			var names = files.map(p -> p.getFileName().toString())
					.filter(n -> n.endsWith(".log"))
					.toList();
			assertEquals(1, names.size(), "only the flagged boundary is written: " + names);
			assertTrue(names.get(0).contains("Scottyagent.Cursors"), names.get(0));
		}
		assertNotNull(persistence.files().keySet().stream()
				.filter(n -> n.endsWith(":services.scottyagent.Scottyagent.Cursors"))
				.findFirst()
				.orElse(null));
	}

	/** A boundary log that exists but cannot be parsed refuses the boot. */
	@Test
	void unreadableBoundaryFileFailsClosed(@TempDir Path volume) throws Exception {
		HazelcastManager first = boot(volume);
		new ScottyagentMap(first).putCursors("jody", cursor("jody", 1));
		Path file = persistence.files().values().iterator().next();
		tearDown();

		// A complete line — a torn FINAL line is a crash mid-append and is
		// recovered, not refused (see BoundaryPersistenceRedoLogTest).
		Files.write(file, new byte[] { 0x42, 0x42, 0x42, 0x42, '\n' });

		HazelcastManager second = boot(volume);
		new ScottyagentMap(second);
		org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class, () -> persistence.rehydrate(),
				"a present-but-corrupt boundary log must stop the boot, not come up empty");
	}

	private static Config isolatedConfig() {
		Config config = new Config();
		config.setClusterName("boundary-persistence-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.setProperty("hazelcast.phone.home.enabled", "false");
		SerializerRegistry.register(config);
		return config;
	}
}
