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
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The shape of the boundary's on-disk file: an append-only redo log that a
 * checkpoint periodically coalesces, NOT a rewrite of the whole boundary inside
 * every mutation.
 *
 * <p>This is the property the flagged set's declared maxima depend on. A
 * rewrite-per-mutation store costs O(rows) per write, so a boundary declared in
 * the millions cannot be written to at all; an append costs O(1) whatever the
 * boundary holds. The tests below assert that directly, in the file, rather
 * than asserting a latency number that a fast disk would hide.
 */
class BoundaryPersistenceRedoLogTest {

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

	private HazelcastManager boot(Path volume) {
		persistence = BoundaryPersistence.at(volume.toString());
		hazelcast = Hazelcast.newHazelcastInstance(isolatedConfig());
		return new HazelcastManager(hazelcast, persistence);
	}

	private static Scottyagent.AgentCursor cursor(String user, long cycles) {
		return Scottyagent.AgentCursor.newBuilder().setUser(user).setCyclesCompleted(cycles).build();
	}

	/** The one boundary this fixture writes, as a file on the volume. */
	private Path log() {
		return persistence.files().entrySet().stream()
				.filter(e -> e.getKey().endsWith(":services.scottyagent.Scottyagent.Cursors"))
				.map(java.util.Map.Entry::getValue)
				.findFirst()
				.orElseThrow();
	}

	private static List<String> lines(Path p) throws Exception {
		return Files.readAllLines(p, StandardCharsets.UTF_8).stream().filter(l -> !l.isBlank()).toList();
	}

	/**
	 * The core of the correction: N writes append N records. Under the rewrite
	 * shape this file replaced, the Nth write re-serialized all N rows, so the
	 * bytes written across the run grew with N squared — this asserts the
	 * linear shape that replaced it.
	 */
	@Test
	void everyWriteAppendsExactlyOneRecord(@TempDir Path volume) throws Exception {
		ScottyagentMap cursors = new ScottyagentMap(boot(volume));
		for (int i = 0; i < 50; i++) {
			cursors.putCursors("user-" + i, cursor("user-" + i, i));
		}
		assertEquals(50, lines(log()).size(), "50 writes, 50 records — one append each");

		// And a rewrite of one existing key is still one record, not a
		// re-serialization of the 50 rows already there.
		long before = Files.size(log());
		cursors.putCursors("user-7", cursor("user-7", 700));
		assertEquals(51, lines(log()).size());
		assertTrue(Files.size(log()) - before < before / 10,
				"one more write must cost roughly one record, not the whole boundary");
	}

	/** A delete appends a tombstone; it does not rewrite the surviving rows. */
	@Test
	void aDeleteAppendsOneTombstone(@TempDir Path volume) throws Exception {
		ScottyagentMap cursors = new ScottyagentMap(boot(volume));
		cursors.putCursors("jody", cursor("jody", 1));
		cursors.putCursors("scotty", cursor("scotty", 1));
		cursors.deleteCursors("scotty");
		assertEquals(3, lines(log()).size(), "two writes and a delete are three records");
		assertTrue(lines(log()).get(2).contains("\"deleted\":true"), lines(log()).get(2));
	}

	/**
	 * A checkpoint coalesces the history down to current state and truncates it.
	 * This is the one place the boundary file IS rewritten, and it is what keeps
	 * the log from growing without bound.
	 */
	@Test
	void checkpointCoalescesAndTruncates(@TempDir Path volume) throws Exception {
		HazelcastManager manager = boot(volume);
		ScottyagentMap cursors = new ScottyagentMap(manager);
		for (int i = 1; i <= 20; i++) {
			cursors.putCursors("jody", cursor("jody", i));
		}
		cursors.putCursors("scotty", cursor("scotty", 1));
		cursors.deleteCursors("scotty");
		assertEquals(22, lines(log()).size());

		String mapName = persistence.files().keySet().stream()
				.filter(n -> n.endsWith(":services.scottyagent.Scottyagent.Cursors"))
				.findFirst()
				.orElseThrow();
		assertEquals(1, persistence.checkpoint(mapName), "one surviving row");
		assertEquals(1, lines(log()).size(), "the log is now exactly the live state");

		// And it is the RIGHT state: the last value of the live key, and no
		// resurrection of the deleted one.
		tearDown();
		HazelcastManager second = boot(volume);
		ScottyagentMap after = new ScottyagentMap(second);
		persistence.rehydrate();
		assertEquals(1, after.proto().getCursorsCount());
		assertEquals(20, after.getCursors("jody").getCyclesCompleted());
	}

	/**
	 * A crash partway through a checkpoint. {@code roll} redirects appends to a
	 * sibling temp log while it builds the new baseline, so a process that died
	 * before the swap leaves records in that temp that the active log does not
	 * have. Replay must fold them in — they are acked writes.
	 */
	@Test
	void replayFoldsInTheTailOfAnUncommittedCheckpoint(@TempDir Path volume) throws Exception {
		ScottyagentMap cursors = new ScottyagentMap(boot(volume));
		cursors.putCursors("jody", cursor("jody", 1));
		cursors.putCursors("scotty", cursor("scotty", 1));

		// Take the record for a write the active log does not hold, then move it
		// where a checkpoint interrupted before its swap would have left it.
		Path active = log();
		cursors.putCursors("jody", cursor("jody", 42));
		List<String> all = lines(active);
		String tail = all.get(all.size() - 1);
		Files.write(active, String.join("\n", all.subList(0, all.size() - 1)).concat("\n")
				.getBytes(StandardCharsets.UTF_8));
		Path temp = active.resolveSibling(active.getFileName() + ".temp");
		Files.write(temp, (tail + "\n").getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);

		tearDown();
		HazelcastManager second = boot(volume);
		ScottyagentMap after = new ScottyagentMap(second);
		persistence.rehydrate();

		assertEquals(2, after.proto().getCursorsCount());
		assertEquals(42, after.getCursors("jody").getCyclesCompleted(),
				"the interrupted checkpoint's temp log holds an acked write and must not be dropped");
		assertEquals(1, after.getCursors("scotty").getCyclesCompleted());
	}

	/**
	 * A crash between an append's write and its fsync leaves the last line
	 * unterminated. That record's RPC threw, so no caller was told it was
	 * durable, and dropping it is correct — the alternative is a pod that
	 * refuses to boot forever after an ordinary kill.
	 */
	@Test
	void anUnterminatedFinalLineIsDroppedNotFatal(@TempDir Path volume) throws Exception {
		ScottyagentMap cursors = new ScottyagentMap(boot(volume));
		cursors.putCursors("jody", cursor("jody", 1));
		Path active = log();
		tearDown();

		Files.write(active, "{\"key\":\"scotty\",\"delet".getBytes(StandardCharsets.UTF_8),
				StandardOpenOption.APPEND);

		HazelcastManager second = boot(volume);
		ScottyagentMap after = new ScottyagentMap(second);
		persistence.rehydrate();
		assertEquals(1, after.proto().getCursorsCount());
		assertEquals(1, after.getCursors("jody").getCyclesCompleted());
	}

	/** A damaged line that is NOT the torn tail is still a refused boot. */
	@Test
	void aCorruptCompleteLineStillFailsClosed(@TempDir Path volume) throws Exception {
		ScottyagentMap cursors = new ScottyagentMap(boot(volume));
		cursors.putCursors("jody", cursor("jody", 1));
		Path active = log();
		tearDown();

		Files.write(active, "@@@ not a record @@@\n".getBytes(StandardCharsets.UTF_8),
				StandardOpenOption.APPEND);

		HazelcastManager second = boot(volume);
		new ScottyagentMap(second);
		assertThrows(RuntimeException.class, () -> persistence.rehydrate(),
				"a corrupt boundary log must stop the boot, not come up short a service's rows");
	}

	private static Config isolatedConfig() {
		Config config = new Config();
		config.setClusterName("boundary-redolog-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.setProperty("hazelcast.phone.home.enabled", "false");
		SerializerRegistry.register(config);
		return config;
	}
}
