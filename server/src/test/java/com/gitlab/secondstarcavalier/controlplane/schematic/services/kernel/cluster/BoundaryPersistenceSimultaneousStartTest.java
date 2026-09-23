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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The incident: {@code kubectl scale statefulset kernel 0 -> 3} with {@code
 * podManagementPolicy: Parallel}.
 *
 * <p>All three pods start at the same moment. Each sees a cluster of three and,
 * under the old member-count gate, concluded it had joined peers that hold the
 * state — so none of them replayed its own log, all of them took "state" from
 * peers that were equally empty, and each then rewrote its own boundary files
 * from that empty memory. Real persisted rows would have been truncated to zero
 * on every volume at once; the live cluster escaped it only because no product
 * rows existed yet.
 *
 * <p>Three properties are asserted here, one per test:
 *
 * <ol>
 *   <li>A simultaneous start of empty pods elects exactly ONE state origin — the
 *       lowest ordinal — and the others wait for it and join non-cold.</li>
 *   <li>A pod whose volume holds real rows, restarting at the same instant as an
 *       empty sibling, keeps those rows: it is the cohort's origin, and nothing
 *       in the join shrinks its log.</li>
 *   <li>The checkpoint guard on its own: a member holding fewer rows in memory
 *       than its file holds on disk cannot write that file down without a
 *       state-bearing cluster to authorise it.</li>
 * </ol>
 */
class BoundaryPersistenceSimultaneousStartTest {

	private final List<HazelcastInstance> instances = new ArrayList<>();
	private final List<BoundaryPersistence> stores = new ArrayList<>();

	@AfterEach
	void tearDown() {
		for (BoundaryPersistence p : stores) {
			p.close();
		}
		stores.clear();
		for (HazelcastInstance hz : instances) {
			hz.shutdown();
		}
		instances.clear();
	}

	private static Scottyagent.AgentCursor cursor(String user, long cycles) {
		return Scottyagent.AgentCursor.newBuilder().setUser(user).setCyclesCompleted(cycles).build();
	}

	/** One pod: its own volume, its own member, its boundaries registered. */
	private final class Pod {
		final int ordinal;
		final HazelcastInstance hazelcast;
		final BoundaryPersistence persistence;
		final ScottyagentMap cursors;
		Boolean coldStart;

		Pod(String cluster, int ordinal, Path volume) {
			this.ordinal = ordinal;
			this.persistence = BoundaryPersistence.at(volume.toString());
			stores.add(persistence);
			this.hazelcast = Hazelcast.newHazelcastInstance(joinableConfig(cluster, ordinal));
			instances.add(hazelcast);
			this.cursors = new ScottyagentMap(new HazelcastManager(hazelcast, persistence));
			persistence.setStateBearingGate(() -> StateBearingLedger.clusterBearsState(hazelcast));
		}

		/**
		 * Exactly what {@code ClusterServer}'s constructor does with the decision,
		 * so what is under test is the production sequence and not a paraphrase of
		 * it.
		 */
		void boot() {
			coldStart = ClusterServer.isColdStart(hazelcast, persistence);
			if (coldStart) {
				StateBearingLedger.settle(hazelcast, persistence.rehydrate() > 0);
			} else {
				StateBearingLedger.settle(hazelcast, StateBearingLedger.clusterBearsState(hazelcast));
			}
		}
	}

	/** Boots every pod at once and waits for all of them, the way Parallel does. */
	private static void bootTogether(List<Pod> pods) throws Exception {
		CountDownLatch go = new CountDownLatch(1);
		CountDownLatch done = new CountDownLatch(pods.size());
		AtomicReference<Throwable> failure = new AtomicReference<>();
		for (Pod pod : pods) {
			Thread t = new Thread(() -> {
				try {
					go.await();
					pod.boot();
				} catch (Throwable e) {
					failure.compareAndSet(null, e);
				} finally {
					done.countDown();
				}
			}, "pod-" + pod.ordinal);
			t.setDaemon(true);
			t.start();
		}
		go.countDown();
		assertTrue(done.await(2, TimeUnit.MINUTES), "every pod's boot decision must terminate");
		if (failure.get() != null) {
			throw new AssertionError("a pod's boot threw", failure.get());
		}
	}

	/**
	 * Three empty pods, started together. Under the member-count gate every one
	 * of them read the other two as state-holding peers; here exactly one is the
	 * state origin, and it is {@code kernel-0}.
	 */
	@Test
	void aSimultaneousStartElectsOneStateOriginAndTruncatesNothing(
			@TempDir Path volume0, @TempDir Path volume1, @TempDir Path volume2) throws Exception {
		String cluster = "simultaneous-empty-" + UUID.randomUUID();
		List<Pod> pods = List.of(
				new Pod(cluster, 2, volume2),
				new Pod(cluster, 0, volume0),
				new Pod(cluster, 1, volume1));

		bootTogether(pods);

		List<Pod> origins = pods.stream().filter(p -> p.coldStart).toList();
		assertEquals(1, origins.size(),
				"exactly one pod of a simultaneous start replays its own volume, not none and not all");
		assertEquals(0, origins.get(0).ordinal,
				"with every volume equally empty the lowest ordinal is the state origin");
		for (Pod pod : pods) {
			if (pod.ordinal != 0) {
				assertFalse(pod.coldStart,
						"kernel-" + pod.ordinal + " waited for the origin and joined as a normal member");
			}
			assertEquals(0, pod.persistence.diskRowCount(),
					"no volume held anything, and nothing invented rows on kernel-" + pod.ordinal);
		}

		// And the cluster is usable afterwards: a write lands on every volume,
		// which is what proves the waiters really joined rather than gave up.
		pods.get(0).cursors.putCursors("jody", cursor("jody", 1));
		for (Pod pod : pods) {
			assertEquals(1, awaitDiskRows(pod.persistence, 1),
					"kernel-" + pod.ordinal + " persists the cluster's writes after the join");
		}
	}

	/**
	 * The incident with real data in it: one volume holds rows and its pod
	 * restarts at the same instant as an empty sibling. The rows must be on disk
	 * and in the cluster when both pods are up — the row count may not shrink.
	 *
	 * <p>The empty sibling is {@code kernel-0}, deliberately: it would win a
	 * naive lowest-ordinal election and replay nothing, so this also pins the one
	 * refinement the election makes — a volume that holds rows outranks one that
	 * does not.
	 */
	@Test
	void existingRowsSurviveASimultaneousStartWithAnEmptyPod(
			@TempDir Path emptyVolume, @TempDir Path seededVolume) throws Exception {
		// A pod that has been serving writes three rows to its volume, then the
		// whole cluster goes down.
		String seeding = "simultaneous-seed-" + UUID.randomUUID();
		Pod seeder = new Pod(seeding, 1, seededVolume);
		seeder.cursors.putCursors("jody", cursor("jody", 7));
		seeder.cursors.putCursors("scotty", cursor("scotty", 2));
		seeder.cursors.putCursors("tacplus", cursor("tacplus", 5));
		assertEquals(3, seeder.persistence.diskRowCount());
		tearDown();

		// Both pods come back at once: kernel-1 with its three rows on disk,
		// kernel-0 with an empty volume.
		String cluster = "simultaneous-mixed-" + UUID.randomUUID();
		Pod empty = new Pod(cluster, 0, emptyVolume);
		Pod seeded = new Pod(cluster, 1, seededVolume);
		bootTogether(List.of(empty, seeded));

		assertTrue(seeded.coldStart, "the volume holding rows is the cohort's state origin");
		assertFalse(empty.coldStart, "the empty pod waits for it and joins as a normal member");

		assertEquals(3, seeded.persistence.diskRowCount(),
				"the rows that were on disk are still on disk — this is the truncation that happened live");
		assertEquals(3, seeded.cursors.proto().getCursorsCount(), "and they are back in the cluster");
		assertEquals(7, seeded.cursors.getCursors("jody").getCyclesCompleted());

		// The empty pod writes the cluster's state to its own volume, so the NEXT
		// simultaneous start has two volumes holding it rather than one.
		empty.persistence.checkpointAll("test: joined a live cluster");
		assertEquals(3, awaitDiskRows(empty.persistence, 3),
				"a pod that joined a state-bearing cluster puts that state on its own disk");
		assertEquals(3, seeded.persistence.diskRowCount(),
				"and the origin's volume is untouched by it");
	}

	/**
	 * The guard by itself. A member whose memory holds fewer rows than its own
	 * log already holds may not write that log down — the checkpoint that, in the
	 * incident, turned "this pod came up empty" into "this pod's durable state is
	 * gone".
	 *
	 * <p>Contract, as documented on {@code checkpointAll}: the write is REFUSED
	 * and logged at error, and the file is left byte-for-byte as it was. The
	 * second half of the test is what proves the refusal is the guard and not the
	 * flusher simply not having run — with a state-bearing cluster to authorise
	 * it, the same call writes the same shrink through.
	 */
	@Test
	void checkpointRefusesToShrinkABoundaryLogWithoutAStateBearingCluster(@TempDir Path volume)
			throws Exception {
		String seeding = "guard-seed-" + UUID.randomUUID();
		Pod seeder = new Pod(seeding, 0, volume);
		seeder.cursors.putCursors("jody", cursor("jody", 7));
		seeder.cursors.putCursors("scotty", cursor("scotty", 2));
		seeder.cursors.putCursors("tacplus", cursor("tacplus", 5));
		assertEquals(3, seeder.persistence.diskRowCount());
		tearDown();

		// A fresh member against the same volume, with nothing replayed: three
		// rows on disk, zero in memory, and nothing anywhere claiming to bear
		// state. This is the pod the incident produced.
		String cluster = "guard-" + UUID.randomUUID();
		Pod reborn = new Pod(cluster, 0, volume);
		assertEquals(0, reborn.cursors.proto().getCursorsCount(), "a fresh member starts empty");

		reborn.persistence.checkpointAll("test: unproven cluster");
		// Give the flusher room to have done it, then assert it did not.
		Thread.sleep(2_000);
		assertEquals(3, reborn.persistence.diskRowCount(),
				"an unproven cluster may not write a boundary log down to what an empty member holds");

		// The same call, once the cluster can prove it holds the state: a smaller
		// file is then the legitimate result of rows having been deleted.
		reborn.persistence.setStateBearingGate(() -> true);
		reborn.persistence.checkpointAll("test: state-bearing cluster");
		assertEquals(0, awaitDiskRows(reborn.persistence, 0),
				"with a state-bearing cluster the checkpoint writes the cluster's view, shrink and all");
	}

	private static long awaitDiskRows(BoundaryPersistence persistence, long expected) throws Exception {
		long deadline = System.currentTimeMillis() + 30_000;
		long rows = persistence.diskRowCount();
		while (System.currentTimeMillis() < deadline && rows != expected) {
			Thread.sleep(50);
			rows = persistence.diskRowCount();
		}
		return rows;
	}

	/** One member of a cluster that joins over loopback, carrying its ordinal. */
	private static Config joinableConfig(String clusterName, int ordinal) {
		Config config = new Config();
		config.setClusterName(clusterName);
		config.setProperty("hazelcast.phone.home.enabled", "false");
		var join = config.getNetworkConfig().getJoin();
		join.getMulticastConfig().setEnabled(false);
		join.getTcpIpConfig().setEnabled(true).addMember("127.0.0.1");
		config.getNetworkConfig().setPort(5720).setPortAutoIncrement(true);
		StateBearingLedger.configure(config);
		StateBearingLedger.publishOrdinal(config, ordinal);
		SerializerRegistry.register(config);
		return config;
	}
}
