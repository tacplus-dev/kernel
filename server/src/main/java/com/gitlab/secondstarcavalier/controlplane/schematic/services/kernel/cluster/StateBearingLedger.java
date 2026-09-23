// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.hazelcast.cluster.Member;
import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Which members of this cluster HOLD boundary state, and which pod of a boot
 * cohort is allowed to put its own disk back.
 *
 * <p><b>The defect this replaces.</b> {@code ClusterServer.isColdStart} used to
 * answer "am I forming the cluster?" with {@code getMembers().size() <= 1}. A
 * StatefulSet with {@code podManagementPolicy: Parallel} scaled 0 -&gt; 3 starts
 * every pod at once, so each of the three sees a cluster of three — all of them
 * empty, all of them booting — and every one of them concludes it is NOT a cold
 * start. None replays its own log, every pod then writes its (empty) memory back
 * over its own boundary files, and the cluster's durable state is gone on all
 * three volumes at the same instant. A member COUNT cannot answer the question
 * that was being asked of it: whether any peer actually HOLDS state.
 *
 * <p><b>The fix, and its precedent.</b> The fact has to be published, not
 * inferred, which is stratum's hot-restore idiom — see {@code
 * HotRestore.LEDGER_MAP} and {@code HotRestore.INFLIGHT_MAP}. Two maps, keyed by
 * member UUID, mirroring that split:
 *
 * <ul>
 *   <li>{@link #LEDGER_MAP} — the state-bearing flag. A member writes it ONCE,
 *       at the end of its boot decision: TRUE if it holds real boundary state
 *       (it just rehydrated its own log, or it joined a cluster that bears
 *       state and is therefore holding those rows in memory now), FALSE if it
 *       genuinely holds nothing. A booting pod is a cold start unless at least
 *       one PEER'S entry here is TRUE.</li>
 *   <li>{@link #BOOTING_MAP} — stratum's inflight half, carrying stratum's
 *       ledger value: a member files one entry here when it ENTERS the boot
 *       decision below, and its value is the number of live rows its own volume
 *       holds. The entry is filed BEFORE anything else is read, so a sibling
 *       can never fail to see a member that is in fact still here. It is the
 *       roster of this boot cycle — every member that has booted, decided or
 *       not — and it is what the cohort and the election are computed from.
 *       Whether a member has DECIDED is read from {@link #LEDGER_MAP}, not from
 *       its absence here.</li>
 *   <li>{@link #ORIGIN_MAP} — the single claim slot. The elected origin takes
 *       it with an atomic {@code putIfAbsent} before it replays anything, and
 *       releases it in {@link #settle}.</li>
 * </ul>
 *
 * <p><b>Why the boot roster is never unfiled, and why the claim is atomic.</b>
 * Both halves of this are the same mistake the member count made: concluding
 * something about the whole cluster from what one member happens to see right
 * now.
 *
 * <ul>
 *   <li>The roster only ever grows within a boot cycle. An earlier revision
 *       removed a member's boot entry when it settled, which made the cohort
 *       SHRINK underneath the pods still assembling theirs: {@code kernel-0}
 *       elected itself from a cohort of three and settled, and {@code kernel-1}
 *       — reading a moment later, with {@code kernel-0} gone from the roster —
 *       computed a cohort of two, found itself the lowest ordinal in it, and
 *       elected itself as a SECOND origin. Two pods replaying their own volumes
 *       independently is the shape this class exists to prevent. Every member
 *       must elect from the same set, so the set may not depend on when it is
 *       read.</li>
 *   <li>Even from an identical roster, membership views converge
 *       asynchronously: a member whose {@code getCluster().getMembers()} has not
 *       yet caught up with a joining peer can stop waiting for a cohort that is
 *       in fact still assembling, and elect itself over a peer that outranks it.
 *       No local view can prove that every member computed the same answer. So
 *       the answer is not trusted to agreement at all: the origin is whoever
 *       WINS the claim slot, and a single-key {@code putIfAbsent} admits exactly
 *       one winner however the cohorts were computed. A member that elected
 *       itself and lost the claim becomes a waiter for the winner. Divergent
 *       views can then cost the ROW-PREFERRING policy below — the boot replays
 *       a volume that is not the fullest one — but they cannot produce two
 *       origins, and the checkpoint shrink-guard is what keeps the unreplayed
 *       volume intact for the next boot.</li>
 * </ul>
 *
 * <p><b>Why the boot entry carries a row count.</b> The election below wants the
 * pod whose volume actually holds something. The literal rule specified was
 * "lowest ordinal rehydrates", and with every volume empty — the incident's own
 * shape — that is exactly what this does. It is refined in one direction only:
 * a pod that reports rows outranks one that reports none, so a cohort where
 * {@code kernel-0}'s volume is empty and {@code kernel-2}'s is not elects
 * {@code kernel-2} instead of replaying nothing and leaving real rows unread.
 * Ordinal breaks the tie within each group.
 *
 * <p><b>Residual, named rather than papered over.</b> A volume whose log holds
 * only tombstones reports zero rows and is treated as empty; its (empty) state
 * is what a cold start would have produced anyway. And a cohort elects ONE
 * origin, so rows that exist only on a non-origin volume are not replayed this
 * boot — they are not lost either, because {@code
 * BoundaryPersistence.checkpointAll} now refuses to shrink that volume's file
 * (see its guard), and the next boot where that pod is the origin replays them.
 *
 * @see com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.graphs.hazelcast.BoundaryPersistence
 */
public final class StateBearingLedger {

	private static final Logger logger = LoggerFactory.getLogger(StateBearingLedger.class);

	/** Member UUID -&gt; does this member hold boundary state. Kernel's own namespace. */
	public static final String LEDGER_MAP = "kernel.cluster.__state_bearing";

	/** Member UUID -&gt; live rows on its volume, filed once when it starts deciding. */
	public static final String BOOTING_MAP = "kernel.cluster.__state_bearing_booting";

	/** {@link #ORIGIN_KEY} -&gt; the member UUID currently holding the origin claim. */
	public static final String ORIGIN_MAP = "kernel.cluster.__state_origin";

	/** The one key {@link #ORIGIN_MAP} ever holds. */
	private static final String ORIGIN_KEY = "origin";

	/**
	 * The member attribute carrying this pod's StatefulSet ordinal, published in
	 * the Hazelcast config so it travels with the cluster view.
	 *
	 * <p>An attribute rather than a third map: the ordinal is an identity, not an
	 * event, and the cluster view is where a member's identity already lives. It
	 * is also readable for a member that has not yet filed anything, which a map
	 * entry is not.
	 */
	public static final String ORDINAL_ATTRIBUTE = "kernel.cluster.ordinal";

	/**
	 * How long a pod waits for the rest of its boot cohort to file. Pods of a
	 * {@code Parallel} StatefulSet reach this within a Hazelcast join of each
	 * other; this bound only exists so a member that dies between joining and
	 * filing cannot hold the cohort open.
	 */
	static final Duration COHORT_TIMEOUT = Duration.ofSeconds(30);

	/**
	 * How long a non-origin pod waits for the origin to finish replaying. It is
	 * generous because the origin is reading every boundary log on its volume,
	 * which is the cold-start cost the whole feature pays once.
	 */
	static final Duration ORIGIN_TIMEOUT = Duration.ofMinutes(5);

	private static final long POLL_MS = 100;

	private StateBearingLedger() {}

	/**
	 * Registers the two coordination maps so they are replicated to every member.
	 *
	 * <p>Same reasoning as {@code StratumMapConfig.coordinationMap}: a
	 * coordination map left on Hazelcast's single-backup default can lose a LIVE
	 * member's entry with the partition replica it lived on, and a lost TRUE
	 * entry reads as "no peer bears state" — the exact misreading this class
	 * exists to stop. Backups are cheap here: both maps hold one small entry per
	 * member.
	 */
	public static void configure(Config config) {
		for (String name : new String[] { LEDGER_MAP, BOOTING_MAP, ORIGIN_MAP }) {
			MapConfig map = new MapConfig(name);
			map.setBackupCount(MapConfig.MAX_BACKUP_COUNT);
			map.setAsyncBackupCount(0);
			config.addMapConfig(map);
		}
	}

	/** Publishes this pod's ordinal on the member it is about to start. */
	public static void publishOrdinal(Config config, int ordinal) {
		config.getMemberAttributeConfig().setAttribute(ORDINAL_ATTRIBUTE, String.valueOf(ordinal));
	}

	/**
	 * This pod's StatefulSet ordinal, parsed from the pod name — {@code kernel-0}
	 * is 0, {@code kernel-11} is 11.
	 *
	 * <p>The pod name is already how this process knows its own identity: the
	 * constructor reads {@code HOSTNAME} for the Hazelcast instance name, and the
	 * self gRPC host falls back to {@code kernel-0}. Nothing new is introduced
	 * here, and no downward API or extra env var is required.
	 *
	 * <p>A name with no trailing ordinal — a Deployment pod, a developer laptop —
	 * is {@link Integer#MAX_VALUE}, so it sorts last and never wins an election
	 * away from a real StatefulSet member. A cohort of only such members ties,
	 * and the tie is broken by member UUID, which is stable within one election
	 * because every member reads the same cluster view.
	 */
	public static int ordinalOf(String hostname) {
		if (hostname == null) {
			return Integer.MAX_VALUE;
		}
		int dash = hostname.lastIndexOf('-');
		if (dash < 0 || dash == hostname.length() - 1) {
			return Integer.MAX_VALUE;
		}
		try {
			return Integer.parseInt(hostname.substring(dash + 1));
		} catch (NumberFormatException e) {
			return Integer.MAX_VALUE;
		}
	}

	/**
	 * Whether any member of the cluster — this one included — has declared itself
	 * state-bearing.
	 *
	 * <p>This is the "provably state-bearing" test the boundary checkpoint guard
	 * asks before it is allowed to write a smaller file than the one on disk.
	 */
	public static boolean clusterBearsState(HazelcastInstance hazelcast) {
		return liveLedger(hazelcast).containsValue(Boolean.TRUE);
	}

	/** The UUID of a live PEER that bears state, or null when none does. */
	static String peerBearingState(HazelcastInstance hazelcast) {
		String self = selfUuid(hazelcast);
		for (Map.Entry<String, Boolean> e : liveLedger(hazelcast).entrySet()) {
			if (!e.getKey().equals(self) && Boolean.TRUE.equals(e.getValue())) {
				return e.getKey();
			}
		}
		return null;
	}

	/**
	 * Files this member's decision and takes it out of the boot cohort.
	 *
	 * <p>Called exactly once per boot, on every path out of {@link
	 * #awaitColdStartDecision} — including the ones that concluded this member
	 * holds nothing. A member that filed a boot entry and never filed a decision
	 * would hold every sibling's wait open until it left the cluster.
	 *
	 * <p>This member's BOOT entry stays where it is: the roster of a boot cycle
	 * may not shrink underneath the pods still assembling their cohort from it,
	 * which is what let two of them elect themselves. The origin CLAIM is
	 * released, so the next boot cycle in this cluster — a pod restarting into
	 * peers that hold nothing — can be its own origin rather than deferring to
	 * a member that finished replaying long ago.
	 *
	 * @param bearsState true once this member holds real boundary state: it
	 *                   replayed its own log with rows in it, or it joined a
	 *                   cluster that bears state and is holding those rows in
	 *                   memory now. A member that is serving IS a durable copy
	 *                   for the restart happening next, which is the same thing
	 *                   stratum's serving-peer contributor rule says.
	 */
	public static void settle(HazelcastInstance hazelcast, boolean bearsState) {
		String self = selfUuid(hazelcast);
		hazelcast.<String, Boolean>getMap(LEDGER_MAP).put(self, bearsState);
		hazelcast.<String, String>getMap(ORIGIN_MAP).remove(ORIGIN_KEY, self);
		logger.info("This member filed itself as {} boundary state", bearsState ? "BEARING" : "holding no");
	}

	/**
	 * The cold-start barrier: decides whether THIS pod is the one that replays
	 * its own volume, waiting for the rest of its boot cohort first.
	 *
	 * <p>The caller must call {@link #settle} once it knows the answer, whatever
	 * the answer is.
	 *
	 * @param diskRows live rows this pod's own boundary logs hold, from {@code
	 *                 BoundaryPersistence.diskRowCount()} — read from disk, not
	 *                 from the maps, because the maps are what is in question
	 * @return true if this pod is the state origin and must rehydrate from its
	 *         own disk; false if it joined peers that hold the state, or waited
	 *         for an origin that turned out to hold none
	 */
	public static boolean awaitColdStartDecision(HazelcastInstance hazelcast, long diskRows) {
		return awaitColdStartDecision(hazelcast, diskRows, COHORT_TIMEOUT, ORIGIN_TIMEOUT);
	}

	static boolean awaitColdStartDecision(HazelcastInstance hazelcast, long diskRows,
			Duration cohortTimeout, Duration originTimeout) {
		String self = selfUuid(hazelcast);
		// Filed FIRST, before anything is read, so a sibling reading the two maps
		// in either order can never see this member as settled while it is still
		// inside this call — stratum's ordering, for stratum's reason.
		hazelcast.<String, Long>getMap(BOOTING_MAP).put(self, diskRows);

		String bearer = peerBearingState(hazelcast);
		if (bearer != null) {
			logger.info("Peer {} bears boundary state — this pod takes its state from the cluster", bearer);
			return false;
		}

		// Wait for the cohort to assemble. Without this, two pods of a
		// simultaneous start can each read a view in which it is the only member
		// that has filed and each elect itself, which is the very "everybody
		// decides alone" shape the member count produced.
		Map<String, Long> cohort = awaitCohort(hazelcast, cohortTimeout);
		bearer = peerBearingState(hazelcast);
		if (bearer != null) {
			logger.info("Peer {} bears boundary state — this pod takes its state from the cluster", bearer);
			return false;
		}

		String origin = elect(hazelcast, cohort);
		if (self.equals(origin)) {
			// Winning the election is a local opinion; winning the claim is the
			// fact. A sibling whose cluster view had not caught up can hold a
			// different opinion, and only one of us may replay.
			origin = claimOrigin(hazelcast, self);
			if (self.equals(origin)) {
				logger.info("No peer bears boundary state; this pod is the state origin of a cohort of {}"
						+ " ({} row(s) on its volume) — replaying its own boundary logs",
						cohort.size(), diskRows);
				return true;
			}
			logger.info("This pod elected itself state origin of a cohort of {} but {} had already claimed"
					+ " the origin — waiting for it rather than replaying alongside it",
					cohort.size(), origin);
		}

		logger.info("No peer bears boundary state yet; {} is this cohort's state origin — waiting for it"
				+ " rather than replaying this pod's own log over its result", origin);
		long deadlineMs = System.currentTimeMillis() + originTimeout.toMillis();
		while (true) {
			bearer = peerBearingState(hazelcast);
			if (bearer != null) {
				logger.info("State origin {} finished and bears state — joining as a normal member", bearer);
				return false;
			}
			if (liveLedger(hazelcast).containsKey(origin) || !liveBooting(hazelcast).containsKey(origin)) {
				// It filed a decision, or it left the cluster. Either way it
				// filed no TRUE,
				// so no volume in this cohort held anything worth replaying and
				// there is nothing for this pod to take from a peer OR to put
				// back. Joining empty is correct; the guard in checkpointAll is
				// what keeps that emptiness off this pod's disk.
				logger.info("State origin {} settled without bearing state — this cohort's volumes are"
						+ " empty; joining as a normal member", origin);
				return false;
			}
			if (System.currentTimeMillis() >= deadlineMs) {
				logger.warn("State origin {} has not settled within {} — joining as a normal member rather"
						+ " than replaying this pod's log over whatever it is still doing",
						origin, originTimeout);
				return false;
			}
			if (!sleepPoll()) {
				return false;
			}
		}
	}

	/**
	 * The boot entries of every live member, once every live member has filed
	 * one (or settled without one, which no pod does).
	 *
	 * <p>A member that has already SETTLED is still in the cohort and can still
	 * be its origin. That is the point: the set every member elects from must not
	 * depend on when that member happens to read it, and a cohort that dropped
	 * each pod as it decided gave a late reader a smaller cohort, a different
	 * lowest ordinal, and a second origin. If the elected origin turns out to have
	 * settled already, the wait below sees its ledger entry and joins — which is
	 * the correct answer for a cohort whose volumes hold nothing.
	 *
	 * <p>The returned set is therefore monotone within a boot cycle, and its
	 * contents are the replicated map's, not this member's view of the cluster.
	 * The one thing still read from the local view is the stopping condition, and
	 * a view that has not caught up with a joining peer can stop it early; the
	 * origin claim in {@link #claimOrigin} is what keeps that from mattering.
	 */
	private static Map<String, Long> awaitCohort(HazelcastInstance hazelcast, Duration timeout) {
		long deadlineMs = System.currentTimeMillis() + timeout.toMillis();
		while (true) {
			Map<String, Long> booting = liveBooting(hazelcast);
			Set<String> settled = liveLedger(hazelcast).keySet();
			Set<String> unaccounted = new HashSet<>(liveUuids(hazelcast));
			unaccounted.removeAll(booting.keySet());
			unaccounted.removeAll(settled);
			if (unaccounted.isEmpty()) {
				return booting;
			}
			if (System.currentTimeMillis() >= deadlineMs) {
				logger.warn("{} of {} members had not filed a boot entry within {} — electing the state"
						+ " origin from the {} that had",
						unaccounted.size(), hazelcast.getCluster().getMembers().size(), timeout,
						booting.size());
				return booting;
			}
			if (!sleepPoll()) {
				return booting;
			}
		}
	}

	/**
	 * Takes the cohort's single origin claim, or reports who already holds it.
	 *
	 * <p>This is the whole guarantee that a boot cycle has ONE origin. Everything
	 * above it is policy — which pod ought to replay — and policy is computed from
	 * views that converge at their own pace. A single-key {@code putIfAbsent} is
	 * settled by one partition owner, so however many members believe they should
	 * replay, exactly one of them is told it may.
	 *
	 * <p>A claim whose holder is no longer in the cluster is void: an origin that
	 * died mid-replay must not lock the cohort out of electing another. It is
	 * cleared with the conditional remove rather than a plain delete so a claim
	 * taken between the read and the clear survives.
	 *
	 * @return the UUID of the member that holds the claim — {@code self} if this
	 *         member won it
	 */
	private static String claimOrigin(HazelcastInstance hazelcast, String self) {
		IMap<String, String> claim = hazelcast.getMap(ORIGIN_MAP);
		while (true) {
			String holder = claim.putIfAbsent(ORIGIN_KEY, self);
			if (holder == null || holder.equals(self)) {
				return self;
			}
			if (liveUuids(hazelcast).contains(holder)) {
				return holder;
			}
			logger.warn("The origin claim was held by {}, which has left the cluster — reclaiming it", holder);
			claim.remove(ORIGIN_KEY, holder);
		}
	}

	/**
	 * The member of {@code cohort} that replays its own volume: the one holding
	 * rows if any does, lowest ordinal within that group, member UUID as the last
	 * tie-break so that every member of the cohort computes the same answer from
	 * the same two maps.
	 */
	private static String elect(HazelcastInstance hazelcast, Map<String, Long> cohort) {
		Map<String, Integer> ordinals = ordinals(hazelcast);
		String best = null;
		for (Map.Entry<String, Long> e : cohort.entrySet()) {
			if (best == null || outranks(e.getKey(), cohort, ordinals, best)) {
				best = e.getKey();
			}
		}
		return best;
	}

	private static boolean outranks(String candidate, Map<String, Long> cohort,
			Map<String, Integer> ordinals, String incumbent) {
		boolean candidateHasRows = cohort.getOrDefault(candidate, 0L) > 0;
		boolean incumbentHasRows = cohort.getOrDefault(incumbent, 0L) > 0;
		if (candidateHasRows != incumbentHasRows) {
			return candidateHasRows;
		}
		int candidateOrdinal = ordinals.getOrDefault(candidate, Integer.MAX_VALUE);
		int incumbentOrdinal = ordinals.getOrDefault(incumbent, Integer.MAX_VALUE);
		if (candidateOrdinal != incumbentOrdinal) {
			return candidateOrdinal < incumbentOrdinal;
		}
		return candidate.compareTo(incumbent) < 0;
	}

	/** Ordinal per live member UUID, from the attribute published at start. */
	private static Map<String, Integer> ordinals(HazelcastInstance hazelcast) {
		Map<String, Integer> out = new LinkedHashMap<>();
		for (Member m : hazelcast.getCluster().getMembers()) {
			String raw = m.getAttribute(ORDINAL_ATTRIBUTE);
			int ordinal = Integer.MAX_VALUE;
			if (raw != null) {
				try {
					ordinal = Integer.parseInt(raw);
				} catch (NumberFormatException e) {
					// A member that publishes an unreadable ordinal sorts last
					// rather than failing the boot of every sibling reading it.
					logger.warn("Member {} published an unreadable ordinal {}", m.getUuid(), raw);
				}
			}
			out.put(m.getUuid().toString(), ordinal);
		}
		return out;
	}

	/**
	 * The ledger entries of members in the CURRENT cluster view, with every other
	 * entry deleted on the way past.
	 *
	 * <p>The correctness is in the filter, exactly as in {@code
	 * HotRestore.liveReports}: a departed member's TRUE would otherwise vouch for
	 * state that left with it, and this class's whole question is about members
	 * that are here NOW. The delete is housekeeping — the key is a UUID Hazelcast
	 * mints fresh on every restart, so an unpruned map grows by one entry per pod
	 * per restart for the life of the cluster.
	 */
	private static Map<String, Boolean> liveLedger(HazelcastInstance hazelcast) {
		Set<String> live = liveUuids(hazelcast);
		IMap<String, Boolean> ledger = hazelcast.getMap(LEDGER_MAP);
		Map<String, Boolean> out = new HashMap<>();
		for (Map.Entry<String, Boolean> e : ledger.entrySet()) {
			if (live.contains(e.getKey())) {
				out.put(e.getKey(), e.getValue());
			} else {
				ledger.delete(e.getKey());
			}
		}
		return out;
	}

	/** The boot entries of members in the current cluster view; same rule as above. */
	private static Map<String, Long> liveBooting(HazelcastInstance hazelcast) {
		Set<String> live = liveUuids(hazelcast);
		IMap<String, Long> booting = hazelcast.getMap(BOOTING_MAP);
		Map<String, Long> out = new HashMap<>();
		for (Map.Entry<String, Long> e : booting.entrySet()) {
			if (live.contains(e.getKey())) {
				out.put(e.getKey(), e.getValue());
			} else {
				booting.delete(e.getKey());
			}
		}
		return out;
	}

	private static Set<String> liveUuids(HazelcastInstance hazelcast) {
		Set<String> live = new HashSet<>();
		for (Member m : hazelcast.getCluster().getMembers()) {
			live.add(m.getUuid().toString());
		}
		return live;
	}

	private static String selfUuid(HazelcastInstance hazelcast) {
		return hazelcast.getCluster().getLocalMember().getUuid().toString();
	}

	/** @return false if the wait was interrupted, which ends it the same way a timeout does. */
	private static boolean sleepPoll() {
		try {
			Thread.sleep(POLL_MS);
			return true;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			logger.warn("Interrupted while waiting on the state-bearing ledger — joining as a normal member");
			return false;
		}
	}
}
