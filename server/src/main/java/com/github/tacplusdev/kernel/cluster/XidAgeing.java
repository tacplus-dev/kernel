// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * XID ageing (decision record tenant-deletion-2026-10-27, kernel#20): a person
 * who has not signed in for {@code Config.xid_ageing_period_seconds} (about a
 * year) is aged out, deleted as DeleteAccount deletes. The sweep runs on every
 * node and goes through {@link IdentityGraph#ageOut}, which reads each person
 * again under its write, so two nodes sweeping at once age a person out once
 * and a sign-in on another node keeps them. It moves with the graph to the
 * people service.
 */
final class XidAgeing {

	private static final Logger logger = LoggerFactory.getLogger(XidAgeing.class);

	/** {@code Config.xid_ageing_period_seconds}'s default: 365 days. */
	static final long DEFAULT_PERIOD_SECONDS = 31_536_000L;

	/**
	 * The shortest period honoured. A sign-in's time is recorded to the hour
	 * ({@link KernelIdentityGraph#SIGN_IN_RECORD_GRANULARITY_MS}), so a shorter
	 * period could age out someone who signed in within it.
	 */
	static final long MIN_PERIOD_SECONDS = 86_400L;

	private static final long SWEEP_INTERVAL_SECONDS = 3_600L;

	private final IdentityGraph graph;
	private final long periodMs;
	private final LongSupplier clock;
	private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread t = new Thread(r, "xid-ageing");
		t.setDaemon(true);
		return t;
	});

	/**
	 * @param periodSeconds {@code Config.xid_ageing_period_seconds}; 0 (unset)
	 *                      is the default, and a positive one below a day is a day
	 */
	XidAgeing(IdentityGraph graph, long periodSeconds, LongSupplier clock) {
		this.graph = graph;
		long seconds = periodSeconds > 0 ? periodSeconds : DEFAULT_PERIOD_SECONDS;
		if (seconds < MIN_PERIOD_SECONDS) {
			logger.warn("xid_ageing_period_seconds={} is below one day; ageing out after one day", seconds);
			seconds = MIN_PERIOD_SECONDS;
		}
		this.periodMs = TimeUnit.SECONDS.toMillis(seconds);
		this.clock = clock;
	}

	/** Sweeps every hour, the first an hour after boot. */
	void start() {
		scheduler.scheduleAtFixedRate(() -> {
			try {
				sweep();
			} catch (Exception e) {
				logger.error("XID ageing sweep failed; nobody was aged out by it", e);
			}
		}, SWEEP_INTERVAL_SECONDS, SWEEP_INTERVAL_SECONDS, TimeUnit.SECONDS);
		logger.info("XID ageing: a person not signed in for {}s is aged out; sweeping every {}s",
				TimeUnit.MILLISECONDS.toSeconds(periodMs), SWEEP_INTERVAL_SECONDS);
	}

	void stop() {
		scheduler.shutdown();
	}

	/** One sweep: ages out everyone whose last sign-in is more than the period ago. */
	List<String> sweep() throws IdentityServiceImpl.StatusException {
		List<String> agedOut = graph.ageOut(clock.getAsLong() - periodMs);
		if (!agedOut.isEmpty()) {
			logger.info("XID ageing: aged out {} person(s)", agedOut.size());
		}
		return agedOut;
	}
}
