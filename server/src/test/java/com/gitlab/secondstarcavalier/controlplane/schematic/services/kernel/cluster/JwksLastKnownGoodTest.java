// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression for the audit finding that a single failed verifying-key state read
 * pushed an EMPTY JWKS fleet-wide.
 *
 * <p>Every JWKS consumer reads through one supplier in {@link ClusterServer}:
 * the generated JWK view server's watchers, the {@code WatchJwks} subscribers in
 * {@link BackendServiceImpl}, and kernel's own {@link Authorizer} via
 * {@link LocalJwkSource}. That supplier caught read failures and returned an
 * empty list, which every one of those consumers read as "the cluster now has
 * zero valid keys" — so one Hazelcast partition-migration timeout became 10-20
 * seconds of platform-wide {@code UNAUTHENTICATED}.
 *
 * <p>A failed read must instead keep serving the last-known-good key set.
 */
class JwksLastKnownGoodTest {

	private static JwkOuterClass.Jwk jwk(String kid) {
		return JwkOuterClass.Jwk.newBuilder().setKid(kid).setAlg("EdDSA").setCreated(1).build();
	}

	private static final List<JwkOuterClass.Jwk> KEYS = List.of(jwk("kid-a"), jwk("kid-b"));

	/** A state read that throws must not empty the served key set. */
	@Test
	void readFailureKeepsServingTheLastKnownGoodKeys() {
		AtomicReference<RuntimeException> fault = new AtomicReference<>();
		Supplier<List<JwkOuterClass.Jwk>> guarded = ClusterServer.lastKnownGoodVerifyingKeys(() -> {
			RuntimeException e = fault.get();
			if (e != null) {
				throw e;
			}
			return KEYS;
		});

		assertEquals(2, guarded.get().size(), "healthy read serves the real keys");

		fault.set(new IllegalStateException("partition migration timed out"));

		List<JwkOuterClass.Jwk> served = guarded.get();
		assertEquals(2, served.size(),
				"a failed read must not be published as an empty JWKS");
		assertEquals(List.of("kid-a", "kid-b"),
				served.stream().map(JwkOuterClass.Jwk::getKid).toList());
	}

	/**
	 * The state read does not always throw — a boundary mid-migration can simply
	 * return nothing. Kernel keeps its own active signing keys published for as
	 * long as it runs, so an empty set after a non-empty one is a failed read too.
	 */
	@Test
	void emptyReadAfterKeysWereSeenKeepsServingTheLastKnownGoodKeys() {
		AtomicReference<List<JwkOuterClass.Jwk>> backing = new AtomicReference<>(KEYS);
		Supplier<List<JwkOuterClass.Jwk>> guarded =
				ClusterServer.lastKnownGoodVerifyingKeys(backing::get);

		assertEquals(2, guarded.get().size());

		backing.set(List.of());

		assertEquals(2, guarded.get().size(),
				"an empty read is a failed read, not zero valid keys");
	}

	/** A genuine cold start has no last-known-good set and must report empty. */
	@Test
	void coldStartWithNoSuccessfulReadYetServesEmpty() {
		Supplier<List<JwkOuterClass.Jwk>> guarded =
				ClusterServer.lastKnownGoodVerifyingKeys(List::of);

		List<JwkOuterClass.Jwk> served = guarded.get();
		assertNotNull(served);
		assertTrue(served.isEmpty(), "before any key is published the set really is empty");
	}

	/** Once the read recovers, the fresh keys are served — the cache is not sticky. */
	@Test
	void recoveredReadServesTheFreshKeys() {
		AtomicReference<List<JwkOuterClass.Jwk>> backing = new AtomicReference<>(KEYS);
		Supplier<List<JwkOuterClass.Jwk>> guarded =
				ClusterServer.lastKnownGoodVerifyingKeys(backing::get);

		assertEquals(2, guarded.get().size());
		backing.set(List.of());
		assertEquals(2, guarded.get().size(), "held over the outage");

		backing.set(List.of(jwk("kid-rotated")));

		assertEquals(List.of("kid-rotated"),
				guarded.get().stream().map(JwkOuterClass.Jwk::getKid).toList(),
				"rotation must still propagate once reads recover");
	}

	/**
	 * The consumer that turns the outage into platform-wide UNAUTHENTICATED:
	 * {@link LocalJwkSource} pushes whatever it reads straight into the kernel
	 * Authorizer's cache, replacing it wholesale. A failed read must leave the
	 * kernel still able to verify its own callers' tokens.
	 */
	@Test
	void localJwkSourceDoesNotClearTheAuthorizerCacheOnAFailedRead() {
		AtomicReference<RuntimeException> fault = new AtomicReference<>();
		Supplier<List<JwkOuterClass.Jwk>> guarded = ClusterServer.lastKnownGoodVerifyingKeys(() -> {
			RuntimeException e = fault.get();
			if (e != null) {
				throw e;
			}
			return KEYS;
		});

		AtomicReference<Map<String, JwkOuterClass.Jwk>> pushed = new AtomicReference<>();
		Authorizer.JwkSink sink = pushed::set;

		// start() pushes once synchronously before scheduling the poller.
		LocalJwkSource healthy = new LocalJwkSource(guarded);
		healthy.start(sink);
		healthy.stop();
		assertEquals(2, pushed.get().size(), "initial push carries the real keys");

		fault.set(new IllegalStateException("partition migration timed out"));

		// The poller's next push, now against a failing state read.
		LocalJwkSource duringOutage = new LocalJwkSource(guarded);
		duringOutage.start(sink);
		duringOutage.stop();

		assertEquals(2, pushed.get().size(),
				"a failed read must not clear the Authorizer's key cache");
		assertTrue(pushed.get().containsKey("kid-a"));
		assertTrue(pushed.get().containsKey("kid-b"));
	}
}
