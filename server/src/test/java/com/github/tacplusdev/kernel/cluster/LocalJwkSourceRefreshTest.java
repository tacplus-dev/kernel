// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.grpcserver.Authorizer;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link LocalJwkSource} must be able to publish a rotation to the kernel's own
 * Authorizer without waiting for its refresh interval.
 *
 * <p>The source only pushed on a fixed 10s schedule, so for up to 10 seconds
 * after a rotation the Authorizer rejected tokens signed with a key this very
 * node had just published as "unknown signing key" — an RPC to TenantAdmin or
 * FencedLock right after a rotation failed UNAUTHENTICATED, which the caller
 * cannot usefully retry. {@code refreshNow()} is the on-demand push the kernel
 * calls from its KeyRotator key-change hook.
 */
class LocalJwkSourceRefreshTest {

	private static JwkOuterClass.Jwk jwk(String kid) {
		return JwkOuterClass.Jwk.newBuilder()
				.setKid(kid)
				.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
				.setAlg("EdDSA")
				.build();
	}

	/** Records every key set pushed to the Authorizer. */
	private static final class RecordingSink implements Authorizer.JwkSink {
		private final List<java.util.Set<String>> pushes = new CopyOnWriteArrayList<>();

		@Override
		public void update(Map<String, JwkOuterClass.Jwk> entries) {
			pushes.add(new java.util.TreeSet<>(entries.keySet()));
		}

		java.util.Set<String> latest() {
			return pushes.get(pushes.size() - 1);
		}
	}

	@Test
	void startPushesTheCurrentKeys() {
		RecordingSink sink = new RecordingSink();
		LocalJwkSource source = new LocalJwkSource(() -> List.of(jwk("kid-1")));
		try {
			source.start(sink);
			assertEquals(java.util.Set.of("kid-1"), sink.latest());
		} finally {
			source.stop();
		}
	}

	/** The regression: a rotation must reach the Authorizer without a 10s wait. */
	@Test
	void refreshNowPublishesARotationImmediately() {
		RecordingSink sink = new RecordingSink();
		List<JwkOuterClass.Jwk> keys = new CopyOnWriteArrayList<>(List.of(jwk("kid-1")));
		LocalJwkSource source = new LocalJwkSource(() -> new ArrayList<>(keys));
		try {
			source.start(sink);
			assertEquals(java.util.Set.of("kid-1"), sink.latest());

			// A rotation: the new key is published into the live key state.
			keys.add(jwk("kid-2"));
			assertEquals(java.util.Set.of("kid-1"), sink.latest(),
					"the periodic push alone leaves the Authorizer behind the rotation");

			source.refreshNow();

			assertEquals(java.util.Set.of("kid-1", "kid-2"), sink.latest(),
					"refreshNow must publish the rotated key set at once");
		} finally {
			source.stop();
		}
	}

	/** A retired key must disappear from the Authorizer on the same push. */
	@Test
	void refreshNowPublishesRetirementsToo() {
		RecordingSink sink = new RecordingSink();
		List<JwkOuterClass.Jwk> keys = new CopyOnWriteArrayList<>(List.of(jwk("old"), jwk("new")));
		LocalJwkSource source = new LocalJwkSource(() -> new ArrayList<>(keys));
		try {
			source.start(sink);
			keys.removeIf(k -> k.getKid().equals("old"));
			source.refreshNow();
			assertEquals(java.util.Set.of("new"), sink.latest());
		} finally {
			source.stop();
		}
	}

	/** Keys with no kid cannot be looked up, so they are not published. */
	@Test
	void keysWithoutAKidAreSkipped() {
		RecordingSink sink = new RecordingSink();
		LocalJwkSource source = new LocalJwkSource(() -> List.of(jwk(""), jwk("kid-1")));
		try {
			source.start(sink);
			assertEquals(java.util.Set.of("kid-1"), sink.latest());
		} finally {
			source.stop();
		}
	}

	/**
	 * The kernel's key-change hook can fire before the Authorizer is built (the
	 * rotator is constructed first), so an early refresh must be a no-op rather
	 * than an NPE on the startup path.
	 */
	@Test
	void refreshNowBeforeStartIsANoop() {
		LocalJwkSource source = new LocalJwkSource(() -> List.of(jwk("kid-1")));
		source.refreshNow();

		RecordingSink sink = new RecordingSink();
		try {
			source.start(sink);
			assertEquals(java.util.Set.of("kid-1"), sink.latest(),
					"start still publishes the keys the early refresh could not");
		} finally {
			source.stop();
		}
	}

	/** A supplier that throws must not kill the caller of refreshNow. */
	@Test
	void aFailingKeyReadLeavesTheLastGoodSetInPlace() {
		RecordingSink sink = new RecordingSink();
		AtomicReference<RuntimeException> fail = new AtomicReference<>();
		LocalJwkSource source = new LocalJwkSource(() -> {
			RuntimeException e = fail.get();
			if (e != null) {
				throw e;
			}
			return List.of(jwk("kid-1"));
		});
		try {
			source.start(sink);
			fail.set(new IllegalStateException("key state unavailable"));

			source.refreshNow();

			assertEquals(java.util.Set.of("kid-1"), sink.latest(),
					"a failed read must not clear the Authorizer's keys");
			assertTrue(sink.pushes.size() == 1, "no push should have been made for the failed read");
		} finally {
			source.stop();
		}
	}
}
