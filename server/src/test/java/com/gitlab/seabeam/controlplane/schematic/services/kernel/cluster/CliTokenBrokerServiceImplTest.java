// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CliTokenBrokerServiceImplTest {
	private static final String NONCE_A =
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	private static final String NONCE_B =
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
	private static final String NONCE_C =
			"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

	private HazelcastInstance hazelcast;

	@AfterEach
	void tearDown() {
		if (hazelcast != null) {
			hazelcast.shutdown();
		}
	}

	@Test
	void normalRegisterThenCompleteDeliversToken() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		List<Boolean> offlineAccessValues = new ArrayList<>();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount, offlineAccessValues);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(registerNonce(NONCE_A));
		requests.onNext(completeNonce(NONCE_A, "user-a"));

		assertEquals(1, mintCount.get());
		assertEquals(List.of(false), offlineAccessValues);
		assertTokenDeliveries(responses, "refresh-user-a");
	}

	@Test
	void offlineAccessNonceRequestsOfflineToken() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		List<Boolean> offlineAccessValues = new ArrayList<>();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount, offlineAccessValues);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(registerNonce(NONCE_A, true));
		requests.onNext(completeNonce(NONCE_A, "user-a"));

		assertEquals(1, mintCount.get());
		assertEquals(List.of(true), offlineAccessValues);
		assertTokenDeliveries(responses, "refresh-user-a");
	}

	@Test
	void completeBeforeRegisterParksTheRequestAndMintsOnceOnRegistration() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(completeNonce(NONCE_B, "user-b"));
		awaitParkedCompletion(NONCE_B);
		assertEquals(0, mintCount.get(),
				"nothing may be minted before a registration states offline_access");
		assertTrue(responses.tokenDeliveries().isEmpty());

		requests.onNext(registerNonce(NONCE_B));
		assertEquals(1, mintCount.get());
		assertTokenDeliveries(responses, "refresh-user-b");

		responses.clear();
		requests.onNext(registerNonce(NONCE_B));
		requests.onNext(completeNonce(NONCE_B, "different-user"));
		assertEquals(1, mintCount.get());
		assertTrue(responses.tokenDeliveries().isEmpty());
	}

	/**
	 * offline_access is stated by the RegisterNonce and is baked into the token at
	 * mint time. A completion that arrives first must therefore wait for it: a
	 * token minted early is a non-offline token the user can never upgrade, and
	 * the CLI session it belongs to expires early with no error anywhere.
	 */
	@Test
	void offlineAccessRegisteredAfterACompletionStillMintsAnOfflineToken() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		List<Boolean> offlineAccessValues = new ArrayList<>();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount, offlineAccessValues);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(completeNonce(NONCE_B, "user-b"));
		awaitParkedCompletion(NONCE_B);

		requests.onNext(registerNonce(NONCE_B, true));

		assertEquals(1, mintCount.get());
		assertEquals(List.of(true), offlineAccessValues,
				"the token was minted without the offline access the registration asked for");
		assertTokenDeliveries(responses, "refresh-user-b");
	}

	/**
	 * The nonce is client-supplied and every log site truncates it to 8
	 * characters. A short one must be refused, not throw: several of those sites
	 * are on the gRPC handling thread and one is inside a mint-failure catch,
	 * where the throw would kill the broker stream for every login on this node.
	 */
	@Test
	void aShortNonceIsRejectedRatherThanThrowing() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(registerNonce("abc"));
		requests.onNext(completeNonce("abc", "user-a"));

		assertFalse(nonceMap().containsKey("abc"), "a below-minimum nonce must not be registered");
		assertEquals(0, mintCount.get(), "a below-minimum nonce must not mint");
		assertTrue(responses.tokenDeliveries().isEmpty());

		// The stream is still usable: a well-formed login after the short one works.
		requests.onNext(registerNonce(NONCE_A));
		requests.onNext(completeNonce(NONCE_A, "user-a"));
		assertTokenDeliveries(responses, "refresh-user-a");
	}

	@Test
	void expiredBufferedDeliveryIsDiscarded() {
		CapturingObserver responses = new CapturingObserver();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, new AtomicInteger());
		requests.onNext(register("oauth-a"));
		responses.clear();

		long expiredCreatedAt = (System.currentTimeMillis() / 1000) - 301;
		hazelcast.<String, CliTokenBrokerServiceImpl.NonceEntry>getMap("cli-token-broker")
				.put("delivery:" + NONCE_C,
						new CliTokenBrokerServiceImpl.NonceEntry("", "refresh-user-c", expiredCreatedAt));

		requests.onNext(registerNonce(NONCE_C));

		assertTrue(responses.tokenDeliveries().isEmpty());
	}

	@Test
	void completeNonceForUnseenRegistrationDoesNotBlockTheHandlingThread() {
		CapturingObserver responses = new CapturingObserver();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, new AtomicInteger());
		requests.onNext(register("oauth-a"));
		responses.clear();

		// No RegisterNonce: the registration is "still replicating". The handler
		// must park the completion and return, not poll for it inline.
		long start = System.nanoTime();
		requests.onNext(completeNonce(NONCE_A, "user-a"));
		long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

		assertTrue(elapsedMillis < 2000,
				"CompleteNonce held the handling thread for " + elapsedMillis + "ms");
	}

	@Test
	void lateNonceRegistrationResumesParkedCompletionOnArrival() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(completeNonce(NONCE_A, "user-a"));
		assertTrue(responses.tokenDeliveries().isEmpty());

		// The registration replicates in from another node after the completion
		// parked. The parked completion must be woken by its arrival.
		long start = System.nanoTime();
		nonceMap().put(NONCE_A, new CliTokenBrokerServiceImpl.NonceEntry("oauth-a"));
		awaitCondition(() -> !responses.tokenDeliveries().isEmpty(),
				"token was never delivered after the nonce registration arrived");
		long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

		assertTokenDeliveries(responses, "refresh-user-a");
		assertEquals(1, mintCount.get());
		assertFalse(nonceMap().containsKey("delivery:" + NONCE_A),
				"completion fell through to buffering instead of being signaled");
		assertTrue(elapsedMillis < 2000,
				"delivery took " + elapsedMillis + "ms after the registration arrived");
	}

	@Test
	void duplicateNonceRegistrationFromAnotherInstanceIsRejected() {
		AtomicInteger mintCount = new AtomicInteger();
		CliTokenBrokerServiceImpl service = service(mintCount, new ArrayList<>());

		// The legitimate CLI's nonce is registered by the oauth instance its
		// session landed on. The nonce is visible in the browser login URL, so an
		// attacker can re-register it — here from a second oauth instance, which
		// oauth's own per-instance pending map cannot see.
		CapturingObserver firstResponses = new CapturingObserver();
		CapturingObserver secondResponses = new CapturingObserver();
		StreamObserver<Kernel.CliTokenBrokerRequest> first = service.brokerStream(null, firstResponses);
		StreamObserver<Kernel.CliTokenBrokerRequest> second = service.brokerStream(null, secondResponses);
		first.onNext(register("oauth-a"));
		second.onNext(register("oauth-b"));
		firstResponses.clear();
		secondResponses.clear();

		first.onNext(registerNonce(NONCE_A));
		second.onNext(registerNonce(NONCE_A));

		assertEquals("oauth-a", nonceMap().get(NONCE_A).instanceId,
				"the second RegisterNonce replaced the first registrant");

		// Browser auth completes. Any oauth instance may send CompleteNonce, so
		// the hijacker's stream carrying it must still not redirect the delivery.
		second.onNext(completeNonce(NONCE_A, "user-a"));

		assertEquals(1, mintCount.get());
		assertTokenDeliveries(firstResponses, "refresh-user-a");
		assertTrue(secondResponses.tokenDeliveries().isEmpty(),
				"token was delivered to the hijacking instance");
	}

	private com.hazelcast.map.IMap<String, CliTokenBrokerServiceImpl.NonceEntry> nonceMap() {
		return hazelcast.getMap("cli-token-broker");
	}

	private void awaitParkedCompletion(String nonce) {
		awaitCondition(() -> nonceMap().containsKey("pending:" + nonce),
				"completion was never parked for nonce " + nonce.substring(0, 8));
	}

	private static void awaitCondition(java.util.function.BooleanSupplier condition, String message) {
		long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
		while (System.nanoTime() < deadline) {
			if (condition.getAsBoolean()) return;
			try {
				Thread.sleep(20);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				fail("interrupted while waiting: " + message);
			}
		}
		fail(message);
	}

	private StreamObserver<Kernel.CliTokenBrokerRequest> broker(
			CapturingObserver responses, AtomicInteger mintCount) {
		return broker(responses, mintCount, new ArrayList<>());
	}

	private StreamObserver<Kernel.CliTokenBrokerRequest> broker(
			CapturingObserver responses, AtomicInteger mintCount, List<Boolean> offlineAccessValues) {
		return service(mintCount, offlineAccessValues).brokerStream(null, responses);
	}

	private CliTokenBrokerServiceImpl service(AtomicInteger mintCount, List<Boolean> offlineAccessValues) {
		hazelcast = Hazelcast.newHazelcastInstance(hazelcastConfig());
		return new CliTokenBrokerServiceImpl((complete, nonce, offlineAccess) -> {
			mintCount.incrementAndGet();
			offlineAccessValues.add(offlineAccess);
			return "refresh-" + complete.getSubject();
		}, hazelcast);
	}

	private static Config hazelcastConfig() {
		Config config = new Config();
		config.setClusterName("cli-token-broker-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		return config;
	}

	private static Kernel.CliTokenBrokerRequest register(String instanceId) {
		return Kernel.CliTokenBrokerRequest.newBuilder()
				.setRegister(Kernel.CliTokenBrokerRegister.newBuilder()
						.setInstanceId(instanceId))
				.build();
	}

	private static Kernel.CliTokenBrokerRequest registerNonce(String nonce) {
		return registerNonce(nonce, false);
	}

	private static Kernel.CliTokenBrokerRequest registerNonce(String nonce, boolean offlineAccess) {
		return Kernel.CliTokenBrokerRequest.newBuilder()
				.setRegisterNonce(Kernel.CliTokenBrokerRegisterNonce.newBuilder()
						.setNonce(nonce)
						.setOfflineAccess(offlineAccess))
				.build();
	}

	private static Kernel.CliTokenBrokerRequest completeNonce(String nonce, String subject) {
		return Kernel.CliTokenBrokerRequest.newBuilder()
				.setCompleteNonce(Kernel.CliTokenBrokerCompleteNonce.newBuilder()
						.setNonce(nonce)
						.setSubject(subject))
				.build();
	}

	private static void assertTokenDeliveries(CapturingObserver responses, String refreshToken) {
		List<Kernel.CliTokenBrokerTokenDelivery> deliveries = responses.tokenDeliveries();
		assertEquals(1, deliveries.size());
		assertEquals(refreshToken, deliveries.getFirst().getRefreshToken());
	}

	private static final class CapturingObserver implements StreamObserver<Kernel.CliTokenBrokerResponse> {
		private final List<Kernel.CliTokenBrokerResponse> responses =
				Collections.synchronizedList(new ArrayList<>());

		@Override
		public void onNext(Kernel.CliTokenBrokerResponse value) {
			responses.add(value);
		}

		@Override
		public void onError(Throwable t) {
		}

		@Override
		public void onCompleted() {
		}

		void clear() {
			responses.clear();
		}

		List<Kernel.CliTokenBrokerTokenDelivery> tokenDeliveries() {
			return List.copyOf(responses).stream()
					.filter(Kernel.CliTokenBrokerResponse::hasTokenDelivery)
					.map(Kernel.CliTokenBrokerResponse::getTokenDelivery)
					.toList();
		}
	}
}
