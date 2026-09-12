// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
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
	void completeBeforeRegisterBuffersAndReplaysOnce() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(completeNonce(NONCE_B, "user-b"));
		awaitBufferedDelivery(NONCE_B);
		assertEquals(1, mintCount.get());
		assertTrue(responses.tokenDeliveries().isEmpty());

		requests.onNext(registerNonce(NONCE_B));
		assertTokenDeliveries(responses, "refresh-user-b");

		responses.clear();
		requests.onNext(registerNonce(NONCE_B));
		requests.onNext(completeNonce(NONCE_B, "different-user"));
		assertEquals(1, mintCount.get());
		assertTrue(responses.tokenDeliveries().isEmpty());
	}

	@Test
	void expiredBufferedDeliveryIsDiscarded() {
		CapturingObserver responses = new CapturingObserver();
		AtomicInteger mintCount = new AtomicInteger();
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(completeNonce(NONCE_C, "user-c"));
		awaitBufferedDelivery(NONCE_C);
		assertEquals(1, mintCount.get());
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

	private com.hazelcast.map.IMap<String, CliTokenBrokerServiceImpl.NonceEntry> nonceMap() {
		return hazelcast.getMap("cli-token-broker");
	}

	private void awaitBufferedDelivery(String nonce) {
		awaitCondition(() -> nonceMap().containsKey("delivery:" + nonce),
				"token was never buffered for nonce " + nonce.substring(0, 8));
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
		hazelcast = Hazelcast.newHazelcastInstance(hazelcastConfig());
		CliTokenBrokerServiceImpl service = new CliTokenBrokerServiceImpl((complete, nonce, offlineAccess) -> {
			mintCount.incrementAndGet();
			offlineAccessValues.add(offlineAccess);
			return "refresh-" + complete.getSubject();
		}, hazelcast);
		return service.brokerStream(null, responses);
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
