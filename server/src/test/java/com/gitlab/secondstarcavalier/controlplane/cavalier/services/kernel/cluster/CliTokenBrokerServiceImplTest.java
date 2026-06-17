// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.services.kernel.Kernel;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = broker(responses, mintCount);
		requests.onNext(register("oauth-a"));
		responses.clear();

		requests.onNext(registerNonce(NONCE_A));
		requests.onNext(completeNonce(NONCE_A, "user-a"));

		assertEquals(1, mintCount.get());
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
		assertEquals(1, mintCount.get());
		long expiredCreatedAt = (System.currentTimeMillis() / 1000) - 301;
		hazelcast.<String, CliTokenBrokerServiceImpl.NonceEntry>getMap("cli-token-broker")
				.put("delivery:" + NONCE_C,
						new CliTokenBrokerServiceImpl.NonceEntry("", "refresh-user-c", expiredCreatedAt));

		requests.onNext(registerNonce(NONCE_C));

		assertTrue(responses.tokenDeliveries().isEmpty());
	}

	private StreamObserver<Kernel.CliTokenBrokerRequest> broker(
			CapturingObserver responses, AtomicInteger mintCount) {
		hazelcast = Hazelcast.newHazelcastInstance(hazelcastConfig());
		CliTokenBrokerServiceImpl service = new CliTokenBrokerServiceImpl((complete, nonce) -> {
			mintCount.incrementAndGet();
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
		return Kernel.CliTokenBrokerRequest.newBuilder()
				.setRegisterNonce(Kernel.CliTokenBrokerRegisterNonce.newBuilder()
						.setNonce(nonce))
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
		private final List<Kernel.CliTokenBrokerResponse> responses = new ArrayList<>();

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
			return responses.stream()
					.filter(Kernel.CliTokenBrokerResponse::hasTokenDelivery)
					.map(Kernel.CliTokenBrokerResponse::getTokenDelivery)
					.toList();
		}
	}
}
