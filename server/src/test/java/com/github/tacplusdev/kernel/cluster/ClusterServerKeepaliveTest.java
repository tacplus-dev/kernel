// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import io.grpc.Attributes;
import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.ServerTransportFilter;
import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthGrpc;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.protobuf.services.HealthStatusManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * DEFECT #12: stratum logged {@code GOAWAY ENHANCE_YOUR_CALM too_many_pings}
 * from kernel because ClusterServer — hand-written, not the generated
 * GrpcServer — left grpc-java's default keepalive enforcement in place
 * (5 minutes, or 2 hours with no active call). A tacplus-generated client
 * pings every 30s with keepAliveWithoutCalls, so with that default an idle
 * connection takes its third ping strike at ~90s and is torn down.
 *
 * <p>This holds an idle connection open with the generated client's exact
 * keepalive settings for longer than that and asserts the server never
 * closed it.
 */
class ClusterServerKeepaliveTest {

	/** Past the third 30s ping (~90s), when the grpc-java default sends GOAWAY. */
	private static final long IDLE_SECONDS = 105;

	private Server server;
	private ManagedChannel channel;

	@AfterEach
	void tearDown() throws Exception {
		if (channel != null) {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
		if (server != null) {
			server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	@Test
	void clientPingingEvery30sIsNeverSentGoaway() throws Exception {
		AtomicInteger opened = new AtomicInteger();
		AtomicInteger closed = new AtomicInteger();
		server = ClusterServer.permitPlatformKeepalive(NettyServerBuilder.forPort(0))
				.addService(new HealthStatusManager().getHealthService())
				.addTransportFilter(new ServerTransportFilter() {
					@Override
					public Attributes transportReady(Attributes attrs) {
						opened.incrementAndGet();
						return attrs;
					}

					@Override
					public void transportTerminated(Attributes attrs) {
						closed.incrementAndGet();
					}
				})
				.build()
				.start();

		// Same keepalive as the generated ServiceConnection / IdentityManager channels.
		channel = NettyChannelBuilder.forAddress("127.0.0.1", server.getPort())
				.usePlaintext()
				.keepAliveTime(30, TimeUnit.SECONDS)
				.keepAliveTimeout(10, TimeUnit.SECONDS)
				.keepAliveWithoutCalls(true)
				.build();
		HealthGrpc.newBlockingStub(channel).check(HealthCheckRequest.getDefaultInstance());

		Thread.sleep(TimeUnit.SECONDS.toMillis(IDLE_SECONDS));

		assertEquals(0, closed.get(), "server closed the client's connection (GOAWAY too_many_pings)");
		assertEquals(1, opened.get(), "client had to reconnect");
		assertEquals(ConnectivityState.READY, channel.getState(false));
	}
}
