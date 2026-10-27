// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.Attributes;
import io.grpc.Context;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Paired control for the service-caller rate class on pollable state reads.
 *
 * <p>{@code GetAllTickets} has a {@code WatchTickets} counterpart, so the
 * interceptor classifies it HAS_STREAMING and caps it at {@code pollingRate}.
 * That is right for an end-user poller but wrong for an internal service, which
 * has no keyed read for a state map and must call GetAll to read one row. A
 * caller carrying a verified service identity is held to {@code unaryRate}
 * instead — raised, not exempt.
 */
class RateLimitInterceptorServiceReadTest {

	private static final String SERVICE = "example.ExampleStateService";
	private static final double POLLING_RATE = 2.0;
	private static final double UNARY_RATE = 10.0;

	private static final MethodDescriptor.Marshaller<byte[]> MARSHALLER = new MethodDescriptor.Marshaller<>() {
		@Override
		public InputStream stream(byte[] value) {
			return new ByteArrayInputStream(value);
		}

		@Override
		public byte[] parse(InputStream stream) {
			return new byte[0];
		}
	};

	private static final MethodDescriptor<byte[], byte[]> GET_ALL_TICKETS = method(
			"GetAllTickets", MethodDescriptor.MethodType.UNARY);
	private static final MethodDescriptor<byte[], byte[]> WATCH_TICKETS = method(
			"WatchTickets", MethodDescriptor.MethodType.SERVER_STREAMING);

	private static MethodDescriptor<byte[], byte[]> method(String bareName, MethodDescriptor.MethodType type) {
		return MethodDescriptor.<byte[], byte[]>newBuilder(MARSHALLER, MARSHALLER)
				.setType(type)
				.setFullMethodName(MethodDescriptor.generateFullMethodName(SERVICE, bareName))
				.build();
	}

	private static RateLimitInterceptor newInterceptor() {
		ServerCallHandler<byte[], byte[]> noop = (call, headers) -> new ServerCall.Listener<>() {
		};
		ServerServiceDefinition def = ServerServiceDefinition.builder(SERVICE)
				.addMethod(GET_ALL_TICKETS, noop)
				.addMethod(WATCH_TICKETS, noop)
				.build();
		return new RateLimitInterceptor(POLLING_RATE, UNARY_RATE, List.of(def), null);
	}

	/** Issues {@code count} back-to-back GetAllTickets calls; returns how many were admitted. */
	private static int burst(RateLimitInterceptor interceptor, int count) {
		AtomicInteger admitted = new AtomicInteger();
		ServerCallHandler<byte[], byte[]> next = (call, headers) -> {
			admitted.incrementAndGet();
			return new ServerCall.Listener<>() {
			};
		};
		for (int i = 0; i < count; i++) {
			interceptor.interceptCall(new RecordingCall(), new Metadata(), next);
		}
		return admitted.get();
	}

	@Test
	void endUserCallerIsStillCappedAtPollingRate() {
		int admitted = burst(newInterceptor(), 6);
		assertEquals(2, admitted,
				"a caller with no service identity must still be capped at pollingRate=2/s");
	}

	@Test
	void serviceCallerGetsTheRaisedUnaryRate() throws Exception {
		RateLimitInterceptor interceptor = newInterceptor();
		int admitted = Context.current()
				.withValue(SecurityAuthenticator.CALLER_SERVICE_PATH_KEY, "/system/services/example")
				.call(() -> burst(interceptor, 6));
		assertEquals(6, admitted,
				"the same burst from a service identity must not be rate limited at 2/s");
	}

	@Test
	void serviceCallerIsStillBounded() throws Exception {
		RateLimitInterceptor interceptor = newInterceptor();
		int admitted = Context.current()
				.withValue(SecurityAuthenticator.CALLER_SERVICE_PATH_KEY, "/system/services/example")
				.call(() -> burst(interceptor, 20));
		assertTrue(admitted >= 10 && admitted <= 12,
				"a service identity is raised to unaryRate=10/s, not exempted; admitted=" + admitted);
	}

	/** Minimal ServerCall that records the close status and reports a fixed peer. */
	private static final class RecordingCall extends ServerCall<byte[], byte[]> {
		private static final Attributes ATTRS = Attributes.newBuilder()
				.set(Grpc.TRANSPORT_ATTR_REMOTE_ADDR, new InetSocketAddress("10.0.0.1", 4242))
				.build();

		@Override
		public void request(int numMessages) {
		}

		@Override
		public void sendHeaders(Metadata headers) {
		}

		@Override
		public void sendMessage(byte[] message) {
		}

		@Override
		public void close(Status status, Metadata trailers) {
		}

		@Override
		public boolean isCancelled() {
			return false;
		}

		@Override
		public Attributes getAttributes() {
			return ATTRS;
		}

		@Override
		public MethodDescriptor<byte[], byte[]> getMethodDescriptor() {
			return GET_ALL_TICKETS;
		}
	}
}
