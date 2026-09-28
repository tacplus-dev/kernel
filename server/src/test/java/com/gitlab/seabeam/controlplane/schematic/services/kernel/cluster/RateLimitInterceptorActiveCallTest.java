// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import io.grpc.Attributes;
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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The in-flight counters must come back to zero however a call ends.
 *
 * <p>{@link RateLimitInterceptor} decrements them in the wrapped call's {@code
 * close()}, but gRPC does not guarantee {@code close()} runs: a client
 * cancellation or a transport drop ends the call through the listener's {@code
 * onCancel()} instead. That override used to do nothing but delegate, so every
 * cancelled call leaked a count and {@code getActiveRpcs()} /
 * {@code getActiveStreams()} — which feed health and metrics — drifted upward
 * forever and never returned to zero on an idle node.
 */
class RateLimitInterceptorActiveCallTest {

	private static final String SERVICE = "scotty.ScottyStateService";

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

	/** Rates high enough that nothing under test is ever rejected before tracking. */
	private static RateLimitInterceptor newInterceptor() {
		ServerCallHandler<byte[], byte[]> noop = (call, headers) -> new ServerCall.Listener<>() {
		};
		ServerServiceDefinition def = ServerServiceDefinition.builder(SERVICE)
				.addMethod(GET_ALL_TICKETS, noop)
				.addMethod(WATCH_TICKETS, noop)
				.build();
		return new RateLimitInterceptor(1000.0, 1000.0, List.of(def), null);
	}

	/**
	 * Admits one call and hands back the listener the interceptor returned plus
	 * the call it wrapped, which is what a real handler would close.
	 */
	private static Admitted admit(RateLimitInterceptor interceptor, MethodDescriptor<byte[], byte[]> md) {
		AtomicReference<ServerCall<byte[], byte[]>> wrapped = new AtomicReference<>();
		ServerCallHandler<byte[], byte[]> next = (call, headers) -> {
			wrapped.set(call);
			return new ServerCall.Listener<>() {
			};
		};
		ServerCall.Listener<byte[]> listener =
				interceptor.interceptCall(new RecordingCall(md), new Metadata(), next);
		return new Admitted(listener, wrapped.get());
	}

	private record Admitted(ServerCall.Listener<byte[]> listener, ServerCall<byte[], byte[]> call) {}

	@Test
	void aCancelledUnaryCallReleasesItsInFlightCount() {
		RateLimitInterceptor interceptor = newInterceptor();
		Admitted a = admit(interceptor, GET_ALL_TICKETS);
		assertEquals(1, interceptor.getActiveRpcs(), "the admitted call is in flight");

		// A client cancellation / transport drop: onCancel, never close.
		a.listener().onCancel();

		assertEquals(0, interceptor.getActiveRpcs(),
				"a cancelled call must release its in-flight count, not leak it");
	}

	@Test
	void aCancelledStreamReleasesBothCounts() {
		RateLimitInterceptor interceptor = newInterceptor();
		Admitted a = admit(interceptor, WATCH_TICKETS);
		assertEquals(1, interceptor.getActiveRpcs());
		assertEquals(1, interceptor.getActiveStreams(), "a server-streaming call counts as a stream");

		a.listener().onCancel();

		assertEquals(0, interceptor.getActiveRpcs());
		assertEquals(0, interceptor.getActiveStreams(),
				"a cancelled stream must release its stream count too");
	}

	@Test
	void manyCancelledCallsLeaveAnIdleNodeAtZero() {
		RateLimitInterceptor interceptor = newInterceptor();
		for (int i = 0; i < 50; i++) {
			admit(interceptor, GET_ALL_TICKETS).listener().onCancel();
			admit(interceptor, WATCH_TICKETS).listener().onCancel();
		}
		assertEquals(0, interceptor.getActiveRpcs(), "reported in-flight count must not drift upward");
		assertEquals(0, interceptor.getActiveStreams());
	}

	@Test
	void closeStillDecrementsExactlyOnce() {
		RateLimitInterceptor interceptor = newInterceptor();
		Admitted a = admit(interceptor, WATCH_TICKETS);

		a.call().close(Status.OK, new Metadata());

		assertEquals(0, interceptor.getActiveRpcs());
		assertEquals(0, interceptor.getActiveStreams());
	}

	/**
	 * gRPC may deliver onCancel after close, and close is itself re-entrant-safe.
	 * The shared flag must make the pair decrement once, never twice — a negative
	 * count misreports just as badly as a leaked one.
	 */
	@Test
	void closeThenCancelDecrementsOnceNotTwice() {
		RateLimitInterceptor interceptor = newInterceptor();
		Admitted a = admit(interceptor, WATCH_TICKETS);

		a.call().close(Status.OK, new Metadata());
		a.listener().onCancel();
		a.call().close(Status.OK, new Metadata());

		assertEquals(0, interceptor.getActiveRpcs(), "must not go negative");
		assertEquals(0, interceptor.getActiveStreams(), "must not go negative");
	}

	/** Minimal ServerCall for a given method that reports a fixed peer. */
	private static final class RecordingCall extends ServerCall<byte[], byte[]> {
		private static final Attributes ATTRS = Attributes.newBuilder()
				.set(Grpc.TRANSPORT_ATTR_REMOTE_ADDR, new InetSocketAddress("10.0.0.1", 4242))
				.build();

		private final MethodDescriptor<byte[], byte[]> md;

		RecordingCall(MethodDescriptor<byte[], byte[]> md) {
			this.md = md;
		}

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
			return md;
		}
	}
}
