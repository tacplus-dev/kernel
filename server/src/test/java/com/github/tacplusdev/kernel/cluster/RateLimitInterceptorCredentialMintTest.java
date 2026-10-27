// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

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
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Credential issuance must be rate limited.
 *
 * <p>{@code Mint*} RPCs are writes, so the interceptor's verb table used to
 * sweep them into the write exemption — and the Mint service is built after
 * the interceptor in {@code ClusterServer}, so its methods were not even in
 * the classification map, which exempts them a second way. Either gap alone
 * leaves the token/cert minting surface unthrottled against brute-forcing a
 * cred_pair or bulk-minting tokens. Both are closed: Mint methods classify as
 * CREDENTIAL and are held to {@code unaryRate}, and the service can be
 * registered with the interceptor after construction.
 *
 * <p>State-map writes stay exempt — this fix is scoped to credential issuance,
 * not to writes in general.
 */
class RateLimitInterceptorCredentialMintTest {

	private static final String MINT_SERVICE = "kernel.Mint";
	private static final String STATE_SERVICE = "example.ExampleStateService";
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

	private static final MethodDescriptor<byte[], byte[]> MINT_TOKEN = method(MINT_SERVICE, "MintToken");
	private static final MethodDescriptor<byte[], byte[]> MINT_X509_CERT = method(MINT_SERVICE, "MintX509Cert");
	private static final MethodDescriptor<byte[], byte[]> PUT_TICKETS = method(STATE_SERVICE, "PutTickets");

	private static MethodDescriptor<byte[], byte[]> method(String service, String bareName) {
		return MethodDescriptor.<byte[], byte[]>newBuilder(MARSHALLER, MARSHALLER)
				.setType(MethodDescriptor.MethodType.UNARY)
				.setFullMethodName(MethodDescriptor.generateFullMethodName(service, bareName))
				.build();
	}

	private static final ServerCallHandler<byte[], byte[]> NOOP = (call, headers) -> new ServerCall.Listener<>() {
	};

	private static ServerServiceDefinition mintService() {
		return ServerServiceDefinition.builder(MINT_SERVICE)
				.addMethod(MINT_TOKEN, NOOP)
				.addMethod(MINT_X509_CERT, NOOP)
				.build();
	}

	private static ServerServiceDefinition stateService() {
		return ServerServiceDefinition.builder(STATE_SERVICE)
				.addMethod(PUT_TICKETS, NOOP)
				.build();
	}

	/** Issues {@code count} back-to-back calls to {@code md}; returns how many were admitted. */
	private static int burst(RateLimitInterceptor interceptor, MethodDescriptor<byte[], byte[]> md, int count) {
		AtomicInteger admitted = new AtomicInteger();
		ServerCallHandler<byte[], byte[]> next = (call, headers) -> {
			admitted.incrementAndGet();
			return new ServerCall.Listener<>() {
			};
		};
		for (int i = 0; i < count; i++) {
			interceptor.interceptCall(new RecordingCall(md), new Metadata(), next);
		}
		return admitted.get();
	}

	@Test
	void mintIsHeldToUnaryRate() {
		var interceptor = new RateLimitInterceptor(POLLING_RATE, UNARY_RATE, List.of(mintService()), null);
		int admitted = burst(interceptor, MINT_TOKEN, 40);
		assertTrue(admitted >= 10 && admitted <= 12,
				"MintToken must be bounded at unaryRate=10/s, not exempt; admitted=" + admitted);
		assertTrue(interceptor.getRateLimitedCount() > 0, "rejected mints must be counted");
	}

	@Test
	void mintX509CertIsHeldToUnaryRate() {
		var interceptor = new RateLimitInterceptor(POLLING_RATE, UNARY_RATE, List.of(mintService()), null);
		int admitted = burst(interceptor, MINT_X509_CERT, 40);
		assertTrue(admitted >= 10 && admitted <= 12,
				"MintX509Cert must be bounded at unaryRate=10/s, not exempt; admitted=" + admitted);
	}

	@Test
	void mintRegisteredAfterConstructionIsStillLimited() {
		// ClusterServer builds the interceptor from the state-plane services
		// only; the Mint service comes later and registers itself.
		var interceptor = new RateLimitInterceptor(POLLING_RATE, UNARY_RATE, List.of(stateService()), null);
		interceptor.registerServices(List.of(mintService()));
		int admitted = burst(interceptor, MINT_TOKEN, 40);
		assertTrue(admitted >= 10 && admitted <= 12,
				"a Mint service registered after construction must be bounded; admitted=" + admitted);
	}

	@Test
	void stateMapWritesStayExempt() {
		var interceptor = new RateLimitInterceptor(POLLING_RATE, UNARY_RATE, List.of(stateService()), null);
		assertEquals(40, burst(interceptor, PUT_TICKETS, 40),
				"this fix is scoped to credential issuance — state-map writes stay exempt");
	}

	/** Minimal ServerCall for one method descriptor, reporting a fixed peer. */
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
