// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.authz;

import com.github.tacplusdev.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.CallOptions;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * F6 — the generated no-auth skip list matched the full {@code package.Service/Method}
 * string with unanchored {@code String.contains}, so any service or RPC whose name
 * merely contained a skip-list entry as a substring lost authentication entirely.
 *
 * <p>Real gRPC server, real generated {@link SecurityAuthenticator#callerInterceptor()},
 * real unauthenticated calls over the wire. The methods are declared by full name only —
 * that is all the interceptor looks at — so the decoys can carry names no proto in the
 * tree defines today, which is exactly the future-service trap being closed.
 */
class NoAuthSkipAnchorTest {

	/** The five services the generated skip list legitimately names. */
	private static final String[] SKIPPED = {
		"tlscert.TlsCertService/ManageCert",
		"smbcert.SmbCertService/ManageSmbCert",
		"grpcconfig.ClusterService/Ping",
		"jwkview.JwkVerifyingKeysViewService/Get",
		"publicjwksview.PublicJwksViewService/Get",
	};

	/**
	 * Names that contain a skip-list entry as a proper substring: a superstring
	 * service name, a superstring package, and a superstring RPC name.
	 */
	private static final String[] DECOYS = {
		"kernel.ClusterServiceV2/Ping",
		"kernel.MyClusterService/Ping",
		"sentinel.Admin/GetClusterServiceStats",
	};

	private static final MethodDescriptor.Marshaller<String> STRINGS =
			new MethodDescriptor.Marshaller<>() {
				@Override
				public InputStream stream(String value) {
					return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
				}

				@Override
				public String parse(InputStream stream) {
					try {
						return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				}
			};

	private final Map<String, MethodDescriptor<String, String>> methods = new LinkedHashMap<>();

	private Server server;
	private ManagedChannel channel;

	@BeforeEach
	void setUp() throws Exception {
		SecurityAuthenticator authenticator = new SecurityAuthenticator();

		ServerBuilder<?> builder = ServerBuilder.forPort(0);
		for (String fullName : SKIPPED) {
			builder.addService(ServerInterceptors.interceptForward(
					echoService(fullName), authenticator.callerInterceptor()));
		}
		for (String fullName : DECOYS) {
			builder.addService(ServerInterceptors.interceptForward(
					echoService(fullName), authenticator.callerInterceptor()));
		}
		server = builder.build().start();
		channel = ManagedChannelBuilder.forAddress("localhost", server.getPort())
				.usePlaintext()
				.build();
	}

	@AfterEach
	void tearDown() throws Exception {
		if (channel != null) {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
		if (server != null) {
			server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	private ServerServiceDefinition echoService(String fullMethodName) {
		MethodDescriptor<String, String> md = MethodDescriptor.<String, String>newBuilder()
				.setType(MethodDescriptor.MethodType.UNARY)
				.setFullMethodName(fullMethodName)
				.setRequestMarshaller(STRINGS)
				.setResponseMarshaller(STRINGS)
				.build();
		methods.put(fullMethodName, md);
		return ServerServiceDefinition
				.builder(MethodDescriptor.extractFullServiceName(fullMethodName))
				.addMethod(md, ServerCalls.asyncUnaryCall((req, obs) -> {
					obs.onNext("reached:" + fullMethodName);
					obs.onCompleted();
				}))
				.build();
	}

	/** Calls {@code fullMethodName} with no authorization metadata at all. */
	private String callUnauthenticated(String fullMethodName) {
		return ClientCalls.blockingUnaryCall(
				channel, methods.get(fullMethodName), CallOptions.DEFAULT, "ping");
	}

	@Test
	void skipListServicesStillPassUnauthenticated() {
		for (String fullMethodName : SKIPPED) {
			assertEquals("reached:" + fullMethodName, callUnauthenticated(fullMethodName),
					fullMethodName + " is on the no-auth skip list and must still be reachable "
							+ "without a token");
		}
	}

	@Test
	void superstringNamesAreNotSkipped() {
		for (String fullMethodName : DECOYS) {
			StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
					() -> callUnauthenticated(fullMethodName),
					fullMethodName + " only contains a skip-list entry as a substring and must "
							+ "not inherit its no-auth exemption");
			assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode(),
					fullMethodName + " must be rejected as unauthenticated");
			assertEquals("missing authorization header", e.getStatus().getDescription());
		}
	}
}
