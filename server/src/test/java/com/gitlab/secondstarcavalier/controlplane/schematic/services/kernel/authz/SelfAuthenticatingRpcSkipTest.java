// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
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
 * The proto tree's per-RPC auth exemption moved from {@code (spec.method_s2s) =
 * {auth_disabled: true}} to {@code (spec.rpc) = {flags: [RPC_FLAG_SELF_AUTHENTICATES]}}.
 * The codegen proto parser only understood the retired form, so the generated
 * SecurityAuthenticator's NO_AUTH_METHODS set came out empty and the caller
 * interceptor rejected every {@code kernel.Mint} call with "missing authorization
 * header" before IdentityServiceImpl could authenticate the caller from the request
 * body itself.
 *
 * <p>Real gRPC server behind the real generated {@link SecurityAuthenticator#callerInterceptor()},
 * real unauthenticated calls over the wire — the interceptor sees nothing but the full
 * method name, so declaring the methods by name is the whole of what it decides on.
 */
class SelfAuthenticatingRpcSkipTest {

	/** kernel.Mint RPCs flagged RPC_FLAG_SELF_AUTHENTICATES — they authenticate from the body. */
	private static final String[] SELF_AUTHENTICATING = {
		"kernel.Mint/MintToken",
		"kernel.Mint/MintServiceToken",
		"kernel.Mint/MintClientToken",
		"kernel.Mint/MintX509Cert",
	};

	/** kernel.Mint RPCs carrying no exemption flag — the interceptor must still enforce. */
	private static final String[] ENFORCED = {
		"kernel.Mint/MintUserToken",
		"kernel.Mint/MintExternalToken",
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

		// Every method here lives on the one service kernel.Mint, so they must be
		// registered as a single ServerServiceDefinition — one per method would
		// leave only the last registration bound.
		ServerServiceDefinition.Builder mint = ServerServiceDefinition.builder("kernel.Mint");
		for (String fullName : SELF_AUTHENTICATING) {
			addEchoMethod(mint, fullName);
		}
		for (String fullName : ENFORCED) {
			addEchoMethod(mint, fullName);
		}
		server = ServerBuilder.forPort(0)
				.addService(ServerInterceptors.interceptForward(
						mint.build(), authenticator.callerInterceptor()))
				.build()
				.start();
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

	private void addEchoMethod(ServerServiceDefinition.Builder builder, String fullMethodName) {
		MethodDescriptor<String, String> md = MethodDescriptor.<String, String>newBuilder()
				.setType(MethodDescriptor.MethodType.UNARY)
				.setFullMethodName(fullMethodName)
				.setRequestMarshaller(STRINGS)
				.setResponseMarshaller(STRINGS)
				.build();
		methods.put(fullMethodName, md);
		builder.addMethod(md, ServerCalls.asyncUnaryCall((req, obs) -> {
			obs.onNext("reached:" + fullMethodName);
			obs.onCompleted();
		}));
	}

	/** Calls {@code fullMethodName} with no authorization metadata at all. */
	private String callUnauthenticated(String fullMethodName) {
		return ClientCalls.blockingUnaryCall(
				channel, methods.get(fullMethodName), CallOptions.DEFAULT, "ping");
	}

	@Test
	void selfAuthenticatingRpcsPassUnauthenticated() {
		for (String fullMethodName : SELF_AUTHENTICATING) {
			assertEquals("reached:" + fullMethodName, callUnauthenticated(fullMethodName),
					fullMethodName + " is flagged RPC_FLAG_SELF_AUTHENTICATES and must reach its "
							+ "handler without a bearer header — the handler does the auth");
		}
	}

	@Test
	void unflaggedRpcsOnTheSameServiceStillEnforce() {
		for (String fullMethodName : ENFORCED) {
			StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
					() -> callUnauthenticated(fullMethodName),
					fullMethodName + " carries no exemption flag and must not inherit one from "
							+ "its self-authenticating siblings");
			assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode(),
					fullMethodName + " must be rejected as unauthenticated");
			assertEquals("missing authorization header", e.getStatus().getDescription());
		}
	}
}
