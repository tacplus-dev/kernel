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

	/**
	 * RPCs flagged RPC_FLAG_SELF_AUTHENTICATES — they authenticate from the body.
	 * The minting contract's four live on minter.Minter (tacplus's sys/minter.proto,
	 * hosted by kernel); kernel's own policy RPCs stay on kernel.Mint.
	 */
	private static final String[] SELF_AUTHENTICATING = {
		"minter.Minter/MintToken",
		"minter.Minter/MintServiceToken",
		"minter.Minter/MintX509Cert",
		"kernel.Mint/MintClientToken",
	};

	/**
	 * kernel.Mint RPCs carrying no exemption flag — the interceptor must still enforce.
	 * CreateTenantUserLink verifies its device assertion inside the handler but is
	 * declared {@code auth_services: ["*"]} with no RPC_FLAG_SELF_AUTHENTICATES, so the
	 * calling service's bearer is still required at the interceptor.
	 */
	private static final String[] ENFORCED = {
		"kernel.Mint/MintUserToken",
		"kernel.Mint/MintExternalToken",
		"kernel.Mint/CreateTenantUserLink",
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

		// Methods are grouped by the service they live on (kernel.Mint, and the
		// sys minting contract minter.Minter), one ServerServiceDefinition per
		// service — one per method would leave only the last registration bound.
		Map<String, ServerServiceDefinition.Builder> byService = new LinkedHashMap<>();
		for (String[] group : new String[][] {SELF_AUTHENTICATING, ENFORCED}) {
			for (String fullName : group) {
				String service = fullName.substring(0, fullName.indexOf('/'));
				addEchoMethod(byService.computeIfAbsent(service, ServerServiceDefinition::builder), fullName);
			}
		}
		ServerBuilder<?> builder = ServerBuilder.forPort(0);
		for (ServerServiceDefinition.Builder svc : byService.values()) {
			builder.addService(ServerInterceptors.interceptForward(
					svc.build(), authenticator.callerInterceptor()));
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
