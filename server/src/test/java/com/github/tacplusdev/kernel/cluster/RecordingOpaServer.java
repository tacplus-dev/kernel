// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.github.tacplusdev.kernel.model.types.generated.entitlements.Entitlements;
import com.github.tacplusdev.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.Userentitlements;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.stub.StreamObserver;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A fake UncleOPA serving both evaluations kernel makes, EvalEntitlement and
 * EvalProxyPolicy, on a real local gRPC server behind the real generated clients.
 * It records the {@code trace_id} (field 200) of every input it receives, so a
 * test can assert that the OPA calls a request causes carry the request's trace
 * (tacplus-dev/looper#51). Entitlements resolve to {@code namespace} with one
 * grant; proxy policy allows.
 */
final class RecordingOpaServer implements AutoCloseable {

	/** trace_id of each EvalEntitlement input, in arrival order. */
	final List<String> entitlementTraceIds = Collections.synchronizedList(new ArrayList<>());
	/** trace_id of each EvalProxyPolicy input, in arrival order. */
	final List<String> proxyPolicyTraceIds = Collections.synchronizedList(new ArrayList<>());

	private final Server server;
	private final ManagedChannel channel;

	/** The proxy policy's answer; tests may replace it before the call. */
	volatile Proxypolicy.ProxyPolicyEvalResult proxyPolicyResult =
			Proxypolicy.ProxyPolicyEvalResult.newBuilder().setAllow(true).build();

	RecordingOpaServer(String namespace) throws IOException {
		server = ServerBuilder.forPort(0)
				.addService(new com.github.tacplusdev.kernel.model.types.vservices.userentitlements.OpaEvalGrpc
						.OpaEvalImplBase() {
					@Override
					public void evalEntitlement(Userentitlements.EntitlementEvalInput request,
							StreamObserver<Userentitlements.EntitlementEvalResult> obs) {
						entitlementTraceIds.add(request.getTraceId());
						obs.onNext(Userentitlements.EntitlementEvalResult.newBuilder()
								.setNamespace(namespace)
								.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder()
										.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
										.build())
								.build());
						obs.onCompleted();
					}
				})
				.addService(new com.github.tacplusdev.kernel.model.types.vservices.proxypolicy.OpaEvalGrpc
						.OpaEvalImplBase() {
					@Override
					public void evalProxyPolicy(Proxypolicy.ProxyPolicyEvalInput request,
							StreamObserver<Proxypolicy.ProxyPolicyEvalResult> obs) {
						proxyPolicyTraceIds.add(request.getTraceId());
						obs.onNext(proxyPolicyResult);
						obs.onCompleted();
					}
				})
				.build()
				.start();
		channel = ManagedChannelBuilder.forAddress("localhost", server.getPort())
				.usePlaintext()
				.build();
	}

	OpaEvalGrpcClient entitlementClient() {
		return new OpaEvalGrpcClient(channel, () -> "test-token");
	}

	com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient
			proxyPolicyClient() {
		return new com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy
				.OpaEvalGrpcClient(channel, () -> "test-token");
	}

	@Override
	public void close() {
		channel.shutdownNow();
		server.shutdownNow();
	}
}
