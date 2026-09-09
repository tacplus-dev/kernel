// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.Opa;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.OpaStateServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The runtime half of the store-authorization wiring: the graph key
 * {@code BackendStoreServerGenerator} now emits — {@code "<proto package>.<value
 * type>"}, {@code AccessPolicy.graphKey()}'s format — must resolve in the shipped
 * {@code GRAPH_POLICIES} map and deny a foreign service. tacplus computes a
 * policy for every {@code (spec.service_store)} message, and
 * {@code kernel.KernelDiskState} is the one the platform declares today:
 * {@code rw: [service:kernel], ro: ["*"]}.
 *
 * <p>The decision is evaluated exactly where a generated store server evaluates
 * it — downstream of the real {@link SecurityAuthenticator#callerInterceptor()},
 * on a real listening server, under a real kernel-signed token — so the caller
 * identity is the one a production RPC would carry, not a synthesized Context.
 *
 * <p>{@code KernelDiskState} has no {@code store_key}, so it emits a UC1 snapshot
 * and no store service; there is no generated store server in this tree to drive
 * over gRPC. That the generator emits this key at all is asserted against real
 * generator output by {@code StoreServerAuthorizationTest} in the codegen module.
 */
class StoreGraphAuthorizationTest extends StateChrootTestBase {

	private static final String STORE_GRAPH = "kernel.KernelDiskState";
	private static final String BOUNDARY = "KernelDiskState";

	/**
	 * Makes one real RPC as {@code serviceName} and, in the handler's Context,
	 * runs the store server's authorization check against {@code graph}.
	 *
	 * @return the denial, or null if the check allowed the caller
	 */
	private ProtoException checkAs(String serviceName, String graph,
			SecurityAuthenticator.OperationType op) throws Exception {
		AtomicReference<ProtoException> denial = new AtomicReference<>();
		ServerInterceptor storeCheck = new ServerInterceptor() {
			@Override
			public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
					ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
				try {
					authenticator.checkAccess(graph, BOUNDARY, op);
				} catch (ProtoException e) {
					denial.set(e);
				}
				return Contexts.interceptCall(Context.current(), call, headers, next);
			}
		};
		startServer(ServerInterceptors.interceptForward(
				stateServer.bindService(), authenticator.callerInterceptor(), storeCheck));

		try {
			OpaStateServiceGrpc.newBlockingStub(channel)
					.withInterceptors(bearer(tokenFor(SpiffeIds.build(TRUST_DOMAIN, serviceName), serviceName)))
					.sizeTenantEntitlementsPolicies(
							Opa.TenantEntitlementsPoliciesSizeRequest.newBuilder().build());
		} catch (StatusRuntimeException e) {
			// The carrier RPC belongs to opa's own state graph, so a caller that is
			// not opa is rejected by the state server after the store check has run.
			// Only the store decision recorded above is under test here.
		}
		return denial.get();
	}

	/** The gap A1 closes: a foreign service could write every row of every store. */
	@Test
	void aForeignServiceIsDeniedWriteOnTheStoreGraph() throws Exception {
		ProtoException denial = checkAs("echo", STORE_GRAPH, SecurityAuthenticator.OperationType.WRITE);

		assertNotNull(denial, "echo owns no part of kernel's store and must not write it");
		assertTrue(denial.getMessage().contains("echo") && denial.getMessage().contains(STORE_GRAPH),
				"the denial must name the caller and the graph: " + denial.getMessage());
	}

	/** The owning service keeps the access its own policy grants. */
	@Test
	void theOwningServiceIsAllowedWriteOnTheStoreGraph() throws Exception {
		assertNull(checkAs("kernel", STORE_GRAPH, SecurityAuthenticator.OperationType.WRITE),
				"kernel is the store's rw subject");
	}

	/**
	 * What A1 does NOT close, recorded rather than glossed: tacplus still computes
	 * {@code ro: ["*"]} for a store, so every authenticated service may still read
	 * it. Tightening that is the tacplus-side change (A2); this test is the
	 * tripwire that will fail — deliberately — when it lands.
	 */
	@Test
	void aForeignServiceIsStillAllowedReadUntilTacplusTightensRo() throws Exception {
		assertNull(checkAs("echo", STORE_GRAPH, SecurityAuthenticator.OperationType.READ),
				"the computed store policy is still ro: [\"*\"] — A2 is what closes reads");
	}

	/** Control: what the store server did before A1 — no check at all. */
	@Test
	void theNoPolicyMarkerAuthorizesEveryCaller() throws Exception {
		assertNull(checkAs("echo", SecurityAuthenticator.NO_POLICY_GRAPH,
				SecurityAuthenticator.OperationType.WRITE),
				"NO_POLICY_GRAPH short-circuits checkAccess before any caller check");
	}
}
