// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.Opa;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.OpaStateServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Goal A item 3 prerequisite: {@code SecurityAuthenticator.CALLER_NAMESPACE_KEY}.
 *
 * <p>Before this, the caller interceptor put only {@code caller-service},
 * {@code caller-service-path} and {@code caller-instance-id} into the gRPC
 * Context — no namespace claim at all — so a state RPC could not compute the
 * caller's key prefix. This asserts the key is populated by the real
 * {@link SecurityAuthenticator#callerInterceptor()} for both subject shapes:
 * a shared {@code /system} service and a tenant-owned {@code /tenants/<t>}
 * instance.
 */
class CallerNamespaceContextTest extends StateChrootTestBase {

	/** Records the Context values a handler downstream of callerInterceptor sees. */
	private static final class Captured {
		String namespace;
		String servicePath;
	}

	private Captured callAs(String subject) throws Exception {
		AtomicReference<Captured> seen = new AtomicReference<>();
		ServerInterceptor capture = new ServerInterceptor() {
			@Override
			public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
					ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
				Captured c = new Captured();
				c.namespace = SecurityAuthenticator.CALLER_NAMESPACE_KEY.get();
				c.servicePath = SecurityAuthenticator.CALLER_SERVICE_PATH_KEY.get();
				seen.set(c);
				return Contexts.interceptCall(Context.current(), call, headers, next);
			}
		};
		// callerInterceptor first, then the capture — so the capture reads the
		// Context the caller interceptor installed, which is what every state
		// fragment reads.
		startServer(ServerInterceptors.interceptForward(
				stateServer.bindService(), authenticator.callerInterceptor(), capture));

		OpaStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(subject, "opa")))
				.sizeTenantEntitlementsPolicies(
						Opa.TenantEntitlementsPoliciesSizeRequest.newBuilder().build());
		return seen.get();
	}

	@Test
	void systemServiceCallerGetsTheSystemNamespace() throws Exception {
		Captured c = callAs(SpiffeIds.build(TRUST_DOMAIN, "opa"));

		assertEquals("/system", c.namespace);
		assertEquals("opa", c.servicePath);
	}

	@Test
	void tenantOwnedCallerGetsItsTenantNamespace() throws Exception {
		Captured c = callAs(SpiffeIds.build(TRUST_DOMAIN, "/tenants/acme", "opa"));

		assertEquals("/tenants/acme", c.namespace);
		// The service path is unchanged by the tenant, which is what keeps the
		// generated auth_services / checkAccess policies matching per service name.
		assertEquals("opa", c.servicePath);
	}
}
