// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.Opa;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.OpaStateServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.NamespaceScope;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Goal B item 4: a NON-service token must not be handed the unconfined scope.
 *
 * <p>Before this, {@code SecurityAuthenticator} computed a caller namespace only
 * for {@code service}/{@code workload} tokens, and {@code NamespaceScope} read
 * anything that was not {@code /tenants/…} — the empty string included — as the
 * ROOT, identity-rewrite scope. A {@code sub_type = user} token therefore reached
 * kernel state fleet-wide unconfined. {@code checkAccess} hides that on every
 * POLICED graph (a user token has no service path, so it is denied there), but the
 * store servers pass {@link SecurityAuthenticator#NO_POLICY_GRAPH} and enforce
 * nothing — there, the scope is the only boundary there is.
 *
 * <p>The kernel generates no store server, so this test exercises that unpoliced
 * surface directly: a real listening gRPC server, real kernel-signed tokens, and
 * the real {@link SecurityAuthenticator#callerInterceptor()}, with a downstream
 * interceptor that applies to a shared map exactly the operations
 * {@code BackendStoreServiceServer} applies — {@code scope} on ingress,
 * {@code owns}/{@code unscope} on enumeration. Nothing about the scope is
 * constructed by hand: it comes from a signed token, over the wire.
 */
class UserTokenNamespaceChrootTest extends StateChrootTestBase {

	/** The shared, tenant-blind backing map every kernel store boundary really is. */
	private static Map<String, String> store() {
		Map<String, String> m = new LinkedHashMap<>();
		m.put("/tenants/acme/k", "acme");
		m.put("/tenants/beta/k", "beta");
		m.put("k", "system");
		return m;
	}

	/** What one caller could observe of {@link #store()} through its own scope. */
	private static final class Seen {
		boolean isRoot;
		String servicePath;
		String get;
		List<String> keys;
		RuntimeException scopeRefused;
	}

	private final AtomicReference<Seen> lastSeen = new AtomicReference<>();

	/**
	 * The unpoliced store surface, as an interceptor so it reads the same gRPC
	 * Context the generated fragments read.
	 */
	@BeforeEach
	void startStoreSurface() throws Exception {
		ServerInterceptor storeFragment = new ServerInterceptor() {
			@Override
			public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
					ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
				Map<String, String> map = store();
				NamespaceScope scope = NamespaceScope.current();
				Seen s = new Seen();
				s.isRoot = scope.isRoot();
				s.servicePath = SecurityAuthenticator.CALLER_SERVICE_PATH_KEY.get();
				// Enumeration first: owns() is total, so it reports the empty
				// slice rather than refusing, for every scope.
				s.keys = map.keySet().stream().filter(scope::owns).map(scope::unscope).sorted().toList();
				try {
					s.get = map.get(scope.scope("k"));
				} catch (RuntimeException e) {
					s.scopeRefused = e;
				}
				lastSeen.set(s);
				return Contexts.interceptCall(Context.current(), call, headers, next);
			}
		};
		startServer(ServerInterceptors.interceptForward(
				stateServer.bindService(), authenticator.callerInterceptor(), storeFragment));
	}

	/**
	 * Runs one authenticated RPC with {@code token} and reports what the scope the
	 * caller interceptor installed lets it see of the shared store.
	 */
	private Seen observe(String token) {
		try {
			OpaStateServiceGrpc.newBlockingStub(channel)
					.withInterceptors(bearer(token))
					.sizeTenantEntitlementsPolicies(
							Opa.TenantEntitlementsPoliciesSizeRequest.newBuilder().build());
		} catch (StatusRuntimeException expectedOnPolicedGraphs) {
			// A token with no service path is denied by checkAccess on opa.OpaState.
			// The store fragment above has already run: that is the unpoliced surface.
		}
		return lastSeen.get();
	}

	// ---- the boundary -------------------------------------------------------

	/**
	 * The guarantee this item exists for: a user token whose kernel-stamped
	 * namespace claim is a tenant is confined to that tenant, exactly as a
	 * tenant-owned SERVICE token already was.
	 */
	@Test
	void aUserTokenStampedWithATenantIsChrootedToThatTenant() {
		Seen acme = observe(principalTokenFor("user", "alice@acme.example", "/tenants/acme"));

		assertFalse(acme.isRoot, "a tenant user token must not get the identity rewrite");
		assertNull(acme.scopeRefused);
		assertEquals("acme", acme.get, "must read its own tenant's row under the bare key");
		assertEquals(List.of("k"), acme.keys, "must enumerate only its own tenant's rows");

		// The other direction, which is the whole point: each sees only its own,
		// and neither sees the shared /system row.
		Seen beta = observe(principalTokenFor("user", "bob@beta.example", "/tenants/beta"));
		assertFalse(beta.isRoot);
		assertEquals("beta", beta.get);
		assertEquals(List.of("k"), beta.keys);
	}

	/**
	 * A token class for which no namespace is computed at all — {@code pipeline}
	 * today, and anything the SubType enum grows tomorrow — must own NOTHING.
	 *
	 * <p>It must specifically not be the root scope (that is the bug), and it must
	 * specifically not be "chrooted under the empty namespace" either: that prefix
	 * is "/", which is a prefix of every tenant's storage key, so it would hand
	 * over every tenant's rows instead of confining anything.
	 */
	@Test
	void aTokenWithNoComputedNamespaceOwnsNothing() {
		Seen none = observe(principalTokenFor("pipeline", "ci-runner", "/tenants/acme"));

		assertFalse(none.isRoot, "an empty caller namespace must not be the root scope");
		assertEquals(List.of(), none.keys, "an empty caller namespace must own no stored key");
		// Naming a key is refused outright rather than resolving to some prefix.
		assertInstanceOf(IllegalStateException.class, none.scopeRefused);
		assertNull(none.get);
	}

	/**
	 * A user token stamped with the cluster root — what
	 * {@code IdentityServiceImpl.namespaceFromOpaOrRoot} stamps when OPA maps the
	 * caller to no tenant, i.e. every CLI user today — is unconfined, and a
	 * {@code /system} one likewise. This half must not move.
	 */
	@Test
	void rootAndSystemUserTokensAreUnconfined() {
		for (String ns : new String[] {"/", "/system", "/system/us-east"}) {
			Seen s = observe(principalTokenFor("user", "operator@example.com", ns));

			assertTrue(s.isRoot, ns + " must be the root scope");
			assertNull(s.scopeRefused);
			assertEquals("system", s.get, ns + " must read the unrewritten key");
			assertEquals(List.of("/tenants/acme/k", "/tenants/beta/k", "k"), s.keys,
					ns + " must see the whole map, unrewritten");
		}
	}

	/**
	 * The namespace grants a SCOPE, never an authorization: a user token still has
	 * no service path, so {@code checkAccess} still denies it on a policed graph.
	 * Without this, item 4 would have widened access rather than narrowed it.
	 */
	@Test
	void aUserTokenGainsAScopeButNoAuthorization() {
		OpaStateServiceGrpc.OpaStateServiceBlockingStub user = OpaStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(principalTokenFor("user", "alice@acme.example", "/tenants/acme")));
		assertThrows(StatusRuntimeException.class, () -> user.sizeTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesSizeRequest.newBuilder().build()));
		assertEquals("", lastSeen.get().servicePath, "a user token must still carry no service path");

		// A tenant-owned SERVICE token on the same graph still works, so the denial
		// above is about the token class, not a broken fixture.
		OpaStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/acme", "opa"), "opa")))
				.sizeTenantEntitlementsPolicies(Opa.TenantEntitlementsPoliciesSizeRequest.newBuilder().build());
	}
}
