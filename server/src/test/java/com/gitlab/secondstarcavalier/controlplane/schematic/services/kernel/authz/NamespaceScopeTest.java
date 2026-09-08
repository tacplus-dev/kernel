// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.NamespaceScope;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.Context;
import org.junit.jupiter.api.Test;

import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The key-rewrite arithmetic every generated state and store fragment depends on.
 *
 * <p>The properties that matter: a root ({@code /system}) scope is the identity in
 * all three directions, so old behaviour is unchanged by construction; and for a
 * tenant scope {@code unscope(scope(k)) == k} for ANY key, including keys that are
 * empty, contain slashes, or look like another tenant's storage key.
 */
class NamespaceScopeTest {

	/** Runs {@code body} with {@code namespace} installed as the caller namespace. */
	private static <T> T as(String namespace, Callable<T> body) throws Exception {
		return Context.current()
				.withValue(SecurityAuthenticator.CALLER_NAMESPACE_KEY, namespace)
				.call(body);
	}

	@Test
	void systemCallersGetTheIdentityRewrite() throws Exception {
		for (String ns : new String[] {"/system", "/system/us-east", "/", ""}) {
			NamespaceScope scope = as(ns, NamespaceScope::current);
			assertTrue(scope.isRoot(), ns + " must be the root scope");
			for (String key : new String[] {"", "k", "/tenants/acme/k", "a/b/c"}) {
				assertEquals(key, scope.scope(key));
				assertEquals(key, scope.unscope(key));
				assertTrue(scope.owns(key));
			}
		}
	}

	@Test
	void aCallerWithNoNamespaceAtAllIsTheRootScope() {
		// No Context value installed — user/CLI tokens, and any path that runs off
		// a gRPC call. checkAccess already denies those on every policed graph.
		assertTrue(NamespaceScope.current().isRoot());
	}

	@Test
	void tenantScopeRoundTripsEveryKeyShape() throws Exception {
		NamespaceScope acme = as("/tenants/acme", NamespaceScope::current);
		assertFalse(acme.isRoot());

		for (String key : new String[] {"", "k", "a/b/c", "/tenants/beta/k", "/tenants/acme/k"}) {
			String stored = acme.scope(key);
			assertEquals("/tenants/acme/" + key, stored);
			assertTrue(acme.owns(stored));
			assertEquals(key, acme.unscope(stored), "round trip must be exact for \"" + key + "\"");
		}
	}

	@Test
	void oneTenantNeverOwnsAnothersKeys() throws Exception {
		NamespaceScope acme = as("/tenants/acme", NamespaceScope::current);
		NamespaceScope beta = as("/tenants/beta", NamespaceScope::current);

		assertFalse(acme.owns(beta.scope("k")));
		assertFalse(beta.owns(acme.scope("k")));
		// A tenant whose name is a prefix of another's is still disjoint: the
		// trailing "/" in the stored prefix is what makes that true.
		NamespaceScope acmeCorp = as("/tenants/acmecorp", NamespaceScope::current);
		assertFalse(acme.owns(acmeCorp.scope("k")));
		assertFalse(acmeCorp.owns(acme.scope("k")));
	}

	@Test
	void scopesAreEqualByPrefixSoWatchersCanBeGrouped() throws Exception {
		// The poller groups watchers by scope to build one snapshot per scope.
		assertEquals(as("/tenants/acme", NamespaceScope::current),
				as("/tenants/acme", NamespaceScope::current));
		assertEquals(as("/tenants/acme", NamespaceScope::current).hashCode(),
				as("/tenants/acme", NamespaceScope::current).hashCode());
		assertEquals(as("/system", NamespaceScope::current), NamespaceScope.root());
	}
}
