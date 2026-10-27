// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.authz;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.NamespaceScope;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.Context;
import org.junit.jupiter.api.Test;

import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
		for (String ns : new String[] {"/system", "/system/us-east", "/"}) {
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
		// No Context value installed. The caller interceptor always installs the
		// key, so this is not a caller at all: it is kernel's own machinery running
		// off a gRPC call, which is unconfined.
		assertTrue(NamespaceScope.current().isRoot());
	}

	/**
	 * Goal B item 4. An EMPTY namespace — as opposed to an absent one — is an
	 * authenticated caller whose token class carries no namespace. It is the case
	 * that used to fall through to ROOT, and it must own nothing at all.
	 *
	 * <p>It is deliberately not "the chroot under the empty namespace" either: that
	 * prefix would be "/", which is a prefix of every tenant's storage key.
	 */
	@Test
	void anEmptyNamespaceOwnsNothing() throws Exception {
		NamespaceScope none = as("", NamespaceScope::current);

		assertFalse(none.isRoot());
		for (String key : new String[] {"", "k", "/", "/tenants/acme/k", "a/b/c"}) {
			assertFalse(none.owns(key), "must own no stored key, including \"" + key + "\"");
		}
		assertThrows(IllegalStateException.class, () -> none.scope("k"));
		assertThrows(IllegalStateException.class, () -> none.unscope("k"));
	}

	/**
	 * Goal B item 4 inverted the default: root is now a closed list ("/" and
	 * "/system…"), so a namespace root nobody has taught this class about — the
	 * retired "/people/<pid>", say — is confined, not unconfined.
	 */
	@Test
	void anUnrecognizedNamespaceRootIsConfinedNotRoot() throws Exception {
		NamespaceScope people = as("/people/p-42", NamespaceScope::current);

		assertFalse(people.isRoot(), "an unknown namespace root must never be the identity rewrite");
		assertEquals("/people/p-42/k", people.scope("k"));
		assertFalse(people.owns("/tenants/acme/k"));
		assertFalse(people.owns("k"));

		// "/systemically" is not "/system": only the exact segment is root.
		assertFalse(as("/systemically", NamespaceScope::current).isRoot());
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

	/**
	 * On a fleet-wide root a confined caller also reads the system entries. A
	 * system entry is a key with no "/" — every key a confined scope stores
	 * contains the "/" its prefix ends in, so none of them, of any tenant, passes.
	 */
	@Test
	void aConfinedScopeReadsOnlyKeysNoConfinedScopeCanWrite() throws Exception {
		NamespaceScope acme = as("/tenants/acme", NamespaceScope::current);
		NamespaceScope beta = as("/tenants/beta", NamespaceScope::current);

		assertTrue(acme.readsSystemEntry("eventbus@i-1"));
		assertTrue(acme.readsSystemEntry("SINGLETON"));
		assertFalse(acme.readsSystemEntry(beta.scope("eventbus@i-1")));
		assertFalse(acme.readsSystemEntry(beta.scope("")));
		// A root-written key with a "/" is not read: fail closed.
		assertFalse(acme.readsSystemEntry("/tenants/drpepper"));

		// Root already owns everything; a namespace-less caller reads nothing.
		assertFalse(NamespaceScope.root().readsSystemEntry("eventbus@i-1"));
		assertFalse(as("", NamespaceScope::current).readsSystemEntry("eventbus@i-1"));
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
