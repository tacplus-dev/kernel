// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.Opa;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.opa.OpaStateServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.opalib.Opalib;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.trace.Trace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Goal A item 3: the key-prefix chroot on kernel state.
 *
 * <p>A tenant-owned service asks for the bare key it wrote; the kernel stores it
 * under {@code /tenants/<t>/<key>} and strips the prefix on the way back. Two
 * tenants writing the same bare key must be fully isolated — that is the actual
 * security boundary this item exists for — and a {@code /system} caller must be
 * byte-identical to before.
 *
 * <p>Every assertion goes through real gRPC against the real generated
 * {@code OpaStateServiceServer} behind the real caller interceptor. Nothing
 * reaches into the backing map: what a caller can observe over the wire is the
 * whole claim.
 */
class StateNamespaceChrootTest extends StateChrootTestBase {

	private OpaStateServiceGrpc.OpaStateServiceBlockingStub acme;
	private OpaStateServiceGrpc.OpaStateServiceBlockingStub beta;
	private OpaStateServiceGrpc.OpaStateServiceBlockingStub system;

	@BeforeEach
	void startAndBuildStubs() throws Exception {
		startServer();
		acme = stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/acme", "opa"));
		beta = stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/beta", "opa"));
		system = stubFor(SpiffeIds.build(TRUST_DOMAIN, "opa"));
	}

	private OpaStateServiceGrpc.OpaStateServiceBlockingStub stubFor(String subject) {
		return OpaStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(subject, "opa")));
	}

	// ---- fixtures -----------------------------------------------------------

	private static Opalib.OpaPolicy policy(String entryPoint) {
		return Opalib.OpaPolicy.newBuilder()
				.setEntryPoint(entryPoint)
				.setCreated(1_735_689_600L)
				.build();
	}

	/**
	 * A collection value. {@code namespace} is the record's {@code (spec.indexed)}
	 * key field: the caller writes it, and the chroot must never rewrite it — the
	 * value the caller reads back has to be byte-identical to what it wrote.
	 */
	private static Opa.NamespaceEntitlementsPolicy entry(String keyField, String entryPoint) {
		return Opa.NamespaceEntitlementsPolicy.newBuilder()
				.setNamespace(keyField)
				.setPolicy(policy(entryPoint))
				.build();
	}

	private static void put(OpaStateServiceGrpc.OpaStateServiceBlockingStub stub,
			String key, Opa.NamespaceEntitlementsPolicy value) {
		stub.putTenantEntitlementsPolicies(Opa.TenantEntitlementsPoliciesPutRequest.newBuilder()
				.setKey(key).setValue(value).build());
	}

	private static Opa.TenantEntitlementsPoliciesValueResponse get(
			OpaStateServiceGrpc.OpaStateServiceBlockingStub stub, String key) {
		return stub.getTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetRequest.newBuilder().setKey(key).build());
	}

	private static List<String> keySet(OpaStateServiceGrpc.OpaStateServiceBlockingStub stub) {
		return stub.keySetTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesKeysRequest.newBuilder().build()).getKeysList();
	}

	private static int size(OpaStateServiceGrpc.OpaStateServiceBlockingStub stub) {
		return stub.sizeTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesSizeRequest.newBuilder().build()).getSize();
	}

	private static Opa.TenantEntitlementsPoliciesEntriesResponse getAll(
			OpaStateServiceGrpc.OpaStateServiceBlockingStub stub) {
		return stub.getAllTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetAllRequest.newBuilder().build());
	}

	// ---- the boundary -------------------------------------------------------

	@Test
	void twoTenantsWritingTheSameBareKeyAreFullyIsolated() {
		put(acme, "k", entry("k", "acme.main"));
		put(beta, "k", entry("k", "beta.main"));

		// Each reads back only its own value, under the bare key it used.
		assertTrue(get(acme, "k").getFound());
		assertEquals("acme.main", get(acme, "k").getValue().getPolicy().getEntryPoint());
		assertTrue(get(beta, "k").getFound());
		assertEquals("beta.main", get(beta, "k").getValue().getPolicy().getEntryPoint());

		// The key-as-field payload comes back exactly as written: the chroot
		// prefixes the map key ONLY, never the record.
		assertEquals("k", get(acme, "k").getValue().getNamespace());

		// Neither can name the other's storage key to escape its prefix.
		assertFalse(get(acme, "/tenants/beta/k").getFound());
		assertFalse(get(beta, "/tenants/acme/k").getFound());
	}

	@Test
	void enumerationNeverCrossesTheTenantBoundary() {
		put(acme, "a1", entry("a1", "acme.1"));
		put(acme, "a2", entry("a2", "acme.2"));
		put(beta, "b1", entry("b1", "beta.1"));

		assertEquals(List.of("a1", "a2"), keySet(acme).stream().sorted().toList());
		assertEquals(List.of("b1"), keySet(beta));

		assertEquals(2, size(acme));
		assertEquals(1, size(beta));

		Opa.TenantEntitlementsPoliciesEntriesResponse acmeAll = getAll(acme);
		assertEquals(2, acmeAll.getEntriesCount());
		// Stripped keys, untouched payloads.
		assertEquals(List.of("a1", "a2"), acmeAll.getEntriesMap().keySet().stream().sorted().toList());
		assertEquals("acme.1", acmeAll.getEntriesMap().get("a1").getPolicy().getEntryPoint());

		assertEquals(1, getAll(beta).getEntriesCount());
		assertTrue(getAll(beta).getEntriesMap().containsKey("b1"));
	}

	@Test
	void clearScopesToTheCallersPrefix() {
		put(acme, "k", entry("k", "acme.main"));
		put(beta, "k", entry("k", "beta.main"));

		acme.clearTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesClearRequest.newBuilder().build());

		assertEquals(0, size(acme));
		assertFalse(get(acme, "k").getFound());
		// beta's entry survived a Clear it did not ask for.
		assertEquals(1, size(beta));
		assertEquals("beta.main", get(beta, "k").getValue().getPolicy().getEntryPoint());
	}

	@Test
	void removeDeleteAndContainsKeyAreScoped() {
		put(acme, "k", entry("k", "acme.main"));
		put(beta, "k", entry("k", "beta.main"));

		assertTrue(acme.containsKeyTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetRequest.newBuilder().setKey("k").build()).getFound());

		Opa.TenantEntitlementsPoliciesValueResponse removed = acme.removeTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetRequest.newBuilder().setKey("k").build());
		assertEquals("acme.main", removed.getValue().getPolicy().getEntryPoint());

		assertFalse(acme.containsKeyTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetRequest.newBuilder().setKey("k").build()).getFound());
		assertTrue(beta.containsKeyTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetRequest.newBuilder().setKey("k").build()).getFound());

		beta.deleteTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesGetRequest.newBuilder().setKey("k").build());
		assertEquals(0, size(beta));
	}

	@Test
	void putIfAbsentAndSetAreScoped() {
		// acme claims "k"; beta's putIfAbsent on "k" must not see it as taken.
		put(acme, "k", entry("k", "acme.main"));

		Opa.TenantEntitlementsPoliciesValueResponse betaClaim = beta.putIfAbsentTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesPutRequest.newBuilder()
						.setKey("k").setValue(entry("k", "beta.main")).build());
		assertFalse(betaClaim.getFound(), "beta must not collide with acme's key");
		assertEquals("beta.main", get(beta, "k").getValue().getPolicy().getEntryPoint());

		// acme's own putIfAbsent does see its own entry.
		assertTrue(acme.putIfAbsentTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesPutRequest.newBuilder()
						.setKey("k").setValue(entry("k", "acme.other")).build()).getFound());

		acme.setTenantEntitlementsPolicies(Opa.TenantEntitlementsPoliciesPutRequest.newBuilder()
				.setKey("k").setValue(entry("k", "acme.set")).build());
		assertEquals("acme.set", get(acme, "k").getValue().getPolicy().getEntryPoint());
		assertEquals("beta.main", get(beta, "k").getValue().getPolicy().getEntryPoint());
	}

	// ---- singletons ---------------------------------------------------------

	@Test
	void singletonsAreNotSharedAcrossTenants() {
		// A singleton lives at one fixed key. Without the prefix every tenant
		// would silently share one value — the easiest thing to miss here.
		acme.setEntitlementsPolicy(policy("acme.entitlements"));
		beta.setEntitlementsPolicy(policy("beta.entitlements"));
		system.setEntitlementsPolicy(policy("system.entitlements"));

		Trace.TraceRequest req = Trace.TraceRequest.newBuilder().build();
		assertEquals("acme.entitlements", acme.getEntitlementsPolicy(req).getEntryPoint());
		assertEquals("beta.entitlements", beta.getEntitlementsPolicy(req).getEntryPoint());
		assertEquals("system.entitlements", system.getEntitlementsPolicy(req).getEntryPoint());
	}

	@Test
	void anUnsetSingletonIsEmptyForATenantEvenWhenSystemHasOne() {
		system.setEntitlementsPolicy(policy("system.entitlements"));

		Trace.TraceRequest req = Trace.TraceRequest.newBuilder().build();
		assertEquals("", acme.getEntitlementsPolicy(req).getEntryPoint());
	}

	// ---- watch / poll -------------------------------------------------------

	/**
	 * Watch is the one path where the scope cannot be read off the gRPC Context at
	 * send time: the poller runs on the server's scheduler thread every 500 ms.
	 * The scope is therefore captured when the watcher subscribes, and the poller
	 * builds one snapshot per distinct watcher scope.
	 */
	@Test
	void watchStreamsOnlyTheWatchersOwnEntries() throws Exception {
		put(acme, "a1", entry("a1", "acme.1"));
		put(beta, "b1", entry("b1", "beta.1"));

		Trace.TraceRequest req = Trace.TraceRequest.newBuilder().build();
		Iterator<Opa.TenantEntitlementsPoliciesEntriesResponse> acmeStream =
				acme.watchTenantEntitlementsPolicies(req);
		Iterator<Opa.TenantEntitlementsPoliciesEntriesResponse> betaStream =
				beta.watchTenantEntitlementsPolicies(req);

		// The initial snapshot each watcher gets is its own slice, stripped.
		Opa.TenantEntitlementsPoliciesEntriesResponse acmeInitial = acmeStream.next();
		assertEquals(Set.of("a1"), acmeInitial.getEntriesMap().keySet());
		assertEquals("acme.1", acmeInitial.getEntriesMap().get("a1").getPolicy().getEntryPoint());
		assertEquals(Set.of("b1"), betaStream.next().getEntriesMap().keySet());

		// A write by beta must not wake acme's stream with beta's data. The next
		// thing acme sees is its OWN next write, never beta's.
		put(beta, "b2", entry("b2", "beta.2"));
		put(acme, "a2", entry("a2", "acme.2"));

		Opa.TenantEntitlementsPoliciesEntriesResponse acmeUpdate = acmeStream.next();
		assertEquals(Set.of("a1", "a2"), acmeUpdate.getEntriesMap().keySet());

		Opa.TenantEntitlementsPoliciesEntriesResponse betaUpdate = betaStream.next();
		assertEquals(Set.of("b1", "b2"), betaUpdate.getEntriesMap().keySet());
	}

	@Test
	void singletonWatchStreamsOnlyTheWatchersOwnValue() throws Exception {
		acme.setEntitlementsPolicy(policy("acme.1"));
		beta.setEntitlementsPolicy(policy("beta.1"));

		Trace.TraceRequest req = Trace.TraceRequest.newBuilder().build();
		Iterator<Opalib.OpaPolicy> acmeStream = acme.watchEntitlementsPolicy(req);
		Iterator<Opalib.OpaPolicy> betaStream = beta.watchEntitlementsPolicy(req);

		assertEquals("acme.1", acmeStream.next().getEntryPoint());
		assertEquals("beta.1", betaStream.next().getEntryPoint());

		beta.setEntitlementsPolicy(policy("beta.2"));
		acme.setEntitlementsPolicy(policy("acme.2"));

		assertEquals("acme.2", acmeStream.next().getEntryPoint());
		assertEquals("beta.2", betaStream.next().getEntryPoint());
	}

	// ---- /system is unchanged ----------------------------------------------

	@Test
	void systemCallerKeysAreNotRewritten() {
		system.setTenantEntitlementsPolicies(Opa.TenantEntitlementsPoliciesPutRequest.newBuilder()
				.setKey("/tenants/drpepper").setValue(entry("/tenants/drpepper", "sys.1")).build());
		put(acme, "k", entry("k", "acme.main"));

		// A /system caller sees exactly what it wrote, under the key it wrote,
		// and — because there is one shared map and /system is the root scope —
		// also sees the tenant's storage keys. That is the existing trust model:
		// only a non-/system caller is confined.
		assertTrue(get(system, "/tenants/drpepper").getFound());
		assertEquals("/tenants/drpepper", get(system, "/tenants/drpepper").getValue().getNamespace());
		assertTrue(get(system, "/tenants/acme/k").getFound());
		assertEquals(2, size(system));
		assertEquals(List.of("/tenants/acme/k", "/tenants/drpepper"),
				keySet(system).stream().sorted().toList());

		// And the tenant sees only its own.
		assertEquals(1, size(acme));
		assertEquals(List.of("k"), keySet(acme));
	}

	@Test
	void systemClearStillClearsTheWholeMap() {
		put(acme, "k", entry("k", "acme.main"));
		system.setTenantEntitlementsPolicies(Opa.TenantEntitlementsPoliciesPutRequest.newBuilder()
				.setKey("sys").setValue(entry("sys", "sys.1")).build());

		system.clearTenantEntitlementsPolicies(
				Opa.TenantEntitlementsPoliciesClearRequest.newBuilder().build());

		assertEquals(0, size(system));
		assertEquals(0, size(acme));
	}
}
