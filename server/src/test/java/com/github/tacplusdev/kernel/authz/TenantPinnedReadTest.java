// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.authz;

import com.github.tacplusdev.kernel.cluster.SpiffeIds;
import com.github.tacplusdev.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.github.tacplusdev.kernel.model.types.services.kernel.ConfigStateServiceGrpc;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.services.oauth.Oauth;
import com.github.tacplusdev.kernel.model.types.services.opa.Opa;
import com.github.tacplusdev.kernel.model.types.sys.opalib.Opalib;
import com.github.tacplusdev.kernel.model.types.sys.trace.Trace;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigStateServiceServer;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.function.Executable;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tenant-pinned reads of {@code kernel.ConfigState.tenant_configs} (tacplus #130),
 * the kernel twin of tacplus's {@code TenantPinnedReadTest}.
 *
 * <p>Kernel writes each tenant's {@code TenantConfigEntry} at root key
 * {@code /tenants/<t>}, the tenant's full namespace, which is also its
 * {@code tenant_name}. {@code opa} and {@code oauth} each own a slice of the
 * config and are in neither rw nor ro of ConfigState, so codegen-config.json
 * carries them as {@code tenantPinnedReads}, not as a boundary grant. A pinned
 * caller in exactly {@code /tenants/<t>} reads the entry keyed {@code /tenants/<t>} only; one in
 * {@code /system} reads every tenant's; both get each entry projected to
 * {@code tenant_name} plus their own slice of {@code config}; anywhere else is
 * PERMISSION_DENIED. rw/ro callers are untouched.
 *
 * <p>Every assertion goes through real gRPC against the real generated
 * {@link ConfigStateServiceServer} behind the real caller interceptor; the
 * entries are written through the generated {@link ConfigMap}, as kernel writes
 * them.
 *
 * <p>Which half runs depends on the codegen-config.json the build generated
 * from. A tacplus that emits tenantPinnedReads produces a server with the pinned
 * read path, and the contract tests run. One that does not (the field absent)
 * must grant the slice owners nothing, and {@link #withoutThePinTheSliceOwnersGetNothing}
 * runs instead.
 */
class TenantPinnedReadTest extends StateChrootTestBase {

	/** Tenant keys as kernel stores them: the tenant's full namespace. */
	private static final String A = "/tenants/A";
	private static final String B = "/tenants/B";
	private static final String C = "/tenants/C";

	private InMemoryManager manager;
	private ConfigMap configMap;
	private ConfigStateServiceServer configServer;

	@BeforeEach
	void startConfigServer() throws Exception {
		manager = new InMemoryManager();
		configMap = new ConfigMap(manager);
		configServer = new ConfigStateServiceServer(manager, authenticator);
		startServer(ServerInterceptors.interceptForward(
				configServer.bindService(), authenticator.callerInterceptor()));
		configMap.putTenantConfigs(A, entry(A, 1));
		configMap.putTenantConfigs(B, entry(B, 1));
	}

	@AfterEach
	void closeConfigServer() {
		configServer.close();
	}

	/** Whether this build generated the pinned read path for tenant_configs. */
	static boolean pinGenerated() {
		return Arrays.stream(ConfigStateServiceServer.class.getDeclaredMethods())
				.anyMatch(m -> m.getName().equals("pinTenantConfigs"));
	}

	// ---- fixtures -----------------------------------------------------------

	/** Tenant t's entry, carrying opa's slice, oauth's secret-bearing slice, and a trace id. */
	private static Kernel.TenantConfigEntry entry(String t, int version) {
		return Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(t)
				.setTraceId("trace-" + t)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setOpa(Opa.OpaTenantConfig.newBuilder()
								.setEntitlementsPolicy(Opalib.OpaPolicy.newBuilder()
										.setEntryPoint("opa-" + t + "-" + version)
										.setCreated(1_735_689_600L)))
						.setOauth(Oauth.OAuthTenantConfig.newBuilder()
								.addProviders(Oauth.OAuthProvider.newBuilder()
										.setIssuerUrl("https://idp.example.com/" + t)
										.setClientId("client-" + t)
										.setClientSecret("secret-" + t))))
				.build();
	}

	private ConfigStateServiceGrpc.ConfigStateServiceBlockingStub as(String service, String namespace) {
		return ConfigStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(SpiffeIds.build(TRUST_DOMAIN, namespace, service), service)));
	}

	private static Kernel.TenantConfigsGetRequest key(String k) {
		return Kernel.TenantConfigsGetRequest.newBuilder().setKey(k).build();
	}

	private static Kernel.TenantConfigsEntriesResponse getAll(ConfigStateServiceGrpc.ConfigStateServiceBlockingStub s) {
		return s.getAllTenantConfigs(Kernel.TenantConfigsGetAllRequest.getDefaultInstance());
	}

	private static List<String> keySet(ConfigStateServiceGrpc.ConfigStateServiceBlockingStub s) {
		return s.keySetTenantConfigs(Kernel.TenantConfigsKeysRequest.getDefaultInstance()).getKeysList();
	}

	private static int size(ConfigStateServiceGrpc.ConfigStateServiceBlockingStub s) {
		return s.sizeTenantConfigs(Kernel.TenantConfigsSizeRequest.getDefaultInstance()).getSize();
	}

	private static Iterator<Kernel.TenantConfigsEntriesResponse> watch(ConfigStateServiceGrpc.ConfigStateServiceBlockingStub s) {
		return s.withDeadlineAfter(10, TimeUnit.SECONDS).watchTenantConfigs(Trace.TraceRequest.getDefaultInstance());
	}

	private static void assertDenied(String what, Executable call) {
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class, call, what);
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode(), what + ": " + e.getStatus());
	}

	/** e is tenant t's entry holding opa's slice and nothing else: no oauth secret, no trace id. */
	private static void assertProjectedForOpa(String t, int version, Kernel.TenantConfigEntry e) {
		Kernel.TenantConfigEntry want = Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(t)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setOpa(entry(t, version).getConfig().getOpa()))
				.build();
		assertEquals(want, e, "a pinned opa caller must get " + t + "'s key and opa slice only");
		assertFalse(e.getConfig().hasOauth(), "oauth's client_secret reached opa");
	}

	// ---- the pinned contract ------------------------------------------------

	@Test
	@EnabledIf("pinGenerated")
	void aTenantPinnedCallerReadsItsOwnEntryOnlyProjected() {
		ConfigStateServiceGrpc.ConfigStateServiceBlockingStub opaA = as("opa", "/tenants/A");

		Kernel.TenantConfigsValueResponse got = opaA.getTenantConfigs(key(A));
		assertTrue(got.getFound());
		assertProjectedForOpa(A, 1, got.getValue());

		Kernel.TenantConfigsValueResponse contains = opaA.containsKeyTenantConfigs(key(A));
		assertTrue(contains.getFound());
		assertProjectedForOpa(A, 1, contains.getValue());

		Kernel.TenantConfigsEntriesResponse all = getAll(opaA);
		assertEquals(Set.of(A), all.getEntriesMap().keySet());
		assertProjectedForOpa(A, 1, all.getEntriesMap().get(A));

		assertEquals(List.of(A), keySet(opaA));
		assertEquals(1, size(opaA));
	}

	@Test
	@EnabledIf("pinGenerated")
	void anotherTenantsKeyIsPermissionDeniedNotNotFound() {
		ConfigStateServiceGrpc.ConfigStateServiceBlockingStub opaA = as("opa", "/tenants/A");

		assertDenied("Get B from /tenants/A", () -> opaA.getTenantConfigs(key(B)));
		assertDenied("ContainsKey B from /tenants/A", () -> opaA.containsKeyTenantConfigs(key(B)));
		assertDenied("Get of an absent other key from /tenants/A", () -> opaA.getTenantConfigs(key(C)));
		assertDenied("Get of the bare leaf from /tenants/A", () -> opaA.getTenantConfigs(key("A")));
	}

	@Test
	@EnabledIf("pinGenerated")
	void aTenantPinnedWatchNeverCarriesAnotherTenant() throws Exception {
		Iterator<Kernel.TenantConfigsEntriesResponse> stream = watch(as("opa", "/tenants/A"));

		Kernel.TenantConfigsEntriesResponse snapshot = stream.next();
		assertEquals(Set.of(A), snapshot.getEntriesMap().keySet());
		assertProjectedForOpa(A, 1, snapshot.getEntriesMap().get(A));

		// Another tenant's change, and a new tenant, must not reach A's stream;
		// the next frame A sees is its own update.
		configMap.putTenantConfigs(B, entry(B, 2));
		configMap.putTenantConfigs(C, entry(C, 1));
		Thread.sleep(1_200);
		configMap.putTenantConfigs(A, entry(A, 2));

		Kernel.TenantConfigsEntriesResponse update = stream.next();
		assertEquals(Set.of(A), update.getEntriesMap().keySet());
		assertProjectedForOpa(A, 2, update.getEntriesMap().get(A));
	}

	@Test
	@EnabledIf("pinGenerated")
	void aSystemPinnedCallerReadsEveryTenantProjected() throws Exception {
		ConfigStateServiceGrpc.ConfigStateServiceBlockingStub opaSystem = as("opa", "");

		Kernel.TenantConfigsEntriesResponse all = getAll(opaSystem);
		assertEquals(Set.of(A, B), all.getEntriesMap().keySet());
		assertProjectedForOpa(A, 1, all.getEntriesMap().get(A));
		assertProjectedForOpa(B, 1, all.getEntriesMap().get(B));
		assertProjectedForOpa(B, 1, opaSystem.getTenantConfigs(key(B)).getValue());
		assertEquals(Set.of(A, B), Set.copyOf(keySet(opaSystem)));
		assertEquals(2, size(opaSystem));

		Kernel.TenantConfigsEntriesResponse snapshot = watch(opaSystem).next();
		assertEquals(Set.of(A, B), snapshot.getEntriesMap().keySet());
		assertProjectedForOpa(B, 1, snapshot.getEntriesMap().get(B));
	}

	/** Each pinned caller sees its own slice: oauth gets oauth's, never opa's. */
	@Test
	@EnabledIf("pinGenerated")
	void eachPinnedCallerIsProjectedToItsOwnSlice() {
		Kernel.TenantConfigEntry got = as("oauth", "/tenants/B").getTenantConfigs(key(B)).getValue();

		assertEquals(Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(B)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setOauth(entry(B, 1).getConfig().getOauth()))
				.build(), got);
	}

	/**
	 * Below a tenant root is not the tenant root. A person — sub
	 * spiffe://<td>/users/<xid>, here in the people tenant — has no service
	 * identity to pin, and is refused like any unpinned caller.
	 */
	@Test
	@EnabledIf("pinGenerated")
	void aCallerInAnyOtherNamespaceIsDenied() {
		List<ConfigStateServiceGrpc.ConfigStateServiceBlockingStub> callers = List.of(
				as("opa", "/tenants/A/workspaces/x"),
				ConfigStateServiceGrpc.newBlockingStub(channel)
						.withInterceptors(bearer(principalTokenFor("user",
								SpiffeIds.userSubject(TRUST_DOMAIN, "a11ce0000000000000000000000000aa"),
								"/tenants/people"))));
		for (ConfigStateServiceGrpc.ConfigStateServiceBlockingStub caller : callers) {
			assertDenied("Get", () -> caller.getTenantConfigs(key(A)));
			assertDenied("ContainsKey", () -> caller.containsKeyTenantConfigs(key(A)));
			assertDenied("GetAll", () -> getAll(caller));
			assertDenied("KeySet", () -> keySet(caller));
			assertDenied("Size", () -> size(caller));
			assertDenied("Watch", () -> watch(caller).next());
		}
	}

	/** The grant is the one collection's reads: no write, and no other boundary of the root. */
	@Test
	@EnabledIf("pinGenerated")
	void thePinGrantsNoWriteAndNoOtherBoundary() {
		ConfigStateServiceGrpc.ConfigStateServiceBlockingStub opaA = as("opa", "/tenants/A");

		assertDenied("Put A by a pinned caller", () -> opaA.putTenantConfigs(
				Kernel.TenantConfigsPutRequest.newBuilder().setKey(A).setValue(entry(A, 9)).build()));
		assertDenied("Delete A by a pinned caller", () -> opaA.deleteTenantConfigs(key(A)));
		assertDenied("Clear by a pinned caller", () -> opaA.clearTenantConfigs(
				Kernel.TenantConfigsClearRequest.getDefaultInstance()));
		assertDenied("GetAll tenants by a pinned caller", () -> opaA.getAllTenants(
				Kernel.TenantsGetAllRequest.getDefaultInstance()));
		assertEquals(entry(A, 1), configMap.getTenantConfigs(A), "the refused write must not have landed");
	}

	/** The rw/ro caller (kernel, ConfigState's only one) is not pinned: every entry, unprojected. */
	@Test
	@EnabledIf("pinGenerated")
	void rwAndRoCallersAreServedUnprojected() {
		ConfigStateServiceGrpc.ConfigStateServiceBlockingStub kernel = as("kernel", "");
		Kernel.TenantConfigsEntriesResponse all = getAll(kernel);
		assertEquals(entry(A, 1), all.getEntriesMap().get(A));
		assertEquals(entry(B, 1), all.getEntriesMap().get(B));
		assertEquals(entry(B, 1), kernel.getTenantConfigs(key(B)).getValue());
	}

	// ---- no pin in codegen-config.json --------------------------------------

	/**
	 * Without tenantPinnedReads the slice owners are in no rw/ro and no boundary
	 * grant of ConfigState, so every read is refused: fail closed, not open.
	 */
	@Test
	@DisabledIf("pinGenerated")
	void withoutThePinTheSliceOwnersGetNothing() {
		for (String ns : List.of("/tenants/A", "")) {
			ConfigStateServiceGrpc.ConfigStateServiceBlockingStub opa = as("opa", ns);
			assertDenied("Get from " + ns, () -> opa.getTenantConfigs(key(A)));
			assertDenied("ContainsKey from " + ns, () -> opa.containsKeyTenantConfigs(key(A)));
			assertDenied("GetAll from " + ns, () -> getAll(opa));
			assertDenied("KeySet from " + ns, () -> keySet(opa));
			assertDenied("Size from " + ns, () -> size(opa));
			assertDenied("Watch from " + ns, () -> watch(opa).next());
		}
	}
}
