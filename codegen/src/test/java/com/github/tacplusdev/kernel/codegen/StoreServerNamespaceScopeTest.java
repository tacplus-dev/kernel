package com.github.tacplusdev.kernel.codegen;

import com.github.tacplusdev.kernel.codegen.generator.TemplateEngine;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code (spec.service_store)} server gets the same key-prefix chroot as the
 * state servers: Put/Get/Delete scope the key on ingress, and List filters on the
 * stored key while returning items untouched (the store key is a payload field —
 * {@code (spec.store_key)} — and rewriting it would corrupt the record).
 *
 * <p>This is asserted against the rendered template rather than a running server
 * because {@code platform/proto} declares exactly one {@code (spec.service_store)}
 * — {@code kernel.KernelDiskState} — and it has NO {@code store_key}, so tacplus
 * emits a UC1 disk snapshot for it and no store service at all. There is no
 * generated store server in this tree to drive over gRPC. The runtime semantics
 * this template relies on are covered directly by {@code NamespaceScopeTest} in
 * the server module.
 */
class StoreServerNamespaceScopeTest {

	private static String renderStoreServer() {
		Map<String, String> vars = new LinkedHashMap<>();
		vars.put("HEADER", "// test");
		vars.put("PACKAGE", "test.pkg");
		vars.put("INTERFACES_PACKAGE", "test.graphs");
		vars.put("ERRORS_PACKAGE", "test.errors");
		vars.put("AUTHENTICATOR_PACKAGE", "test.backend");
		vars.put("TYPES_PACKAGE", "test.types");
		vars.put("OUTER_CLASS", "Widgets");
		vars.put("CLASS_NAME", "WidgetStoreServiceServer");
		vars.put("GRPC_BASE", "WidgetStoreServiceGrpc.WidgetStoreServiceImplBase");
		vars.put("GRAPH_KEY", "test.Widget");
		vars.put("VALUE_TYPE", "Widget");
		vars.put("QUALIFIED_VALUE_TYPE", "Widgets.Widget");
		vars.put("KEY_FIELD_NAME", "widget_id");
		vars.put("KEY_FIELD_PASCAL", "WidgetId");
		vars.put("STORE_MAP_NAME", "WidgetStore");
		vars.put("TRACE_REQUEST_TYPE", "test.types.Trace.TraceRequest");
		return TemplateEngine.render("BackendStoreServiceServer.java.template", vars);
	}

	@Test
	void putGetAndDeleteScopeTheKeyOnIngress() {
		String src = renderStoreServer();

		assertTrue(src.contains("storeMap.put(NamespaceScope.current().scope(key), request);"),
				"Put must store under the caller's scoped key");
		assertTrue(src.contains("storeMap.get(NamespaceScope.current().scope(key));"),
				"Get must read the caller's scoped key");
		assertTrue(src.contains("storeMap.remove(NamespaceScope.current().scope(key));"),
				"Delete must remove the caller's scoped key");
	}

	@Test
	void listFiltersOnTheStoredKeyAndReturnsItemsUntouched() {
		String src = renderStoreServer();

		assertTrue(src.contains("for (java.util.Map.Entry<String, Widgets.Widget> e : storeMap.entrySet())"),
				"List must walk entries so it can see the stored key, not just values");
		assertTrue(src.contains("if (scope.owns(e.getKey()))"),
				"List must filter on the stored (scoped) key");
		assertTrue(src.contains("builder.addItems(e.getValue());"),
				"List must return the item exactly as stored — the store key is a payload field");
		assertTrue(!src.contains("storeMap.values()"),
				"List must no longer return every tenant's values");
	}
}
