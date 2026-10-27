package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.generator.TemplateEngine;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The generated BackendMap's conditional writes go straight to the boundary's
 * own IMap op, so the compare and the write happen together at the key's
 * partition owner, and they validate what they store the same way put does.
 */
class StateMapConditionalWriteTest {

	private static Map<String, String> vars() {
		Map<String, String> vars = new LinkedHashMap<>();
		vars.put("QUALIFIED_TYPE", "Widgets.Widget");
		vars.put("TYPE_NAME", "Widget");
		vars.put("FIELD_CAMEL", "widgets");
		vars.put("FIELD_PASCAL", "Widgets");
		vars.put("MAP_NAME", "test.Widgets");
		vars.put("HELPERS_REF", "Helpers");
		return vars;
	}

	@Test
	void putIfAbsentValidatesThenDelegatesAndReturnsTheBoundValue() {
		String src = TemplateEngine.renderFragment("statemap_collection_put_if_absent.java.template", vars());

		assertTrue(src.contains("public Widgets.Widget putIfAbsentWidgets(String key, Widgets.Widget value) throws ProtoException {"),
				"putIfAbsent<F> must take the key and value and return the bound value");
		assertTrue(src.contains("Helpers.validateWidget(value);"), "putIfAbsent must validate like put");
		assertTrue(src.contains("Widgets.Widget existing = widgetsMap.putIfAbsent(key, value);"),
				"putIfAbsent must be the IMap's own putIfAbsent");
		assertTrue(src.contains("return existing != null ? existing : value;"),
				"putIfAbsent must return the existing value on conflict, else the inserted one");
	}

	@Test
	void epochPutIfAbsentCarriesTheSameTtlAsPut() {
		Map<String, String> vars = vars();
		vars.put("EPOCH_GETTER", "getExp");
		String src = TemplateEngine.renderFragment("statemap_collection_put_if_absent_epoch.java.template", vars);

		assertTrue(src.contains("public Widgets.Widget putIfAbsentWidgets(String key, Widgets.Widget value) throws ProtoException {"),
				"putIfAbsent<F> must take the key and value and return the bound value");
		assertTrue(src.contains("Helpers.validateWidget(value);"), "putIfAbsent must validate like put");
		assertTrue(src.contains("long ttl = epochExp - (System.currentTimeMillis() / 1000);"),
				"putIfAbsent must derive the TTL from the epoch field as put does");
		assertTrue(src.contains("existing = widgetsMap.putIfAbsent(key, value, ttl, java.util.concurrent.TimeUnit.SECONDS);"),
				"putIfAbsent must be the IMap's own putIfAbsent, with the TTL");
		assertTrue(src.contains("existing = widgetsMap.putIfAbsent(key, value);"),
				"a value with no epoch set is stored without a TTL, as put stores it");
		assertTrue(src.contains("return existing != null ? existing : value;"),
				"putIfAbsent must return the existing value on conflict, else the inserted one");
	}

	@Test
	void replaceValidatesNextThenDelegatesToCompareAndReplace() {
		String src = TemplateEngine.renderFragment("statemap_collection_replace.java.template", vars());

		assertTrue(src.contains("public boolean replaceWidgets(String key, Widgets.Widget expected, Widgets.Widget next) throws ProtoException {"),
				"replace<F> must take the key, expected and next values and return whether it replaced");
		assertTrue(src.contains("Helpers.validateWidget(next);"), "replace must validate the value it stores");
		assertTrue(src.contains("return widgetsMap.replace(key, expected, next);"),
				"replace must be the IMap's own compare-and-replace");
	}
}
