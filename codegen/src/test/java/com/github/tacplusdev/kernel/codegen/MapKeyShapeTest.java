package com.github.tacplusdev.kernel.codegen;

import com.github.tacplusdev.kernel.codegen.generator.TemplateEngine;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A collection boundary's map accessors took the key as a parameter named
 * {@code key}, followed by the value's type: to gitleaks' generic-api-key rule
 * that is the keyword {@code key}, an assignment (the comma) and a high-entropy
 * value (a type such as Ca.service_cas's {@code X509.X509CertChain}), and
 * kernel's Ca boundary failed every build's security job on it (#61). The key
 * parameter is named so that no accessor reads as a key assignment, whatever
 * the type.
 */
class MapKeyShapeTest {

	/** gitleaks 8.30's generic-api-key rule, its regex and entropy threshold verbatim. */
	private static final Pattern GENERIC_API_KEY = Pattern.compile(
			"(?i)[\\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)"
					+ "(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}"
					+ "([\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
	private static final double ENTROPY = 3.5;

	/** kernel's Ca.service_cas, the boundary gitleaks flagged. */
	private static Map<String, String> vars() {
		Map<String, String> vars = new LinkedHashMap<>();
		vars.put("HEADER", "");
		vars.put("PACKAGE", "com.example");
		vars.put("INTERFACES_PACKAGE", "com.example");
		vars.put("ERRORS_PACKAGE", "com.example");
		vars.put("TYPES_IMPORT", "");
		vars.put("CROSS_IMPORTS", "");
		vars.put("CLASS_NAME", "X509CertChainMap");
		vars.put("QUALIFIED_TYPE", "X509.X509CertChain");
		vars.put("TYPE_NAME", "X509CertChain");
		vars.put("FIELD_CAMEL", "serviceCas");
		vars.put("FIELD_PASCAL", "ServiceCas");
		vars.put("MAP_NAME", "kernel.ServiceCas");
		vars.put("HELPERS_REF", "com.example.types.sys.x509.Helpers");
		vars.put("EPOCH_GETTER", "getExp");
		return vars;
	}

	@Test
	void collectionMapAccessorsReadAsNoGenericApiKey() {
		List<String> findings = new ArrayList<>();
		for (String fragment : List.of(
				"statemap_collection_get.java.template",
				"statemap_collection_put_convergent.java.template",
				"statemap_collection_put_epoch.java.template",
				"statemap_collection_put_if_absent.java.template",
				"statemap_collection_put_if_absent_epoch.java.template",
				"statemap_collection_replace.java.template",
				"statemap_collection_delete.java.template")) {
			findings.addAll(findings(fragment, TemplateEngine.renderFragment(fragment, vars())));
		}
		String typed = "TypedMapCollection.java.template";
		findings.addAll(findings(typed, TemplateEngine.render(typed, vars())));

		assertEquals(List.of(), findings, "generated map accessors gitleaks reads as a generic API key");
	}

	private static List<String> findings(String template, String src) {
		List<String> out = new ArrayList<>();
		for (String line : src.split("\n")) {
			Matcher m = GENERIC_API_KEY.matcher(line);
			while (m.find()) {
				if (entropy(m.group(1)) >= ENTROPY) {
					out.add(template + ": " + line.strip());
				}
			}
		}
		return out;
	}

	/** Shannon entropy in bits per character, as gitleaks computes it. */
	private static double entropy(String s) {
		Map<Character, Integer> counts = new HashMap<>();
		for (char c : s.toCharArray()) counts.merge(c, 1, Integer::sum);
		double h = 0;
		for (int n : counts.values()) {
			double p = (double) n / s.length();
			h -= p * Math.log(p) / Math.log(2);
		}
		return h;
	}
}
