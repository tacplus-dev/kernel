package com.github.tacplusdev.kernel.codegen.generator;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple template engine that loads {{VAR}}-based templates from classpath resources.
 */
public class TemplateEngine {

    private static final Map<String, String> cache = new ConcurrentHashMap<>();

    /** Loads a template from /templates/{name} on the classpath, caching the result. */
    public static String load(String name) {
        return cache.computeIfAbsent(name, k -> {
            String path = "/templates/" + k;
            try (InputStream is = TemplateEngine.class.getResourceAsStream(path)) {
                if (is == null) {
                    throw new RuntimeException("Template not found: " + path);
                }
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read template: " + path, e);
            }
        });
    }

    /** Loads and renders a template, replacing all {{KEY}} with values from the map. */
    public static String render(String name, Map<String, String> vars) {
        String template = load(name);
        return substitute(template, vars);
    }

    /** Shorthand for render("fragments/" + name, vars). */
    public static String renderFragment(String name, Map<String, String> vars) {
        return render("fragments/" + name, vars);
    }

    private static String substitute(String template, Map<String, String> vars) {
        String result = template;
        for (var entry : vars.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }
}
