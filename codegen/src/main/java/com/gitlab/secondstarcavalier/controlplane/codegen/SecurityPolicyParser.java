package com.gitlab.secondstarcavalier.controlplane.codegen;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.AccessPolicy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal line-by-line parser for backenddb.yaml security policy files.
 * No external YAML library needed — the format is simple and machine-generated.
 *
 * <p>Expected format:
 * <pre>
 * policies:
 *   - name: "ClusterState"
 *     rw: ["service:snoopy"]
 *     ro: ["service:oauth"]
 *     exec: ["service:admin"]
 * </pre>
 */
public class SecurityPolicyParser {

    /**
     * Parses a backenddb.yaml file and returns the list of access policies.
     */
    public static List<AccessPolicy> parse(Path yamlFile) throws IOException {
        List<String> lines = Files.readAllLines(yamlFile);
        List<AccessPolicy> policies = new ArrayList<>();

        String currentName = null;
        List<String> currentRw = new ArrayList<>();
        List<String> currentRo = new ArrayList<>();
        List<String> currentExec = new ArrayList<>();

        for (String rawLine : lines) {
            String trimmed = rawLine.trim();

            // Skip comments and empty lines
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }

            // New policy entry
            if (trimmed.startsWith("- name:")) {
                // Flush previous policy
                if (currentName != null) {
                    policies.add(new AccessPolicy(currentName,
                            List.copyOf(currentRw), List.copyOf(currentRo), List.copyOf(currentExec)));
                }
                currentName = extractQuotedValue(trimmed.substring("- name:".length()));
                currentRw = new ArrayList<>();
                currentRo = new ArrayList<>();
                currentExec = new ArrayList<>();
                continue;
            }

            // Parse list fields
            if (trimmed.startsWith("rw:")) {
                currentRw = parseInlineList(trimmed.substring("rw:".length()));
            } else if (trimmed.startsWith("ro:")) {
                currentRo = parseInlineList(trimmed.substring("ro:".length()));
            } else if (trimmed.startsWith("exec:")) {
                currentExec = parseInlineList(trimmed.substring("exec:".length()));
            }
        }

        // Flush last policy
        if (currentName != null) {
            policies.add(new AccessPolicy(currentName,
                    List.copyOf(currentRw), List.copyOf(currentRo), List.copyOf(currentExec)));
        }

        return policies;
    }

    /**
     * Extracts a quoted string value from YAML, e.g. {@code "ClusterState"} -> {@code ClusterState}.
     */
    private static String extractQuotedValue(String s) {
        s = s.trim();
        if (s.startsWith("\"") && s.endsWith("\"")) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    /**
     * Parses a YAML inline list like {@code ["service:oauth", "service:snoopy"]}.
     */
    private static List<String> parseInlineList(String s) {
        s = s.trim();
        if (s.isEmpty() || s.equals("[]")) {
            return new ArrayList<>();
        }

        // Strip brackets
        if (s.startsWith("[")) s = s.substring(1);
        if (s.endsWith("]")) s = s.substring(0, s.length() - 1);

        List<String> result = new ArrayList<>();
        for (String item : s.split(",")) {
            String val = extractQuotedValue(item.trim());
            if (!val.isEmpty()) {
                result.add(val);
            }
        }
        return result;
    }
}
