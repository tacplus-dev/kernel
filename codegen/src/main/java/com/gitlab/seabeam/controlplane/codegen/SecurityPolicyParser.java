package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal line-by-line parser for backenddb.yaml security policy files.
 * No external YAML library needed — the format is simple and machine-generated.
 *
 * <p>Both the inline and the block spelling of a principal list are understood:
 * <pre>
 * policies:
 *   - name: "ClusterState"
 *     rw: ["service:snoopy"]
 *     ro:
 *       - "service:oauth"
 *     exec: []
 * </pre>
 *
 * <p>Anything else is a hard error naming the line. A policy file this parser
 * does not fully understand must fail the build rather than yield a policy with
 * silently missing principals: that direction fails closed at runtime, but it
 * fails closed invisibly, which is how a format change would ship unnoticed.
 */
public class SecurityPolicyParser {

    /**
     * Parses a backenddb.yaml file and returns the list of access policies.
     *
     * @throws IllegalArgumentException if a line cannot be classified, or if a
     *         policy declares none of {@code rw}, {@code ro} or {@code exec}
     */
    public static List<AccessPolicy> parse(Path yamlFile) throws IOException {
        List<String> lines = Files.readAllLines(yamlFile);
        List<AccessPolicy> policies = new ArrayList<>();

        String currentName = null;
        List<String> currentRw = new ArrayList<>();
        List<String> currentRo = new ArrayList<>();
        List<String> currentExec = new ArrayList<>();
        // Non-null while a block sequence is open: the list its "- item" lines append to.
        List<String> openBlock = null;
        boolean sawAnyList = false;
        int currentLineNo = 0;

        for (int i = 0; i < lines.size(); i++) {
            int lineNo = i + 1;
            String trimmed = stripComment(lines.get(i).trim()).trim();

            // Skip comments and empty lines
            if (trimmed.isEmpty()) {
                continue;
            }

            // New policy entry
            if (trimmed.startsWith("- name:")) {
                // Flush previous policy
                if (currentName != null) {
                    policies.add(flush(currentName, currentRw, currentRo, currentExec, sawAnyList, currentLineNo));
                }
                currentName = extractQuotedValue(trimmed.substring("- name:".length()));
                currentLineNo = lineNo;
                currentRw = new ArrayList<>();
                currentRo = new ArrayList<>();
                currentExec = new ArrayList<>();
                openBlock = null;
                sawAnyList = false;
                continue;
            }

            // An item of the block sequence opened by the preceding rw:/ro:/exec: line
            if (trimmed.startsWith("- ")) {
                if (openBlock == null) {
                    throw new IllegalArgumentException(yamlFile + ":" + lineNo
                            + ": list item outside any rw/ro/exec list: " + trimmed);
                }
                String val = extractQuotedValue(trimmed.substring("- ".length()));
                if (!val.isEmpty()) {
                    openBlock.add(val);
                }
                continue;
            }

            // Parse list fields, inline or block
            if (trimmed.startsWith("rw:")) {
                currentRw = new ArrayList<>();
                openBlock = startList(currentRw, trimmed.substring("rw:".length()));
                sawAnyList = true;
            } else if (trimmed.startsWith("ro:")) {
                currentRo = new ArrayList<>();
                openBlock = startList(currentRo, trimmed.substring("ro:".length()));
                sawAnyList = true;
            } else if (trimmed.startsWith("exec:")) {
                currentExec = new ArrayList<>();
                openBlock = startList(currentExec, trimmed.substring("exec:".length()));
                sawAnyList = true;
            } else if (trimmed.equals("policies:")) {
                openBlock = null;
            } else {
                throw new IllegalArgumentException(yamlFile + ":" + lineNo
                        + ": unrecognized line in security policy file: " + trimmed);
            }
        }

        // Flush last policy
        if (currentName != null) {
            policies.add(flush(currentName, currentRw, currentRo, currentExec, sawAnyList, currentLineNo));
        }

        return policies;
    }

    /**
     * Fills {@code target} from the text after a {@code rw:}/{@code ro:}/{@code exec:}
     * key and returns it if the key opened a block sequence — i.e. carried no inline
     * value — or null if the list is complete on this line.
     */
    private static List<String> startList(List<String> target, String afterKey) {
        String rest = afterKey.trim();
        if (rest.isEmpty()) {
            return target;
        }
        target.addAll(parseInlineList(rest));
        return null;
    }

    private static AccessPolicy flush(String name, List<String> rw, List<String> ro, List<String> exec,
            boolean sawAnyList, int lineNo) {
        if (!sawAnyList) {
            // Every list absent means the principals were never parsed, not that the
            // policy authorizes nobody. An empty policy must be written out explicitly.
            throw new IllegalArgumentException("line " + lineNo + ": policy \"" + name
                    + "\" declares none of rw, ro or exec");
        }
        return new AccessPolicy(name, List.copyOf(rw), List.copyOf(ro), List.copyOf(exec));
    }

    /**
     * Drops a trailing {@code #} comment, ignoring a {@code #} inside a quoted string.
     */
    private static String stripComment(String line) {
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == '#' && !inQuotes) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    /**
     * Extracts a quoted string value from YAML, e.g. {@code "ClusterState"} -> {@code ClusterState}.
     */
    private static String extractQuotedValue(String s) {
        s = s.trim();
        if (s.startsWith("\"") && s.endsWith("\"") && s.length() >= 2) {
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
