package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;
import com.gitlab.seabeam.controlplane.codegen.model.TenantPinnedRead;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses codegen-config.json written by tacplus.
 * The JSON is machine-generated with a known, stable format.
 * No external JSON library needed — uses line-by-line parsing.
 *
 * <p>Format:
 * <pre>
 * {
 *   "javaPackageBase": "...",
 *   "interfacesPackage": "...",
 *   "securityPolicies": [
 *     {
 *       "name": "ClusterState",
 *       "package": "myservice",
 *       "rw": ["service:myservice"],
 *       "ro": ["*"],
 *       "disableAuth": false,
 *       "internal": false
 *     }
 *   ]
 * }
 * </pre>
 */
public class CodegenConfig {
    public String javaPackageBase;
    public String interfacesPackage;
    /** Token audiences this service accepts: its service label plus any vservice it hosts. */
    public List<String> acceptedAudiences = new ArrayList<>();
    public List<AccessPolicy> securityPolicies = new ArrayList<>();
    /** Service name → list of RPC method names, for entitlements enforcement. */
    public Map<String, List<String>> serviceRPCMappings = new HashMap<>();

    /**
     * Parses a codegen-config.json file.
     */
    public static CodegenConfig parse(File configFile) throws IOException {
        String content = Files.readString(configFile.toPath());
        CodegenConfig config = new CodegenConfig();

        // Parse top-level string fields
        config.javaPackageBase = extractStringField(content, "javaPackageBase");
        config.interfacesPackage = extractStringField(content, "interfacesPackage");
        config.acceptedAudiences = extractStringArray(content, "acceptedAudiences");

        // Parse securityPolicies array
        int policiesStart = content.indexOf("\"securityPolicies\"");
        if (policiesStart >= 0) {
            int arrayStart = content.indexOf('[', policiesStart);
            int arrayEnd = findMatchingBracket(content, arrayStart);
            if (arrayStart >= 0 && arrayEnd > arrayStart) {
                String arrayContent = content.substring(arrayStart + 1, arrayEnd);
                config.securityPolicies = parsePolicies(arrayContent);
            }
        }

        // Parse serviceRPCMappings array
        int mappingsStart = content.indexOf("\"serviceRPCMappings\"");
        if (mappingsStart >= 0) {
            int arrayStart = content.indexOf('[', mappingsStart);
            int arrayEnd = findMatchingBracket(content, arrayStart);
            if (arrayStart >= 0 && arrayEnd > arrayStart) {
                String arrayContent = content.substring(arrayStart + 1, arrayEnd);
                config.serviceRPCMappings = parseServiceRPCMappings(arrayContent);
            }
        }

        return config;
    }

    private static String extractStringField(String json, String fieldName) {
        String search = "\"" + fieldName + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colonIdx = json.indexOf(':', idx + search.length());
        if (colonIdx < 0) return null;
        String rest = json.substring(colonIdx + 1).trim();
        if (rest.startsWith("\"")) {
            int endQuote = rest.indexOf('"', 1);
            if (endQuote > 0) {
                return rest.substring(1, endQuote);
            }
        }
        return null;
    }

    private static List<AccessPolicy> parsePolicies(String arrayContent) {
        List<AccessPolicy> policies = new ArrayList<>();
        int pos = 0;
        while (pos < arrayContent.length()) {
            int objStart = arrayContent.indexOf('{', pos);
            if (objStart < 0) break;
            int objEnd = findMatchingBrace(arrayContent, objStart);
            if (objEnd < 0) break;

            String obj = arrayContent.substring(objStart, objEnd + 1);
            AccessPolicy policy = parsePolicy(obj);
            if (policy != null) {
                policies.add(policy);
            }
            pos = objEnd + 1;
        }
        return policies;
    }

    private static AccessPolicy parsePolicy(String obj) {
        String name = extractStringField(obj, "name");
        if (name == null) return null;

        String pkg = extractStringField(obj, "package");
        List<String> rw = extractStringArray(obj, "rw");
        List<String> ro = extractStringArray(obj, "ro");
        Map<String, List<String>> boundaryGrants = parseBoundaryGrants(obj);
        List<TenantPinnedRead> tenantPinnedReads = parseTenantPinnedReads(name, obj);
        boolean disableAuth = extractBoolField(obj, "disableAuth");
        boolean internal = extractBoolField(obj, "internal");

        return new AccessPolicy(name, pkg == null ? "" : pkg, rw, ro, List.of(),
                boundaryGrants, tenantPinnedReads, disableAuth, internal);
    }

    /**
     * Parses the optional "tenantPinnedReads" array of a policy object (tacplus #130).
     * Each entry is {"boundary", "keyField", "configField",
     * "slices": [{"caller", "sliceField"}, ...]}. It is deliberately not a
     * boundaryGrants entry: a reader that does not know this field grants nothing.
     * An entry missing any part fails generation rather than being dropped.
     */
    private static List<TenantPinnedRead> parseTenantPinnedReads(String policyName, String obj) {
        int idx = obj.indexOf("\"tenantPinnedReads\"");
        if (idx < 0) return List.of();
        int arrayStart = obj.indexOf('[', idx);
        int arrayEnd = findMatchingBracket(obj, arrayStart);
        if (arrayStart < 0 || arrayEnd < arrayStart) {
            throw new IllegalStateException("codegen-config.json: malformed tenantPinnedReads on " + policyName);
        }

        String arrayContent = obj.substring(arrayStart + 1, arrayEnd);
        List<TenantPinnedRead> reads = new ArrayList<>();
        int pos = 0;
        while (pos < arrayContent.length()) {
            int objStart = arrayContent.indexOf('{', pos);
            if (objStart < 0) break;
            int objEnd = findMatchingBrace(arrayContent, objStart);
            if (objEnd < 0) break;

            String entry = arrayContent.substring(objStart, objEnd + 1);
            String boundary = extractStringField(entry, "boundary");
            String keyField = extractStringField(entry, "keyField");
            String configField = extractStringField(entry, "configField");
            Map<String, String> slices = parseSlices(entry);
            if (isEmpty(boundary) || isEmpty(keyField) || isEmpty(configField) || slices.isEmpty()) {
                throw new IllegalStateException("codegen-config.json: tenantPinnedReads entry on " + policyName
                        + " needs boundary, keyField, configField and at least one slice: " + entry);
            }
            reads.add(new TenantPinnedRead(boundary, keyField, configField, slices));
            pos = objEnd + 1;
        }
        return reads;
    }

    /** Parses a tenantPinnedReads entry's "slices" array: caller → sliceField, in file order. */
    private static Map<String, String> parseSlices(String entry) {
        int idx = entry.indexOf("\"slices\"");
        if (idx < 0) return Map.of();
        int arrayStart = entry.indexOf('[', idx);
        int arrayEnd = findMatchingBracket(entry, arrayStart);
        if (arrayStart < 0 || arrayEnd < arrayStart) return Map.of();

        String arrayContent = entry.substring(arrayStart + 1, arrayEnd);
        Map<String, String> slices = new LinkedHashMap<>();
        int pos = 0;
        while (pos < arrayContent.length()) {
            int objStart = arrayContent.indexOf('{', pos);
            if (objStart < 0) break;
            int objEnd = findMatchingBrace(arrayContent, objStart);
            if (objEnd < 0) break;

            String slice = arrayContent.substring(objStart, objEnd + 1);
            String caller = extractStringField(slice, "caller");
            String sliceField = extractStringField(slice, "sliceField");
            if (isEmpty(caller) || isEmpty(sliceField)) {
                throw new IllegalStateException("codegen-config.json: tenantPinnedReads slice needs caller and sliceField: "
                        + slice);
            }
            slices.put(caller, sliceField);
            pos = objEnd + 1;
        }
        return slices;
    }

    private static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }

    /**
     * Parses the optional "boundaryGrants" array of a policy object. Each entry is
     * {"boundary": "<field>", "callers": [...], "type": "queue"|"topic"|"command"}.
     * Only boundary and callers are consumed — the operation the caller is granted
     * is the boundary itself, not a read/write mode.
     */
    private static Map<String, List<String>> parseBoundaryGrants(String obj) {
        int idx = obj.indexOf("\"boundaryGrants\"");
        if (idx < 0) return Map.of();
        int arrayStart = obj.indexOf('[', idx);
        int arrayEnd = findMatchingBracket(obj, arrayStart);
        if (arrayStart < 0 || arrayEnd < arrayStart) return Map.of();

        String arrayContent = obj.substring(arrayStart + 1, arrayEnd);
        Map<String, List<String>> grants = new HashMap<>();
        int pos = 0;
        while (pos < arrayContent.length()) {
            int objStart = arrayContent.indexOf('{', pos);
            if (objStart < 0) break;
            int objEnd = findMatchingBrace(arrayContent, objStart);
            if (objEnd < 0) break;

            String entry = arrayContent.substring(objStart, objEnd + 1);
            String boundary = extractStringField(entry, "boundary");
            List<String> callers = extractStringArray(entry, "callers");
            if (boundary != null && !boundary.isEmpty() && !callers.isEmpty()) {
                grants.put(boundary, callers);
            }
            pos = objEnd + 1;
        }
        return grants;
    }

    private static List<String> extractStringArray(String json, String fieldName) {
        String search = "\"" + fieldName + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return List.of();
        int colonIdx = json.indexOf(':', idx + search.length());
        if (colonIdx < 0) return List.of();
        String rest = json.substring(colonIdx + 1).trim();
        if (!rest.startsWith("[")) return List.of();

        int bracketEnd = findMatchingBracket(rest, 0);
        if (bracketEnd < 0) return List.of();

        String arrayStr = rest.substring(1, bracketEnd);
        List<String> result = new ArrayList<>();
        int pos = 0;
        while (pos < arrayStr.length()) {
            int quoteStart = arrayStr.indexOf('"', pos);
            if (quoteStart < 0) break;
            int quoteEnd = arrayStr.indexOf('"', quoteStart + 1);
            if (quoteEnd < 0) break;
            result.add(arrayStr.substring(quoteStart + 1, quoteEnd));
            pos = quoteEnd + 1;
        }
        return result;
    }

    private static boolean extractBoolField(String json, String fieldName) {
        String search = "\"" + fieldName + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return false;
        int colonIdx = json.indexOf(':', idx + search.length());
        if (colonIdx < 0) return false;
        String rest = json.substring(colonIdx + 1).trim();
        return rest.startsWith("true");
    }

    private static int findMatchingBracket(String s, int openPos) {
        if (openPos < 0 || openPos >= s.length() || s.charAt(openPos) != '[') return -1;
        int depth = 1;
        for (int i = openPos + 1; i < s.length(); i++) {
            if (s.charAt(i) == '[') depth++;
            else if (s.charAt(i) == ']') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private static int findMatchingBrace(String s, int openPos) {
        if (openPos < 0 || openPos >= s.length() || s.charAt(openPos) != '{') return -1;
        int depth = 1;
        for (int i = openPos + 1; i < s.length(); i++) {
            if (s.charAt(i) == '{') depth++;
            else if (s.charAt(i) == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    /**
     * Parses the serviceRPCMappings array from codegen-config.json.
     * Each entry has "serviceName" (string) and "rpcs" (string array).
     */
    private static Map<String, List<String>> parseServiceRPCMappings(String arrayContent) {
        Map<String, List<String>> result = new HashMap<>();
        int pos = 0;
        while (pos < arrayContent.length()) {
            int objStart = arrayContent.indexOf('{', pos);
            if (objStart < 0) break;
            int objEnd = findMatchingBrace(arrayContent, objStart);
            if (objEnd < 0) break;

            String obj = arrayContent.substring(objStart, objEnd + 1);
            String serviceName = extractStringField(obj, "serviceName");
            List<String> rpcs = extractStringArray(obj, "rpcs");
            if (serviceName != null && !serviceName.isEmpty()) {
                result.put(serviceName, rpcs);
            }
            pos = objEnd + 1;
        }
        return result;
    }
}
