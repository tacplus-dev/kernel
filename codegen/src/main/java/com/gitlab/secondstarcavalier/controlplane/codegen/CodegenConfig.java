package com.gitlab.secondstarcavalier.controlplane.codegen;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.AccessPolicy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
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

        List<String> rw = extractStringArray(obj, "rw");
        List<String> ro = extractStringArray(obj, "ro");
        boolean disableAuth = extractBoolField(obj, "disableAuth");
        boolean internal = extractBoolField(obj, "internal");

        return new AccessPolicy(name, rw, ro, List.of(), disableAuth, internal);
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
