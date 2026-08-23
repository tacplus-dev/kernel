package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.AccessPolicy;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Generates SecurityAuthenticator.java and SecurityInterceptor.java.
 *
 * <p>SecurityAuthenticator provides caller identity extraction for generated
 * BackendServiceServer classes.
 *
 * <p>SecurityInterceptor validates JWT tokens and enforces graph access policies.
 * Security policies are derived from proto annotations at build time:
 * <ul>
 *   <li>backend_internal → no cross-namespace access</li>
 *   <li>backend_disable_auth → skip authentication for this backend's RPCs</li>
 *   <li>instance_keyed → any authenticated service writes its own entry</li>
 *   <li>Default: cross-namespace RO for singletons/collections</li>
 * </ul>
 */
public class SecurityAuthenticatorGenerator {

    public static void generate(GeneratorContext ctx) throws IOException {
        String pkg = ctx.getJavaPackageBase();

        // Build the no-auth service skip condition from proto annotations
        List<String> noAuthServices = ctx.getNoAuthServiceNames();
        String noAuthSkipCondition = buildNoAuthSkipCondition(noAuthServices);

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header("security_authenticator"));
        vars.put("PACKAGE", pkg);
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TOKEN_PACKAGE", ctx.getTokenPackage());
        vars.put("JWK_LIB_PACKAGE", ctx.getJwkLibPackage());
        vars.put("JWK_TYPES_PACKAGE", ctx.getJwkTypesPackage());
        vars.put("NO_AUTH_SKIP", noAuthSkipCondition);
        vars.put("POLICY_MAP_INIT", buildAuthenticatorPolicyMapInit(ctx.getSecurityPolicies()));

        String content = TemplateEngine.render("SecurityAuthenticator.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("SecurityAuthenticator.java"), content);

        // Generate SecurityInterceptor if security policies are available
        if (!ctx.getSecurityPolicies().isEmpty()) {
            generateSecurityInterceptor(ctx, dir);
        }
    }

    private static void generateSecurityInterceptor(GeneratorContext ctx, Path dir) throws IOException {
        String pkg = ctx.getJavaPackageBase();

        // Build the policy map initialization code and no-auth set from policies
        String policyMapInit = buildPolicyMapInit(ctx.getSecurityPolicies());
        String noAuthGraphsInit = buildNoAuthGraphsInit(ctx.getSecurityPolicies());
        String serviceEntitlementsInit = buildServiceEntitlementsInit(ctx.getServiceRPCMappings());

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header("security_interceptor"));
        vars.put("PACKAGE", pkg);
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TOKEN_PACKAGE", ctx.getTokenPackage());
        vars.put("JWK_LIB_PACKAGE", ctx.getJwkLibPackage());
        vars.put("JWK_TYPES_PACKAGE", ctx.getJwkTypesPackage());
        vars.put("BACKENDDB_TYPES_PACKAGE", ctx.getBackenddbTypesPackage());
        vars.put("POLICY_MAP_INIT", policyMapInit);
        vars.put("NO_AUTH_GRAPHS_INIT", noAuthGraphsInit);
        vars.put("SERVICE_ENTITLEMENTS_INIT", serviceEntitlementsInit);

        String content = TemplateEngine.render("SecurityInterceptor.java.template", vars);
        Files.writeString(dir.resolve("SecurityInterceptor.java"), content);
    }

    /**
     * Builds the GRAPH_POLICIES initializer for SecurityAuthenticator.checkAccess.
     * Keyed by "&lt;proto package&gt;.&lt;state root&gt;" — the same key the generated
     * state servers pass — because the state root name alone does not identify a
     * graph across packages.
     */
    private static String buildAuthenticatorPolicyMapInit(List<AccessPolicy> policies) {
        StringBuilder sb = new StringBuilder();
        for (AccessPolicy policy : policies) {
            sb.append("        policies.put(\"").append(policy.graphKey()).append("\", new Policy(");
            sb.append(toJavaList(policy.rw()));
            sb.append(", ").append(toJavaList(policy.ro()));
            sb.append(", ").append(toJavaMap(policy.boundaryGrants()));
            sb.append("));\n");
        }
        return sb.toString();
    }

    private static String toJavaMap(Map<String, List<String>> grants) {
        if (grants == null || grants.isEmpty()) {
            return "Map.of()";
        }
        StringBuilder sb = new StringBuilder("Map.of(");
        boolean first = true;
        for (var entry : new java.util.TreeMap<>(grants).entrySet()) {
            if (!first) sb.append(", ");
            first = false;
            sb.append("\"").append(entry.getKey()).append("\", ").append(toJavaList(entry.getValue()));
        }
        sb.append(")");
        return sb.toString();
    }

    /**
     * Builds Java source code for initializing the policy map.
     * All policies are derived from proto annotations — no hardcoded built-ins.
     */
    private static String buildPolicyMapInit(List<AccessPolicy> policies) {
        StringBuilder sb = new StringBuilder();

        for (AccessPolicy policy : policies) {
            sb.append("        policies.put(\"").append(policy.name()).append("\", ");
            sb.append("buildPolicy(\"").append(policy.name()).append("\"");
            sb.append(", ").append(toJavaList(policy.rw()));
            sb.append(", ").append(toJavaList(policy.ro()));
            sb.append(", ").append(toJavaList(policy.exec()));
            sb.append("));\n");
        }

        return sb.toString();
    }

    /**
     * Builds the Set.of() initializer for NO_AUTH_GRAPHS from disableAuth policies.
     */
    private static String buildNoAuthGraphsInit(List<AccessPolicy> policies) {
        List<String> noAuthGraphs = new ArrayList<>();
        for (AccessPolicy policy : policies) {
            if (policy.disableAuth()) {
                noAuthGraphs.add("\"" + policy.name() + "\"");
            }
        }
        if (noAuthGraphs.isEmpty()) {
            return "Set.of()";
        }
        return "Set.of(" + String.join(", ", noAuthGraphs) + ")";
    }

    /**
     * Builds Java source code for initializing the SERVICE_ENTITLEMENTS map.
     * Maps service name → list of RPC method names for token entitlements.
     */
    private static String buildServiceEntitlementsInit(Map<String, List<String>> mappings) {
        StringBuilder sb = new StringBuilder();
        for (var entry : new java.util.TreeMap<>(mappings).entrySet()) {
            sb.append("        m.put(\"").append(entry.getKey()).append("\", ");
            sb.append(toJavaList(entry.getValue()));
            sb.append(");\n");
        }
        return sb.toString();
    }

    /**
     * Builds the Java condition for skipping auth on no-auth services/methods.
     * Entries without "/" are service-level: method.contains("ServiceName")
     * Entries with "/" are per-method: method.contains("ServiceName/RpcName")
     */
    private static String buildNoAuthSkipCondition(List<String> entries) {
        if (entries.isEmpty()) {
            return "false";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) sb.append("\n                    || ");
            sb.append("method.contains(\"").append(entries.get(i)).append("\")");
        }
        return sb.toString();
    }

    private static String toJavaList(List<String> items) {
        if (items == null || items.isEmpty()) {
            return "List.of()";
        }
        StringBuilder sb = new StringBuilder("List.of(");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(items.get(i)).append("\"");
        }
        sb.append(")");
        return sb.toString();
    }
}
