package com.gitlab.seabeam.controlplane.codegen.generator;

import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;
import com.gitlab.seabeam.controlplane.codegen.model.TenantPinnedRead;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Generates SecurityAuthenticator.java, NamespaceScope.java and SecurityInterceptor.java.
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

        // Build the no-auth skip sets from proto annotations
        List<String> noAuthEntries = ctx.getNoAuthServiceNames();

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", ctx.header("security_authenticator"));
        vars.put("PACKAGE", pkg);
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TOKEN_PACKAGE", ctx.getTokenPackage());
        vars.put("SPIFFE_PACKAGE", ctx.getSpiffePackage());
        vars.put("JWK_LIB_PACKAGE", ctx.getJwkLibPackage());
        vars.put("JWK_TYPES_PACKAGE", ctx.getJwkTypesPackage());
        vars.put("NO_AUTH_SERVICES", buildNoAuthSet(noAuthEntries, false));
        vars.put("NO_AUTH_METHODS", buildNoAuthSet(noAuthEntries, true));
        vars.put("ACCEPTED_AUDIENCES", buildAcceptedAudiences(ctx.getAcceptedAudiences()));
        vars.put("POLICY_MAP_INIT", buildAuthenticatorPolicyMapInit(ctx.getSecurityPolicies()));
        vars.put("TENANT_PINNED_READS", buildTenantPinnedReads(ctx.getSecurityPolicies()));

        String content = TemplateEngine.render("SecurityAuthenticator.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("SecurityAuthenticator.java"), content);

        // NamespaceScope reads SecurityAuthenticator.CALLER_NAMESPACE_KEY and is
        // emitted alongside it, once per build, in the same package.
        Map<String, String> scopeVars = new LinkedHashMap<>();
        scopeVars.put("HEADER", ctx.header("namespace_scope"));
        scopeVars.put("PACKAGE", pkg);
        scopeVars.put("SPIFFE_PACKAGE", ctx.getSpiffePackage());
        Files.writeString(dir.resolve("NamespaceScope.java"),
                TemplateEngine.render("NamespaceScope.java.template", scopeVars));

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
        vars.put("HEADER", ctx.header("security_interceptor"));
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

    /**
     * Builds SecurityAuthenticator's tenant-pinned read authorization (tacplus #130):
     * the TENANT_PINNED_READS table, checkPinnedRead and the TenantPin class. Empty
     * when no policy carries tenantPinnedReads, so such a build generates exactly
     * what it did before the field existed.
     */
    private static String buildTenantPinnedReads(List<AccessPolicy> policies) {
        List<String> entries = new ArrayList<>();
        for (AccessPolicy policy : policies) {
            for (TenantPinnedRead read : policy.tenantPinnedReads()) {
                List<String> slices = new ArrayList<>();
                for (var slice : read.slices().entrySet()) {
                    slices.add("Map.entry(\"" + slice.getKey() + "\", \"" + slice.getValue() + "\")");
                }
                entries.add("            Map.entry(\"" + policy.graphKey() + "/" + read.boundary()
                        + "\", new PinnedRead(\"" + read.keyField() + "\", \"" + read.configField()
                        + "\", Map.ofEntries(" + String.join(", ", slices) + ")))");
            }
        }
        if (entries.isEmpty()) {
            return "";
        }
        return TemplateEngine.renderFragment("authenticator_tenant_pinned_reads.java.template",
                Map.of("TENANT_PINNED_READS_INIT", String.join(",\n", entries)));
    }

    /**
     * Builds the ACCEPTED_AUDIENCES initializer. tacplus computes the set (service
     * label plus hosted vservices) and publishes it in codegen-config.json; an empty
     * set would make the audience check vacuous, so generation fails instead.
     */
    private static String buildAcceptedAudiences(List<String> audiences) {
        if (audiences == null || audiences.isEmpty()) {
            throw new IllegalStateException(
                    "codegen-config.json carries no acceptedAudiences — regenerate with tacplus; "
                            + "the state-plane audience check cannot be generated without it");
        }
        List<String> quoted = new ArrayList<>();
        for (String aud : audiences) {
            quoted.add("\"" + aud + "\"");
        }
        return String.join(", ", quoted);
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
     * Builds the contents of a Set.of(...) initializer for the no-auth skip list.
     * Entries without "/" are service-level ("ServiceName"); entries with "/" are
     * per-RPC ("ServiceName/RpcName"). Both are matched for exact equality at
     * runtime, so a name that merely contains an entry is not exempt.
     */
    private static String buildNoAuthSet(List<String> entries, boolean perMethod) {
        Set<String> selected = new LinkedHashSet<>();
        for (String entry : entries) {
            if (entry.contains("/") == perMethod) {
                selected.add("\"" + entry + "\"");
            }
        }
        return String.join(", ", selected);
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
