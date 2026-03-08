package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Generates {BackendName}Map.java — typed IMap accessors per boundary.
 * Singletons get/put/lock, collections get/put/delete.
 */
public class BackendMapGenerator {

    public static void generate(BackendServiceInfo svc, SharedBackendInfo info, GeneratorContext ctx) throws IOException {
        String pkg = ctx.getFullPackage(svc);
        String outerClassName = ctx.getOuterClassName(svc);
        String className = info.getClassName();

        // Build cross-imports section
        List<String> crossImports = ctx.getCrossPackageImports(info, outerClassName);
        StringBuilder crossSb = new StringBuilder();
        if (!crossImports.isEmpty()) {
            crossSb.append("\n");
            for (String imp : crossImports) crossSb.append(imp).append("\n");
        }

        // Build fields
        StringBuilder fields = new StringBuilder();
        for (SharedBoundary b : info.getSingletons()) {
            String qt = ctx.getQualifiedType(outerClassName, b);
            fields.append("    private final IMap<String, ").append(qt).append("> ").append(b.getFieldCamel()).append("Map;\n");
        }
        for (SharedBoundary b : info.getCollections()) {
            String qt = ctx.getQualifiedType(outerClassName, b);
            fields.append("    private final IMap<String, ").append(qt).append("> ").append(b.getFieldCamel()).append("Map;\n");
        }
        for (SharedBoundary b : info.getQueues()) {
            String qt = ctx.getQualifiedType(outerClassName, b);
            fields.append("    private final IQueue<").append(qt).append("> ").append(b.getFieldCamel()).append("Queue;\n");
        }
        for (SharedBoundary b : info.getPriorityQueues()) {
            String qt = ctx.getQualifiedType(outerClassName, b);
            fields.append("    private final IQueue<").append(qt).append("> ").append(b.getFieldCamel()).append("Queue;\n");
        }
        for (SharedBoundary b : info.getTopics()) {
            String qt = ctx.getQualifiedType(outerClassName, b);
            fields.append("    private final ITopic<").append(qt).append("> ").append(b.getFieldCamel()).append("Topic;\n");
        }

        // Check if manager field is needed (atomic singletons use manager.getLock() at runtime)
        boolean needsManager = info.getSingletons().stream().anyMatch(SharedBoundary::isAtomic);

        // Build constructor
        StringBuilder ctor = new StringBuilder();
        ctor.append("\n    public ").append(className).append("(Manager manager) {\n");
        if (needsManager) {
            ctor.append("        this.manager = manager;\n");
        }
        for (SharedBoundary b : info.getSingletons()) {
            String mapGetter = b.isAtomic() ? "getAtomicMap" : b.isReplicated() ? "getReplicatedMap" : "getConvergentMap";
            ctor.append("        this.").append(b.getFieldCamel()).append("Map = manager.").append(mapGetter)
              .append("(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
        }
        for (SharedBoundary b : info.getCollections()) {
            String mapGetter = b.isAtomic() ? "getAtomicMap" : b.isReplicated() ? "getReplicatedMap" : "getConvergentMap";
            ctor.append("        this.").append(b.getFieldCamel()).append("Map = manager.").append(mapGetter)
              .append("(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
        }
        for (SharedBoundary b : info.getQueues()) {
            ctor.append("        this.").append(b.getFieldCamel()).append("Queue = manager.getQueue(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
        }
        for (SharedBoundary b : info.getPriorityQueues()) {
            ctor.append("        this.").append(b.getFieldCamel()).append("Queue = manager.getQueue(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
        }
        for (SharedBoundary b : info.getTopics()) {
            ctor.append("        this.").append(b.getFieldCamel()).append("Topic = manager.getTopic(CLASS_NAME + \":").append(b.getMapName()).append("\");\n");
        }
        ctor.append("    }\n");

        // Build proto() method
        StringBuilder proto = new StringBuilder();
        proto.append("\n    /**\n");
        proto.append("     * Assembles the full ").append(info.getBackendName()).append(" proto from all cached boundaries.\n");
        proto.append("     *\n");
        proto.append("     * @return the reconstructed state proto\n");
        proto.append("     */\n");
        proto.append("    public ").append(outerClassName).append(".").append(info.getBackendName())
          .append(" proto() throws ProtoException {\n");
        proto.append("        ").append(outerClassName).append(".").append(info.getBackendName())
          .append(".Builder builder = ").append(outerClassName).append(".").append(info.getBackendName())
          .append(".newBuilder();\n");
        for (SharedBoundary b : info.getSingletons()) {
            proto.append("        builder.set").append(b.getFieldPascal()).append("(get").append(b.getFieldPascal()).append("());\n");
        }
        for (SharedBoundary b : info.getCollections()) {
            proto.append("        builder.addAll").append(b.getFieldPascal()).append("(new java.util.ArrayList<>(").append(b.getFieldCamel()).append("Map.values()));\n");
        }
        proto.append("        return builder.build();\n");
        proto.append("    }\n");

        // Build methods via fragments
        StringBuilder methods = new StringBuilder();

        if (!info.getSingletons().isEmpty()) {
            methods.append("\n    // ==================== Singleton Boundaries ====================\n");
            for (SharedBoundary b : info.getSingletons()) {
                Map<String, String> vars = boundaryVars(b, outerClassName, svc, ctx);
                String consType = b.isAtomic() ? "ATOMIC" : "CONVERGENT";
                methods.append("\n    // --- ").append(b.getTypeName()).append(" (").append(consType).append(" singleton) ---\n");
                methods.append(TemplateEngine.renderFragment("statemap_singleton_get.java.template", vars));
                if (b.isAtomic()) {
                    methods.append(TemplateEngine.renderFragment("statemap_singleton_put_atomic.java.template", vars));
                } else {
                    methods.append(TemplateEngine.renderFragment("statemap_singleton_put_convergent.java.template", vars));
                }
            }
        }

        methods.append("\n    // ==================== Collection Boundaries ====================\n");
        for (SharedBoundary b : info.getCollections()) {
            Map<String, String> vars = boundaryVars(b, outerClassName, svc, ctx);
            methods.append("\n    // --- ").append(b.getTypeName()).append(" (collection) ---\n");
            methods.append(TemplateEngine.renderFragment("statemap_collection_get.java.template", vars));
            if (b.getEpochExpirationGetter() != null) {
                // TTL-aware put: compute TTL from epoch expiration field
                methods.append(generateEpochPut(b, vars, outerClassName));
            } else if (b.isAtomic()) {
                methods.append(TemplateEngine.renderFragment("statemap_collection_put_atomic.java.template", vars));
            } else {
                methods.append(TemplateEngine.renderFragment("statemap_collection_put_convergent.java.template", vars));
            }
            methods.append(TemplateEngine.renderFragment("statemap_collection_delete.java.template", vars));
        }

        if (!info.getQueues().isEmpty()) {
            methods.append("\n    // ==================== Queue Boundaries ====================\n");
            for (SharedBoundary b : info.getQueues()) {
                Map<String, String> vars = boundaryVars(b, outerClassName, svc, ctx);
                String label = "FIFO queue";
                methods.append("\n    // --- ").append(b.getTypeName()).append(" (").append(label).append(") ---\n");
                methods.append(TemplateEngine.renderFragment("statemap_queue.java.template", vars));
            }
        }

        if (!info.getPriorityQueues().isEmpty()) {
            methods.append("\n    // ==================== Priority Queue Boundaries ====================\n");
            for (SharedBoundary b : info.getPriorityQueues()) {
                Map<String, String> vars = boundaryVars(b, outerClassName, svc, ctx);
                String label = "priority queue, priority: " + b.getPriorityField();
                methods.append("\n    // --- ").append(b.getTypeName()).append(" (").append(label).append(") ---\n");
                methods.append(TemplateEngine.renderFragment("statemap_queue.java.template", vars));
            }
        }

        if (!info.getTopics().isEmpty()) {
            methods.append("\n    // ==================== Topic Boundaries ====================\n");
            for (SharedBoundary b : info.getTopics()) {
                Map<String, String> vars = boundaryVars(b, outerClassName, svc, ctx);
                methods.append("\n    // --- ").append(b.getTypeName()).append(" (topic) ---\n");
                methods.append(TemplateEngine.renderFragment("statemap_topic.java.template", vars));
            }
        }

        // Build conditional imports
        StringBuilder extraImports = new StringBuilder();
        boolean hasQueues = !info.getQueues().isEmpty() || !info.getPriorityQueues().isEmpty();
        boolean hasTopics = !info.getTopics().isEmpty();
        boolean hasAtomic = info.getSingletons().stream().anyMatch(SharedBoundary::isAtomic)
                || info.getCollections().stream().anyMatch(SharedBoundary::isAtomic);
        if (hasQueues) {
            extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".IQueue;\n");
        }
        if (hasTopics) {
            extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".ITopic;\n");
        }
        if (hasAtomic) {
            extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".Lock;\n");
        }
        if (!info.getSingletons().isEmpty()) {
            extraImports.append("import ").append(ctx.getInterfacesPackage()).append(".Singleton;\n");
        }

        // Render main template
        Map<String, String> mainVars = new LinkedHashMap<>();
        mainVars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        mainVars.put("PACKAGE", pkg);
        mainVars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        mainVars.put("EXTRA_IMPORTS", extraImports.toString());
        mainVars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        mainVars.put("CROSS_IMPORTS", crossSb.toString());
        mainVars.put("TYPES_PACKAGE", ctx.getTypesPackage(svc));
        mainVars.put("OUTER_CLASS", outerClassName);
        mainVars.put("BACKEND_NAME", info.getBackendName());
        mainVars.put("PROTO_FILE", svc.getProtoFile());
        mainVars.put("CLASS_NAME", className);
        mainVars.put("MANAGER_FIELD", needsManager ? "    private final Manager manager;\n" : "");
        mainVars.put("FIELDS", fields.toString());
        mainVars.put("CONSTRUCTOR", ctor.toString());
        mainVars.put("PROTO_METHOD", proto.toString());
        mainVars.put("METHODS", methods.toString());

        String content = TemplateEngine.render("BackendMap.java.template", mainVars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(className + ".java"), content);
    }

    private static String generateEpochPut(SharedBoundary b, Map<String, String> vars, String outerClassName) {
        StringBuilder sb = new StringBuilder();
        String qualifiedType = vars.get("QUALIFIED_TYPE");
        String helpersRef = vars.get("HELPERS_REF");
        String typeName = b.getTypeName();
        String fieldPascal = b.getFieldPascal();
        String fieldCamel = b.getFieldCamel();
        String getter = b.getEpochExpirationGetter();

        if (b.isAtomic()) {
            sb.append("\n    public void put").append(fieldPascal).append("(String key, ").append(qualifiedType)
              .append(" value, Lock lock) throws ProtoException {\n");
            sb.append("        if (!lock.isLockedByCurrentThread()) {\n");
            sb.append("            throw new ProtoException(\n");
            sb.append("                    ProtoException.FAILED_PRECONDITION, \"Must hold lock to update atomic state: ").append(fieldPascal).append("\");\n");
            sb.append("        }\n");
        } else {
            sb.append("\n    public void put").append(fieldPascal).append("(String key, ").append(qualifiedType)
              .append(" value) throws ProtoException {\n");
        }
        sb.append("        ").append(helpersRef).append(".validate").append(typeName).append("(value);\n");
        sb.append("        long epochExp = value.").append(getter).append("();\n");
        sb.append("        if (epochExp > 0) {\n");
        sb.append("            long ttl = epochExp - (System.currentTimeMillis() / 1000);\n");
        sb.append("            ").append(fieldCamel).append("Map.put(key, value, ttl, java.util.concurrent.TimeUnit.SECONDS);\n");
        sb.append("        } else {\n");
        sb.append("            ").append(fieldCamel).append("Map.put(key, value);\n");
        sb.append("        }\n");
        sb.append("    }\n");

        return sb.toString();
    }

    private static Map<String, String> boundaryVars(SharedBoundary b, String outerClassName,
            BackendServiceInfo svc, GeneratorContext ctx) {
        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("QUALIFIED_TYPE", ctx.getQualifiedType(outerClassName, b));
        vars.put("TYPE_NAME", b.getTypeName());
        vars.put("FIELD_CAMEL", b.getFieldCamel());
        vars.put("FIELD_PASCAL", b.getFieldPascal());
        vars.put("MAP_NAME", b.getMapName());
        vars.put("HELPERS_REF", ctx.getHelpersRef(svc, b));
        return vars;
    }
}
