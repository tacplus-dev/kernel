package com.gitlab.seabeam.controlplane.codegen.generator;

import com.gitlab.seabeam.controlplane.codegen.model.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Generates per-boundary {Type}Map.java files.
 * Each boundary gets a typed wrapper around IMap with get/set/delete.
 */
public class TypedMapGenerator {

    public static void generate(BackendServiceInfo svc, SharedBackendInfo info, GeneratorContext ctx) throws IOException {
        String outerClassName = ctx.getOuterClassName(svc);

        for (SharedBoundary b : info.getSingletons()) {
            generateTypedMap(svc, info, b, outerClassName, ctx, false);
        }
        for (SharedBoundary b : info.getCollections()) {
            generateTypedMap(svc, info, b, outerClassName, ctx, true);
        }
        for (SharedBoundary b : info.getQueues()) {
            generateTypedQueue(svc, info, b, outerClassName, ctx);
        }
        for (SharedBoundary b : info.getPriorityQueues()) {
            generateTypedQueue(svc, info, b, outerClassName, ctx);
        }
        for (SharedBoundary b : info.getTopics()) {
            generateTypedTopic(svc, info, b, outerClassName, ctx);
        }
    }

    private static void generateTypedMap(BackendServiceInfo svc, SharedBackendInfo info, SharedBoundary b,
            String outerClassName, GeneratorContext ctx, boolean isCollection) throws IOException {
        String pkg = ctx.getFullPackage(svc);
        String qualifiedType = ctx.getQualifiedType(outerClassName, b);
        String helpersRef = ctx.getHelpersRef(svc, b);
        String className = b.getTypeName() + "Map";

        String templateName = isCollection ? "TypedMapCollection.java.template" : "TypedMapSingleton.java.template";

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TYPES_IMPORT", typesImport(b, ctx, svc));
        vars.put("CROSS_IMPORTS", ctx.getCrossPackageImport(b));
        vars.put("CLASS_NAME", className);
        vars.put("TYPE_NAME", b.getTypeName());
        vars.put("QUALIFIED_TYPE", qualifiedType);
        vars.put("HELPERS_REF", helpersRef);

        String content = TemplateEngine.render(templateName, vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(className + ".java"), content);
    }

    private static void generateTypedQueue(BackendServiceInfo svc, SharedBackendInfo info, SharedBoundary b,
            String outerClassName, GeneratorContext ctx) throws IOException {
        String pkg = ctx.getFullPackage(svc);
        String qualifiedType = ctx.getQualifiedType(outerClassName, b);
        String helpersRef = ctx.getHelpersRef(svc, b);
        String className = b.getTypeName() + "Queue";

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TYPES_IMPORT", typesImport(b, ctx, svc));
        vars.put("CROSS_IMPORTS", ctx.getCrossPackageImport(b));
        vars.put("CLASS_NAME", className);
        vars.put("TYPE_NAME", b.getTypeName());
        vars.put("QUALIFIED_TYPE", qualifiedType);
        vars.put("HELPERS_REF", helpersRef);

        String content = TemplateEngine.render("TypedQueue.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(className + ".java"), content);
    }

    private static void generateTypedTopic(BackendServiceInfo svc, SharedBackendInfo info, SharedBoundary b,
            String outerClassName, GeneratorContext ctx) throws IOException {
        String pkg = ctx.getFullPackage(svc);
        String qualifiedType = ctx.getQualifiedType(outerClassName, b);
        String helpersRef = ctx.getHelpersRef(svc, b);
        String className = b.getTypeName() + "Topic";

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TYPES_IMPORT", typesImport(b, ctx, svc));
        vars.put("CROSS_IMPORTS", ctx.getCrossPackageImport(b));
        vars.put("CLASS_NAME", className);
        vars.put("TYPE_NAME", b.getTypeName());
        vars.put("QUALIFIED_TYPE", qualifiedType);
        vars.put("HELPERS_REF", helpersRef);

        String content = TemplateEngine.render("TypedTopic.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(className + ".java"), content);
    }

    /** Returns the types wildcard import only when the boundary uses the local outer class. */
    private static String typesImport(SharedBoundary b, GeneratorContext ctx, BackendServiceInfo svc) {
        if (b.isCrossPackage()) {
            return "";
        }
        return "import " + ctx.getTypesPackage(svc) + ".*;\n";
    }
}
