package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.*;

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

        List<String> crossImports = ctx.getCrossPackageImports(info, outerClassName);
        StringBuilder crossSb = new StringBuilder();
        for (String imp : crossImports) crossSb.append(imp).append("\n");
        if (!crossImports.isEmpty()) crossSb.append("\n");

        String templateName = isCollection ? "TypedMapCollection.java.template" : "TypedMapSingleton.java.template";

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TYPES_PACKAGE", ctx.getTypesPackage(svc));
        vars.put("OUTER_CLASS", outerClassName);
        vars.put("CROSS_IMPORTS", crossSb.toString());
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

        List<String> crossImports = ctx.getCrossPackageImports(info, outerClassName);
        StringBuilder crossSb = new StringBuilder();
        for (String imp : crossImports) crossSb.append(imp).append("\n");
        if (!crossImports.isEmpty()) crossSb.append("\n");

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TYPES_PACKAGE", ctx.getTypesPackage(svc));
        vars.put("OUTER_CLASS", outerClassName);
        vars.put("CROSS_IMPORTS", crossSb.toString());
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

        List<String> crossImports = ctx.getCrossPackageImports(info, outerClassName);
        StringBuilder crossSb = new StringBuilder();
        for (String imp : crossImports) crossSb.append(imp).append("\n");
        if (!crossImports.isEmpty()) crossSb.append("\n");

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header(svc.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("TYPES_PACKAGE", ctx.getTypesPackage(svc));
        vars.put("OUTER_CLASS", outerClassName);
        vars.put("CROSS_IMPORTS", crossSb.toString());
        vars.put("CLASS_NAME", className);
        vars.put("TYPE_NAME", b.getTypeName());
        vars.put("QUALIFIED_TYPE", qualifiedType);
        vars.put("HELPERS_REF", helpersRef);

        String content = TemplateEngine.render("TypedTopic.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(className + ".java"), content);
    }
}
