package com.gitlab.seabeam.controlplane.codegen.generator;

import com.gitlab.seabeam.controlplane.codegen.StringUtils;
import com.gitlab.seabeam.controlplane.codegen.model.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Generates Hazelcast Compact Serializers for boundary proto types.
 *
 * <p>Each boundary type gets a {@code CompactSerializer<ProtoMessage>} that:
 * <ul>
 *   <li>Writes the full proto as {@code __proto__} bytes for lossless round-trip</li>
 *   <li>Writes scalar fields individually as queryable projections</li>
 *   <li>Reads only from {@code __proto__} bytes (scalars are query-only)</li>
 * </ul>
 *
 * <p>This allows Hazelcast to query scalar fields (string, int32, int64, float,
 * double, bool) via predicates and SQL without deserializing the full message,
 * while nested messages and repeated fields are preserved losslessly in the proto bytes.
 */
public class SerializableWrapperGenerator {

    /** Tracks which Java classes we've already generated serializers for, to avoid duplicates. */
    private final Set<String> generatedClasses = new LinkedHashSet<>();

    /** All serializer info for the registry. */
    private final List<SerializerInfo> allSerializers = new ArrayList<>();

    private record SerializerInfo(String pkg, String className, String javaType) {}

    public static void generate(Map<BackendServiceInfo, SharedBackendInfo> infoMap, GeneratorContext ctx) throws IOException {
        new SerializableWrapperGenerator().doGenerate(infoMap, ctx);
    }

    private void doGenerate(Map<BackendServiceInfo, SharedBackendInfo> infoMap, GeneratorContext ctx) throws IOException {
        for (var entry : infoMap.entrySet()) {
            BackendServiceInfo svc = entry.getKey();
            SharedBackendInfo info = entry.getValue();

            for (SharedBoundary b : info.getSingletons()) {
                generateForBoundary(b, svc, ctx);
            }
            for (SharedBoundary b : info.getCollections()) {
                generateForBoundary(b, svc, ctx);
            }
        }

        generateRegistry(ctx.getJavaPackageBase(), ctx);
    }

    private void generateForBoundary(SharedBoundary b, BackendServiceInfo svc, GeneratorContext ctx) throws IOException {
        String outerClassName = ctx.getOuterClassName(svc);
        String qualifiedType = ctx.getQualifiedType(outerClassName, b);

        // Determine the serializer's package and the Java class identity
        String serializerPkg;
        String javaClassFqn;
        String importLine;

        if (b.isCrossPackage()) {
            String crossOuterClass = qualifiedType.substring(0, qualifiedType.indexOf('.'));
            String typeDir = ctx.getParser().resolveTypeDir(b.getCrossPkg());
            serializerPkg = ctx.getJavaPackageBase() + "." + typeDir + "." + b.getCrossPkg();
            String typesImportPkg = ctx.getTypesPackageBase() + ".types." + typeDir + "." + b.getCrossPkg();
            javaClassFqn = typesImportPkg + "." + crossOuterClass + "." + b.getTypeName();
            importLine = "import " + typesImportPkg + "." + crossOuterClass + ";";
        } else {
            serializerPkg = ctx.getFullPackage(svc);
            javaClassFqn = ctx.getTypesPackage(svc) + "." + outerClassName + "." + b.getTypeName();
            importLine = "import " + ctx.getTypesPackage(svc) + "." + outerClassName + ";";
        }

        // Deduplicate by Java class
        if (generatedClasses.contains(javaClassFqn)) return;
        generatedClasses.add(javaClassFqn);

        String serializerClassName = b.getTypeName() + "CompactSerializer";

        // Look up the message descriptor for scalar field projections
        String protoPackage = b.isCrossPackage() ? b.getCrossPkg() : svc.getPackageName();
        MessageDescriptor msgDesc = ctx.getParser().findMessage(protoPackage, b.getTypeName());

        // Build scalar projections
        StringBuilder scalarProjections = new StringBuilder();
        if (msgDesc != null) {
            List<FieldDescriptor> scalarFields = msgDesc.getFields().stream()
                    .filter(f -> "scalar".equals(f.getTypeKind()) && !f.isRepeated())
                    .toList();
            if (!scalarFields.isEmpty()) {
                scalarProjections.append("        // Queryable scalar field projections\n");
                for (FieldDescriptor field : scalarFields) {
                    String getter = "msg.get" + StringUtils.toPascalCase(field.getName()) + "()";
                    String writeMethod = scalarWriteMethod(field.getType());
                    if (writeMethod != null) {
                        scalarProjections.append("        writer.").append(writeMethod).append("(\"")
                          .append(field.getName()).append("\", ").append(getter).append(");\n");
                    }
                }
            }
        }

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", ctx.header("serialization"));
        vars.put("PACKAGE", serializerPkg);
        vars.put("IMPORT_LINE", importLine);
        vars.put("CLASS_NAME", serializerClassName);
        vars.put("QUALIFIED_TYPE", qualifiedType);
        vars.put("PROTO_PACKAGE", protoPackage);
        vars.put("TYPE_NAME", b.getTypeName());
        vars.put("SCALAR_PROJECTIONS", scalarProjections.toString());

        String content = TemplateEngine.render("CompactSerializer.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + serializerPkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(serializerClassName + ".java"), content);

        allSerializers.add(new SerializerInfo(serializerPkg, serializerClassName, qualifiedType));
    }

    private void generateRegistry(String rootPkg, GeneratorContext ctx) throws IOException {
        StringBuilder registrations = new StringBuilder();
        for (SerializerInfo s : allSerializers) {
            registrations.append("        compact.addSerializer(new ").append(s.pkg).append(".").append(s.className).append("());\n");
        }

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", ctx.header("serialization"));
        vars.put("PACKAGE", rootPkg);
        vars.put("REGISTRATIONS", registrations.toString());

        String content = TemplateEngine.render("SerializerRegistry.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + rootPkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("SerializerRegistry.java"), content);
    }

    /** Maps proto scalar type to CompactWriter method name. */
    private static String scalarWriteMethod(String protoType) {
        return switch (protoType) {
            case "string" -> "writeString";
            case "int32", "sint32", "sfixed32", "uint32", "fixed32" -> "writeInt32";
            case "int64", "sint64", "sfixed64", "uint64", "fixed64" -> "writeInt64";
            case "float" -> "writeFloat32";
            case "double" -> "writeFloat64";
            case "bool" -> "writeBoolean";
            case "bytes" -> null; // handled separately via writeArrayOfInt8
            default -> null;
        };
    }
}
