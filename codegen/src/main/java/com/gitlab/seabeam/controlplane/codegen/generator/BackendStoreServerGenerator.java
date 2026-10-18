package com.gitlab.seabeam.controlplane.codegen.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import com.gitlab.seabeam.controlplane.codegen.StringUtils;
import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;
import com.gitlab.seabeam.controlplane.codegen.model.BackendStoreInfo;
import com.gitlab.seabeam.controlplane.codegen.model.FileDescriptor;

/**
 * Generates {ValueType}StoreServiceServer.java — gRPC server implementation
 * for durable key-value store services backed by Hazelcast IMap.
 *
 * <p>Unlike BackendServiceServerGenerator (which handles convergent state with
 * Watch/poll), store services are simple CRUD with no Watch streams.
 */
public class BackendStoreServerGenerator {

    public static void generate(BackendStoreInfo store, GeneratorContext ctx) throws IOException {
        String pkg = getFullPackage(store, ctx);
        String outerClassName = getOuterClassName(store, ctx);
        String className = store.getValueTypeName() + "StoreServiceServer";
        String grpcBase = store.getValueTypeName() + "StoreServiceGrpc."
                + store.getValueTypeName() + "StoreServiceImplBase";
        String qualifiedValueType = outerClassName + "." + store.getValueTypeName();

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", ctx.header(store.getProtoFile()));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("ERRORS_PACKAGE", ctx.getErrorsPackage());
        vars.put("AUTHENTICATOR_PACKAGE", ctx.getJavaPackageBase());
        vars.put("TYPES_PACKAGE", getTypesPackage(store, ctx));
        vars.put("OUTER_CLASS", outerClassName);
        vars.put("CLASS_NAME", className);
        vars.put("GRPC_BASE", grpcBase);
        vars.put("GRAPH_KEY", graphKey(store, ctx));
        vars.put("VALUE_TYPE", store.getValueTypeName());
        vars.put("QUALIFIED_VALUE_TYPE", qualifiedValueType);
        vars.put("KEY_FIELD_NAME", store.getKeyFieldName());
        vars.put("KEY_FIELD_PASCAL", store.getKeyFieldPascal());
        vars.put("STORE_MAP_NAME", store.getValueTypeName() + "Store");
        vars.put("TRACE_REQUEST_TYPE", ctx.getTypesPackageBase() + ".types.sys.trace.Trace.TraceRequest");

        String content = TemplateEngine.render("BackendStoreServiceServer.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(className + ".java"), content);
    }

    /**
     * The security-policy key for a store: "&lt;proto package&gt;.&lt;value
     * type&gt;", the same (package, name) pair tacplus writes into
     * codegen-config.json. Unlike a state root, a store with no computed policy
     * is a hard error: a store server generated with no policy authorizes nothing
     * on put/get/delete/list, and that must not be reachable by omission.
     */
    private static String graphKey(BackendStoreInfo store, GeneratorContext ctx) {
        for (AccessPolicy policy : ctx.getSecurityPolicies()) {
            if (store.getPackageName().equals(policy.pkg())
                    && store.getValueTypeName().equals(policy.name())) {
                return policy.graphKey();
            }
        }
        throw new IllegalStateException("[tacplus-backend] no security policy for store \""
                + store.getPackageName() + "." + store.getValueTypeName()
                + "\" — refusing to generate an unauthorized store server."
                + " Expected a securityPolicies entry in codegen-config.json.");
    }

    static String getFullPackage(BackendStoreInfo store, GeneratorContext ctx) {
        String dir = deriveDir(store.getProtoFile());
        return ctx.getJavaPackageBase() + "." + dir + "." + store.getPackageName();
    }

    static String getTypesPackage(BackendStoreInfo store, GeneratorContext ctx) {
        String dir = deriveDir(store.getProtoFile());
        return ctx.getTypesPackageBase() + ".types." + dir + "." + store.getPackageName();
    }

    static String getOuterClassName(BackendStoreInfo store, GeneratorContext ctx) {
        FileDescriptor fd = ctx.getParser().getFileDescriptor(store.getProtoFile());
        if (fd != null && fd.getJavaOuterClassname() != null) {
            return fd.getJavaOuterClassname();
        }
        String fileName = store.getProtoFile();
        int slash = fileName.lastIndexOf('/');
        if (slash >= 0) {
            fileName = fileName.substring(slash + 1);
        }
        fileName = fileName.replace(".proto", "");
        return StringUtils.toPascalCase(fileName);
    }

    private static String deriveDir(String protoFile) {
        int slash = protoFile.indexOf('/');
        return slash > 0 ? protoFile.substring(0, slash) : "services";
    }
}
