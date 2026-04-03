package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.AnnotationValue;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.FieldDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.FileDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.MessageDescriptor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Generates service-specific view servers owned by the kernel code generator.
 */
public class ViewServerGenerator {

    public static void generate(GeneratorContext ctx) throws IOException {
        if (!hasJwkVerifyingKeysView(ctx)) {
            return;
        }

        String pkg = ctx.getJavaPackageBase() + ".views";
        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header("jwk_view_server"));
        vars.put("PACKAGE", pkg);
        vars.put("JWK_OUTER_CLASS", ctx.getTypesPackageBase() + ".types.libs.jwk.JwkOuterClass");
        vars.put("JWK_VIEW_GRPC_CLASS", ctx.getTypesPackageBase() + ".types.libs.jwkview.JwkVerifyingKeysViewServiceGrpc");
        vars.put("JWK_VIEW_PROTO_CLASS", ctx.getTypesPackageBase() + ".types.libs.jwkview.Jwkview");
        vars.put("SECURITY_AUTH_CLASS", ctx.getJavaPackageBase() + ".SecurityAuthenticator");

        String content = TemplateEngine.render("JwkVerifyingKeysViewServer.java.template", vars);
        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("JwkVerifyingKeysViewServer.java"), content);
    }

    private static boolean hasJwkVerifyingKeysView(GeneratorContext ctx) {
        for (FileDescriptor fileDesc : ctx.getParser().getAllFiles().values()) {
            for (MessageDescriptor msg : fileDesc.getMessages()) {
                // Check both simple and structured service_state annotations
                boolean hasServiceState = false;
                AnnotationValue backendRoot = msg.getAnnotations().get("service_state");
                if (backendRoot != null && backendRoot.getStringValue() != null && !backendRoot.getStringValue().isEmpty()) {
                    hasServiceState = true;
                }
                if (!hasServiceState) {
                    java.util.List<AnnotationValue> repeated = msg.getRepeatedAnnotations("service_state");
                    if (!repeated.isEmpty() && repeated.get(0).isStruct()) {
                        var struct = repeated.get(0).getStructValue();
                        if (struct.containsKey("name") || struct.containsKey("tag")) {
                            hasServiceState = true;
                        }
                    }
                }
                if (!hasServiceState) continue;

                for (FieldDescriptor field : msg.getFields()) {
                    AnnotationValue viewMember = field.getAnnotations().get("view_member");
                    if (viewMember != null && "JwkVerifyingKeysView".equals(viewMember.getStringValue())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
