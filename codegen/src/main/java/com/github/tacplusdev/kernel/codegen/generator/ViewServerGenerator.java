package com.github.tacplusdev.kernel.codegen.generator;

import com.github.tacplusdev.kernel.codegen.model.AnnotationValue;
import com.github.tacplusdev.kernel.codegen.model.FieldDescriptor;
import com.github.tacplusdev.kernel.codegen.model.FileDescriptor;
import com.github.tacplusdev.kernel.codegen.model.MessageDescriptor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Generates the cluster's cross-boundary view servers (one per named view that
 * any collection registers into via (spec.view_member)).
 *
 * view_member is repeated: a collection may feed multiple views (e.g. an
 * internal signing key that belongs to both JwkVerifyingKeysView and
 * GatewayJwksView). Each known view renders the generic ViewServer template
 * with its own gRPC/proto classes; all views aggregate jwk.Jwk entries.
 */
public class ViewServerGenerator {

    /** Per-view codegen parameters. The message types differ per view; the
     *  aggregated value type (jwk.Jwk) is shared. */
    private record ViewSpec(
            String className,        // e.g. JwkVerifyingKeysViewServer
            String grpcSimple,       // e.g. JwkVerifyingKeysViewServiceGrpc
            String grpcSubPkg,       // e.g. jwkview
            String protoOuter,       // e.g. Jwkview
            String respType,         // e.g. JwkViewResponse
            String getReqType,       // e.g. JwkViewGetRequest
            String getRespType,      // e.g. JwkViewGetResponse
            String resourceName) {}  // e.g. jwk_verifying_keys_view

    private static final Map<String, ViewSpec> KNOWN_VIEWS = new LinkedHashMap<>();
    static {
        KNOWN_VIEWS.put("JwkVerifyingKeysView", new ViewSpec(
                "JwkVerifyingKeysViewServer", "JwkVerifyingKeysViewServiceGrpc", "jwkview",
                "Jwkview", "JwkViewResponse", "JwkViewGetRequest", "JwkViewGetResponse",
                "jwk_verifying_keys_view"));
        KNOWN_VIEWS.put("GatewayJwksView", new ViewSpec(
                "GatewayJwksViewServer", "GatewayJwksViewServiceGrpc", "gatewayjwksview",
                "Gatewayjwksview", "GatewayJwksViewResponse", "GatewayJwksViewGetRequest",
                "GatewayJwksViewGetResponse", "gateway_jwks_view"));
    }

    public static void generate(GeneratorContext ctx) throws IOException {
        Set<String> declaredViews = collectViewNames(ctx);
        if (declaredViews.isEmpty()) {
            return;
        }

        String pkg = ctx.getJavaPackageBase() + ".views";
        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));

        for (String viewName : declaredViews) {
            ViewSpec spec = KNOWN_VIEWS.get(viewName);
            if (spec == null) {
                // Unknown view name — no proto service to bind; skip (a typo in
                // view_member or a view not yet wired into KNOWN_VIEWS).
                continue;
            }

            String grpcFqn = ctx.getTypesPackageBase() + ".types.sys." + spec.grpcSubPkg() + "." + spec.grpcSimple();
            String protoFqn = ctx.getTypesPackageBase() + ".types.sys." + spec.grpcSubPkg() + "." + spec.protoOuter();

            Map<String, String> vars = new LinkedHashMap<>();
            vars.put("HEADER", ctx.header("view_server"));
            vars.put("PACKAGE", pkg);
            vars.put("CLASS_NAME", spec.className());
            vars.put("VIEW_NAME", viewName);
            vars.put("JWK_OUTER_CLASS", ctx.getTypesPackageBase() + ".types.sys.jwk.JwkOuterClass");
            vars.put("GRPC_FQN", grpcFqn);
            // protoc-gen-grpc-java names the server base <ServiceName>ImplBase,
            // where ServiceName is the grpc class name minus its trailing "Grpc"
            // (e.g. JwkVerifyingKeysViewServiceGrpc -> JwkVerifyingKeysViewServiceImplBase).
            String grpcServiceName = spec.grpcSimple().endsWith("Grpc")
                    ? spec.grpcSimple().substring(0, spec.grpcSimple().length() - "Grpc".length())
                    : spec.grpcSimple();
            vars.put("GRPC_IMPL", spec.grpcSimple() + "." + grpcServiceName + "ImplBase");
            vars.put("PROTO_FQN", protoFqn);
            vars.put("RESP_TYPE", spec.protoOuter() + "." + spec.respType());
            vars.put("GET_REQ_TYPE", spec.protoOuter() + "." + spec.getReqType());
            vars.put("GET_RESP_TYPE", spec.protoOuter() + "." + spec.getRespType());
            vars.put("RESOURCE_NAME", spec.resourceName());
            vars.put("SECURITY_AUTH_CLASS", ctx.getJavaPackageBase() + ".SecurityAuthenticator");
            vars.put("TRACE_REQUEST_TYPE", ctx.getTypesPackageBase() + ".types.sys.trace.Trace.TraceRequest");

            String content = TemplateEngine.render("ViewServer.java.template", vars);
            Files.createDirectories(dir);
            Files.writeString(dir.resolve(spec.className() + ".java"), content);
        }
    }

    /** Collect every distinct view name registered by any state collection's
     *  (repeated) view_member annotation. */
    private static Set<String> collectViewNames(GeneratorContext ctx) {
        Set<String> views = new LinkedHashSet<>();
        for (FileDescriptor fileDesc : ctx.getParser().getAllFiles().values()) {
            for (MessageDescriptor msg : fileDesc.getMessages()) {
                if (!hasServiceState(msg)) continue;
                for (FieldDescriptor field : msg.getFields()) {
                    for (AnnotationValue vm : field.getRepeatedAnnotations("view_member")) {
                        if (vm.getStringValue() != null && !vm.getStringValue().isEmpty()) {
                            views.add(vm.getStringValue());
                        }
                    }
                }
            }
        }
        return views;
    }

    private static boolean hasServiceState(MessageDescriptor msg) {
        AnnotationValue backendRoot = msg.getAnnotations().get("service_state");
        if (backendRoot != null && backendRoot.getStringValue() != null && !backendRoot.getStringValue().isEmpty()) {
            return true;
        }
        java.util.List<AnnotationValue> repeated = msg.getRepeatedAnnotations("service_state");
        // The struct form alone marks a state root; every key in it is optional.
        // Matching on specific keys made this blind to `{label: [...]}` states.
        return !repeated.isEmpty() && repeated.get(0).isStruct();
    }
}
