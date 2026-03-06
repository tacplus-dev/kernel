package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import com.gitlab.secondstarcavalier.controlplane.codegen.StringUtils;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.*;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Generates BackendServers.java aggregators at both the group and root levels.
 * Group level: aggregates per-service backend servers and backend RPC services.
 * Root level: references group aggregators.
 */
public class BackendServersGenerator {

    /**
     * Groups services by their proto directory (services/, common/, etc.)
     * and generates both levels of aggregators.
     */
    public static void generate(List<BackendServiceInfo> services, Map<BackendServiceInfo, SharedBackendInfo> infoMap,
                                GeneratorContext ctx) throws IOException {
        generate(services, infoMap, List.of(), ctx);
    }

    /**
     * Groups services by their proto directory (services/, common/, etc.)
     * and generates both levels of aggregators, including backend RPC services.
     */
    public static void generate(List<BackendServiceInfo> services, Map<BackendServiceInfo, SharedBackendInfo> infoMap,
                                List<BackendRpcServiceInfo> rpcServices, GeneratorContext ctx) throws IOException {
        // Group state services by directory prefix
        Map<String, List<BackendServiceInfo>> groups = new LinkedHashMap<>();
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;

            String dir = "services";
            String path = svc.getProtoFile();
            int slash = path.indexOf('/');
            if (slash > 0) {
                dir = path.substring(0, slash);
            }
            groups.computeIfAbsent(dir, k -> new ArrayList<>()).add(svc);
        }

        // Group RPC services by directory prefix
        Map<String, List<BackendRpcServiceInfo>> rpcGroups = new LinkedHashMap<>();
        for (BackendRpcServiceInfo rpc : rpcServices) {
            String dir = "services";
            String path = rpc.getProtoFile();
            int slash = path.indexOf('/');
            if (slash > 0) {
                dir = path.substring(0, slash);
            }
            rpcGroups.computeIfAbsent(dir, k -> new ArrayList<>()).add(rpc);
            // Ensure the group exists in the main groups map too
            groups.computeIfAbsent(dir, k -> new ArrayList<>());
        }

        // Generate group-level aggregator for each group
        for (var entry : groups.entrySet()) {
            String group = entry.getKey();
            List<BackendServiceInfo> groupServices = entry.getValue();
            List<BackendRpcServiceInfo> groupRpcServices = rpcGroups.getOrDefault(group, List.of());
            generateGroupAggregator(group, groupServices, infoMap, groupRpcServices, ctx);
        }

        // Generate root-level aggregator
        generateRootAggregator(groups, ctx);
    }

    private static void generateGroupAggregator(String group, List<BackendServiceInfo> services,
            Map<BackendServiceInfo, SharedBackendInfo> infoMap, List<BackendRpcServiceInfo> rpcServices,
            GeneratorContext ctx) throws IOException {
        String pkg = ctx.getJavaPackageBase() + "." + group;

        // Build fields
        StringBuilder fields = new StringBuilder();
        fields.append("    private final SecurityAuthenticator authenticator;\n");
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String svcPkg = ctx.getFullPackage(svc);
            String stateMapClass = svcPkg + "." + info.getClassName();
            String svcServerClass = svcPkg + "." + info.getServicePrefix() + "BackendServiceServer";
            String fieldName = StringUtils.toLowerCamelCase(info.getClassName());
            String svcFieldName = fieldName + "BackendSvc";
            fields.append("    private final ").append(stateMapClass).append(" ").append(fieldName).append(";\n");
            fields.append("    private final ").append(svcServerClass).append(" ").append(svcFieldName).append(";\n");
        }
        // Backend RPC service fields (volatile, set via register method)
        for (BackendRpcServiceInfo rpc : rpcServices) {
            String rpcFieldName = StringUtils.toLowerCamelCase(rpc.getBackendName()) + "Service";
            fields.append("    private volatile BindableService ").append(rpcFieldName).append(";\n");
        }

        // Build constructor
        StringBuilder ctor = new StringBuilder();
        ctor.append("\n    public BackendServers(Manager manager, SecurityAuthenticator authenticator) {\n");
        ctor.append("        this.manager = manager;\n");
        ctor.append("        this.authenticator = authenticator;\n");
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String svcPkg = ctx.getFullPackage(svc);
            String fieldName = StringUtils.toLowerCamelCase(info.getClassName());
            String svcFieldName = fieldName + "BackendSvc";
            String svcServerClass = info.getServicePrefix() + "BackendServiceServer";
            ctor.append("        this.").append(fieldName).append(" = new ").append(svcPkg).append(".").append(info.getClassName()).append("(manager);\n");
            ctor.append("        this.").append(svcFieldName).append(" = new ").append(svcPkg).append(".").append(svcServerClass).append("(manager, authenticator);\n");
        }
        ctor.append("    }\n\n");
        ctor.append("    public BackendServers(Manager manager) {\n");
        ctor.append("        this(manager, new SecurityAuthenticator());\n");
        ctor.append("    }\n");

        // Build grpc service adds (each wrapped with caller interceptor)
        StringBuilder grpcAdds = new StringBuilder();
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String fieldName = StringUtils.toLowerCamelCase(info.getClassName());
            grpcAdds.append("        services.add(io.grpc.ServerInterceptors.interceptForward(\n");
            grpcAdds.append("            ").append(fieldName).append("BackendSvc.bindService(), callerInterceptor));\n");
        }
        // Add backend RPC services (if registered)
        for (BackendRpcServiceInfo rpc : rpcServices) {
            String rpcFieldName = StringUtils.toLowerCamelCase(rpc.getBackendName()) + "Service";
            grpcAdds.append("        if (").append(rpcFieldName).append(" != null) {\n");
            grpcAdds.append("            services.add(io.grpc.ServerInterceptors.interceptForward(\n");
            grpcAdds.append("                ").append(rpcFieldName).append(".bindService(), callerInterceptor));\n");
            grpcAdds.append("        }\n");
        }

        // Build quorum propagation calls
        StringBuilder quorumCalls = new StringBuilder();
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String fieldName = StringUtils.toLowerCamelCase(info.getClassName());
            quorumCalls.append("        ").append(fieldName).append("BackendSvc.setQuorumAvailable(available);\n");
        }

        // Build close calls
        StringBuilder closeCalls = new StringBuilder();
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String fieldName = StringUtils.toLowerCamelCase(info.getClassName());
            closeCalls.append("        ").append(fieldName).append("BackendSvc.close();\n");
        }

        // Build getters
        StringBuilder getters = new StringBuilder();
        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String svcPkg = ctx.getFullPackage(svc);
            String stateMapClass = svcPkg + "." + info.getClassName();
            String fieldName = StringUtils.toLowerCamelCase(info.getClassName());
            getters.append("\n    /**\n");
            getters.append("     * Returns the ").append(info.getClassName()).append(" for ").append(info.getBackendName()).append("Service.\n");
            getters.append("     */\n");
            getters.append("    public ").append(stateMapClass).append(" get").append(info.getClassName()).append("() {\n");
            getters.append("        return ").append(fieldName).append(";\n");
            getters.append("    }\n");
        }
        // Register methods for backend RPC services
        for (BackendRpcServiceInfo rpc : rpcServices) {
            String rpcFieldName = StringUtils.toLowerCamelCase(rpc.getBackendName()) + "Service";
            String methodName = "register" + rpc.getBackendName() + "Service";
            getters.append("\n    /**\n");
            getters.append("     * Registers the hand-written ").append(rpc.getServiceName()).append(" implementation.\n");
            getters.append("     * The service will be included in getGrpcServices() after registration.\n");
            getters.append("     */\n");
            getters.append("    public void ").append(methodName).append("(BindableService impl) {\n");
            getters.append("        this.").append(rpcFieldName).append(" = impl;\n");
            getters.append("    }\n");
        }

        // Build installConfigHolder method for ConfigState services.
        // ConfigState services (backend name ending in "ConfigState") have a config
        // singleton that maps 1:1 to a ConfigHolder field. This method installs all
        // configs from a ConfigHolder into their respective state maps.
        StringBuilder configInstaller = new StringBuilder();
        String configHolderType = null;
        List<String[]> configStateMappings = new ArrayList<>(); // [mapField, configPrefix]

        for (BackendServiceInfo svc : services) {
            SharedBackendInfo info = infoMap.get(svc);
            if (info == null) continue;
            String backendName = info.getBackendName();
            if (!backendName.endsWith("ConfigState")) continue;

            // ServiceConfigState is a shared runtime config boundary (OPA policy),
            // NOT a per-service typed config in ConfigHolder. Skip it.
            if (backendName.equals("ServiceConfigState")) continue;

            // Derive ConfigHolder type reference (same proto package as ConfigState services)
            if (configHolderType == null) {
                String typesPackage = ctx.getTypesPackage(svc);
                String outerClass = ctx.getOuterClassName(svc);
                configHolderType = typesPackage + "." + outerClass + ".ConfigHolder";
            }

            // AwsConnectorConfigState → AwsConnector → has/getAwsConnectorConfig()
            String configPrefix = backendName.substring(0, backendName.length() - "ConfigState".length());
            String mapField = StringUtils.toLowerCamelCase(info.getClassName());
            configStateMappings.add(new String[]{mapField, configPrefix});
        }

        if (configHolderType != null && !configStateMappings.isEmpty()) {
            getters.append("\n    /**\n");
            getters.append("     * Installs configs from a ConfigHolder into per-service config state maps.\n");
            getters.append("     * @return the number of configs installed\n");
            getters.append("     */\n");
            getters.append("    public int installConfigHolder(").append(configHolderType).append(" configHolder) {\n");
            getters.append("        int installed = 0;\n");
            for (String[] mapping : configStateMappings) {
                String mapField = mapping[0];
                String configPrefix = mapping[1];
                getters.append("        if (configHolder.has").append(configPrefix).append("Config()) {\n");
                getters.append("            ").append(mapField).append(".putConfig(configHolder.get")
                       .append(configPrefix).append("Config());\n");
                getters.append("            installed++;\n");
                getters.append("        }\n");
            }
            getters.append("        return installed;\n");
            getters.append("    }\n");
        }

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header("servicetypestate/registry"));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("AUTHENTICATOR_PACKAGE", ctx.getJavaPackageBase());
        vars.put("FIELDS", fields.toString());
        vars.put("CONSTRUCTOR", ctor.toString());
        vars.put("GRPC_SERVICE_ADDS", grpcAdds.toString());
        vars.put("QUORUM_CALLS", quorumCalls.toString());
        vars.put("CLOSE_CALLS", closeCalls.toString());
        vars.put("GETTERS", getters.toString());

        String content = TemplateEngine.render("BackendServersGroup.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("BackendServers.java"), content);
    }

    private static void generateRootAggregator(Map<String, List<BackendServiceInfo>> groups,
                                                GeneratorContext ctx) throws IOException {
        String pkg = ctx.getJavaPackageBase();

        // Build fields
        StringBuilder fields = new StringBuilder();
        for (String group : groups.keySet()) {
            String groupPkg = ctx.getJavaPackageBase() + "." + group + ".BackendServers";
            fields.append("    private final ").append(groupPkg).append(" ").append(group).append(";\n");
        }

        // Build constructor
        StringBuilder ctor = new StringBuilder();
        ctor.append("\n    public BackendServers(Manager manager, SecurityAuthenticator authenticator) {\n");
        ctor.append("        this.authenticator = authenticator;\n");
        for (String group : groups.keySet()) {
            String groupPkg = ctx.getJavaPackageBase() + "." + group + ".BackendServers";
            ctor.append("        this.").append(group).append(" = new ").append(groupPkg).append("(manager, authenticator);\n");
        }
        ctor.append("    }\n\n");
        ctor.append("    public BackendServers(Manager manager) {\n");
        ctor.append("        this(manager, new SecurityAuthenticator());\n");
        ctor.append("    }\n");

        // Build getters
        StringBuilder getters = new StringBuilder();
        for (String group : groups.keySet()) {
            String groupPkg = ctx.getJavaPackageBase() + "." + group + ".BackendServers";
            getters.append("\n    /** Returns the backend servers for the ").append(group).append(" group. */\n");
            getters.append("    public ").append(groupPkg).append(" ").append(group).append("() {\n");
            getters.append("        return ").append(group).append(";\n");
            getters.append("    }\n");
        }

        // Build root quorum method
        StringBuilder rootQuorum = new StringBuilder();
        rootQuorum.append("    public void setQuorumAvailable(boolean available) {\n");
        for (String group : groups.keySet()) {
            rootQuorum.append("        ").append(group).append(".setQuorumAvailable(available);\n");
        }
        rootQuorum.append("    }\n");

        Map<String, String> vars = new LinkedHashMap<>();
        vars.put("HEADER", GeneratorContext.header("backend_servers"));
        vars.put("PACKAGE", pkg);
        vars.put("INTERFACES_PACKAGE", ctx.getInterfacesPackage());
        vars.put("AUTHENTICATOR_PACKAGE", ctx.getJavaPackageBase());
        vars.put("FIELDS", fields.toString());
        vars.put("CONSTRUCTOR", ctor.toString());
        vars.put("GETTERS", getters.toString());
        vars.put("ROOT_QUORUM_METHOD", rootQuorum.toString());

        String content = TemplateEngine.render("BackendServersRoot.java.template", vars);

        Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("BackendServers.java"), content);
    }
}
