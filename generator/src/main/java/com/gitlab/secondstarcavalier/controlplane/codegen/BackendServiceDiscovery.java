package com.gitlab.secondstarcavalier.controlplane.codegen;

import com.gitlab.secondstarcavalier.controlplane.codegen.model.*;

import java.util.*;

/**
 * Discovers backend services by finding messages with service_backend annotations
 * in the tacplus-flattened proto files.
 *
 * The flattened protos contain auto-generated services with Get/Set/Watch RPCs
 * for each boundary. This class identifies them via the service_backend annotation
 * on the backend root message.
 */
public class BackendServiceDiscovery {

    /**
     * Scans all parsed file descriptors for messages with service_backend annotations.
     * For each, derives the backend service metadata from the annotation value and
     * the associated service definitions.
     */
    public static List<BackendServiceInfo> discover(ProtoDescriptorParser parser) {
        List<BackendServiceInfo> services = new ArrayList<>();

        for (var entry : parser.getAllFiles().entrySet()) {
            String relPath = entry.getKey();
            FileDescriptor fileDesc = entry.getValue();

            // Skip vendored protos
            if (relPath.startsWith("google/")) continue;

            // Find messages with service_backend annotation
            for (MessageDescriptor msg : fileDesc.getMessages()) {
                AnnotationValue ann = msg.getAnnotations().get("service_backend");
                if (ann == null || ann.getStringValue() == null || ann.getStringValue().isEmpty()) {
                    continue;
                }

                String backendName = ann.getStringValue();
                String packageName = derivePackageName(fileDesc, relPath);

                BackendServiceInfo svc = new BackendServiceInfo();
                svc.setProtoFile(relPath);
                svc.setPackageName(packageName);
                svc.setServiceName(backendName + "BackendService");
                svc.setBackendName(backendName);
                svc.setBackendRootMsg(msg.getName());
                services.add(svc);
            }
        }

        return services;
    }

    /**
     * Scans all parsed file descriptors for services with service_backend_rpc annotations.
     * These are hand-written backend RPC services (not auto-generated state services).
     */
    public static List<BackendRpcServiceInfo> discoverRpcServices(ProtoDescriptorParser parser) {
        List<BackendRpcServiceInfo> rpcServices = new ArrayList<>();

        for (var entry : parser.getAllFiles().entrySet()) {
            String relPath = entry.getKey();
            FileDescriptor fileDesc = entry.getValue();

            if (relPath.startsWith("google/")) continue;

            for (ServiceDescriptor svc : fileDesc.getServices()) {
                String backendRpcName = svc.getBackendRpcName();
                if (backendRpcName == null || backendRpcName.isEmpty()) {
                    continue;
                }

                String packageName = derivePackageName(fileDesc, relPath);

                BackendRpcServiceInfo rpcSvc = new BackendRpcServiceInfo();
                rpcSvc.setProtoFile(relPath);
                rpcSvc.setPackageName(packageName);
                rpcSvc.setServiceName(svc.getName());
                rpcSvc.setBackendName(backendRpcName);
                rpcSvc.setRpcs(svc.getRpcs());
                rpcServices.add(rpcSvc);
            }
        }

        return rpcServices;
    }

    private static String derivePackageName(FileDescriptor fd, String relPath) {
        // Prefer proto package declaration (always valid Java identifier)
        String packageName = fd.getPackageName();
        if (packageName != null && !packageName.isEmpty()) {
            int dot = packageName.indexOf('.');
            if (dot > 0) return packageName.substring(0, dot);
            return packageName;
        }

        // Fallback: derive from directory/file path
        String[] parts = relPath.split("/");
        if (parts.length == 2) {
            return parts[1].replace(".proto", "").replace("-", "_");
        } else if (parts.length >= 3) {
            return parts[1].replace("-", "_");
        }

        return "";
    }
}
