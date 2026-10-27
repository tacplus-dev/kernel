package com.github.tacplusdev.kernel.codegen;

import com.github.tacplusdev.kernel.codegen.model.*;
import com.github.tacplusdev.kernel.codegen.StringUtils;

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

            // Find messages with service_state annotation
            for (MessageDescriptor msg : fileDesc.getMessages()) {
                String backendName = null;
                // The annotation's own state name, never suffix-stripped — this is
                // the key tacplus writes into codegen-config.json's securityPolicies.
                String stateName = null;

                // Check simple string annotation first
                AnnotationValue ann = msg.getAnnotations().get("service_state");
                if (ann != null && ann.getStringValue() != null && !ann.getStringValue().isEmpty()) {
                    backendName = ann.getStringValue();
                    stateName = backendName;
                }

                // Check structured annotation (e.g. {name: "IdentityConfigState", store: "kernel"})
                if (backendName == null) {
                    List<AnnotationValue> repeated = msg.getRepeatedAnnotations("service_state");
                    if (!repeated.isEmpty()) {
                        AnnotationValue first = repeated.get(0);
                        if (first.isStruct()) {
                            if (first.getStructValue().containsKey("name")) {
                                backendName = first.getStructValue().get("name");
                                stateName = backendName;
                            } else {
                                // Every other key of the annotation is optional, so the
                                // struct form alone marks the state root -- do NOT gate
                                // this on a particular sibling key. Gating it on `tag`
                                // is what silently dropped all seven of kernel's own
                                // states when that annotation was renamed to `label`.
                                //
                                // Fallback: derive backend name from message name,
                                // stripping "State" suffix if present (convention:
                                // GatewayTlsState → GatewayTls, Identity → Identity).
                                String msgName = msg.getName();
                                if (msgName.endsWith("State")) {
                                    backendName = msgName.substring(0, msgName.length() - 5);
                                } else {
                                    backendName = msgName;
                                }
                                // name omitted → the state name defaults to the message name.
                                stateName = msgName;
                            }
                        }
                    }
                }

                if (backendName == null || backendName.isEmpty()) {
                    continue;
                }

                String packageName = derivePackageName(fileDesc, relPath);

                BackendServiceInfo svc = new BackendServiceInfo();
                svc.setProtoFile(relPath);
                svc.setPackageName(packageName);
                svc.setServiceName(backendName + "StateService");
                svc.setBackendName(backendName);
                svc.setStateName(stateName != null ? stateName : msg.getName());
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

    /**
     * Scans all parsed file descriptors for messages with service_store annotations.
     * For each, derives the store service metadata including key field and quorum setting.
     */
    public static List<BackendStoreInfo> discoverStoreServices(ProtoDescriptorParser parser) {
        List<BackendStoreInfo> stores = new ArrayList<>();

        for (var entry : parser.getAllFiles().entrySet()) {
            String relPath = entry.getKey();
            FileDescriptor fileDesc = entry.getValue();

            if (relPath.startsWith("google/")) continue;

            for (MessageDescriptor msg : fileDesc.getMessages()) {
                // service_store can be a string annotation or a struct annotation
                // (e.g., {tag: "kernel"}). Check both forms.
                String valueTypeName = null;

                // Check simple string annotation
                AnnotationValue ann = msg.getAnnotations().get("service_store");
                if (ann != null && ann.getStringValue() != null && !ann.getStringValue().isEmpty()) {
                    valueTypeName = ann.getStringValue();
                }

                // Check structured annotation (e.g., {tag: "kernel"})
                if (valueTypeName == null) {
                    List<AnnotationValue> repeated = msg.getRepeatedAnnotations("service_store");
                    if (!repeated.isEmpty()) {
                        AnnotationValue first = repeated.get(0);
                        if (first.isStruct()) {
                            // Derive value type name from message name
                            valueTypeName = msg.getName();
                        }
                    }
                }

                if (valueTypeName == null || valueTypeName.isEmpty()) {
                    continue;
                }

                String packageName = derivePackageName(fileDesc, relPath);

                // Find the store_key field
                String keyFieldName = null;
                boolean quorumWrite = false;
                for (FieldDescriptor field : msg.getFields()) {
                    AnnotationValue storeKey = field.getAnnotations().get("store_key");
                    if (storeKey != null && storeKey.getBoolValue()) {
                        keyFieldName = field.getName();
                    }
                    AnnotationValue qw = field.getAnnotations().get("quorum_write");
                    if (qw != null && qw.getBoolValue()) {
                        quorumWrite = true;
                    }
                }

                if (keyFieldName == null) {
                    // No store_key field found — skip (validation error in tacplus)
                    continue;
                }

                BackendStoreInfo store = new BackendStoreInfo();
                store.setProtoFile(relPath);
                store.setPackageName(packageName);
                store.setServiceName(valueTypeName + "StoreService");
                store.setValueTypeName(valueTypeName);
                store.setKeyFieldName(keyFieldName);
                store.setKeyFieldPascal(StringUtils.toPascalCase(keyFieldName));
                store.setQuorumWrite(quorumWrite);
                stores.add(store);
            }
        }

        return stores;
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
