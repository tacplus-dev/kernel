package com.gitlab.secondstarcavalier.controlplane.codegen.model;

import java.util.List;

/**
 * Metadata for a backend RPC service declared with service_backend_rpc annotation.
 * Unlike BackendServiceInfo (which represents auto-generated state services),
 * this represents hand-written RPC services that run on the backend.
 * Only client wrappers and server registration plumbing are generated.
 */
public class BackendRpcServiceInfo {
    private String protoFile;     // relative path: "services/backenddb.proto"
    private String packageName;   // proto package: "backenddb"
    private String serviceName;   // proto service name: "TokenExchangerService"
    private String backendName;   // annotation value: "TokenExchanger"
    private List<RpcDescriptor> rpcs;

    public String getProtoFile() { return protoFile; }
    public void setProtoFile(String protoFile) { this.protoFile = protoFile; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }

    public String getBackendName() { return backendName; }
    public void setBackendName(String backendName) { this.backendName = backendName; }

    public List<RpcDescriptor> getRpcs() { return rpcs; }
    public void setRpcs(List<RpcDescriptor> rpcs) { this.rpcs = rpcs; }
}
