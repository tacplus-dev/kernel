package com.gitlab.secondstarcavalier.controlplane.codegen.model;

public class BackendServiceInfo {
    private String protoFile;    // relative path: "services/baseball.proto"
    private String packageName;  // proto package: "baseball"
    private String serviceName;  // "BaseballStateBackendService"
    private String backendName;    // "BaseballState"
    private String backendRootMsg; // "BaseballState"

    public String getProtoFile() { return protoFile; }
    public void setProtoFile(String protoFile) { this.protoFile = protoFile; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }

    public String getBackendName() { return backendName; }
    public void setBackendName(String backendName) { this.backendName = backendName; }

    public String getBackendRootMsg() { return backendRootMsg; }
    public void setBackendRootMsg(String backendRootMsg) { this.backendRootMsg = backendRootMsg; }
}
