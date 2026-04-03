package com.gitlab.secondstarcavalier.controlplane.codegen.model;

/**
 * Metadata for a service_store message — a durable key-value store backed
 * by a Hazelcast IMap. Unlike BackendServiceInfo (convergent state with
 * fan-out/Watch), store services are read-on-demand with no Watch streams.
 *
 * <p>tacplus generates a gRPC service with Put/Get/Delete/List RPCs.
 * The kernel codegen generates the server implementation.
 */
public class BackendStoreInfo {
    private String protoFile;      // relative path: "services/kernel.proto"
    private String packageName;    // proto package: "kernel"
    private String serviceName;    // "CredPairStoreService"
    private String valueTypeName;  // "CredPair"
    private String keyFieldName;   // "client_id"
    private String keyFieldPascal; // "ClientId"
    private boolean quorumWrite;

    public String getProtoFile() { return protoFile; }
    public void setProtoFile(String protoFile) { this.protoFile = protoFile; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }

    public String getValueTypeName() { return valueTypeName; }
    public void setValueTypeName(String valueTypeName) { this.valueTypeName = valueTypeName; }

    public String getKeyFieldName() { return keyFieldName; }
    public void setKeyFieldName(String keyFieldName) { this.keyFieldName = keyFieldName; }

    public String getKeyFieldPascal() { return keyFieldPascal; }
    public void setKeyFieldPascal(String keyFieldPascal) { this.keyFieldPascal = keyFieldPascal; }

    public boolean isQuorumWrite() { return quorumWrite; }
    public void setQuorumWrite(boolean quorumWrite) { this.quorumWrite = quorumWrite; }
}
