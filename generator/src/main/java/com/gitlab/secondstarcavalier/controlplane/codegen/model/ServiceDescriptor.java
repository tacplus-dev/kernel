package com.gitlab.secondstarcavalier.controlplane.codegen.model;

import java.util.ArrayList;
import java.util.List;

public class ServiceDescriptor {
    private String name;
    private String backendRpcName; // from service_backend_rpc annotation on service
    private final List<RpcDescriptor> rpcs = new ArrayList<>();

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getBackendRpcName() { return backendRpcName; }
    public void setBackendRpcName(String backendRpcName) { this.backendRpcName = backendRpcName; }
    public List<RpcDescriptor> getRpcs() { return rpcs; }
}
