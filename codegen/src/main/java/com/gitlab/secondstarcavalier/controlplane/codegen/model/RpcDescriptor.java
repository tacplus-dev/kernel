package com.gitlab.secondstarcavalier.controlplane.codegen.model;

public class RpcDescriptor {
    private String name;
    private String inputType;
    private String outputType;
    private boolean serverStreaming;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getInputType() { return inputType; }
    public void setInputType(String inputType) { this.inputType = inputType; }

    public String getOutputType() { return outputType; }
    public void setOutputType(String outputType) { this.outputType = outputType; }

    public boolean isServerStreaming() { return serverStreaming; }
    public void setServerStreaming(boolean serverStreaming) { this.serverStreaming = serverStreaming; }
}
