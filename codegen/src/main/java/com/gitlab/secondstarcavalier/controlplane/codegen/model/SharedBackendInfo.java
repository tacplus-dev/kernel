package com.gitlab.secondstarcavalier.controlplane.codegen.model;

import java.util.ArrayList;
import java.util.List;

public class SharedBackendInfo {
    private String packageName;    // "baseball"
    private String backendName;      // "BaseballState"
    private String servicePrefix;  // "Baseball"
    private String className;      // "BaseballStateMap"
    private String mapPrefix;      // "baseball"
    private String backendRootName;  // actual message name
    private String parentDir;      // "services"
    private String instanceName;   // "House" (for multi-instance) or empty
    private final List<SharedBoundary> singletons = new ArrayList<>();
    private final List<SharedBoundary> collections = new ArrayList<>();
    private final List<SharedBoundary> queues = new ArrayList<>();
    private final List<SharedBoundary> priorityQueues = new ArrayList<>();
    private final List<SharedBoundary> topics = new ArrayList<>();
    private final List<SharedView> views = new ArrayList<>();

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getBackendName() { return backendName; }
    public void setBackendName(String backendName) { this.backendName = backendName; }

    public String getServicePrefix() { return servicePrefix; }
    public void setServicePrefix(String servicePrefix) { this.servicePrefix = servicePrefix; }

    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }

    public String getMapPrefix() { return mapPrefix; }
    public void setMapPrefix(String mapPrefix) { this.mapPrefix = mapPrefix; }

    public String getBackendRootName() { return backendRootName; }
    public void setBackendRootName(String backendRootName) { this.backendRootName = backendRootName; }

    public String getParentDir() { return parentDir; }
    public void setParentDir(String parentDir) { this.parentDir = parentDir; }

    public String getInstanceName() { return instanceName; }
    public void setInstanceName(String instanceName) { this.instanceName = instanceName; }

    public List<SharedBoundary> getSingletons() { return singletons; }
    public List<SharedBoundary> getCollections() { return collections; }
    public List<SharedBoundary> getQueues() { return queues; }
    public List<SharedBoundary> getPriorityQueues() { return priorityQueues; }
    public List<SharedBoundary> getTopics() { return topics; }
    public List<SharedView> getViews() { return views; }
}
