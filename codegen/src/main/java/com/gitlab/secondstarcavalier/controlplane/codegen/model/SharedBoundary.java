package com.gitlab.secondstarcavalier.controlplane.codegen.model;

public class SharedBoundary {
    private String fieldName;      // snake_case: "roster"
    private String fieldPascal;    // PascalCase: "Roster"
    private String fieldCamel;     // camelCase: "roster"
    private String typeName;       // PascalCase message type: "TeamRoster"
    private String mapName;        // distributed map name: "baseball_roster"
    private boolean atomic;
    private boolean repeated;
    private String keyFieldName;   // for collections: "player_id"
    private String keyFieldPascal; // for collections: "PlayerId"
    private boolean privateField;
    private boolean crossPackage;
    private String crossPkg;
    private boolean queue;
    private boolean priorityQueue;
    private String priorityField;
    private boolean topic;
    private boolean leader;  // per-graph leader election (on queue/topic/priority_queue)
    private String epochExpirationGetter;  // e.g., "getExpiresAt" — null when no epoch field
    private boolean replicated;
    private boolean instanceKeyed;  // server builds key from auth context (instance_id claim)
    private long evictionTtlSeconds;
    private boolean persistent;     // (spec.persistence) = true — redo log persisted

    public String getFieldName() { return fieldName; }
    public void setFieldName(String fieldName) { this.fieldName = fieldName; }

    public String getFieldPascal() { return fieldPascal; }
    public void setFieldPascal(String fieldPascal) { this.fieldPascal = fieldPascal; }

    public String getFieldCamel() { return fieldCamel; }
    public void setFieldCamel(String fieldCamel) { this.fieldCamel = fieldCamel; }

    public String getTypeName() { return typeName; }
    public void setTypeName(String typeName) { this.typeName = typeName; }

    public String getMapName() { return mapName; }
    public void setMapName(String mapName) { this.mapName = mapName; }

    public boolean isAtomic() { return atomic; }
    public void setAtomic(boolean atomic) { this.atomic = atomic; }

    public boolean isRepeated() { return repeated; }
    public void setRepeated(boolean repeated) { this.repeated = repeated; }

    public String getKeyFieldName() { return keyFieldName; }
    public void setKeyFieldName(String keyFieldName) { this.keyFieldName = keyFieldName; }

    public String getKeyFieldPascal() { return keyFieldPascal; }
    public void setKeyFieldPascal(String keyFieldPascal) { this.keyFieldPascal = keyFieldPascal; }

    public boolean isPrivateField() { return privateField; }
    public void setPrivateField(boolean privateField) { this.privateField = privateField; }

    public boolean isCrossPackage() { return crossPackage; }
    public void setCrossPackage(boolean crossPackage) { this.crossPackage = crossPackage; }

    public String getCrossPkg() { return crossPkg; }
    public void setCrossPkg(String crossPkg) { this.crossPkg = crossPkg; }

    public boolean isQueue() { return queue; }
    public void setQueue(boolean queue) { this.queue = queue; }

    public boolean isPriorityQueue() { return priorityQueue; }
    public void setPriorityQueue(boolean priorityQueue) { this.priorityQueue = priorityQueue; }

    public String getPriorityField() { return priorityField; }
    public void setPriorityField(String priorityField) { this.priorityField = priorityField; }

    public boolean isTopic() { return topic; }
    public void setTopic(boolean topic) { this.topic = topic; }

    public boolean isLeader() { return leader; }
    public void setLeader(boolean leader) { this.leader = leader; }

    public String getEpochExpirationGetter() { return epochExpirationGetter; }
    public void setEpochExpirationGetter(String epochExpirationGetter) { this.epochExpirationGetter = epochExpirationGetter; }

    public boolean isReplicated() { return replicated; }
    public void setReplicated(boolean replicated) { this.replicated = replicated; }

    public boolean isInstanceKeyed() { return instanceKeyed; }
    public void setInstanceKeyed(boolean instanceKeyed) { this.instanceKeyed = instanceKeyed; }

    public long getEvictionTtlSeconds() { return evictionTtlSeconds; }
    public void setEvictionTtlSeconds(long evictionTtlSeconds) { this.evictionTtlSeconds = evictionTtlSeconds; }

    public boolean isPersistent() { return persistent; }
    public void setPersistent(boolean persistent) { this.persistent = persistent; }
}
