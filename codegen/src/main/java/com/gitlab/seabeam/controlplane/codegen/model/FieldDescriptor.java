package com.gitlab.seabeam.controlplane.codegen.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FieldDescriptor {
    private String name;
    private String type;
    private String typeKind; // "message", "enum", "scalar"
    private boolean repeated;
    private final Map<String, AnnotationValue> annotations = new HashMap<>();
    private final Map<String, List<AnnotationValue>> repeatedAnnotations = new HashMap<>();

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getTypeKind() { return typeKind; }
    public void setTypeKind(String typeKind) { this.typeKind = typeKind; }

    public boolean isRepeated() { return repeated; }
    public void setRepeated(boolean repeated) { this.repeated = repeated; }

    public Map<String, AnnotationValue> getAnnotations() { return annotations; }

    /** Returns all values for a repeated annotation (e.g. boundary_perms). */
    public List<AnnotationValue> getRepeatedAnnotations(String name) {
        return repeatedAnnotations.getOrDefault(name, List.of());
    }

    /** Adds a value to a repeated annotation list. */
    public void addRepeatedAnnotation(String name, AnnotationValue value) {
        repeatedAnnotations.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }
}
