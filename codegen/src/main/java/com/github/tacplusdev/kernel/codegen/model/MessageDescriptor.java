package com.github.tacplusdev.kernel.codegen.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MessageDescriptor {
    private String name;
    private final List<FieldDescriptor> fields = new ArrayList<>();
    private final Map<String, AnnotationValue> annotations = new HashMap<>();
    private final Map<String, List<AnnotationValue>> repeatedAnnotations = new HashMap<>();

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public List<FieldDescriptor> getFields() { return fields; }
    public Map<String, AnnotationValue> getAnnotations() { return annotations; }

    /** Returns all values for a repeated annotation (e.g. backend_perms). */
    public List<AnnotationValue> getRepeatedAnnotations(String name) {
        return repeatedAnnotations.getOrDefault(name, List.of());
    }

    /** Adds a value to a repeated annotation list. */
    public void addRepeatedAnnotation(String name, AnnotationValue value) {
        repeatedAnnotations.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }
}
