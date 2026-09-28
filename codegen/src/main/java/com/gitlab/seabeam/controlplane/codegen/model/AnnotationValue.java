package com.gitlab.seabeam.controlplane.codegen.model;

import java.util.Map;

public class AnnotationValue {
    private final String stringValue;
    private final String enumValue;
    private final boolean boolValue;
    private final Map<String, String> structValue;

    private AnnotationValue(String stringValue, String enumValue, boolean boolValue, Map<String, String> structValue) {
        this.stringValue = stringValue;
        this.enumValue = enumValue;
        this.boolValue = boolValue;
        this.structValue = structValue;
    }

    public static AnnotationValue ofString(String value) {
        return new AnnotationValue(value, null, false, null);
    }

    public static AnnotationValue ofEnum(String value) {
        return new AnnotationValue(null, value, false, null);
    }

    public static AnnotationValue ofBool(boolean value) {
        return new AnnotationValue(null, null, value, null);
    }

    public static AnnotationValue ofStruct(Map<String, String> value) {
        return new AnnotationValue(null, null, false, value);
    }

    public String getStringValue() { return stringValue; }
    public String getEnumValue() { return enumValue; }
    public boolean getBoolValue() { return boolValue; }
    public Map<String, String> getStructValue() { return structValue; }
    public boolean isStruct() { return structValue != null; }
}
