package com.github.tacplusdev.kernel.codegen.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a view field — a read-only merge of multiple source collections.
 * Views don't have their own Hazelcast map; they read from source collection maps.
 */
public class SharedView {
    private String fieldName;      // snake_case: "all_certs"
    private String fieldPascal;    // PascalCase: "AllCerts"
    private String fieldCamel;     // camelCase: "allCerts"
    private String typeName;       // element type: "GatewayTlsCert"
    private final List<String> sourceFieldNames = new ArrayList<>();   // ["config_certs", "acme_certs"]
    private final List<String> sourceFieldCamels = new ArrayList<>();  // ["configCerts", "acmeCerts"]

    public String getFieldName() { return fieldName; }
    public void setFieldName(String fieldName) { this.fieldName = fieldName; }

    public String getFieldPascal() { return fieldPascal; }
    public void setFieldPascal(String fieldPascal) { this.fieldPascal = fieldPascal; }

    public String getFieldCamel() { return fieldCamel; }
    public void setFieldCamel(String fieldCamel) { this.fieldCamel = fieldCamel; }

    public String getTypeName() { return typeName; }
    public void setTypeName(String typeName) { this.typeName = typeName; }

    public List<String> getSourceFieldNames() { return sourceFieldNames; }
    public List<String> getSourceFieldCamels() { return sourceFieldCamels; }
}
