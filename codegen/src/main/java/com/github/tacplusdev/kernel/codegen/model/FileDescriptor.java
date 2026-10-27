package com.github.tacplusdev.kernel.codegen.model;

import java.util.ArrayList;
import java.util.List;

public class FileDescriptor {
    private String path;
    private String packageName;
    private String javaOuterClassname;
    private String javaPackage;
    private final List<MessageDescriptor> messages = new ArrayList<>();
    private final List<ServiceDescriptor> services = new ArrayList<>();

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getJavaOuterClassname() { return javaOuterClassname; }
    public void setJavaOuterClassname(String javaOuterClassname) { this.javaOuterClassname = javaOuterClassname; }

    public String getJavaPackage() { return javaPackage; }
    public void setJavaPackage(String javaPackage) { this.javaPackage = javaPackage; }

    public List<MessageDescriptor> getMessages() { return messages; }
    public List<ServiceDescriptor> getServices() { return services; }
}
