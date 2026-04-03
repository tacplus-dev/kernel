package com.gitlab.secondstarcavalier.controlplane.codegen.generator;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.gitlab.secondstarcavalier.controlplane.codegen.ProtoDescriptorParser;
import com.gitlab.secondstarcavalier.controlplane.codegen.StringUtils;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.AccessPolicy;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.BackendServiceInfo;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.FileDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.MessageDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.ServiceDescriptor;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedBackendInfo;
import com.gitlab.secondstarcavalier.controlplane.codegen.model.SharedBoundary;

/**
 * Shared context for all generators, holding configuration and computed values.
 */
public class GeneratorContext {

	private final String javaPackageBase;
	private final String typesPackageBase;
	private final String interfacesPackage;
	private final String peerContextClass;
	private final Path outputDir;
	private final Path protoAnnotatedDir;
	private final ProtoDescriptorParser parser;
	private final List<AccessPolicy> securityPolicies;
	private final Map<String, List<String>> serviceRPCMappings;

	public GeneratorContext(String javaPackageBase, String typesPackageBase, String interfacesPackage,
			String peerContextClass, Path outputDir, Path protoAnnotatedDir, ProtoDescriptorParser parser) {
		this(javaPackageBase, typesPackageBase, interfacesPackage, peerContextClass, outputDir, protoAnnotatedDir,
				parser, List.of(), Map.of());
	}

	public GeneratorContext(String javaPackageBase, String typesPackageBase, String interfacesPackage,
			String peerContextClass, Path outputDir, Path protoAnnotatedDir, ProtoDescriptorParser parser,
			List<AccessPolicy> securityPolicies) {
		this(javaPackageBase, typesPackageBase, interfacesPackage, peerContextClass, outputDir, protoAnnotatedDir,
				parser, securityPolicies, Map.of());
	}

	public GeneratorContext(String javaPackageBase, String typesPackageBase, String interfacesPackage,
			String peerContextClass, Path outputDir, Path protoAnnotatedDir, ProtoDescriptorParser parser,
			List<AccessPolicy> securityPolicies, Map<String, List<String>> serviceRPCMappings) {
		this.javaPackageBase = javaPackageBase;
		this.typesPackageBase = typesPackageBase;
		this.interfacesPackage = interfacesPackage;
		this.peerContextClass = peerContextClass;
		this.outputDir = outputDir;
		this.protoAnnotatedDir = protoAnnotatedDir;
		this.parser = parser;
		this.securityPolicies = securityPolicies;
		this.serviceRPCMappings = serviceRPCMappings != null ? serviceRPCMappings : Map.of();
	}

	public String getJavaPackageBase() {
		return javaPackageBase;
	}

	public String getTypesPackageBase() {
		return typesPackageBase;
	}

	public String getInterfacesPackage() {
		return interfacesPackage;
	}

	public String getPeerContextClass() {
		return peerContextClass;
	}

	public boolean hasPeerContext() {
		return peerContextClass != null && !peerContextClass.isEmpty();
	}

	public Path getOutputDir() {
		return outputDir;
	}

	public Path getProtoAnnotatedDir() {
		return protoAnnotatedDir;
	}

	public ProtoDescriptorParser getParser() {
		return parser;
	}

	public String getErrorsPackage() {
		return typesPackageBase + ".types.libs.errors";
	}

	public String getSecurityPackage() {
		return typesPackageBase + ".types.libs.backendsec";
	}

	public String getTokenPackage() {
		return deriveLibsBase() + ".token";
	}

	public String getJwkLibPackage() {
		return deriveLibsBase() + ".jwk";
	}

	public String getJwkTypesPackage() {
		return typesPackageBase + ".types.libs.jwk";
	}

	/**
	 * Derives the libs base package from interfacesPackage (strips ".graphs"
	 * suffix).
	 */
	private String deriveLibsBase() {
		// interfacesPackage is like "com.gitlab...proto.interfaces.java.graphs"
		// libs base is the same root but with the libs packages, e.g.:
		// "com.gitlab...proto.libs.token"
		// We use javaPackageBase as the root, then replace the last segment pattern.
		// The libs are generated into the same artifact with package like:
		// <typesPackageBase>.libs.token.TokenWrapper -> that's the types
		// The actual lib wrappers are at <javaPackageBase - last segment>.libs.token
		// Actually, looking at the template: package {{.LibsBase}}.token
		// LibsBase is set in the Go template renderer. Let's compute it here.
		// From the Go code: LibsBase = cfg.Lang.Java.JavaImportBase() + ".libs"
		// JavaImportBase strips the trailing .graphs from interfacesPackage's parent.
		// interfacesPackage =
		// "com.gitlab.secondstarcavalier.controlplane.services.backenddb.tacplus.libs.messaging"
		// No wait - interfacesPackage = "com...proto.interfaces.java.graphs"
		// The libs are at the same level: "com...proto.libs"
		// Let's derive from javaPackageBase: "com...backenddb.tacplusbackend"
		// The libs sibling would be "com...backenddb.tacplus.libs"
		// This matches: typesPackageBase = "com...backenddb.tacplus"
		// So libsBase = typesPackageBase + ".libs"
		return typesPackageBase + ".libs";
	}

	/**
	 * Computes the output package for generated backend server code.
	 * Derives the directory from the proto file path (e.g. "services", "libs").
	 */
	public String getFullPackage(BackendServiceInfo svc) {
		String dir = deriveDir(svc.getProtoFile());
		return javaPackageBase + "." + dir + "." + svc.getPackageName();
	}

	/**
	 * Computes the types package import path (from tacplus-generated code).
	 */
	public String getTypesPackage(BackendServiceInfo svc) {
		String dir = deriveDir(svc.getProtoFile());
		return typesPackageBase + ".types." + dir + "." + svc.getPackageName();
	}

	/**
	 * Derives the top-level directory from a proto file path.
	 * E.g. "services/baseball.proto" -> "services", "libs/backendsec.proto" ->
	 * "libs".
	 */
	private String deriveDir(String protoFile) {
		int slash = protoFile.indexOf('/');
		return slash > 0 ? protoFile.substring(0, slash) : "services";
	}

	/**
	 * Detects the outer class name for a service's proto types.
	 */
	public String getOuterClassName(BackendServiceInfo svc) {
		FileDescriptor fd = parser.getFileDescriptor(svc.getProtoFile());
		if (fd != null && fd.getJavaOuterClassname() != null) {
			return fd.getJavaOuterClassname();
		}
		// Default: PascalCase from proto filename without extension
		// e.g. "iron-maiden" → "IronMaiden", "aws_connector" → "AwsConnector"
		String fileName = svc.getProtoFile();
		int slash = fileName.lastIndexOf('/');
		if (slash >= 0) {
			fileName = fileName.substring(slash + 1);
		}
		fileName = fileName.replace(".proto", "");
		return StringUtils.toPascalCase(fileName);
	}

	/**
	 * Computes helpers reference for a boundary.
	 */
	public String getHelpersRef(BackendServiceInfo svc, SharedBoundary boundary) {
		if (boundary.isCrossPackage()) {
			String typeDir = parser.resolveTypeDir(boundary.getCrossPkg());
			return typesPackageBase + ".types." + typeDir + "." + boundary.getCrossPkg() + ".Helpers";
		}
		String dir = deriveDir(svc.getProtoFile());
		return typesPackageBase + ".types." + dir + "." + svc.getPackageName() + ".Helpers";
	}

	/**
	 * Resolves the Java outer class name for a cross-package proto reference.
	 * Handles explicit java_outer_classname and protoc's automatic OuterClass
	 * suffix
	 * when a message name collides with the default outer class name.
	 */
	public String resolveCrossOuterClass(String pkg) {
		String outerClass = StringUtils.toPascalCase(pkg);
		for (var entry : parser.getAllFiles().entrySet()) {
			FileDescriptor fd = entry.getValue();
			if (fd.getPackageName() != null && fd.getPackageName().equals(pkg)) {
				if (fd.getJavaOuterClassname() != null) {
					outerClass = fd.getJavaOuterClassname();
				} else {
					// Protoc appends "OuterClass" when a message name collides
					for (MessageDescriptor msg : fd.getMessages()) {
						if (msg.getName().equals(outerClass)) {
							outerClass = outerClass + "OuterClass";
							break;
						}
					}
				}
				break;
			}
		}
		return outerClass;
	}

	/**
	 * Computes the qualified Java type for a boundary.
	 */
	public String getQualifiedType(String outerClassName, SharedBoundary boundary) {
		if (boundary.isCrossPackage()) {
			return resolveCrossOuterClass(boundary.getCrossPkg()) + "." + boundary.getTypeName();
		}
		return outerClassName + "." + boundary.getTypeName();
	}

	/**
	 * Collects cross-package import statements for a state root.
	 */
	public List<String> getCrossPackageImports(SharedBackendInfo info, String outerClassName) {
		Set<String> seen = new HashSet<>();
		List<String> imports = new ArrayList<>();

		for (SharedBoundary b : info.getSingletons()) {
			addCrossImport(b, seen, imports);
		}
		for (SharedBoundary b : info.getCollections()) {
			addCrossImport(b, seen, imports);
		}

		return imports;
	}

	private void addCrossImport(SharedBoundary b, Set<String> seen, List<String> imports) {
		if (!b.isCrossPackage() || seen.contains(b.getCrossPkg())) {
			return;
		}
		seen.add(b.getCrossPkg());

		String typeDir = parser.resolveTypeDir(b.getCrossPkg());
		String outerClass = resolveCrossOuterClass(b.getCrossPkg());
		String javaPkg = typesPackageBase + ".types." + typeDir + "." + b.getCrossPkg();
		imports.add("import " + javaPkg + "." + outerClass + ";");
	}

	/**
	 * Returns the cross-package import statement for a single boundary,
	 * or empty string if the boundary is not cross-package.
	 */
	public String getCrossPackageImport(SharedBoundary b) {
		if (!b.isCrossPackage()) {
			return "";
		}
		String typeDir = parser.resolveTypeDir(b.getCrossPkg());
		String outerClass = resolveCrossOuterClass(b.getCrossPkg());
		String javaPkg = typesPackageBase + ".types." + typeDir + "." + b.getCrossPkg();
		return "import " + javaPkg + "." + outerClass + ";\n";
	}

	/**
	 * Returns entries for the no-auth skip condition in the security interceptor.
	 * Each entry is either a service name (for unannotated services that handle
	 * their own auth) or a "ServiceName/RpcName" path (for individual RPCs with
	 * method-level auth_disabled).
	 */
	public List<String> getNoAuthServiceNames() {
		List<String> names = new ArrayList<>();
		for (FileDescriptor fd : parser.getAllFiles().values()) {
			for (ServiceDescriptor svc : fd.getServices()) {
				if (!svc.hasAuthAnnotation()) {
					// Unannotated services handle their own auth entirely
					names.add(svc.getName());
				} else if (svc.isDisableAuth()) {
					// Service-level auth_disabled (legacy service_grpc)
					names.add(svc.getName());
				} else {
					// Check per-RPC auth_disabled
					for (var rpc : svc.getRpcs()) {
						if (rpc.isDisableAuth()) {
							names.add(svc.getName() + "/" + rpc.getName());
						}
					}
				}
			}
		}
		return names;
	}

	public List<AccessPolicy> getSecurityPolicies() {
		return securityPolicies;
	}

	public Map<String, List<String>> getServiceRPCMappings() {
		return serviceRPCMappings;
	}

	/**
	 * Returns the types package for backenddb protos (for SecurityInterceptor
	 * imports).
	 */
	public String getBackenddbTypesPackage() {
		return typesPackageBase + ".types.services.backenddb";
	}

	/**
	 * The generated file header comment.
	 */
	public static String header(String source) {
		return """
				// Copyright (c) 2024 Second Star Cavalier, LLC.
				// Generated by tacplus
				//
				// CODE GENERATED - DO NOT EDIT
				// This file is automatically generated by the tacplus compiler.
				// Manual modifications will be overwritten on next generation.
				//
				// IMPORTANT FOR AGENTS: Do NOT modify this generated code.
				// If changes are needed, update the tacplus compiler at:
				// gitlab.com/secondstarcavalier/controlplane/services/tacplus
				//
				// Source: """ + source + "\n";
	}
}
