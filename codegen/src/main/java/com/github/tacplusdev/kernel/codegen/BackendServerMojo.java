package com.github.tacplusdev.kernel.codegen;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import com.github.tacplusdev.kernel.codegen.generator.BackendMapGenerator;
import com.github.tacplusdev.kernel.codegen.generator.BackendServersGenerator;
import com.github.tacplusdev.kernel.codegen.generator.BackendServiceServerGenerator;
import com.github.tacplusdev.kernel.codegen.generator.BackendStoreServerGenerator;
import com.github.tacplusdev.kernel.codegen.generator.EpochExpirationHelperGenerator;
import com.github.tacplusdev.kernel.codegen.generator.GeneratorContext;
import com.github.tacplusdev.kernel.codegen.generator.SecurityAuthenticatorGenerator;
import com.github.tacplusdev.kernel.codegen.generator.SerializableWrapperGenerator;
import com.github.tacplusdev.kernel.codegen.generator.TypedMapGenerator;
import com.github.tacplusdev.kernel.codegen.generator.ViewServerGenerator;
import com.github.tacplusdev.kernel.codegen.model.AccessPolicy;
import com.github.tacplusdev.kernel.codegen.model.BackendRpcServiceInfo;
import com.github.tacplusdev.kernel.codegen.model.BackendServiceInfo;
import com.github.tacplusdev.kernel.codegen.model.BackendStoreInfo;
import com.github.tacplusdev.kernel.codegen.model.SharedBackendInfo;

/**
 * Maven mojo that generates Java backend server code from proto definitions.
 * <p>
 * Reads the annotated proto files written by tacplus (proto-annotated/
 * directory)
 * to discover backend services (via service_backend annotation), analyzes
 * their boundaries, and generates:
 * <ul>
 * <li>{BackendName}Map.java — typed IMap accessors</li>
 * <li>{Type}Map.java — per-boundary typed map files</li>
 * <li>{Prefix}BackendServiceServer.java — gRPC server</li>
 * <li>BackendServers.java — aggregators at group and root level</li>
 * </ul>
 */
@Mojo(name = "generate-backend-servers", defaultPhase = LifecyclePhase.GENERATE_SOURCES)
public class BackendServerMojo extends AbstractMojo {

	/**
	 * Directory containing the annotated proto files (with special.* annotations).
	 * This is the proto-annotated/ directory written by tacplus during code
	 * generation.
	 */
	@Parameter(property = "protoDir", defaultValue = "${project.build.directory}/generated-sources/tacplus/proto-annotated")
	private File protoDir;

	/**
	 * Output directory for generated Java sources.
	 */
	@Parameter(property = "outputDir", defaultValue = "${project.build.directory}/generated-sources/tacplus")
	private File outputDir;

	/**
	 * Base Java package for generated code.
	 * If not set, read from codegen-config.json in protoDir.
	 */
	@Parameter(property = "javaPackageBase")
	private String javaPackageBase;

	/**
	 * Base Java package for tacplus-generated types (proto types, errors, helpers).
	 * The generated backend code imports types from this base.
	 * If not set, defaults to javaPackageBase (from config or explicit parameter).
	 */
	@Parameter(property = "typesPackageBase")
	private String typesPackageBase;

	/**
	 * Package for the interfaces library (Manager, IMap, Lock, Singleton).
	 * If not set, read from codegen-config.json in protoDir.
	 */
	@Parameter(property = "interfacesPackage")
	private String interfacesPackage;

	/**
	 * Fully-qualified class name of the PeerContext utility that holds the
	 * gRPC Context.Key for peer address identification. When set, generated
	 * topic publish RPCs will skip sending messages back to the originating peer.
	 * Example:
	 * com.github.tacplusdev.kernel.cluster.PeerContext
	 */
	@Parameter(property = "peerContextClass")
	private String peerContextClass;

	/**
	 * The service's tacplus.yaml. Its {@code header:} is stamped on every
	 * generated file, the same text tacplus stamps on its own output.
	 */
	@Parameter(property = "tacplusConfig", defaultValue = "${project.basedir}/../tacplus.yaml")
	private File tacplusConfig;

	@Override
	public void execute() throws MojoExecutionException {
		getLog().info("Backend server codegen: parsing protos from " + protoDir);

		// Clean output directory to prevent stale files from previous builds.
		// Without this, renamed or removed state services leave orphan Java files
		// that fail to compile (e.g., referencing non-existent gRPC base classes).
		if (outputDir.exists()) {
			getLog().info("Cleaning output directory: " + outputDir);
			deleteRecursively(outputDir);
		}

		if (!protoDir.exists()) {
			throw new MojoExecutionException(
					"Annotated proto directory not found: " + protoDir +
							"\nEnsure tacplus has been run first (tacplus update --backend-servers)");
		}

		// Read codegen-config.json from proto-annotated directory for default values.
		// Explicit Maven parameters override config file values.
		// Security policies are embedded inline in the JSON (computed from proto
		// annotations).
		List<AccessPolicy> securityPolicies = List.of();
		Map<String, List<String>> serviceRPCMappings = new java.util.HashMap<>();
		List<String> acceptedAudiences = List.of();
		File configFile = new File(protoDir, "codegen-config.json");
		if (configFile.exists()) {
			try {
				CodegenConfig cc = CodegenConfig.parse(configFile);
				if (javaPackageBase == null)
					javaPackageBase = cc.javaPackageBase;
				if (typesPackageBase == null)
					typesPackageBase = cc.javaPackageBase;
				if (interfacesPackage == null)
					interfacesPackage = cc.interfacesPackage;
				securityPolicies = cc.securityPolicies;
				serviceRPCMappings = cc.serviceRPCMappings;
				acceptedAudiences = cc.acceptedAudiences;
				getLog().info("Loaded codegen-config.json: javaPackageBase=" + javaPackageBase
						+ ", interfacesPackage=" + interfacesPackage
						+ ", policies=" + securityPolicies.size()
						+ ", serviceRPCMappings=" + serviceRPCMappings.size()
						+ ", acceptedAudiences=" + acceptedAudiences);
			} catch (IOException e) {
				throw new MojoExecutionException("Failed to read codegen-config.json", e);
			}
		}

		// State roots declared in tacplus's own infra protos never get a computed
		// policy (ComputeSecurityPolicies skips infra protos), so supply theirs
		// here rather than generating a server that authorizes nothing.
		securityPolicies = InfraStatePolicies.merge(securityPolicies);

		if (javaPackageBase == null || typesPackageBase == null || interfacesPackage == null) {
			throw new MojoExecutionException(
					"Missing required configuration: javaPackageBase, typesPackageBase, and interfacesPackage "
							+ "must be set via codegen-config.json (generated by tacplus) or explicit Maven parameters");
		}

		String copyright;
		try {
			copyright = TacplusConfig.header(tacplusConfig);
		} catch (IOException e) {
			throw new MojoExecutionException("Failed to read the header from " + tacplusConfig, e);
		}

		try {
			// Step 1: Parse proto descriptors from annotated protos
			ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir.toPath());
			parser.parseAll();

			getLog().info("Parsed " + parser.getAllFiles().size() + " proto files");

			// Step 2: Discover backend services (sorted by package name for deterministic
			// output)
			List<BackendServiceInfo> services = BackendServiceDiscovery.discover(parser);
			services.sort(Comparator.comparing(BackendServiceInfo::getPackageName));
			getLog().info("Discovered " + services.size() + " backend state services");

			// Discover backend RPC services (hand-written, service_backend_rpc annotation)
			List<BackendRpcServiceInfo> rpcServices = BackendServiceDiscovery.discoverRpcServices(parser);
			rpcServices.sort(Comparator.comparing(BackendRpcServiceInfo::getPackageName));
			getLog().info("Discovered " + rpcServices.size() + " backend RPC services");

			// Discover store services (service_store annotation — durable key-value stores)
			List<BackendStoreInfo> storeServices = BackendServiceDiscovery.discoverStoreServices(parser);
			storeServices.sort(Comparator.comparing(BackendStoreInfo::getPackageName));
			getLog().info("Discovered " + storeServices.size() + " backend store services");

			if (services.isEmpty() && rpcServices.isEmpty() && storeServices.isEmpty()) {
				getLog().info("No backend services found, skipping generation");
				return;
			}

			// Step 3: Analyze boundaries for each service
			Path outPath = outputDir.toPath();
			GeneratorContext ctx = new GeneratorContext(javaPackageBase, typesPackageBase, interfacesPackage,
					peerContextClass, outPath, protoDir.toPath(), parser, securityPolicies, serviceRPCMappings,
					acceptedAudiences, copyright);

			Map<BackendServiceInfo, SharedBackendInfo> infoMap = new LinkedHashMap<>();
			for (BackendServiceInfo svc : services) {
				SharedBackendInfo info = BoundaryAnalyzer.analyze(svc, parser);
				if (info != null) {
					infoMap.put(svc, info);
					long leaderCount = info.getQueues().stream().filter(b -> b.isLeader()).count()
							+ info.getPriorityQueues().stream().filter(b -> b.isLeader()).count()
							+ info.getTopics().stream().filter(b -> b.isLeader()).count();
					getLog().info("  " + svc.getPackageName() + ": " + info.getSingletons().size()
							+ " singletons, " + info.getCollections().size() + " collections, "
							+ info.getQueues().size() + " queues, "
							+ info.getPriorityQueues().size() + " priority queues, "
							+ info.getTopics().size() + " topics, "
							+ leaderCount + " leader-enabled boundaries");
				} else {
					getLog().warn("  " + svc.getPackageName() + ": no boundaries found");
				}
			}

			// Step 4: Generate code for each service
			for (var entry : infoMap.entrySet()) {
				BackendServiceInfo svc = entry.getKey();
				SharedBackendInfo info = entry.getValue();
				getLog().info("Generating backend server for " + svc.getPackageName());

				BackendMapGenerator.generate(svc, info, ctx);
				TypedMapGenerator.generate(svc, info, ctx);
				BackendServiceServerGenerator.generate(svc, info, ctx);
			}

			// Step 4b: Generate store service servers
			for (BackendStoreInfo store : storeServices) {
				getLog().info("Generating store service server for " + store.getValueTypeName());
				BackendStoreServerGenerator.generate(store, ctx);
			}

			// Step 5: Generate serializable wrappers, factory, and registry
			SerializableWrapperGenerator.generate(infoMap, ctx);

			// Step 6: Generate SecurityAuthenticator (once per project)
			SecurityAuthenticatorGenerator.generate(ctx);

			// Step 7: Generate service-specific view servers.
			ViewServerGenerator.generate(ctx);

			// Step 8: Generate aggregators (including backend RPC and store services)
			BackendServersGenerator.generate(new ArrayList<>(infoMap.keySet()), infoMap, rpcServices, storeServices, ctx);

			// Step 9: Generate epoch expiration helper for StateRestorer
			EpochExpirationHelperGenerator.generate(infoMap, ctx);

			getLog().info("Backend server codegen complete: generated " + infoMap.size() + " services");

		} catch (IOException e) {
			throw new MojoExecutionException("Backend server codegen failed", e);
		}
	}

	private static void deleteRecursively(File file) {
		if (file.isDirectory()) {
			File[] children = file.listFiles();
			if (children != null) {
				for (File child : children) {
					deleteRecursively(child);
				}
			}
		}
		file.delete();
	}
}
