package com.gitlab.secondstarcavalier.controlplane.codegen;

import com.gitlab.secondstarcavalier.controlplane.codegen.generator.GeneratorContext;
import com.gitlab.secondstarcavalier.controlplane.codegen.generator.SecurityAuthenticatorGenerator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The no-auth skip list is collected across every proto in the build, not only
 * those of the service being generated. It used to record each exemption under
 * the bare {@code ServiceName} / {@code ServiceName/RpcName}, and the generated
 * {@code isNoAuthMethod} stripped the package off the incoming method before
 * comparing — so one {@code auth_disabled} RPC exempted every identically-named
 * RPC in every other package, shipping an unauthenticated RPC the moment two
 * packages happened to agree on a name.
 *
 * <p>Both sides are now qualified with the proto package, and the comparison stays
 * exact equality — never a substring of the full name, which is the property
 * {@link #anExemptionIsNeverMatchedAsASubstring} pins.
 */
class NoAuthExemptionPackageScopeTest {

	/** kernel.Mint/MintToken is auth_disabled; kernel.Mint/GetMintStatus is not. */
	private static final String KERNEL_PROTO = """
			syntax = "proto3";
			package kernel;
			option java_package = "com.example.kernel";
			option java_outer_classname = "MintProto";

			service Mint {
			  option (spec.service_s2s) = {auth_disabled: false};

			  rpc MintToken(TokenMintRequest) returns (TokenMintResponse);
			  rpc GetMintStatus(StatusRequest) returns (StatusResponse);
			}
			""";

	/**
	 * A different package with a service of the same name and an RPC of the same
	 * name, exempt nowhere, plus an unannotated service that handles its own auth.
	 */
	private static final String GATEWAY_PROTO = """
			syntax = "proto3";
			package gateway;
			option java_package = "com.example.gateway";
			option java_outer_classname = "GatewayProto";

			service Mint {
			  option (spec.service_s2s) = {auth_disabled: false};

			  rpc MintToken(TokenMintRequest) returns (TokenMintResponse);
			}

			service Health {
			  rpc Check(CheckRequest) returns (CheckResponse);
			}
			""";

	private static final String REGISTRY = """
			{
			  "name": "root",
			  "children": [
			    {
			      "name": "services",
			      "children": [
			        {
			          "name": "kernel",
			          "services": [
			            {
			              "name": "Mint",
			              "package": "kernel",
			              "grpc_service": "kernel.Mint",
			              "rpcs": [
			                {"rpc": "MintToken", "auth_disabled": true},
			                {"rpc": "GetMintStatus"}
			              ]
			            }
			          ]
			        },
			        {
			          "name": "gateway",
			          "services": [
			            {
			              "name": "Mint",
			              "package": "gateway",
			              "grpc_service": "gateway.Mint",
			              "rpcs": [
			                {"rpc": "MintToken"}
			              ]
			            }
			          ]
			        }
			      ]
			    }
			  ]
			}
			""";

	@Test
	void perRpcExemptionsCarryTheProtoPackage(@TempDir Path tmp) throws IOException {
		List<String> entries = noAuthEntries(tmp);

		assertTrue(entries.contains("kernel.Mint/MintToken"),
				"the exempt RPC must be recorded under its own package: " + entries);
		assertFalse(entries.contains("Mint/MintToken"),
				"an unqualified entry exempts gateway.Mint/MintToken too: " + entries);
		assertFalse(entries.contains("gateway.Mint/MintToken"),
				"a same-named RPC in another package is not exempt: " + entries);
		assertFalse(entries.contains("kernel.Mint/GetMintStatus"),
				"an RPC registry.json does not exempt must stay authenticated: " + entries);
	}

	@Test
	void wholeServiceExemptionsCarryTheProtoPackage(@TempDir Path tmp) throws IOException {
		List<String> entries = noAuthEntries(tmp);

		assertTrue(entries.contains("gateway.Health"),
				"an unannotated service handles its own auth, under its own package: " + entries);
		assertFalse(entries.contains("Health"),
				"an unqualified entry exempts a Health service in every package: " + entries);
	}

	@Test
	void theGeneratedAuthenticatorMatchesOnTheFullMethodName(@TempDir Path tmp) throws IOException {
		String src = generateAuthenticator(tmp);

		assertTrue(src.contains("\"kernel.Mint/MintToken\""),
				"the emitted NO_AUTH_METHODS must carry the qualified path");
		assertTrue(src.contains("NO_AUTH_METHODS.contains(fullMethodName)"),
				"the lookup must use the full package.Service/Rpc name the interceptor is handed");
		assertFalse(src.contains("service.lastIndexOf('.')"),
				"stripping the package off the incoming method is what made the match "
						+ "package-blind in the first place");
	}

	/** The exact-equality property the previous fix established must survive this one. */
	@Test
	void anExemptionIsNeverMatchedAsASubstring(@TempDir Path tmp) throws IOException {
		String src = generateAuthenticator(tmp);

		assertFalse(src.contains("fullMethodName.contains("),
				"the skip list is matched by exact set membership, never as a substring");
		assertTrue(src.contains("NO_AUTH_SERVICES.contains(fullMethodName.substring(0, slash))"),
				"the service arm compares the whole qualified service name");
	}

	private static List<String> noAuthEntries(Path tmp) throws IOException {
		return context(tmp).getNoAuthServiceNames();
	}

	private static String generateAuthenticator(Path tmp) throws IOException {
		SecurityAuthenticatorGenerator.generate(context(tmp));
		return Files.readString(tmp.resolve("out/src/main/java/com/example/backend/SecurityAuthenticator.java"));
	}

	private static GeneratorContext context(Path tmp) throws IOException {
		Path protoDir = layout(tmp);
		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();
		return new GeneratorContext("com.example.backend", "com.example",
				"com.example.graphs", "", tmp.resolve("out"), protoDir, parser,
				List.of(), Map.of(), List.of("kernel"));
	}

	private static Path layout(Path tmp) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("kernel"));
		Files.createDirectories(protoDir.resolve("gateway"));
		Files.writeString(protoDir.resolve("kernel/mint.proto"), KERNEL_PROTO);
		Files.writeString(protoDir.resolve("gateway/mint.proto"), GATEWAY_PROTO);
		Files.writeString(tmp.resolve("registry.json"), REGISTRY);
		return protoDir;
	}
}
