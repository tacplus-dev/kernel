package com.github.tacplusdev.kernel.codegen;

import com.github.tacplusdev.kernel.codegen.model.FileDescriptor;
import com.github.tacplusdev.kernel.codegen.model.RpcDescriptor;
import com.github.tacplusdev.kernel.codegen.model.ServiceDescriptor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Paired control for the per-RPC auth exemption source of truth.
 *
 * <p>The parser used to re-derive the exemption by regexing the {@code (spec.rpc)}
 * flags list out of proto text. That second derivation drifted from tacplus's own
 * once already: proto commit 637a06f moved the exemption from
 * {@code method_s2s {auth_disabled: true}} to {@code (spec.rpc) {flags: [...]}},
 * the regex only knew the retired spelling, and 19 RPCs — kernel.Mint/MintToken
 * among them — silently lost their exemption and started rejecting every caller
 * with UNAUTHENTICATED.
 *
 * <p>Both RPCs below are exempt as far as tacplus is concerned; registry.json
 * records both as {@code auth_disabled: true}. One is written in the spelling the
 * old regex handled, the other in a spelling it does not — the same failure shape
 * as the incident. The parser must now agree with registry.json on both.
 */
class ProtoDescriptorParserAuthExemptionTest {

	/** The exact flags regex the parser used to derive the exemption with. */
	private static final Pattern LEGACY_RPC_FLAGS_PATTERN =
			Pattern.compile("flags\\s*:\\s*\\[([^\\]]*)\\]");

	private static final String LIST_SPELLING =
			"option (spec.rpc) = {flags: [RPC_FLAG_SELF_AUTHENTICATES]};";
	/** protobuf text format also spells a repeated field as one entry per assignment. */
	private static final String REPEATED_SCALAR_SPELLING =
			"option (spec.rpc) = {flags: RPC_FLAG_SELF_AUTHENTICATES};";

	private static final String PROTO = """
			syntax = "proto3";
			package kernel;
			option java_package = "com.example.kernel";
			option java_outer_classname = "MintProto";

			service Mint {
			  option (spec.service_s2s) = {auth_disabled: false};

			  rpc MintToken(TokenMintRequest) returns (TokenMintResponse) {
			    %s
			  }
			  rpc MintServiceToken(TokenMintRequest) returns (TokenMintResponse) {
			    %s
			  }
			  rpc GetMintStatus(StatusRequest) returns (StatusResponse) {
			    option (spec.rpc) = {flags: [RPC_FLAG_IDEMPOTENT]};
			  }
			}
			""".formatted(LIST_SPELLING, REPEATED_SCALAR_SPELLING);

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
			                {"rpc": "MintServiceToken", "auth_disabled": true},
			                {"rpc": "GetMintStatus"}
			              ]
			            }
			          ]
			        }
			      ]
			    }
			  ]
			}
			""";

	/**
	 * Before: the regex sees the bracketed list and misses the equivalent
	 * repeated-scalar spelling — one exemption kept, one silently dropped.
	 */
	@Test
	void legacyRegexDisagreesWithTacplusOnTheSecondSpelling() {
		assertTrue(matchesLegacyFlags(LIST_SPELLING),
				"control: the old regex did read the bracketed flags list");
		assertFalse(matchesLegacyFlags(REPEATED_SCALAR_SPELLING),
				"the old regex cannot see a repeated-scalar flags spelling — this is the drift");
	}

	/** After: both exemptions come from registry.json, so both are read correctly. */
	@Test
	void parserReadsExemptionsFromRegistry(@TempDir Path tmp) throws IOException {
		Path protoDir = layout(tmp);

		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();

		assertTrue(rpc(parser, "MintToken").isDisableAuth(),
				"kernel.Mint/MintToken is auth_disabled in registry.json");
		assertTrue(rpc(parser, "MintServiceToken").isDisableAuth(),
				"kernel.Mint/MintServiceToken is auth_disabled in registry.json even though "
						+ "its flags spelling defeats the old regex");
		assertFalse(rpc(parser, "GetMintStatus").isDisableAuth(),
				"an RPC registry.json does not exempt must stay authenticated");
	}

	@Test
	void exemptionsAreKeyedByProtoPackage(@TempDir Path tmp) throws IOException {
		RegistryAuthExemptions exemptions =
				RegistryAuthExemptions.loadForProtoDir(layout(tmp));

		assertTrue(exemptions.isAuthDisabled("kernel", "Mint", "MintToken"));
		assertFalse(exemptions.isAuthDisabled("gateway", "Mint", "MintToken"),
				"a same-named service in another package must not inherit the exemption");
	}

	private static Path layout(Path tmp) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("kernel"));
		Files.writeString(protoDir.resolve("kernel/mint.proto"), PROTO);
		Files.writeString(tmp.resolve("registry.json"), REGISTRY);
		return protoDir;
	}

	private static boolean matchesLegacyFlags(String optionLine) {
		Matcher m = LEGACY_RPC_FLAGS_PATTERN.matcher(optionLine);
		return m.find() && m.group(1).contains("RPC_FLAG_SELF_AUTHENTICATES");
	}

	private static RpcDescriptor rpc(ProtoDescriptorParser parser, String name) {
		for (FileDescriptor fd : parser.getAllFiles().values()) {
			for (ServiceDescriptor svc : fd.getServices()) {
				for (RpcDescriptor rpc : svc.getRpcs()) {
					if (rpc.getName().equals(name)) return rpc;
				}
			}
		}
		return fail("RPC not parsed: " + name);
	}
}
