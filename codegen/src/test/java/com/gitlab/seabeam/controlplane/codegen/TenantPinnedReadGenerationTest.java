package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.generator.BackendServiceServerGenerator;
import com.gitlab.seabeam.controlplane.codegen.generator.GeneratorContext;
import com.gitlab.seabeam.controlplane.codegen.generator.SecurityAuthenticatorGenerator;
import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;
import com.gitlab.seabeam.controlplane.codegen.model.BackendServiceInfo;
import com.gitlab.seabeam.controlplane.codegen.model.SharedBackendInfo;
import com.gitlab.seabeam.controlplane.codegen.model.TenantPinnedRead;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * codegen-config.json {@code securityPolicies[].tenantPinnedReads} (tacplus #130):
 * parsed apart from boundaryGrants, generated as a pinned authorization on the
 * read RPCs of that one collection only, and refused at generation for a shape
 * the generated filter cannot serve. A config without the field generates what
 * it generated before.
 *
 * <p>Drives the real parser, discovery, boundary analysis and generators over a
 * fixture state root, as {@link StateServerAuthorizationTest} does.
 */
class TenantPinnedReadGenerationTest {

	private static final String PROTO = """
			syntax = "proto3";
			package fixtures;
			option java_package = "com.example.fixtures";
			option java_outer_classname = "FixturesProto";

			message AlphaSlice {
			  string value = 1;
			}

			message BetaSlice {
			  string secret = 1;
			}

			message FixtureConfig {
			  AlphaSlice alpha = 1;
			  BetaSlice beta = 2;
			}

			message FixtureEntry {
			  string tenant_name = 1 [(spec.indexed) = true];
			  FixtureConfig config = 2;
			  string note = 3;
			}

			message FixtureOther {
			  string other_id = 1 [(spec.indexed) = true];
			}

			message FixtureState {
			  option (spec.service_state) = {name: "FixtureState", label: ["fixtures"]};

			  repeated FixtureEntry entries = 1;
			  repeated FixtureOther others = 2;
			}
			""";

	private static final TenantPinnedRead PIN = new TenantPinnedRead("entries", "tenant_name", "config",
			slices("alpha", "alpha"));

	/** The read RPCs of a collection kernel generates: tacplus's eight less Query and WatchQuery. */
	private static final List<String> READS = List.of(
			"getEntries", "containsKeyEntries", "getAllEntries", "keySetEntries", "sizeEntries", "watchEntries");
	private static final List<String> WRITES = List.of(
			"putEntries", "setEntries", "removeEntries", "deleteEntries", "clearEntries", "putIfAbsentEntries");

	private static Map<String, String> slices(String... callerSlice) {
		Map<String, String> m = new LinkedHashMap<>();
		for (int i = 0; i < callerSlice.length; i += 2) {
			m.put(callerSlice[i], callerSlice[i + 1]);
		}
		return m;
	}

	private static AccessPolicy policy(List<TenantPinnedRead> pins) {
		return policy(pins, false);
	}

	private static AccessPolicy policy(List<TenantPinnedRead> pins, boolean disableAuth) {
		return new AccessPolicy("FixtureState", "fixtures",
				List.of("service:fixtures"), List.of("service:fixtures", "service:reader"), List.of(),
				Map.of("others", List.of("granted")), pins, disableAuth, false);
	}

	// ---- codegen-config.json -----------------------------------------------

	@Test
	void tenantPinnedReadsIsParsedApartFromBoundaryGrants(@TempDir Path tmp) throws IOException {
		Path json = Files.writeString(tmp.resolve("codegen-config.json"), """
				{
				  "javaPackageBase": "com.example",
				  "securityPolicies": [
				    {
				      "name": "ConfigState",
				      "package": "kernel",
				      "rw": ["service:kernel"],
				      "ro": ["service:kernel", "service:operator"],
				      "boundaryGrants": [{"boundary": "jobs", "callers": ["worker"], "type": "queue"}],
				      "tenantPinnedReads": [
				        {
				          "boundary": "tenant_configs",
				          "keyField": "tenant_name",
				          "configField": "config",
				          "slices": [{"caller": "oauth", "sliceField": "oauth"}, {"caller": "opa", "sliceField": "opa"}]
				        }
				      ]
				    },
				    {
				      "name": "Other",
				      "package": "kernel",
				      "rw": ["service:kernel"],
				      "ro": ["service:kernel"]
				    }
				  ]
				}
				""");

		CodegenConfig config = CodegenConfig.parse(json.toFile());

		AccessPolicy cs = config.securityPolicies.get(0);
		assertEquals(List.of(new TenantPinnedRead("tenant_configs", "tenant_name", "config",
				slices("oauth", "oauth", "opa", "opa"))), cs.tenantPinnedReads());
		assertEquals(Map.of("jobs", List.of("worker")), cs.boundaryGrants(),
				"a tenant-pinned read must never become a boundary grant: kernel reads those as full access");
		assertEquals(List.of("service:kernel", "service:operator"), cs.ro(), "ro is unchanged by the pin");
		assertEquals(List.of(), config.securityPolicies.get(1).tenantPinnedReads(), "the field is optional");
	}

	@Test
	void aMalformedTenantPinnedReadFailsInsteadOfBeingDropped(@TempDir Path tmp) throws IOException {
		Path json = Files.writeString(tmp.resolve("codegen-config.json"), """
				{"securityPolicies": [{"name": "ConfigState", "package": "kernel", "rw": [], "ro": [],
				  "tenantPinnedReads": [{"boundary": "tenant_configs", "keyField": "tenant_name",
				    "slices": [{"caller": "opa", "sliceField": "opa"}]}]}]}
				""");

		IllegalStateException e = assertThrows(IllegalStateException.class, () -> CodegenConfig.parse(json.toFile()));
		assertTrue(e.getMessage().contains("configField"), e.getMessage());
	}

	// ---- the generated state server -----------------------------------------

	@Test
	void onlyThePinnedCollectionsReadRpcsArePinned(@TempDir Path tmp) throws IOException {
		String src = generateStateServer(tmp, policy(List.of(PIN)));

		for (String rpc : READS) {
			String body = method(src, rpc);
			assertTrue(body.contains("authenticator.checkPinnedRead(GRAPH, \"entries\")"), rpc + " must resolve the pin");
			assertFalse(body.contains("checkAccess("), rpc + " must authorize through checkPinnedRead alone");
		}
		for (String rpc : WRITES) {
			String body = method(src, rpc);
			assertTrue(body.contains("checkAccess(\"entries\", SecurityAuthenticator.OperationType.WRITE)"), rpc);
			assertFalse(body.contains("Pin"), rpc + " is a write: the pin grants none");
		}
		for (String rpc : List.of("getOthers", "getAllOthers", "keySetOthers", "sizeOthers", "watchOthers")) {
			assertFalse(method(src, rpc).contains("Pin"), rpc + " is another boundary: the pin grants none");
		}
		assertEquals(READS.size(), count(src, "authenticator.checkPinnedRead("), "exactly the read RPCs are pinned");
	}

	/**
	 * Without the field, nothing about the server changes: no pin code, and every
	 * method other than the pinned collection's reads is the same either way.
	 */
	@Test
	void aConfigWithoutThePinGeneratesTheUnpinnedServer(@TempDir Path tmp) throws IOException {
		String plain = generateStateServer(tmp.resolve("plain"), policy(List.of()));
		String pinned = generateStateServer(tmp.resolve("pinned"), policy(List.of(PIN)));

		assertFalse(plain.contains("Pin"), "a server without tenantPinnedReads must carry no pin code");
		assertEquals(READS.size(), count(plain, "checkAccess(\"entries\", SecurityAuthenticator.OperationType.READ)"));
		for (String rpc : List.of("putEntries", "setEntries", "removeEntries", "deleteEntries", "clearEntries",
				"putIfAbsentEntries", "getOthers", "putOthers", "getAllOthers", "watchOthers", "buildEntriesSnapshot",
				"pollCollectionEntries")) {
			assertEquals(method(plain, rpc), method(pinned, rpc), rpc + " must not change with the pin");
		}
	}

	@Test
	void theAuthenticatorCarriesThePinApartFromTheBoundaryGrants(@TempDir Path tmp) throws IOException {
		String plain = generateAuthenticator(tmp.resolve("plain"), policy(List.of()));
		String pinned = generateAuthenticator(tmp.resolve("pinned"), policy(List.of(PIN)));

		String policyInit = "policies.put(\"fixtures.FixtureState\", new Policy(List.of(\"service:fixtures\"), "
				+ "List.of(\"service:fixtures\", \"service:reader\"), Map.of(\"others\", List.of(\"granted\"))));";
		assertTrue(plain.contains(policyInit), plain);
		assertTrue(pinned.contains(policyInit), "boundaryGrants must be unchanged by the pin");
		assertTrue(pinned.contains("Map.entry(\"fixtures.FixtureState/entries\", new PinnedRead(\"tenant_name\", "
				+ "\"config\", Map.ofEntries(Map.entry(\"alpha\", \"alpha\"))))"), pinned);

		assertFalse(plain.contains("TenantPin"), "an authenticator without tenantPinnedReads must carry no pin code");
		assertEquals(plain, pinned.replaceAll("(?s)    /\\*\\*\n     \\* Tenant-pinned reads.*?\n    }\n\n(?=    /\\*\\*\n     \\* Matches)", ""),
				"the pin adds its block and changes nothing else");
	}

	// ---- fail closed --------------------------------------------------------

	@Test
	void aPinThisGeneratorCannotFilterFailsGeneration(@TempDir Path tmp) {
		Map<String, AccessPolicy> refused = new LinkedHashMap<>();
		refused.put("not a collection", policy(List.of(new TenantPinnedRead("missing", "tenant_name", "config",
				slices("alpha", "alpha")))));
		refused.put("(spec.indexed) key", policy(List.of(new TenantPinnedRead("entries", "note", "config",
				slices("alpha", "alpha")))));
		refused.put("singular message field", policy(List.of(new TenantPinnedRead("entries", "tenant_name", "note",
				slices("alpha", "alpha")))));
		refused.put("slice field", policy(List.of(new TenantPinnedRead("entries", "tenant_name", "config",
				slices("alpha", "gamma")))));
		refused.put("disables auth", policy(List.of(PIN), true));

		for (var c : refused.entrySet()) {
			Path dir = tmp.resolve(c.getKey().replaceAll("[^a-z]+", "-"));
			IllegalStateException e = assertThrows(IllegalStateException.class,
					() -> generateStateServer(dir, c.getValue()), c.getKey());
			assertTrue(e.getMessage().contains("fixtures.FixtureState.") && e.getMessage().contains(c.getKey()),
					c.getKey() + ": " + e.getMessage());
			assertFalse(Files.exists(generatedFile(dir)), c.getKey() + ": no server may be written");
		}
	}

	// ---- helpers --------------------------------------------------------------

	/** The text of one generated method, from its signature to the next method. */
	private static String method(String src, String name) {
		Matcher m = Pattern.compile("(?s)\n    (?:public|private)[^\n]* " + name + "\\(.*?\n    }\n").matcher(src);
		assertTrue(m.find(), "no generated method " + name);
		return m.group();
	}

	private static int count(String src, String needle) {
		return src.split(Pattern.quote(needle), -1).length - 1;
	}

	private static GeneratorContext context(Path tmp, AccessPolicy policy) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("services"));
		Files.writeString(protoDir.resolve("services/fixtures.proto"), PROTO);
		Files.writeString(tmp.resolve("registry.json"), "{\"name\": \"root\", \"children\": []}");
		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();
		return new GeneratorContext("com.example.backend", "com.example", "com.example.graphs", "",
				tmp.resolve("out"), protoDir, parser, List.of(policy), Map.of(), List.of("fixtures"), "Copyright test");
	}

	private static String generateStateServer(Path tmp, AccessPolicy policy) throws IOException {
		GeneratorContext ctx = context(tmp, policy);
		List<BackendServiceInfo> services = BackendServiceDiscovery.discover(ctx.getParser());
		assertEquals(1, services.size(), "the fixture state root must be discovered");
		BackendServiceInfo svc = services.get(0);
		SharedBackendInfo info = BoundaryAnalyzer.analyze(svc, ctx.getParser());
		BackendServiceServerGenerator.generate(svc, info, ctx);
		return Files.readString(generatedFile(tmp));
	}

	private static String generateAuthenticator(Path tmp, AccessPolicy policy) throws IOException {
		SecurityAuthenticatorGenerator.generate(context(tmp, policy));
		return Files.readString(tmp.resolve("out/src/main/java/com/example/backend/SecurityAuthenticator.java"));
	}

	private static Path generatedFile(Path tmp) {
		return tmp.resolve("out/src/main/java/com/example/backend/services/fixtures/"
				+ "FixtureStateStateServiceServer.java");
	}
}
