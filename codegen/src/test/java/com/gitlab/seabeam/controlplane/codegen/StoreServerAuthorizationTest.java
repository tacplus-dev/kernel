package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.generator.BackendStoreServerGenerator;
import com.gitlab.seabeam.controlplane.codegen.generator.GeneratorContext;
import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;
import com.gitlab.seabeam.controlplane.codegen.model.BackendStoreInfo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code (spec.service_store)} server used to hardcode
 * {@code SecurityAuthenticator.NO_POLICY_GRAPH}, on the stated but false premise
 * that ComputeSecurityPolicies emits no policy for a store. It does — a store
 * gets a {@code rw: [service:&lt;pkg&gt;]} policy alongside the state roots, and
 * that policy already ships in the generated {@code GRAPH_POLICIES} map. The
 * store server simply never looked it up, so {@code checkAccess} returned on the
 * no-policy short circuit and put/get/delete/list authorized nothing.
 *
 * <p>These tests drive the real pipeline — real {@link ProtoDescriptorParser},
 * real {@link BackendServiceDiscovery#discoverStoreServices}, real
 * {@link BackendStoreServerGenerator} — over a keyed store fixture, because the
 * defect is in the generator, not in a template read by hand. {@code platform/proto}
 * declares exactly one store, {@code kernel.KernelDiskState}, and it deliberately
 * has no {@code store_key} (UC1 snapshot only), so it emits no store server and
 * cannot serve as this fixture.
 */
class StoreServerAuthorizationTest {

	private static final String PROTO = """
			syntax = "proto3";
			package fixtures;
			option java_package = "com.example.fixtures";
			option java_outer_classname = "FixturesProto";

			message FixtureStoreEntry {
			  option (spec.service_store) = {label: ["fixtures"]};

			  string entry_id = 1 [
			    (spec.assert_required) = true,
			    (spec.store_key) = true
			  ];
			  string value = 2;
			}
			""";

	/** The policy tacplus computes for that store, as codegen-config.json carries it. */
	private static final AccessPolicy FIXTURE_POLICY = new AccessPolicy(
			"FixtureStoreEntry", "fixtures",
			List.of("service:fixtures"), List.of("*"), List.of(),
			Map.of(), List.of(), false, false);

	@Test
	void generatedStoreServerLooksUpItsComputedPolicy(@TempDir Path tmp) throws IOException {
		String src = generateStoreServer(tmp, List.of(FIXTURE_POLICY));

		assertTrue(src.contains("private static final String GRAPH = \"fixtures.FixtureStoreEntry\";"),
				"the store server must carry the graph key of its computed policy");
		assertFalse(src.contains("NO_POLICY_GRAPH"),
				"NO_POLICY_GRAPH short-circuits checkAccess before any caller check — "
						+ "a store server carrying it authorizes nothing on any RPC");
		assertEquals(FIXTURE_POLICY.graphKey(), "fixtures.FixtureStoreEntry",
				"the emitted key must be AccessPolicy.graphKey()'s format, not a second spelling");
	}

	/** All four store RPCs go through the one policed checkAccess helper. */
	@Test
	void everyStoreRpcIsChecked(@TempDir Path tmp) throws IOException {
		String src = generateStoreServer(tmp, List.of(FIXTURE_POLICY));

		assertTrue(src.contains("checkAccess(\"FixtureStoreEntry\", SecurityAuthenticator.OperationType.WRITE)"),
				"put and delete must check WRITE");
		assertTrue(src.contains("checkAccess(\"FixtureStoreEntry\", SecurityAuthenticator.OperationType.READ)"),
				"get and list must check READ");
		assertTrue(src.contains("authenticator.checkAccess(GRAPH, boundary, op);"),
				"the checks must resolve against the store's own graph");
	}

	/**
	 * Fail-closed: a store with no computed policy fails generation rather than
	 * emitting a server that authorizes nothing. A warning is what let the
	 * NO_POLICY_GRAPH gap live unnoticed through several landed changes.
	 */
	@Test
	void generationFailsWhenTheStoreHasNoComputedPolicy(@TempDir Path tmp) throws IOException {
		IllegalStateException e = assertThrows(IllegalStateException.class,
				() -> generateStoreServer(tmp, List.of()));

		assertTrue(e.getMessage().contains("fixtures.FixtureStoreEntry"),
				"the failure must name the store that has no policy: " + e.getMessage());
		assertFalse(Files.exists(generatedFile(tmp)),
				"no store server may be written when its policy is missing");
	}

	/** A policy for some other store must not be mistaken for this one's. */
	@Test
	void aPolicyForADifferentStoreDoesNotSatisfyTheLookup(@TempDir Path tmp) {
		AccessPolicy other = new AccessPolicy("FixtureStoreEntry", "otherpkg",
				List.of("service:otherpkg"), List.of("*"), List.of(), Map.of(), List.of(), false, false);

		assertThrows(IllegalStateException.class, () -> generateStoreServer(tmp, List.of(other)));
	}

	/** Runs discovery and generation exactly as BackendServerMojo does. */
	private static String generateStoreServer(Path tmp, List<AccessPolicy> policies) throws IOException {
		Path protoDir = layout(tmp);

		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();

		List<BackendStoreInfo> stores = BackendServiceDiscovery.discoverStoreServices(parser);
		assertEquals(1, stores.size(), "the keyed fixture store must be discovered");

		GeneratorContext ctx = new GeneratorContext("com.example.backend", "com.example",
				"com.example.graphs", "", tmp.resolve("out"), protoDir, parser, policies, "Copyright test");
		BackendStoreServerGenerator.generate(stores.get(0), ctx);

		return Files.readString(generatedFile(tmp));
	}

	private static Path generatedFile(Path tmp) {
		return tmp.resolve("out/src/main/java/com/example/backend/services/fixtures/"
				+ "FixtureStoreEntryStoreServiceServer.java");
	}

	private static Path layout(Path tmp) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("services"));
		Files.writeString(protoDir.resolve("services/fixtures.proto"), PROTO);
		Files.writeString(tmp.resolve("registry.json"), "{\"name\": \"root\", \"children\": []}");
		return protoDir;
	}
}
