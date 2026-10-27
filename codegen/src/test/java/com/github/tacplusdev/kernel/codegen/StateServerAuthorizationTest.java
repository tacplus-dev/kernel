package com.github.tacplusdev.kernel.codegen;

import com.github.tacplusdev.kernel.codegen.generator.BackendServiceServerGenerator;
import com.github.tacplusdev.kernel.codegen.generator.GeneratorContext;
import com.github.tacplusdev.kernel.codegen.model.AccessPolicy;
import com.github.tacplusdev.kernel.codegen.model.BackendServiceInfo;
import com.github.tacplusdev.kernel.codegen.model.SharedBackendInfo;

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
 * A backend state server whose state root has no security policy used to be
 * generated with {@code GRAPH = "*"} — {@code SecurityAuthenticator.NO_POLICY_GRAPH}
 * — behind a build-log warning. That marker is an explicit early-return PASS in
 * {@code checkAccess}, so every RPC on the root, writes included, authorized
 * nothing. It exists for generated read-only View servers, which pass it
 * deliberately; reaching it by a failed policy lookup on a write-capable state
 * service is a silent authorization bypass.
 *
 * <p>These tests drive the real pipeline — real {@link ProtoDescriptorParser},
 * real {@link BackendServiceDiscovery#discover}, real {@link BoundaryAnalyzer},
 * real {@link BackendServiceServerGenerator} — over a fixture state root, because
 * the defect is in the generator rather than in a template read by hand. They
 * mirror {@link StoreServerAuthorizationTest}, which pins the same fail-closed
 * posture for {@code (spec.service_store)} servers.
 */
class StateServerAuthorizationTest {

	private static final String PROTO = """
			syntax = "proto3";
			package fixtures;
			option java_package = "com.example.fixtures";
			option java_outer_classname = "FixturesProto";

			message FixtureSetting {
			  string setting_id = 1;
			  string value = 2;
			}

			message FixtureState {
			  option (spec.service_state) = {name: "FixtureState", label: ["fixtures"]};

			  FixtureSetting setting = 1;
			}
			""";

	/** The policy tacplus computes for that state root, as codegen-config.json carries it. */
	private static final AccessPolicy FIXTURE_POLICY = new AccessPolicy(
			"FixtureState", "fixtures",
			List.of("service:fixtures"), List.of("service:fixtures"), List.of(),
			Map.of(), List.of(), false, false);

	@Test
	void generatedStateServerCarriesTheGraphKeyOfItsPolicy(@TempDir Path tmp) throws IOException {
		String src = generateStateServer(tmp, List.of(FIXTURE_POLICY));

		assertTrue(src.contains("private static final String GRAPH = \"fixtures.FixtureState\";"),
				"the state server must carry the graph key of its computed policy");
		assertFalse(src.contains("NO_POLICY_GRAPH"),
				"NO_POLICY_GRAPH short-circuits checkAccess before any caller check — "
						+ "a state server carrying it authorizes nothing on any RPC");
		assertEquals("fixtures.FixtureState", FIXTURE_POLICY.graphKey(),
				"the emitted key must be AccessPolicy.graphKey()'s format, not a second spelling");
	}

	/**
	 * A service's typed Config root (<Svc>ConfigState) reads through to the
	 * system entry: the bundle installs the fleet's config there, and a
	 * tenant-owned instance of the service is a confined caller with no entry of
	 * its own until a tenant-level config is written. Without this every
	 * per-tenant instance started on an empty config.
	 */
	@Test
	void aServiceConfigRootReadsTheFleetEntryAsItsDefault(@TempDir Path tmp) throws IOException {
		String proto = PROTO.replace("FixtureState", "FixturesConfigState");
		AccessPolicy ownOnly = new AccessPolicy("FixturesConfigState", "fixtures",
				List.of("service:fixtures"), List.of("service:fixtures"), List.of(), Map.of(), List.of(), false, false);
		assertTrue(generateStateServer(tmp, List.of(ownOnly), proto, "FixturesConfigState")
				.contains("private static final boolean FLEET_WIDE_READ = true;"),
				"a per-service config root must read the fleet's entry when the tenant has none");
	}

	/**
	 * A root whose policy grants every service is fleet-wide: tenant callers read
	 * its system entries. Any root that names its callers stays a plain chroot.
	 */
	@Test
	void onlyARootGrantingEveryServiceIsFleetWide(@TempDir Path tmp) throws IOException {
		assertTrue(generateStateServer(tmp.resolve("named"), List.of(FIXTURE_POLICY))
				.contains("private static final boolean FLEET_WIDE_READ = false;"));

		List<AccessPolicy> grantingEveryone = List.of(
				new AccessPolicy("FixtureState", "fixtures", List.of("*"), List.of("service:fixtures"),
						List.of(), Map.of(), List.of(), false, false),
				new AccessPolicy("FixtureState", "fixtures", List.of("service:fixtures"), List.of("*"),
						List.of(), Map.of(), List.of(), false, false));
		for (int i = 0; i < grantingEveryone.size(); i++) {
			AccessPolicy everyone = grantingEveryone.get(i);
			assertTrue(generateStateServer(tmp.resolve("everyone-" + i), List.of(everyone))
					.contains("private static final boolean FLEET_WIDE_READ = true;"),
					"a policy granting \"*\" must generate a fleet-wide server: " + everyone);
		}
	}

	/**
	 * Fail-closed: a state root with no policy fails generation rather than
	 * emitting a server that authorizes nothing. A build warning is what let this
	 * gap ship — {@code grpcconfig.ServiceConfigState} was generated with
	 * {@code GRAPH = "*"}, leaving SetConfig callable by any authenticated caller.
	 */
	@Test
	void generationFailsWhenTheStateRootHasNoPolicy(@TempDir Path tmp) throws IOException {
		IllegalStateException e = assertThrows(IllegalStateException.class,
				() -> generateStateServer(tmp, List.of()));

		assertTrue(e.getMessage().contains("fixtures.FixtureState"),
				"the failure must name the state root that has no policy: " + e.getMessage());
		assertFalse(e.getMessage().contains("WARNING"),
				"this must be a hard failure, not a warning: " + e.getMessage());
		assertFalse(Files.exists(generatedFile(tmp, "FixtureState")),
				"no state server may be written when its policy is missing");
	}

	/** A policy for a same-named state root in another package must not satisfy the lookup. */
	@Test
	void aPolicyForADifferentPackageDoesNotSatisfyTheLookup(@TempDir Path tmp) {
		AccessPolicy other = new AccessPolicy("FixtureState", "otherpkg",
				List.of("service:otherpkg"), List.of("service:otherpkg"), List.of(),
				Map.of(), List.of(), false, false);

		assertThrows(IllegalStateException.class, () -> generateStateServer(tmp, List.of(other)));
	}

	/**
	 * The infra-proto state roots kernel serves but tacplus cannot compute a
	 * policy for are supplied by InfraStatePolicies, so the fail-closed generator
	 * still has a policy to find.
	 */
	@Test
	void infraStatePoliciesSuppliesServiceConfigState() {
		AccessPolicy policy = InfraStatePolicies.merge(List.of()).stream()
				.filter(p -> "grpcconfig.ServiceConfigState".equals(p.graphKey()))
				.findFirst()
				.orElseThrow(() -> new AssertionError(
						"grpcconfig.ServiceConfigState has no computed policy and none declared"));

		assertEquals(List.of("service:kernel"), policy.rw(),
				"kernel is the only writer of the cluster-wide service config");
		assertEquals(List.of("*"), policy.ro(),
				"every service reads the shared config singleton to boot");
	}

	/**
	 * ServiceHealth moved from kernel.proto to the sys contract
	 * (sys/servicehealth.proto); every service writes its own instances and
	 * reads the whole root, as before.
	 */
	@Test
	void infraStatePoliciesSuppliesServiceHealth() {
		AccessPolicy policy = InfraStatePolicies.merge(List.of()).stream()
				.filter(p -> "servicehealth.ServiceHealth".equals(p.graphKey()))
				.findFirst()
				.orElseThrow(() -> new AssertionError(
						"servicehealth.ServiceHealth has no computed policy and none declared"));

		assertEquals(List.of("*"), policy.rw(),
				"every service reports its own instance health (instance-keyed writes)");
		assertEquals(List.of("*"), policy.ro(),
				"every service may read fleet health");
	}

	/** A computed policy always wins over the declared infra fallback. */
	@Test
	void aComputedPolicyIsNotOverriddenByInfraStatePolicies() {
		AccessPolicy computed = new AccessPolicy("ServiceConfigState", "grpcconfig",
				List.of("service:someone"), List.of("service:someone"), List.of(),
				Map.of(), List.of(), false, false);

		List<AccessPolicy> merged = InfraStatePolicies.merge(List.of(computed));

		assertEquals(1, merged.stream().filter(p -> "grpcconfig.ServiceConfigState".equals(p.graphKey())).count(),
				"merge must not add a duplicate entry for an already-computed graph key");
		assertEquals(List.of("service:someone"), merged.get(0).rw(),
				"the computed policy must win");
	}

	/** Runs discovery, boundary analysis and generation exactly as BackendServerMojo does. */
	private static String generateStateServer(Path tmp, List<AccessPolicy> policies) throws IOException {
		return generateStateServer(tmp, policies, PROTO, "FixtureState");
	}

	private static String generateStateServer(Path tmp, List<AccessPolicy> policies, String proto, String stateName) throws IOException {
		Path protoDir = layout(tmp, proto);

		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();

		List<BackendServiceInfo> services = BackendServiceDiscovery.discover(parser);
		assertEquals(1, services.size(), "the fixture state root must be discovered");

		BackendServiceInfo svc = services.get(0);
		SharedBackendInfo info = BoundaryAnalyzer.analyze(svc, parser);

		GeneratorContext ctx = new GeneratorContext("com.example.backend", "com.example",
				"com.example.graphs", "", tmp.resolve("out"), protoDir, parser, policies, "Copyright test");
		BackendServiceServerGenerator.generate(svc, info, ctx);

		return Files.readString(generatedFile(tmp, stateName));
	}

	private static Path generatedFile(Path tmp, String stateName) {
		return tmp.resolve("out/src/main/java/com/example/backend/services/fixtures/"
				+ stateName + "StateServiceServer.java");
	}

	private static Path layout(Path tmp, String proto) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("services"));
		Files.writeString(protoDir.resolve("services/fixtures.proto"), proto);
		Files.writeString(tmp.resolve("registry.json"), "{\"name\": \"root\", \"children\": []}");
		return protoDir;
	}
}
