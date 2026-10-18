package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.generator.BackendServiceServerGenerator;
import com.gitlab.seabeam.controlplane.codegen.generator.GeneratorContext;
import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;
import com.gitlab.seabeam.controlplane.codegen.model.BackendServiceInfo;
import com.gitlab.seabeam.controlplane.codegen.model.SharedBackendInfo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A view is a read-only merge of source collections in the same state root. Its
 * generated {@code watch<View>} RPC used to go straight from
 * {@code NamespaceScope.current()} to the snapshot and the watcher registration
 * with no {@code checkAccess} — while every other read on the same server, the
 * collection watch included, authorizes against the server's graph policy first.
 * That made the view the one unpoliced read path on an otherwise policed server:
 * any authenticated caller could stream the merged contents of collections it was
 * not in the policy for.
 *
 * <p>Like {@link StateServerAuthorizationTest}, this drives the real pipeline over
 * a fixture state root rather than reading the emitter by hand.
 */
class ViewRpcAuthorizationTest {

	private static final String PROTO = """
			syntax = "proto3";
			package fixtures;
			option java_package = "com.example.fixtures";
			option java_outer_classname = "FixturesProto";

			message FixtureCert {
			  string cert_id = 1;
			  string pem = 2;
			}

			message FixtureState {
			  option (spec.service_state) = {name: "FixtureState", label: ["fixtures"]};

			  repeated FixtureCert config_certs = 1;
			  repeated FixtureCert acme_certs = 2;
			  FixtureCert all_certs = 3 [
			    (spec.view_sources) = "config_certs",
			    (spec.view_sources) = "acme_certs"
			  ];
			}
			""";

	private static final AccessPolicy FIXTURE_POLICY = new AccessPolicy(
			"FixtureState", "fixtures",
			List.of("service:fixtures"), List.of("service:fixtures"), List.of(),
			Map.of(), false, false);

	@Test
	void theViewWatchAuthorizesBeforeItStreams(@TempDir Path tmp) throws IOException {
		String watch = viewWatchMethod(generateStateServer(tmp));

		assertTrue(watch.contains("checkAccess(\"all_certs\", SecurityAuthenticator.OperationType.READ);"),
				"the view watch must authorize READ on the view boundary:\n" + watch);
		assertTrue(watch.indexOf("checkAccess(") < watch.indexOf("NamespaceScope.current()"),
				"authorization must come before the snapshot is built and sent:\n" + watch);
		assertTrue(watch.contains("responseObserver.onError(toGrpcError(e));"),
				"a denial must be reported on the stream, the same way the collection "
						+ "watch fragment reports it:\n" + watch);
	}

	/** The view inherits the state root's policy — it must not be generated policy-free. */
	@Test
	void theViewWatchIsGuardedByTheServersOwnGraph(@TempDir Path tmp) throws IOException {
		String src = generateStateServer(tmp);

		assertTrue(src.contains("private static final String GRAPH = \"fixtures.FixtureState\";"),
				"the fixture server carries its computed graph key");
		assertEquals(1, countOccurrences(src, "public void watchAllCerts("),
				"exactly one view watch is generated for the fixture view");
	}

	/** The view watch is authorized exactly as a collection watch on the same root is. */
	@Test
	void theViewWatchMatchesTheCollectionWatchShape(@TempDir Path tmp) throws IOException {
		String src = generateStateServer(tmp);
		String collectionWatch = method(src, "public void watchConfigCerts(");
		String viewWatch = method(src, "public void watchAllCerts(");

		assertTrue(collectionWatch.contains("SecurityAuthenticator.OperationType.READ"),
				"control: the collection watch authorizes READ");
		assertTrue(viewWatch.contains("SecurityAuthenticator.OperationType.READ"),
				"the view watch authorizes the same operation as the collection watch");
	}

	private static String viewWatchMethod(String src) {
		return method(src, "public void watchAllCerts(");
	}

	/** The source text from a method's signature to the start of the next @Override. */
	private static String method(String src, String signature) {
		int start = src.indexOf(signature);
		assertTrue(start >= 0, "method not generated: " + signature);
		int end = src.indexOf("@Override", start);
		return end < 0 ? src.substring(start) : src.substring(start, end);
	}

	private static int countOccurrences(String src, String needle) {
		int count = 0;
		for (int i = src.indexOf(needle); i >= 0; i = src.indexOf(needle, i + needle.length())) {
			count++;
		}
		return count;
	}

	/** Runs discovery, boundary analysis and generation exactly as BackendServerMojo does. */
	private static String generateStateServer(Path tmp) throws IOException {
		Path protoDir = layout(tmp);

		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();

		List<BackendServiceInfo> services = BackendServiceDiscovery.discover(parser);
		assertEquals(1, services.size(), "the fixture state root must be discovered");

		BackendServiceInfo svc = services.get(0);
		SharedBackendInfo info = BoundaryAnalyzer.analyze(svc, parser);
		assertEquals(1, info.getViews().size(), "the fixture view must be discovered");

		GeneratorContext ctx = new GeneratorContext("com.example.backend", "com.example",
				"com.example.graphs", "", tmp.resolve("out"), protoDir, parser, List.of(FIXTURE_POLICY), "Copyright test");
		BackendServiceServerGenerator.generate(svc, info, ctx);

		return Files.readString(tmp.resolve("out/src/main/java/com/example/backend/services/fixtures/"
				+ "FixtureStateStateServiceServer.java"));
	}

	private static Path layout(Path tmp) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("services"));
		Files.writeString(protoDir.resolve("services/fixtures.proto"), PROTO);
		Files.writeString(tmp.resolve("registry.json"), "{\"name\": \"root\", \"children\": []}");
		return protoDir;
	}
}
