package com.gitlab.seabeam.controlplane.codegen;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A proto the parser cannot read used to be swallowed by an empty
 * {@code catch (IOException e)} with no log and no rethrow. Codegen then ran
 * against a partial model: the services in that file got no server, and its
 * {@code auth_disabled} exemptions and security policies simply were not there.
 * The build succeeded and the hole showed up at run time — a missing RPC, or a
 * policy that silently never applied.
 *
 * <p>Fail closed instead, the same stance {@code BackendServiceServerGenerator.graphKey}
 * takes for a state root with no policy.
 */
class ProtoDescriptorParserUnreadableProtoTest {

	private static final String GOOD_PROTO = """
			syntax = "proto3";
			package fixtures;
			option java_package = "com.example.fixtures";

			service Good {
			  rpc Ping(PingRequest) returns (PingResponse);
			}
			""";

	@Test
	void anUnreadableProtoFailsTheBuild(@TempDir Path tmp) throws IOException {
		Path protoDir = layout(tmp);
		// A directory named *.proto passes the walk's name filter and then fails the
		// read — an unreadable path that does not depend on the build user's uid.
		Files.createDirectories(protoDir.resolve("services/broken.proto"));

		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		UncheckedIOException e = assertThrows(UncheckedIOException.class, parser::parseAll);

		assertTrue(e.getMessage().contains("broken.proto"),
				"the failure must name the file that could not be read: " + e.getMessage());
	}

	@Test
	void aReadableProtoStillParses(@TempDir Path tmp) throws IOException {
		Path protoDir = layout(tmp);

		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();

		assertEquals(1, parser.getAllFiles().size(), "control: the well-formed proto is parsed");
	}

	private static Path layout(Path tmp) throws IOException {
		Path protoDir = tmp.resolve("proto-annotated");
		Files.createDirectories(protoDir.resolve("services"));
		Files.writeString(protoDir.resolve("services/good.proto"), GOOD_PROTO);
		Files.writeString(tmp.resolve("registry.json"), "{\"name\": \"root\", \"children\": []}");
		return protoDir;
	}
}
