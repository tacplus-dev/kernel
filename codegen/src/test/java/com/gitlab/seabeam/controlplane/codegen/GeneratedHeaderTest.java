package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.generator.GeneratorContext;
import com.gitlab.seabeam.controlplane.codegen.generator.SecurityAuthenticatorGenerator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The backend codegen stamped its own hard-coded copyright line, which drifted
 * from the one tacplus stamps once the company name changed. The header now
 * comes from the service's tacplus.yaml {@code header:}, the same source
 * tacplus reads, so the two cannot disagree.
 */
class GeneratedHeaderTest {

	/** kernel's own tacplus.yaml, which BackendServerMojo reads by default. */
	private static final File KERNEL_TACPLUS_YAML = new File("../tacplus.yaml");

	@Test
	void generatedFileStartsWithTheServiceTacplusYamlHeader(@TempDir Path tmp) throws IOException {
		String header = TacplusConfig.header(KERNEL_TACPLUS_YAML);

		Path protoDir = Files.createDirectories(tmp.resolve("proto-annotated"));
		Files.writeString(tmp.resolve("registry.json"), "{\"name\": \"root\", \"children\": []}");
		ProtoDescriptorParser parser = new ProtoDescriptorParser(protoDir);
		parser.parseAll();
		GeneratorContext ctx = new GeneratorContext("com.example.backend", "com.example",
				"com.example.graphs", "", tmp.resolve("out"), protoDir, parser,
				List.of(), Map.of(), List.of("kernel"), header);
		SecurityAuthenticatorGenerator.generate(ctx);

		Path generated = tmp.resolve("out/src/main/java/com/example/backend/SecurityAuthenticator.java");
		String firstLine = Files.readAllLines(generated).get(0);
		assertEquals("// " + header.strip().lines().findFirst().orElseThrow(), firstLine);
	}

	@Test
	void aTacplusYamlWithoutAHeaderFailsInsteadOfStampingNothing(@TempDir Path tmp) throws IOException {
		Path yaml = Files.writeString(tmp.resolve("tacplus.yaml"), "language: java\n");

		IOException e = assertThrows(IOException.class,
				() -> TacplusConfig.header(yaml.toFile()));
		assertEquals(yaml + " declares no header:", e.getMessage());
	}
}
