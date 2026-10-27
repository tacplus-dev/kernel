package com.github.tacplusdev.kernel.codegen;

import com.github.tacplusdev.kernel.codegen.generator.GeneratorContext;
import com.github.tacplusdev.kernel.codegen.generator.SecurityAuthenticatorGenerator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
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

	/**
	 * The header tells an agent where the generator lives: this repository, not
	 * the upstream GitLab project it was copied from, which tacplus-dev cannot
	 * assume exists.
	 */
	@Test
	void generatedFileNamesThisRepositoryAsTheGenerator() {
		String header = new GeneratorContext("com.example.backend", "com.example",
				"com.example.graphs", "", Path.of("out"), Path.of("proto"), null,
				List.of(), Map.of(), List.of("kernel"), "Copyright\n").header("x.proto");

		assertTrue(header.contains("// github.com/tacplus-dev/kernel/codegen\n"), header);
		assertFalse(header.contains("gitlab.com"), header);
	}

	@Test
	void aTacplusYamlWithoutAHeaderFailsInsteadOfStampingNothing(@TempDir Path tmp) throws IOException {
		Path yaml = Files.writeString(tmp.resolve("tacplus.yaml"), "language: java\n");

		IOException e = assertThrows(IOException.class,
				() -> TacplusConfig.header(yaml.toFile()));
		assertEquals(yaml + " declares no header:", e.getMessage());
	}
}
