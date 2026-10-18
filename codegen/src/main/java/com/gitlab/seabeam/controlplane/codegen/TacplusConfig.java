package com.gitlab.seabeam.controlplane.codegen;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

/**
 * Reads the service's tacplus.yaml. Its {@code header:} is the one source of the
 * copyright header: tacplus stamps it on everything it generates, and the
 * backend codegen stamps the same text rather than keeping a second copy.
 */
public final class TacplusConfig {

	private TacplusConfig() {
	}

	/**
	 * Returns the {@code header:} value of the given tacplus.yaml.
	 *
	 * @throws IOException if the file cannot be read or declares no header
	 */
	public static String header(File tacplusYaml) throws IOException {
		Map<String, Object> config = new Yaml().load(Files.readString(tacplusYaml.toPath()));
		Object header = config == null ? null : config.get("header");
		if (!(header instanceof String text) || text.isBlank()) {
			throw new IOException(tacplusYaml + " declares no header:");
		}
		return text;
	}
}
