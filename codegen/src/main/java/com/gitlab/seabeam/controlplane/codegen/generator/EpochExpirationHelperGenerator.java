package com.gitlab.seabeam.controlplane.codegen.generator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.gitlab.seabeam.controlplane.codegen.model.BackendServiceInfo;
import com.gitlab.seabeam.controlplane.codegen.model.SharedBackendInfo;
import com.gitlab.seabeam.controlplane.codegen.model.SharedBoundary;

/**
 * Generates EpochExpirationHelper.java — a type-safe helper that extracts
 * epoch expiration timestamps from protobuf values stored in maps that have
 * an epoch_expiration-annotated field.
 *
 * <p>
 * The generated class provides:
 * <ul>
 * <li>{@code getEpochExpiration(mapName, value)} — returns epoch seconds or
 * 0</li>
 * <li>{@code isExpired(mapName, value)} — true if the entry has expired</li>
 * <li>{@code computeTtlSeconds(mapName, value)} — remaining TTL or -1 if no
 * epoch field</li>
 * </ul>
 *
 * <p>
 * Used wherever a boundary's entries are reinstated after a restart — to skip
 * entries that expired while the node was down, and to apply TTL-aware puts.
 */
public class EpochExpirationHelperGenerator {

	/**
	 * Collects all boundaries with epoch_expiration across all services and
	 * generates a single helper class.
	 */
	public static void generate(Map<BackendServiceInfo, SharedBackendInfo> infoMap,
			GeneratorContext ctx) throws IOException {
		// Collect (mapName → typeRef, getter, importStmt) for all epoch boundaries
		List<EpochEntry> entries = new ArrayList<>();

		for (var entry : infoMap.entrySet()) {
			BackendServiceInfo svc = entry.getKey();
			SharedBackendInfo info = entry.getValue();
			String outerClassName = ctx.getOuterClassName(svc);
			String backendClassName = ctx.getFullPackage(svc) + "." + info.getClassName();

			for (SharedBoundary b : info.getCollections()) {
				if (b.getEpochExpirationGetter() != null) {
					String mapNameExpr = backendClassName + ".class.getName() + \":" + b.getMapName() + "\"";
					String typeRef;
					String importStmt;
					if (b.isCrossPackage()) {
						importStmt = ctx.getCrossPackageImport(b);
						typeRef = ctx.getQualifiedType(outerClassName, b);
					} else {
						String fullOuter = ctx.getTypesPackage(svc) + "." + outerClassName;
						importStmt = "import " + fullOuter + ";\n";
						typeRef = outerClassName + "." + b.getTypeName();
					}
					entries.add(new EpochEntry(mapNameExpr, typeRef, b.getEpochExpirationGetter(), importStmt));
				}
			}
		}

		String pkg = ctx.getJavaPackageBase();

		StringBuilder sb = new StringBuilder();
		sb.append(GeneratorContext.header("epoch_expiration"));
		sb.append("package ").append(pkg).append(";\n\n");
		sb.append("import com.google.protobuf.MessageLite;\n\n");

		// Import outer classes for types used in epoch entries
		Set<String> imports = new TreeSet<>();
		for (EpochEntry e : entries) {
			if (!e.importStmt.isEmpty()) {
				imports.add(e.importStmt.trim());
			}
		}
		for (String imp : imports) {
			sb.append(imp).append("\n");
		}
		sb.append("\n");

		sb.append("/**\n");
		sb.append(" * Generated helper for extracting epoch expiration timestamps from\n");
		sb.append(" * protobuf values in maps annotated with {@code epoch_expiration}.\n");
		sb.append(" *\n");
		sb.append(" * <p>Used wherever a boundary's entries are reinstated after a restart —\n");
		sb.append(" * to skip entries that expired while the node was down, and to compute\n");
		sb.append(" * their remaining TTLs.\n");
		sb.append(" */\n");
		sb.append("public final class EpochExpirationHelper {\n\n");
		sb.append("    private EpochExpirationHelper() {}\n\n");

		// Build map name constants
		for (int i = 0; i < entries.size(); i++) {
			EpochEntry e = entries.get(i);
			sb.append("    private static final String EPOCH_MAP_").append(i).append(" = ").append(e.mapNameExpr)
					.append(";\n");
		}
		sb.append("\n");

		// getEpochExpiration
		sb.append("    /**\n");
		sb.append("     * Returns the epoch expiration (seconds since Unix epoch) for the given\n");
		sb.append("     * map entry, or 0 if the map does not have an epoch_expiration field.\n");
		sb.append("     */\n");
		sb.append("    public static long getEpochExpiration(String mapName, MessageLite value) {\n");
		if (entries.isEmpty()) {
			sb.append("        return 0;\n");
		} else {
			for (int i = 0; i < entries.size(); i++) {
				EpochEntry e = entries.get(i);
				// Use the simple type name (last segment) for instanceof
				String condition = i == 0 ? "if" : "} else if";
				sb.append("        ").append(condition).append(" (EPOCH_MAP_").append(i)
						.append(".equals(mapName) && value instanceof ").append(e.typeRef).append(" v").append(i)
						.append(") {\n");
				sb.append("            return v").append(i).append(".").append(e.getter).append("();\n");
			}
			sb.append("        }\n");
			sb.append("        return 0;\n");
		}
		sb.append("    }\n\n");

		// isExpired
		sb.append("    /**\n");
		sb.append("     * Returns true if the entry has an epoch_expiration field and its\n");
		sb.append("     * expiration timestamp is in the past.\n");
		sb.append("     */\n");
		sb.append("    public static boolean isExpired(String mapName, MessageLite value) {\n");
		sb.append("        long epoch = getEpochExpiration(mapName, value);\n");
		sb.append("        return epoch > 0 && epoch <= System.currentTimeMillis() / 1000;\n");
		sb.append("    }\n\n");

		// computeTtlSeconds
		sb.append("    /**\n");
		sb.append("     * Computes the remaining TTL in seconds for the entry. Returns -1 if the\n");
		sb.append("     * map does not have an epoch_expiration field, or 0 if already expired.\n");
		sb.append("     */\n");
		sb.append("    public static long computeTtlSeconds(String mapName, MessageLite value) {\n");
		sb.append("        long epoch = getEpochExpiration(mapName, value);\n");
		sb.append("        if (epoch <= 0) return -1;\n");
		sb.append("        long ttl = epoch - System.currentTimeMillis() / 1000;\n");
		sb.append("        return Math.max(ttl, 0);\n");
		sb.append("    }\n\n");

		// hasEpochExpiration
		sb.append("    /**\n");
		sb.append("     * Returns true if the given map name has an epoch_expiration field.\n");
		sb.append("     */\n");
		sb.append("    public static boolean hasEpochExpiration(String mapName) {\n");
		if (entries.isEmpty()) {
			sb.append("        return false;\n");
		} else {
			sb.append("        return ");
			for (int i = 0; i < entries.size(); i++) {
				if (i > 0)
					sb.append("\n            || ");
				sb.append("EPOCH_MAP_").append(i).append(".equals(mapName)");
			}
			sb.append(";\n");
		}
		sb.append("    }\n");

		sb.append("}\n");

		Path dir = ctx.getOutputDir().resolve("src/main/java/" + pkg.replace('.', '/'));
		Files.createDirectories(dir);
		Files.writeString(dir.resolve("EpochExpirationHelper.java"), sb.toString());
	}

	private static class EpochEntry {
		final String mapNameExpr;
		final String typeRef;
		final String getter;
		final String importStmt;

		EpochEntry(String mapNameExpr, String typeRef, String getter, String importStmt) {
			this.mapNameExpr = mapNameExpr;
			this.typeRef = typeRef;
			this.getter = getter;
			this.importStmt = importStmt;
		}
	}
}
