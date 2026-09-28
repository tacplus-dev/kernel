package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The hand-rolled line parser only understood inline {@code rw:}/{@code ro:}/
 * {@code exec:} lists. A block sequence —
 * <pre>
 * rw:
 *   - "service:snoopy"
 * </pre>
 * left {@code rw:} to the inline parser, which returned an empty list, and the
 * {@code - "service:snoopy"} lines that followed were skipped because they did not
 * start with {@code - name:}. The result was a policy with no principals at all,
 * emitted with no warning. That fails closed at run time — nobody is authorized —
 * but it fails closed invisibly, which is how a format change ships unnoticed.
 */
class SecurityPolicyParserTest {

	@Test
	void blockSequenceListsAreParsed(@TempDir Path tmp) throws IOException {
		List<AccessPolicy> policies = parse(tmp, """
				policies:
				  - name: "ClusterState"
				    rw:
				      - "service:snoopy"
				    ro:
				      - "service:oauth"
				      - "service:gateway"
				    exec: []
				""");

		assertEquals(1, policies.size());
		AccessPolicy p = policies.get(0);
		assertEquals("ClusterState", p.name());
		assertEquals(List.of("service:snoopy"), p.rw(),
				"a block-sequence rw list used to parse as no principals at all");
		assertEquals(List.of("service:oauth", "service:gateway"), p.ro());
		assertEquals(List.of(), p.exec());
	}

	@Test
	void inlineListsStillParse(@TempDir Path tmp) throws IOException {
		List<AccessPolicy> policies = parse(tmp, """
				policies:
				  - name: "ClusterState"
				    rw: ["service:snoopy"]
				    ro: ["service:oauth", "service:gateway"]
				    exec: []
				  - name: "IdentityState"
				    rw: ["service:kernel"]
				    ro: []
				    exec: []
				""");

		assertEquals(2, policies.size());
		assertEquals(List.of("service:snoopy"), policies.get(0).rw());
		assertEquals(List.of("service:oauth", "service:gateway"), policies.get(0).ro());
		assertEquals("IdentityState", policies.get(1).name());
		assertEquals(List.of("service:kernel"), policies.get(1).rw());
	}

	@Test
	void bothSpellingsMayBeMixedInOneFile(@TempDir Path tmp) throws IOException {
		List<AccessPolicy> policies = parse(tmp, """
				policies:
				  - name: "ClusterState"
				    rw:
				      - "service:snoopy"
				    ro: ["service:oauth"]
				    exec: []
				  - name: "IdentityState"
				    rw: ["service:kernel"]
				    ro:
				      - "service:gateway"
				    exec: []
				""");

		assertEquals(List.of("service:snoopy"), policies.get(0).rw());
		assertEquals(List.of("service:oauth"), policies.get(0).ro());
		assertEquals(List.of("service:kernel"), policies.get(1).rw());
		assertEquals(List.of("service:gateway"), policies.get(1).ro());
	}

	/** A spelling the parser does not understand must fail the build, not parse as empty. */
	@Test
	void anUnrecognizedLineIsAHardError(@TempDir Path tmp) {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse(tmp, """
				policies:
				  - name: "ClusterState"
				    rw: ["service:snoopy"]
				    ro: []
				    exec: []
				    admin: ["service:root"]
				"""));

		assertTrue(e.getMessage().contains("admin:"),
				"the failure must quote the line it could not classify: " + e.getMessage());
	}

	/** A list item with no list open is a structural miss, not something to drop silently. */
	@Test
	void aStrayListItemIsAHardError(@TempDir Path tmp) {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse(tmp, """
				policies:
				  - "service:snoopy"
				"""));

		assertTrue(e.getMessage().contains("service:snoopy"), e.getMessage());
	}

	/**
	 * A policy whose principal lists were never parsed is indistinguishable, once
	 * emitted, from one that authorizes nobody on purpose. Require the lists to be
	 * written out so the difference is visible at build time.
	 */
	@Test
	void aPolicyWithNoListsAtAllIsAHardError(@TempDir Path tmp) {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> parse(tmp, """
				policies:
				  - name: "ClusterState"
				"""));

		assertTrue(e.getMessage().contains("ClusterState"),
				"the failure must name the policy: " + e.getMessage());
	}

	/** An explicitly empty policy is intentional and must still parse. */
	@Test
	void anExplicitlyEmptyPolicyIsAccepted(@TempDir Path tmp) throws IOException {
		List<AccessPolicy> policies = parse(tmp, """
				policies:
				  - name: "ClusterState"
				    rw: []
				    ro: []
				    exec: []
				""");

		assertEquals(1, policies.size());
		assertEquals(List.of(), policies.get(0).rw());
	}

	@Test
	void trailingCommentsAreNotPartOfAValue(@TempDir Path tmp) throws IOException {
		List<AccessPolicy> policies = parse(tmp, """
				# the whole file is machine-generated
				policies:
				  - name: ClusterState   # unquoted, with a note
				    rw:
				      - service:snoopy   # the owner
				    ro: []
				    exec: []
				""");

		assertEquals("ClusterState", policies.get(0).name(),
				"an unquoted name used to carry its trailing comment verbatim");
		assertEquals(List.of("service:snoopy"), policies.get(0).rw());
	}

	private static List<AccessPolicy> parse(Path tmp, String yaml) throws IOException {
		Path file = tmp.resolve("backenddb.yaml");
		Files.writeString(file, yaml);
		return SecurityPolicyParser.parse(file);
	}
}
