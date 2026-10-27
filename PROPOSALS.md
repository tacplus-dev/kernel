# Proposals: kernel

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **<title>** (<date>, <issue/run link>): <what and why>
- **One source for Java dependency versions** (2026-10-27, #12): `proto/dependencies.yaml` `lang.java.dependencies`
  and the poms (root `pom.xml`, `tacplus/pom.xml`) both state versions, and `tacplus build` on 2.4 writes
  neither pom, so the two drift unless every bump edits both by hand (#12 did). Either drop the Java list
  from `dependencies.yaml`, or have the poms take every version from it (or check in `just gates` that
  they agree).
- **An advisory check in the gates or CI** (2026-10-27, #12): Bouncy Castle 1.80 carried two CRITICAL
  advisories until a nightly scan found them. An OSV check of the resolved `mvn dependency:list` (or the
  OWASP dependency-check plugin) in CI would fail the build when it happens, not the next scan.
  #13 is the same story for transitive Jackson (2.17.0 via opa, 3.1.4 via mcp), now pinned by BOM in the
  root pom: a pin only holds until the next advisory, so the check is what keeps it honest.

## Promoted / declined
