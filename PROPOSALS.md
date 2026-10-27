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
- **Drop Javalin from the generated Java chassis, in tacplus** (2026-10-27, #16): kernel moved Javalin
  6.7.0 -> 7.2.4 because Jetty 11 has HIGH advisories and no fixed 11.x on Maven Central. But nothing
  serves HTTP through it: the tacplus-generated `GrpcServer` declares a `Javalin httpServer` that is never
  assigned (only `stop()`ped if non-null), and `ServiceImplementation.registerRESTEndpoints(Javalin, …)` is
  a no-op in kernel's `ServiceManager`. Javalin and Jetty are dead weight on every Java service's
  classpath and its advisory surface. tacplus could drop them from the Java generator (or, while REST
  endpoints are still planned, at least emit Javalin 7 for every Java service, not just kernel).
- **A start check for the release image** (2026-10-27, #17): this repository has no workflow that builds
  `Dockerfile` (the issue's `package-arm64` job is not here, only `planning-files.yml`), so a base image
  move is checked only by hand. #17 did it with a stand-in launcher and a generated config baked into a
  derived image; booting the kernel to "Kernel node ready" in CI would catch a base that breaks it.
- **Ratis JMX bean fails to register** (2026-10-27, #17): on boot Ratis logs
  `ERROR JmxRegister ... MalformedObjectNameException: Invalid character ':'`, because the Raft peer id is
  `host:port`. Harmless (the node still becomes leader and ready) and the same on java21-debian12 and
  java25-debian13, but an ERROR on every boot is noise: quote the id, or a peer id without `:`.
- **Raise `maven.compiler.release` to 25, platform-wide** (2026-10-27, #17): the image now runs Java 25;
  the compile target stays 21 because tacplus may set the Java line for every service. Decide it there.

## Promoted / declined
