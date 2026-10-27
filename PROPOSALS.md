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
- **A deleted tenant's old tokens must not reach a new tenant of the same name** (2026-10-27, #19): DeleteTenant
  now refuses every mint into the deleted tenant, but the refusal ends when a tenant of the same name is created:
  tokens, grants and delegates name the tenant by name, not by tid (#3 left SPIFFE paths and grants on the name).
  A refresh token (24h) or offline token (90 days) issued in the old tenant would then mint in the new one. Either
  name the tid in token namespaces and SPIFFE paths, or refuse a token whose `iat` predates the latest tombstone
  of its namespace (the `TenantIdRow.tombstoned_at_ms` is already there).
- **The operator drops a deleted tenant's delegates and grants** (2026-10-27, #19): kernel refuses every mint
  through a deleted tenant's `Config.delegates` (and their Kubernetes service-account matchers) and revokes its
  `Config.grants`, but both are the deployment's config and stay in it. The decision's flow (kernel, then
  operator, then nsproxy) should end with the operator no longer rendering them. That is an operator issue.
- **Index tombstoned tids by namespace if the mint check shows up in profiles** (2026-10-27, #19):
  `TenantIds.deletedTenantOf` costs one keyed read per namespace segment when the tenant and project records exist,
  but reads every `TenantIdRow` (`ConfigMap.proto()`) on each mint for a namespace kernel has no record of. Those
  are deleted tenants, and tenants the deployment names only in its delegates. A namespace-keyed view of the
  tombstones would make that one read too.
- **`just gates` fails on any change to `proto/services/kernel.proto`** (2026-10-27, #19): `tacplus build`
  resolves kernel's proto again as a dependency of a dependency (`tacplus-dev/kernel` at `latest`, which is
  origin/main) and refuses the merge: `proto file "services/kernel.proto" conflicts between sources
  ".../checkout/proto" and "/tmp/tacplus-dep-…": same path, different contents`. A comment-only edit is enough.
  So no kernel contract change can pass the gates before it is pushed, which rule 5 forbids. #19 took its two
  proto comment edits back out (PersonMembership's no-delete rule and DeleteTenant's scope; IDENTITY.md says
  both). tacplus could let the local `src` win over a dependency's copy of the same repository, or skip a
  dependency whose repository is the one being built.

## Promoted / declined
