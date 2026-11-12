# Proposals: kernel

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **<title>** (<date>, <issue/run link>): <what and why>
- **Say on `extra_claims` which keys kernel refuses** (2026-11-03, #41; waits on tacplus-dev/tacplus#205): #41
  refuses at mint every `extra_claims` key that names a kernel-set claim (`EXCLUDED_CLAIM_KEYS`, every
  `JwtPayloadType` name and the registered JWT claims, plus `tid`). The contract does not say so yet: any edit to
  `proto/vservices/proxy-policy.proto`, a comment included, fails `just gates` with "same path, different
  contents" until tacplus#205 is fixed, and so would the land. The comment to add under `extra_claims`:
  "A key may not name a claim kernel sets: every JwtPayloadType name (token_use, linked, namespace, sub, azp, exp,
  ...), the registered JWT claims (nbf, typ) and tid. Kernel refuses a result naming one with PERMISSION_DENIED;
  namespace is always the verified caller token's." `MintExternalToken`'s comment in `kernel.proto` could say the
  same.
- **Refuse a reserved `extra_claims` key when the proxy policy is loaded** (2026-11-03, #41): kernel refuses one at
  every mint, which is where it sees the result; it never loads the Rego. A policy is loaded by opa from what the
  deployment (operator) hands it, and `extra_claims` is computed per request, so a load-time check could only be a
  lint of the policy's literal keys (or a test evaluation) in whichever of those owns the policy. That is an opa or
  operator issue, once one of them is named its owner.
- **Decide `tid` on external tokens with kernel#32** (2026-11-03, #40): #32 stamps `tid` on user, session, service
  and device tokens. It does not mention the external token. #40 makes sure no policy can set `tid` there. Once
  `tid` is a `JwtPayloadType` name, `EXCLUDED_CLAIM_KEYS` stops it being forwarded from the user token, so an external
  token will carry no `tid` unless #32 derives one at mint, the way it derives the others.
- **A grammar for tenant names** (2026-11-02, #31): `CreateTenant` checks only that the leaf is non-empty and not
  tid-shaped (the boot seed adds "no `/`"), so upper case, dots or spaces pass, and the name becomes a SPIFFE path
  segment and a delegate key. One rule (say `^[a-z0-9][a-z0-9-]{0,62}$`, minus the tid shape), checked in
  `TenantIds` beside `rejectTidShapedName`, would keep create and seed from drifting apart.
- **Gates for a contract change before tacplus#205** (2026-11-02, #31): a dependency depends back on kernel, so
  `just gates` merges kernel's *published* proto beside the checkout's and refuses any `kernel.proto` change
  until it is on main. #28 and #31 got past it with a private tacplus home whose `.gitconfig` points
  `https://github.com/tacplus-dev/kernel.git` at a bare clone of the checkout's HEAD (`LOOPER_WORK` set to it, so
  the shared home is untouched). A `just gates-contract` recipe doing that would make it one command until
  tacplus#205 is fixed.
- **Refuse a foreign member-port audience when a workload key is registered** (2026-10-30, #30): `CreateWorkloadKey`
  accepts any `member:<x>` in `audiences`; the exchange refuses every one but `member:<the subject's own svc>`
  (and all of them for a workload subject). Refusing at registration would surface the mistake to the admin
  instead of to the workload at its first exchange.
- **Carry the member-port audience rule into the kernel rewrite** (2026-10-30, #30): the rewrite without Hazelcast
  must keep `member:<svc>` own-label-only and at most 5 minutes (`IdentityServiceImpl.assertOwnMemberAudience`,
  `MEMBER_TOKEN_MAX_TTL_SECONDS`); `MemberPortAudienceTest` is the contract to port with it. tacplus#212 and
  stratum#17 depend on it.
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
  #21 is the third: Guava 33.5.0-android via gRPC 1.79.0 (GHSA-xxph-c9ww-hj94), now pinned at 33.7.2-android.
  The check has to scan the built `kernel.jar`, not only the resolved tree (2026-11-04, nightly scan, #43, #44):
  Netty 4.1.127 shaded inside ratis-thirdparty (1 CRITICAL) and Jackson 2.21.2 shaded inside Hazelcast 5.7.0
  (8 HIGH) never appear in `mvn dependency:list`, so an OSV check of it passes. `trivy rootfs --scanners vuln
  server/target/kernel.jar` reads the bundled `META-INF/maven/*/pom.properties` and finds both. Hazelcast 5.7.0
  also shades Jackson 3.1.2 (`tools.jackson`, the same 8 HIGH), which a `kernel.jar` scan cannot see: the uber
  jar keeps one `pom.properties` per artifact, and kernel's own 3.1.8 overwrites Hazelcast's (and Hazelcast's
  2.21.2 overwrites kernel's 2.21.8). The check must scan each dependency jar before shading (or read each copy's
  `PackageVersion`), not the merged `pom.properties` (decisions/2026-11-04-hazelcast-shaded-jackson.md).
- **The build's security checks cover none of kernel's Java dependencies or bytecode yet** (2026-11-12, nightly
  scan; tacplus-dev/looper#49): the latest `security-kernel` report (eb21f7aa) lists OSV-Scanner as "Not analyzed"
  (`failed resolution for .../codegen/pom.xml: ... version Maven:com.github.tacplusdev.kernel:kern...`: it cannot
  resolve the reactor's own SNAPSHOT `kernel-model`, which is in no registry) and SpotBugs too ("the gates compiled no
  target/classes", although `mvn verify` writes `server/target/classes` and the other modules' classes). So the
  build's floor checks no Maven advisory and no Java bytecode for kernel, and only this nightly scan does (#57, #58).
  The fix is in looper-scan (resolve the reactor as `mvn dependency:list` does, or scan its output, and keep each
  module's `target/classes` in the gates job's `built/` artifact), not in this repository: a tacplus-dev/looper issue.
- **Refuse the Hazelcast client protocol on kernel's member port** (2026-11-04, #44): kernel uses no Hazelcast
  client, but with the advanced network config off, open-source Hazelcast accepts clients on 5001 beside members,
  so anything reaching the port can put a `HazelcastJsonValue` and drive the shaded jackson-core 3.1.2. An
  advanced network config with a member endpoint and no client endpoint would close that surface (not the
  member one, #24). Needs a test that a `HazelcastClient` is refused, and a check that nothing (tooling,
  debugging) connects as a client today.
- **Drop the ratis-thirdparty pin with the next Ratis bump** (2026-11-04, #43): `ratis-thirdparty.version` (1.1.1)
  in the root pom overrides the 1.1.0 Ratis 3.3.1 asks for, for its shaded Netty. Once a Ratis release asks for
  `>= 1.1.1`, remove the property and its `dependencyManagement` entry, or the pin will later hold thirdparty
  *below* what Ratis needs. `ShadedNettyVersionTest` keeps the shaded Netty at 4.1.137.Final or later either way.
  #42 (Raft over the member port) starts its Ratis pin from this one.
- **Rolling Ratis upgrades, before production** (2026-11-04, #43): #43 moved Ratis 3.2.1 to 3.3.1, and whether a
  mixed 3.2/3.3 group works was not tested: a deploy of it restarts the whole FencedLock group at once, accepted
  only because nothing is in production (Jody, #43). Before production, a Ratis bump needs a mixed-version group
  test (or a documented whole-group restart in the deploy). For tacplus-dev/roadmap's PRODUCTION.md, which the hub
  keeps.
- **Drop the Guava pin with the next gRPC bump** (2026-10-28, #21): `guava.version` in the root pom overrides
  what gRPC asks for. Once a gRPC release depends on Guava `>= 33.7.2` and kernel moves to it, remove the
  property and its `dependencyManagement` entry, or the pin will later hold Guava *below* what gRPC needs.
- **Drop the plexus-utils override on maven-shade-plugin** (2026-11-02, #33): the root `pluginManagement` gives shade
  plexus-utils 3.6.1 (GHSA-6fmv-xxpf-w3cw); shade 3.6.1 asks for 3.5.1 and 3.6.2 for 3.6.0. Once a shade release asks
  for `>= 3.6.1` and fleet-dev pins it, remove the override, or it will later hold plexus-utils *below* what shade
  needs. An advisory check of plugins has to read the plugin realm (`mvn -X package`, `Populating class realm
  plugin>...`): `dependency:resolve-plugins` reports the plugin pom's version, not the override. Not covered by #33:
  `codegen` (a Maven plugin) compiles against plexus-utils 3.5.1, `provided` through maven-plugin-api 3.9.9; at run time
  it gets whatever the running Maven core ships, so that one moves with the Maven version, not with a pin here.
- **Drop the other build-plugin plexus-utils and commons-io overrides** (2026-11-03, #36): the root `pluginManagement`
  also gives plexus-utils 4.0.3 to compiler 3.15.0, jar 3.5.0, resources 3.4.0, plugin-plugin 3.15.1 and antrun 3.2.0,
  plexus-utils 3.6.1 to protobuf-maven-plugin 0.6.1 and os-maven-plugin 1.7.1 (GHSA-6fmv-xxpf-w3cw), and commons-io
  2.21.0 to compiler (GHSA-78wr-2p64-hpwj). Same rule as shade's: remove each once a release of that plugin asks for
  a fixed version and fleet-dev pins it. protobuf-maven-plugin and os-maven-plugin have no newer release, so theirs
  stay. os-maven-plugin is now a plugin with `<extensions>true</extensions>` rather than a build `<extension>`,
  because only a plugin takes `<dependencies>`; server declares it but nothing there reads `os.detected.*`, so it
  could go from server altogether. build-helper (3.6.2) and exec (3.6.4) moved to fleet-dev's pins and need none.
- **Drop the plexus-archiver overrides** (2026-11-03, #37): the root `pluginManagement` gives plexus-archiver 4.15.0
  to jar 3.5.0 (which asks for 4.10.4) and plugin-plugin 3.15.1 (4.10.0), because those load aircompressor 0.27
  (GHSA-vx9q-rhv9-3jvg, HIGH) and 4.15.0 no longer depends on aircompressor. Remove each once a release of that
  plugin asks for plexus-archiver 4.15.0 or later (the fixed lines are 4.0.0-beta-2 today) and fleet-dev pins it.
  With the override, `kernel.jar` and the other module jars have the same entries with the same CRCs as without.
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
  #23 closed the service-token half: a tenant-owned service's subject names its tid, and a tombstoned tid is refused.
  User and session tokens still name the tenant only by its name.
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
  #20 needed two new fields (`Person.last_signed_in_at_ms`, `Config.xid_ageing_period_seconds`), so it could not
  take them out. It ran the gates before the push with a private tacplus HOME whose `.gitconfig` points
  `https://github.com/tacplus-dev/kernel.git` at a local clone holding the change (`url.<clone>.insteadOf`;
  `LOOPER_WORK=<dir> just gates`), and ran them plain on main after it. That works for any contract change until
  tacplus handles it.
- **The people service takes over XID ageing** (2026-10-27, #20): `IdentityGraph.ageOut` and the sign-in time that
  `resolveOrCreate` and `mergePeople` record are part of the graph's contract now. tacplus-dev/people#1 should carry
  both, and `Person.last_signed_in_at_ms` with them, so the sweep (`XidAgeing`) keeps working when the graph moves.
- **Check that no generated service reads the caller's tenant from the SAN** (2026-10-28, #23): a tenant-owned
  instance's SPIFFE ID now names its tenant's tid (`/tenants/<tid>/services/<svc>`), while its token's `namespace`
  claim keeps the name. Kernel's own generated `SecurityAuthenticator` took a service caller's namespace from the
  subject and had to be changed (codegen `callerNamespace`); the Java chassis `Authorizer` reads the claim, and
  `ServiceConnection` matches peers on the service path only. The Go and Rust chassis, the generated policy
  (`target_namespace_field`, tacplus-dev/tacplus#170) and any hand-written service were not checked here. A tacplus
  issue should check that each takes the caller's tenant from the `namespace` claim, never from
  `Spiffe.namespaceFromSpiffe` of the peer's SAN or `sub`.
- **Carry the tid subject into `kernel.proto`'s comments** (2026-10-28, #23): the `Delegate` and `tenant_namespace`
  comments still say a tenant-owned instance is `spiffe://<td>/tenants/<tenant>/services/<name>` and takes its
  namespace claim from it. #23 left `kernel.proto` alone because any edit fails the gates before the push (the #19
  proposal above); IDENTITY.md records the change. The next contract change should carry the comment fix.
  Done in #28 (the `Delegate` and `tenant_namespace` comments name the tid).
- **Kernel's Hazelcast members admit any peer: give them the member admission Stratum gets** (2026-10-29, #24):
  kernel's member traffic is plain, unauthenticated Hazelcast (`KernelMemberTransportTest`). Anything that reaches
  the member port (5001) and knows the cluster name joins, and reads and writes every map, signing keys and
  identity state included. Open-source Hazelcast has no member TLS. Until #24, the SeaBeam
  `hazelcast.internal.override.enterprise` flag hid this: it got an `SSLConfig` past the Enterprise check, and the
  open-source pipeline then ignored it. The `SSLConfig` was also only in the unused `HazelcastFactory`. The
  admission design being settled for Stratum (tacplus-dev/stratum#17: member mTLS with a root of trust per tenant
  on Jody's direction, falling back to option A, an in-process TLS forwarder, because open source can't do it)
  should cover kernel's members too. Until then, a NetworkPolicy on kernel's member port (operator) would admit
  only kernel pods. ROADMAP Later removes Hazelcast from kernel; this is the exposure until then.
  Settled 2026-10-29 (Jody, on #24): the generated member port (tacplus-dev/tacplus#212: server TLS plus
  `member:<svc>` tokens, which kernel mints since #30). It is on tacplus main but in no release yet (2.5.x lacks
  `option (spec.member_port)`), so #24 adopts it once the floor can move to 2.6 (tacplus-dev/tacplus#213). The
  port may move onto gRPC first (tacplus-dev/tacplus#259); the adoption is the same.
  Superseded 2026-11-06 (Jody, on #24, closed as done): kernel's Hazelcast is not wired onto the 2.6 loopback member
  port, which is planned to go away. Its real protection is #42 on tacplus-dev/tacplus#259's gRPC member port, or
  Hazelcast leaving kernel. Meanwhile there are no public IPs, and the interim NetworkPolicy (tacplus-dev/operator#20)
  selects kernel. That policy limits the Raft port to kernel pods but leaves 5001 open to the deployment's own
  namespaces. Restricting 5001 too is the one-line change operator#20 held back until it is verified on a live
  kernel cluster. PRODUCTION.md's security review (tacplus-dev/roadmap) should list this traffic.
- **`kernel.proto` claims Hazelcast mTLS that does not exist** (2026-10-29, #24): the `tls` and `cluster_ca`
  comments say they are used for "Hazelcast mTLS" and its trust, and the `option (spec.smb)` comment says kernel
  uses its SMB member cert "for Hazelcast peer mTLS". Kernel has never configured member TLS that works, and
  nothing implements `Handler.newSmbCert`. Fix the comments with the next contract change (the #19 proposal), or
  with the admission work above. Done in #28 (`tls`, `cluster_ca` and `option (spec.smb)` say member traffic is plain).
- **A cluster-wide replay set for client-minted proofs** (2026-10-30, #28): `seenProofJtis` is per kernel node, so a
  captured assertion can be replayed once per other node inside its window. Workload keys widen that window from 60s
  to 300s (the issue's cap). A cluster-wide TTL map (or the FencedLock) would make "a `jti` is refused on reuse" hold
  across nodes, for cred_pair, device and workload-key proofs alike.
- **`aud` on `MintClientTokenRequest`, in tacplus** (2026-10-30, #28): the request (tacplus's `sys/tokenrequest.proto`)
  has no audience, so a workload key gets a kernel access token from `MintClientToken` and then exchanges it via
  `MintToken` for each service token: two calls where one would do. An `aud` / `service_auds` on the request would let
  `MintClientToken` return the service tokens directly, as `MintToken` batches them.
- **Workload-key use is a config write** (2026-10-30, #28): `last_used_at` lives in the tenant's config, as the issue
  asks, so recording it replaces the tenant's whole config entry (at most once an hour per key). A mint racing an
  `UpdateTenantConfig` on another node can lose one write. If that ever matters, compare-and-set on the entry, or
  keep `last_used_at` in its own row keyed by key id.
- **Workload keys in the CLI and the gateway** (2026-10-30, #28): `CreateWorkloadKey`, `ListWorkloadKeys` and
  `RevokeWorkloadKey` are new external `TenantAdmin` RPCs. Whatever fronts `TenantAdmin` and `MintClientToken` for
  external clients (the gateway's C2S routes, an admin CLI) should carry them; docs/workload-keys.md uses `grpcurl`.
- **Kernel issues its own serving certificate** (2026-10-30, #29): `Kernel.Config.tls` (field 11, `assert_required`)
  is signed by the operator with the cluster CA key at deploy time (`Pki.NodeTls`, operator `deploycrypto.go`). Kernel
  could issue it to itself from its node intermediate (`signing_ca`), the way it issues every service's certificate,
  which removes one more deploy-time use of the cluster CA key. It changes a public config contract (`tls` optional or
  gone) and the operator must stop minting `NodeTls`, so it needs its own roadmap entry. Kept out of #29 (Jody's answer
  on the issue): kmaker's retirement does not need it.
- **Pin the default-lifecycle Maven plugins** (2026-11-02, nightly scan): the root pom pins compiler, shade, exec,
  antrun and build-helper, but clean (3.2.0), resources, jar, surefire (3.2.5), install, deploy and site (3.12.1) come
  from whichever Maven runs the build (3.9.16 on the scanner). So their versions, and their advisory surface, change with
  the runner, not with a commit here. An OSV check of `mvn dependency:resolve-plugins` finds advisories only on those
  build-time classpaths, none on what ships in `kernel.jar`: surefire 3.2.5 brings guava 16.0.1 (GHSA-xxph-c9ww-hj94) and
  maven-core 3.2.5, and site 3.12.1 brings Jetty 9.4.46, velocity 1.7, dom4j 1.1 and jsoup 1.10.2 (site is not
  part of `verify`). Pinning current releases in `pluginManagement` makes the build reproducible and lets the advisory check
  above cover plugins too.
- **ROADMAP "Now" names floor 2.4; the floor in force is 2.6** (2026-11-06, #46): Jody's decision on #46 asks for
  "Now" to name the floor in force, but a looper may not push a commit touching ROADMAP.md. The line to change:
  "Unreleased; tacplus floor 2.4." becomes "Unreleased; tacplus floor 2.6 (2.6.1 pinned in tacplus.lock)."
- **Make `just verify` a gate again, in the pinned build image** (2026-11-06, #46): the justfile says `verify` is
  not a gate because "the compiler image has no mvn". Since #46 tacplus runs in the build image tacplus.lock pins
  (tools/tacplus.sh), which carries every toolchain; whether it resolves the proofs' classpath there is untried. 2.6
  also made formal verification no gate in tacplus itself (tacplus#275), so this is a choice, not a fix.

## Promoted / declined
- **Tenant-owned service identity carries the tid** (2026-10-28, #23): promoted 2026-10-28 (kernel ROADMAP.md, Next),
  built in #23 as proposed: the subject names the tid, and the namespace claim, delegate keys and grants stay on
  the name through `TenantIds.namespaceOfSubject`.
