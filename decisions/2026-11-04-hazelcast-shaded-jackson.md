# Hazelcast 5.7.0's shaded Jackson: who can reach it, and what we wait for

Issue: kernel#44. Decision (Jody, hub, 2026-11-04): **option 1, mitigate and track**. Record the
reachability analysis here; bump `hazelcast.version` as soon as a Hazelcast release ships a patched
Jackson; keep #44 open until then. Removing Hazelcast from kernel stays on ROADMAP "Later", not
re-prioritized by this.

---

## What `kernel.jar` carries

`hazelcast-5.7.0.jar` (the latest on Maven Central, 2026-11-04) bundles **two** relocated Jackson
copies, and `kernel.jar` ships both. No BOM reaches either: kernel's own Jackson (`jackson2.version`
2.21.8, #13, for `com.styra:opa`) is a separate, unshaded copy.

| Copy | Relocated to | Version | HIGH (trivy 0.76.1, 2026-11-04) | First fixed |
|---|---|---|---|---|
| Jackson 2 core + databind | `com.hazelcast.shaded.com.fasterxml.jackson` | 2.21.2 | 8 (5 databind, 3 core) | 2.21.7 |
| Jackson 3 core + databind + jr | `com.hazelcast.shaded.tools.jackson` | 3.1.2 | the same 8 CVEs (5 databind, 3 core) | 3.1.7 |

The issue's scan listed only the Jackson 2 copy. `trivy rootfs --scanners vuln hazelcast-5.7.0.jar`
reports both: the 3.x copy is `tools.jackson.core:jackson-core` / `jackson-databind` 3.1.2, with
CVE-2026-54512, -54513, -68497, -91776, -91777 (databind) and CVE-2026-68494, -89407, -89425 (core),
plus 10 MEDIUM.

## Which copy Hazelcast actually calls

Read from the class files of `hazelcast-5.7.0.jar` (constant pools: every class outside the shaded
Jackson packages that names one of them):

- **Jackson 2.21.2 (core and databind): nothing.** No Hazelcast class, and no other shaded library in
  the jar, references `com.hazelcast.shaded.com.fasterxml.jackson`. The only mention outside its own
  packages is a string constant in the 3.x copy's `BeanUtil` (an error message naming the Joda
  module) and two `META-INF/services` files that only Jackson 2 itself would load. The copy is dead
  code in kernel: its databind advisories, the arbitrary-code-execution ones included, have no
  caller.
- **Jackson 3.1.2 databind: nothing either.** No class outside `shaded.tools.jackson.databind`
  references it.
- **Jackson 3.1.2 core (and jackson-jr): used.** The streaming parser backs Hazelcast's JSON
  support: `query.impl.getters.JsonGetter`/`AbstractJsonGetter` (predicates on a
  `HazelcastJsonValue`), `map.impl.JsonMetadataInitializer` and `recordstore.JsonMetadataMutationObserver`
  (metadata built when a `HazelcastJsonValue` is stored, under the default `MetadataPolicy`),
  `internal.serialization.impl.*NavigableJson*Adapter`, `json.internal.JsonSchemaHelper` (SQL JSON
  mappings) and `jet.json.JsonUtil` (with jackson-jr). Its three HIGH advisories are denial of service
  (CVE-2026-68494, async parser; CVE-2026-89407, regex backtracking; CVE-2026-89425, unbounded
  `StringBuilder` on a malformed token).

So the exposure that remains is **denial of service through the 3.x jackson-core, fed by a
`HazelcastJsonValue`**. It is not code execution.

## Who can feed it a `HazelcastJsonValue`

- **Kernel itself: never.** `server/src/main` stores protobuf values through `SerializerRegistry`;
  nothing in it names `HazelcastJsonValue`, SQL or Jet.
- **REST: off.** `ClusterServer.hazelcastConfig` sets `getRestConfig().setEnabled(false)`; kernel
  configures no `RestApiConfig`/`RestEndpointGroup`, so the legacy REST and memcache text endpoints
  keep their 5.x default, disabled.
- **The Hazelcast client protocol: open, on the member port.** Kernel uses no Hazelcast client
  (no `ClientConfig` or `HazelcastClient` in `server/src/main`), but it does not enable the advanced
  network config (`KernelMemberTransportTest` asserts it is off), and open-source Hazelcast then
  accepts client connections on the member port (`networkConfig.setPort(hzPort)`, 5001) beside
  member connections. A client that knows the cluster name can put a `HazelcastJsonValue` or run a
  JSON predicate.
- **The member protocol: open to any peer.** Member traffic is plain, unauthenticated Hazelcast
  (#24, `KernelMemberTransportTest`): anything that reaches the port and knows the cluster name
  joins, then reads and writes every map.

So the set that can reach the vulnerable parser is exactly the set that can already reach port 5001,
the same population #24 is about. Anyone in it already owns kernel's state (signing keys and
identity state included); a jackson-core DoS adds nothing they lack. The control is therefore the
network, not Hazelcast:

- The nodes have no public IPs, and the firewall admits no internet ingress (Jody, 2026-11-03). From
  outside the cluster nothing reaches 5001.
- Inside the cluster, "the member port takes kernel members only" holds as far as a NetworkPolicy on
  kernel's member port admits only kernel pods (the operator's; PROPOSALS, #24). This repository
  cannot show that policy; it is the operator's to keep, and the generated member port
  (tacplus-dev/tacplus#212, adopted by #24 once the floor reaches 2.6) replaces it with admission.

## What closes #44

Bump `hazelcast.version` to the first release whose bundled copies are **both** patched: Jackson 2
>= 2.21.7 **and** Jackson 3 >= 3.1.7. Checking only the 2.x copy, as the issue's criteria do, would
leave three reachable HIGH.

**`kernel.jar`'s `pom.properties` cannot show this.** The shade plugin keeps one
`META-INF/maven/<group>/<artifact>/pom.properties` per artifact, whichever jar it writes last.
Kernel bundles its own unshaded Jackson too (2.21.8 via opa, 3.1.8 via mcp), so in the 2026-11-04 build
`META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties` reads Hazelcast's 2.21.2 and
hides kernel's 2.21.8, and `META-INF/maven/tools.jackson.core/jackson-core/pom.properties` reads kernel's
3.1.8 and hides Hazelcast's 3.1.2. `trivy rootfs --scanners vuln server/target/kernel.jar` reads those
files, so it reports the 2.x copy and **does not see the 3.x copy at all**. A `kernel.jar` scan with no
Jackson HIGH therefore does not prove the bump. The version each copy was built as is in its
`PackageVersion` class, which the relocation keeps per copy:

```
for p in core/json databind/cfg; do
  for root in com/hazelcast/shaded/com/fasterxml/jackson com/hazelcast/shaded/tools/jackson; do
    printf '%s/%s ' $root $p
    unzip -p server/target/kernel.jar $root/$p/PackageVersion.class | strings | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+$' || echo absent
  done
done
```

On 5.7.0 it prints 2.21.2 for both `fasterxml` lines and 3.1.2 for both `tools` lines. Done when:

- each line prints 2.21.7 or later (`fasterxml`), 3.1.7 or later (`tools`), or `absent`;
- `trivy rootfs --scanners vuln` on the new `hazelcast-<version>.jar` itself (from `~/.m2`, where its own
  `pom.properties` are not overwritten) reports no Jackson HIGH, and the same scan of `kernel.jar` does
  too;
- `just gates` passes.

Until then, kernel ships both copies knowingly, on the reasoning above. If the reasoning stops
holding (kernel starts using `HazelcastJsonValue`, SQL or Jet, enables REST, or the member port gains
a path from outside the cluster), revisit this record.

## Since: #44 closed, #59 tracks it (2026-11-13)

#44 was closed by a closing keyword in the commit that landed this record, not by the bump. #59 now tracks the
wait (Jody, #59, 2026-11-13): it stays open until `kernel.jar` carries a Hazelcast with both copies patched, by the
checks above, which now close #59. Until then `security-exceptions.yaml` accepts exactly the 8 CVEs above, one
entry each, citing #59 and expiring **2026-12-14** (the batch on #48, 2026-11-14); on expiry the security gate
goes red and this decision is revisited. The bump removes the eight entries.

The build's security job finds them in three jars, 24 findings: `kernel.jar`, kernel-model's jar and codegen's,
each shading `hazelcast-5.7.0.jar` (codegen through kernel-model). kernel-model has no Jackson 2 core or databind
of its own (`mvn -pl tacplus dependency:tree`), so the 2.21.2 they read is Hazelcast's `pom.properties`. An entry
matches its CVE id anywhere, not Hazelcast's copy alone (looper-scan's format has no path): kernel's own Jackson
is patched against all 8, so today it accepts nothing else.

Risk rating (Jody, 2026-11-13, #59): **low**. "The kernel vulnerability is thru hazelcast which is only exposed to
other kernels." The scanners' severity stays as reported. The rating rests on the member port being kernel-only,
which #47 (member endpoint only, no client endpoint) and tacplus-dev/operator#30 (5001 admitted only from kernel
pods) enforce; until both land it describes the design, not the deployed state.
