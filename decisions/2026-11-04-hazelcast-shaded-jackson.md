# Hazelcast 5.7.0's shaded Jackson (and org.json): who can reach it, and what we wait for

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

---

## The shaded org.json (kernel#57)

Issue: kernel#57. Decision (Jody, 2026-11-12): **option 1, record and track**, as for Jackson above.
Bump `hazelcast.version` once a release ships org.json >= 20260719; #57 stays open until then.

`hazelcast-5.7.0.jar` also bundles org.json `json` **20250107**, relocated to
`com.hazelcast.shaded.org.json` (its own `META-INF/maven/org.json/json/pom.properties`), and `kernel.jar`
ships it. It has GHSA-ghc9-756g-vrcv / CVE-2026-59171 (MEDIUM, unbounded numeric string in `JSONTokener`,
a denial of service; fixed in 20260719). 5.7.0 is still the latest Hazelcast on Maven Central
(2026-11-12). Kernel's resolved runtime tree has no org.json of its own (#57's scan of
`mvn dependency:list -DincludeScope=runtime` against OSV), so `kernel.jar`'s `pom.properties` for it
is Hazelcast's, and a `kernel.jar` scan sees this copy, unlike the Jackson 3 one.

**Who calls it.** Read from the class files of `hazelcast-5.7.0.jar` (sha1
`ff3b468e3c76421444a3a11ebacdfbb617cf62dc`, 2026-11-12):

- Outside the copy itself, only two Hazelcast classes reference `com.hazelcast.shaded.org.json`:
  `internal.yaml.YamlToJsonConverter` and `internal.config.YamlConfigSchemaValidator`, plus the shaded
  everit json-schema library, which only `YamlConfigSchemaValidator` references.
- `YamlToJsonConverter` builds `JSONObject`/`JSONArray` node by node (`put`), with no `JSONTokener`. The one
  `JSONTokener` Hazelcast creates is in `YamlConfigSchemaValidator`'s static initializer, which parses
  Hazelcast's own bundled schema resource, never a caller's input.
- `YamlConfigSchemaValidator` runs only from the YAML config builders: `config.YamlConfigBuilder`
  (behind `Config.load*`, `FileSystemYamlConfig`, `ClasspathYamlConfig`, `UrlYamlConfig`,
  `InMemoryYamlConfig`, and `HazelcastServerCachingProvider` given a config URI) and the client's
  `YamlClientConfigBuilder` / `YamlClientFailoverConfigBuilder` (client config loading, the JCache client
  provider, and Jet's `ImdgUtil` for a remote-cluster client config). Within Hazelcast, `Config.load*` is
  called only by `HazelcastInstanceFactory` when `newHazelcastInstance` is given a null config,
  `ConsoleApp` and `HazelcastBootstrap` (command-line entry points).
- **Kernel: none of these.** `ClusterServer.hazelcastConfig` builds the `Config` in code
  (`new com.hazelcast.config.Config()`) and passes it to `Hazelcast.newHazelcastInstance`, never null.
  `server/src/main` loads no Hazelcast YAML or XML config (kernel's own `config.yaml` is read by
  SnakeYAML, `Helpers.configFromYaml`), and uses no Hazelcast client, JCache or Jet (Jet stays at its
  disabled default).

So nothing in kernel reaches the parser, and the only input it could be given there is a local
config file, a schema shipped inside the jar, or a config kernel never loads. No network peer, member
or client, can feed it. The copy is dead code in kernel, like the Jackson 2 copy.

**What closes #57.** Bump `hazelcast.version` to the first release whose bundled org.json is
>= 20260719. Done when:

- `unzip -p hazelcast-<version>.jar META-INF/maven/org.json/json/pom.properties` (from `~/.m2`) shows
  `version` 20260719 or later, or the jar no longer bundles org.json;
- `trivy rootfs --scanners vuln server/target/kernel.jar` reports no `org.json:json` finding;
- `just gates` passes.

The bump that closes #44 and the one that closes #57 may be the same release or not: check both
lists on each Hazelcast release. If kernel starts loading a Hazelcast YAML config (`Config.load*`, a
`*YamlConfig`, a null config to `newHazelcastInstance`, a Hazelcast client or JCache), revisit this
section.
