# Downstream Progress

## 2026-06-12

- Normalized active kernel checkout back to `main`.
- Applied the narrow proto/tacplus compatibility fix for the generated SPIFFE API:
  - `kernel.Config.spiffe_prefix` is retired; kernel now reads `spiffe_trust_domain`
    and `location_path`.
  - `ServiceConfigState` seeding now writes `spiffe_trust_domain` and
    `location_path`.
  - Kernel token minting and namespace derivation now use the generated
    `libs/spiffe` helper through `SpiffeIds`.
  - Kernel authorizer construction now matches the generated one-argument
    `Authorizer(JwkSource)` API.
- Verified locally against proto `v1.2.183-main.183`:
  - `tacplus build --tag v1.2.183-main.183`
  - `JAVA_HOME=/Library/Java/JavaVirtualMachines/graalvm-jdk-24.0.2+11.1/Contents/Home mvn -pl server -am -Dtacplus.skip=true -Dmaven.test.skip=true package`

## 2026-06-13

- Entitlement-shape follow-up after tacplus `v1.2.202`: kernel now writes the
  JWT `service_entitlements` claim as flat grant strings, e.g.
  `{"grants":["OPENAI_RPCS_ANY"]}`.
- Added descriptor-driven conversion so current generated code with
  `EntitlementGrant{token}` and future generated code with `repeated string`
  both work during token minting and service-token scoping.
- Verification passed:
  - `JAVA_HOME=/Library/Java/JavaVirtualMachines/graalvm-jdk-24.0.2+11.1/Contents/Home mvn -Dmaven.test.skip=true package`

## 2026-06-17

- OPA `v1.2.187-main.194` built with tacplus `v1.2.213` and now calls
  `kernel.Mint/MintX509Cert` during startup X509 minting.
- Live kernel `v1.2.187-main.264` still returned
  `UNIMPLEMENTED: Method not found: kernel.Mint/MintX509Cert`, so OPA stayed
  in the generated `ServiceManager` constructor retry loop before binding
  `:8443`.
- Next kernel tag is a rebuild-only compatibility tag so Java generated server
  descriptors pick up the current mint RPC name from tacplus/proto.
- Kernel `v1.2.187-main.265` rolled to all three pods, but a direct grpcurl
  check against `pod/kernel-0` still returned `UNIMPLEMENTED` for
  `kernel.Mint/MintX509Cert` while `MintServiceToken` was live.
- Added a source-level kernel binding guard: if the generated `Mint` service
  definition omits `MintX509Cert`, `ClusterServer` installs the missing unary
  method explicitly against the existing `IdentityServiceImpl.mintX509Cert`
  implementation and logs the registered method table at startup.
- Added a CI post-package check that `server/target/kernel.jar` contains
  `MintGrpc.getMintX509CertMethod`, so a stale generated method table cannot
  silently ship again.
- Fixed external WIF audience construction for Anthropic proxy tokens:
  policy-supplied upstream audiences now become the external assertion `aud`
  directly, instead of being collapsed into a synthetic `service:audience`
  value that Anthropic cannot exact-match.
- Verification passed:
  - `JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.0.8.jdk/Contents/Home mvn -pl server -am -Dtest=ExternalSigningKeyTypeTest -Dsurefire.failIfNoSpecifiedTests=false test`
- Tagged and rolled kernel `v1.2.192-main.275`; pipeline `2609429991`
  completed green and all three kernel pods are Ready on the tag.
- Live verification after rollout confirmed Anthropic WIF exchange succeeds
  with ES256 public discovery and the corrected upstream audience.

## 2026-07-11

- Full sys-rename migration to the current tacplus contract. Proto repo
  (`platform/proto`) migrated: `libs/` -> `sys/` imports; `assert_max_length/
  min_length` -> `assert_max_size/min_size` (value-preserving, double-size fields
  deduped); `eventdb` -> `record` (+ `s2s` producer surface on the 4 record
  messages); `tenant_config_slice`/`tenant_config_service` -> `config_slice`
  {scope: `CONFIG_SLICE_SCOPE_TENANT`, service_name: "kernel"}; `hot_store` ->
  `record_store`; colddb retired (`colddb.off` deleted, `TimeRange` moved to
  `timedb.proto`); `common/tokenrequest.proto` deleted in favor of
  `sys/tokenrequest.proto`.
- tacplus fixes required (pushed to tacplus main): completed the
  `common->sys` tokenrequest fold — restored 3 dropped messages
  (`ExternalTokenMintResponse`, `WorkloadMintRequest/Response`) and the dropped
  `ExternalTokenMintRequest.requested_signing_key_type` field, reconciling the
  canonical contract with the kernel's committed shape.
- Kernel handwritten Java: imports repointed `libs`->`chassis` (runtime) and
  `types.libs`/`common.tokenrequest` -> `types.sys`/`sys.tokenrequest` (types);
  `backendServers.libs()` -> `sys()`; `ServiceConnection.channelFactory()` now
  takes the trust domain (fail-closed S2S TLS).
- Kernel `codegen` plugin: emit `sys`/`chassis` packages so the regenerated
  `tacplus-backend` tree compiles.
- Test execution enabled: pinned `maven-surefire-plugin` 3.2.5 (the default
  provider silently discovered 0 JUnit 5 tests) and dropped
  `-Dmaven.test.skip=true` from the CI `build` job.
- Verified against dev tacplus `tacplus-0-0` (containerized, temurin-21):
  regen (375 Java files) -> `mvn -Dtacplus.skip=true package` BUILD SUCCESS ->
  `mvn -Dtacplus.skip=true test` **36/36 pass** (Mint/CliTokenBroker/Identity/
  ExternalSigningKeyType/TokenReview).
- Note: CI `build` still pulls the released `$TACPLUS_IMAGE` (tacplus-1-2), so
  these changes are exercised in CI only once the tacplus changes ship in a
  release.
