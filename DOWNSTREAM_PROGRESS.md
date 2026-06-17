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
