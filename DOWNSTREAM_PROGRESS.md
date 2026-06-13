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
