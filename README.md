# kernel

The fleet's state host and token authority. A tacplus service (Java).

## Provenance and the rule

Copied **wholesale** on 2026-10-23 from `gitlab.com/seabeam/schematic`
(`platform/services/kernel` at commit `674733ad`; `proto/services/kernel.proto`,
`proto/common/hazelcast.proto`, `proto/common/credentials.proto` and `proto/dependencies.yaml`
from `platform/proto` at `ca7c322` on branch `big8-p1-messaging`). Build outputs, logs and the launcher binary
were not copied.

Jody, 2026-10-23: *"We will copy kernel over to its github home and only make changes to it. we will
keep these as ships in the night for now. For the new stuff we want to do it the right way."*

So: the private schematic kernel keeps running the launch fleet and is not changed for this work.
All kernel changes for the new design (sys-contract messages imported from tacplus, composition,
the Rust rewrite with Hazelcast removed) happen here. The two are not kept in sync.

## Divergences from the private copy (2026-10-23)

1. Headers in `tacplus.yaml`: `Copyright (c) 2026 Jody Scott`, Apache-2.0 (LICENSE added).
   `pkg` is unchanged so the hand-written Java keeps compiling; it moves with the Java packages later.
2. `src: proto` (this repo) instead of the private platform proto repo. This repo holds only kernel's
   own proto and the two common protos it imports.
3. `proto/registry.yaml` is a lock of github.com/tacplus-dev/registry (kernel = 8).

## Does not build standalone yet

kernel.proto imports `generated/*.proto`, which the fleet build synthesizes from every service in
the deployment. Kernel is the centre of the fleet build (roadmap item `tacplus-registry-and-floor`),
so it is built there, from a manifest, not alone.
