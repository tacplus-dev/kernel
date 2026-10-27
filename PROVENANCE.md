# Provenance

This repository continues the history of `gitlab.com/seabeam/schematic/platform/services/kernel` (shared
history from its initial commit). The port scan (tacplus-dev/looper#2) carries later SeaBeam commits in
through port issues; this mark moves with each port.

Ported through `1672d4d4db6e8ef685ea0e19de26035843c94040`.

2026-10-27, no SeaBeam (#10): tacplus-dev works by itself, so nothing outside this note and dated records
names SeaBeam. The kernel protos (`proto/services/kernel.proto`, `proto/common/*.proto`,
`proto/vservices/*.proto`) are this repository's own, not vendored or fetched: `proto/registry.yaml` locks
kernel's and the proxypolicy vservice's contract at `github.com/tacplus-dev/kernel` (public), as
tacplus-dev/registry has them, and opa, oauth, gateway and llmproxy come from their tacplus-dev homes through
the registry. The Java package of the server and the generated model (`pkg`), and the Maven groupId, are
`com.github.tacplusdev.kernel` (was `com.gitlab.seabeam.controlplane.schematic.services.kernel`); the codegen
plugin is `com.github.tacplusdev.kernel.codegen` (was `com.gitlab.seabeam.controlplane.codegen`). Removed:
`.gitlab-ci.yml` and `ci_settings.xml` (SeaBeam's GitLab pipeline, compiler image and package registry;
release CI to ghcr.io is #7), the GitLab Maven package repository and distributionManagement in the POMs,
and the GitLab project id and Rust interfaces crate in `proto/dependencies.yaml`. Source and proto headers
and image labels name Jody Scott and tacplus.dev; comments no longer cite SeaBeam's products.
