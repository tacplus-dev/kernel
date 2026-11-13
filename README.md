# kernel

The fleet's state host and token authority. A tacplus service (Java).

## Provenance and the rule

Copied **wholesale** on 2026-10-23 from `gitlab.com/seabeam/schematic`
(`platform/services/kernel` at commit `674733ad`; `proto/services/kernel.proto`,
`proto/common/hazelcast.proto`, `proto/common/credentials.proto` and `proto/dependencies.yaml`
from `platform/proto` at `ca7c322` on branch `big8-p1-messaging`). Build outputs, logs and the launcher binary
were not copied. `platform/services/kernel` was its own git repository inside schematic, so its
full history (405 commits, origin `gitlab.com/seabeam/schematic/platform/services/kernel`) came with
it; this repo's history is that history plus the copy commit.

Jody, 2026-10-23: *"We will copy kernel over to its github home and only make changes to it. we will
keep these as ships in the night for now. For the new stuff we want to do it the right way."*

So: the private schematic kernel keeps running the launch fleet and is not changed for this work.
All kernel changes for the new design (sys-contract messages imported from tacplus, composition,
the Rust rewrite with Hazelcast removed) happen here. The two are not kept in sync.

## Divergences from the private copy (2026-10-23)

1. Headers in `tacplus.yaml`: `Copyright (c) 2026 Jody Scott`, Apache-2.0 (LICENSE added).
   `pkg` was unchanged at first; since 2026-10-27 (#10) it is `com.github.tacplusdev.kernel`, as are
   the Java packages and the Maven groupId (see PROVENANCE.md).
2. `src: proto` (this repo) instead of the private platform proto repo. This repo holds only kernel's
   own proto and the two common protos it imports.
3. `proto/registry.yaml` is a lock of github.com/tacplus-dev/registry (kernel = 8).

## Does not build standalone yet

kernel.proto imports `generated/*.proto`, which the fleet build synthesizes from every service in
the deployment. Kernel is the centre of the fleet build (roadmap item `tacplus-registry-and-floor`),
so it is built there, from a manifest, not alone.

## Releasing

Releases are tags `vMAJOR.MINOR.PATCH` on main (on a `release/MAJOR.MINOR` branch for a patch to an older
line). Fleets pin a release line, `MAJOR.MINOR` (tacplus-dev/tacplus#180). The line is `0.x` until
SeaBeam's launch, when `1.0.0` is cut. On `0.x` a minor may break; a patch never does. A looper change merged
to main is released as a patch (a fix) or a minor (a feature).

To cut one, tag the commit and push the tag:

    git tag -a v0.1.1 -m v0.1.1 <commit> && git push origin v0.1.1

The tag starts `.github/workflows/release.yml`. It runs the gates on the tag in the build image its
`tacplus.lock` pins (`ci/release-gates.sh`) and builds the Dockerfile for the workflow's `PLATFORMS`
(`arm64`; `amd64 arm64` builds both into one image). It pushes `ghcr.io/tacplus-dev/kernel:X.Y.Z`, and
`:X.Y` when this is the line's highest release, so the line tag never moves backwards and a patch never
moves another line (`ci/release-tags.sh`). It then creates the GitHub release with the commits since the
previous release (`ci/release-notes.sh`). The release is marked Latest only when it is the highest
(`ci/release-latest.sh`). The image is labelled with the version and the commit. `ci/release_test.sh` tests
the scripts, and the workflow runs it first. Never move or delete a tag once it is pushed.

Run by hand (Actions, release, Run workflow, or `gh workflow run release.yml -f tag=vX.Y.Z`), the workflow is
a dry run: it builds the given tag, or HEAD when that tag does not exist yet, and prints the image tags and
notes that release would get. It publishes nothing. With `-f publish=true` it publishes a tag that already
exists, for a tag on a commit without the workflow (v0.1.0).
