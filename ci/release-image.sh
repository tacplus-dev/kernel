#!/usr/bin/env bash
# Assembles the release image (.github/workflows/release.yml) from the released commit's Dockerfile, once per
# platform, and publishes them as one image.
#
# Usage:  ci/release-image.sh VERSION REVISION JAR LAUNCHERS [TAG...]
#
# The Dockerfile takes server/target/kernel.jar from its build context and downloads the launcher release it
# pins, verified against its sha256: for each platform in PLATFORMS (default "arm64") this stages a context with
# the Dockerfile at REVISION (run in a checkout that has it) and JAR (the gated build's kernel.jar), and builds it
# labelled with VERSION, REVISION, REVISION's commit date and this repository as its source (which links the
# package to it). Each platform's image is then started, to check that it runs under the launcher: with no
# LAUNCH_CMD the launcher refuses to start, and with LAUNCH_CMD "java -version" it runs java and exits 0. With
# TAGs, each platform is pushed by digest and $IMAGE:<TAG> (each TAG) is pointed at all of them. Without,
# nothing is pushed: the dry run.
#
# LAUNCHERS is not read: release.yml still builds the launcher at its LAUNCHER_COMMIT and passes it, until a
# person drops those steps (the looper may not change .github/workflows/, #22).
set -euo pipefail

version="$1"
revision="$2"
jar="$3"
shift 4
image="${IMAGE:-ghcr.io/tacplus-dev/kernel}"
source="${SOURCE:-https://github.com/tacplus-dev/kernel}"
root="$(cd "$(dirname "$0")/.." && pwd)"
created="$(git -C "$root" log -1 --format=%cI "$revision")"

digests=()
for arch in ${PLATFORMS:-arm64}; do
  case "$arch" in
    amd64|arm64) ;;
    *) echo "release-image.sh: unsupported platform $arch (amd64, arm64)" >&2; exit 1 ;;
  esac
  ctx="$root/target/image/$arch"
  rm -rf "$ctx"
  mkdir -p "$ctx/server/target"
  git -C "$root" show "$revision:Dockerfile" > "$ctx/Dockerfile"
  cp "$jar" "$ctx/server/target/kernel.jar"

  build=(docker buildx build --platform "linux/$arch"
    --build-arg "VERSION=$version" --build-arg "VCS_REF=$revision" --build-arg "BUILD_DATE=$created"
    --label "org.opencontainers.image.source=$source")

  # The image starts under the launcher: built into the local daemon and run (the build below is then cached).
  checked="kernel-release-check:$arch"
  "${build[@]}" --output "type=docker,name=$checked" "$ctx"
  if out="$(docker run --rm --platform "linux/$arch" -e LAUNCH_CMD= "$checked" 2>&1)" \
    || [[ "$out" != *"LAUNCH_CMD is not set"* ]]; then
    echo "release-image.sh: linux/$arch: the entrypoint is not the launcher: $out" >&2; exit 1
  fi
  if ! out="$(docker run --rm --platform "linux/$arch" -e LAUNCH_CMD="java -version" "$checked" 2>&1)"; then
    echo "release-image.sh: linux/$arch: the launcher did not run java: $out" >&2; exit 1
  fi
  echo "linux/$arch: starts under the launcher: $(head -1 <<< "$out")"

  output="type=cacheonly"
  (($#)) && output="type=image,name=$image,push-by-digest=true,name-canonical=true,push=true"
  "${build[@]}" --output "$output" --metadata-file "$ctx.json" "$ctx"
  if (($#)); then
    digest="$(jq -r '."containerimage.digest"' "$ctx.json")"
    echo "linux/$arch: $image@$digest"
    digests+=("$image@$digest")
  fi
done

(($#)) || exit 0
refs=()
for tag in "$@"; do refs+=(-t "$image:$tag"); done
docker buildx imagetools create --annotation "index:org.opencontainers.image.source=$source" \
  "${refs[@]}" "${digests[@]}"
