#!/usr/bin/env bash
# Assembles the release image (.github/workflows/release.yml) from the released commit's Dockerfile, once per
# platform, and publishes them as one image.
#
# Usage:  ci/release-image.sh VERSION REVISION JAR LAUNCHERS [TAG...]
#
# The Dockerfile takes server/target/kernel.jar and launcher-linux-<arch> from its build context: for each
# platform in PLATFORMS (default "arm64") this stages a context with the Dockerfile at REVISION (run in a
# checkout that has it), JAR (the gated build's kernel.jar) and LAUNCHERS/launcher-linux-<arch>, and builds it
# labelled with VERSION, REVISION, REVISION's commit date and this repository as its source (which links the
# package to it). With TAGs, each platform is pushed by digest and $IMAGE:<TAG> (each TAG) is pointed at all of
# them. Without, nothing is pushed: the dry run.
set -euo pipefail

version="$1"
revision="$2"
jar="$3"
launchers="$4"
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
  cp "$launchers/launcher-linux-$arch" "$ctx/"

  output="type=cacheonly"
  (($#)) && output="type=image,name=$image,push-by-digest=true,name-canonical=true,push=true"
  docker buildx build --platform "linux/$arch" \
    --build-arg "VERSION=$version" --build-arg "VCS_REF=$revision" --build-arg "BUILD_DATE=$created" \
    --label "org.opencontainers.image.source=$source" \
    --output "$output" --metadata-file "$ctx.json" "$ctx"
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
