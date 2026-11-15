#!/usr/bin/env bash
# The gates as a release runs them (.github/workflows/release.yml): `just gates` in the build image the
# checkout's tacplus.lock pins, by digest, with the image's tacplus (TACPLUS_BIN), so a release is built by
# the toolchain its own commit pins, as the looper's build jobs build it. HOME (the Maven repository, the
# tacplus cache) is a directory outside the checkout, so the gates' check that generation changed nothing
# under version control sees only the checkout.
#
# Usage:  ci/release-gates.sh CHECKOUT HOME
#
# GH_TOKEN, when set, is passed through for tacplus's GitHub API reads (its releases): give it a read-only one.
set -euo pipefail

src="$(cd "$1" && pwd)"
mkdir -p "$2"
home="$(cd "$2" && pwd)"
lock="$src/tacplus.lock"
[[ -f "$lock" ]] || { echo "release-gates.sh: $src has no tacplus.lock" >&2; exit 1; }
image="$(sed -n -E 's/^build_image:[[:space:]]*"?([^"[:space:]]+)"?.*$/\1/p' "$lock" | head -1)"
[[ "$image" == *@sha256:* ]] || { echo "release-gates.sh: $lock names no build_image by digest" >&2; exit 1; }

env=(-e HOME="$home" -e TACPLUS_BIN=tacplus)
[[ -z "${GH_TOKEN:-}" ]] || env+=(-e GH_TOKEN)
echo "the gates of $(git -C "$src" rev-parse HEAD) in $image"
docker run --rm -u "$(id -u):$(id -g)" "${env[@]}" -v "$src:$src" -v "$home:$home" -w "$src" \
  "$image" just gates
