#!/usr/bin/env bash
# Copyright (c) 2026 Jody Scott
# SPDX-License-Identifier: Apache-2.0
#
# tacplus as the justfile runs it: the exact release and build image that
# tacplus.lock pins (`tacplus pin` writes it), the image by digest, run on this
# checkout. A newer patch arrives only as a commit that moves the lock
# (tacplus-dev/roadmap decisions/deterministic-builds-2026-10-27.md; tacplus#193).
#
# The image's tacplus is a launcher that runs the pinned binary, cached under
# target/tacplus-home. PROTOC_BINARY (the justfile's pinned protoc, under this
# checkout) is passed through, and so are GH_TOKEN/GITHUB_TOKEN, which git in
# the image uses for github.com alone: `depends` resolve through the private
# tacplus-dev/registry.
#
# Usage:  tools/tacplus.sh build --tag latest
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
lock="$root/tacplus.lock"
[[ -f "$lock" ]] || { echo "tacplus.sh: no tacplus.lock: run \`tacplus pin\` in the build image of the floor tacplus.yaml declares and commit it" >&2; exit 1; }
image="$(sed -n -E 's/^build_image:[[:space:]]*"?([^"[:space:]]+)"?.*$/\1/p' "$lock" | head -1)"
[[ "$image" == *@sha256:* ]] || { echo "tacplus.sh: tacplus.lock names no build_image by digest" >&2; exit 1; }

home="$root/target/tacplus-home"
mkdir -p "$home"
if [[ -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]] && command -v gh >/dev/null && t="$(gh auth token 2>/dev/null)" && [[ -n "$t" ]]; then
  export GH_TOKEN="$t"
fi
env=(-e HOME="$home")
[[ -n "${PROTOC_BINARY:-}" ]] && env+=(-e PROTOC_BINARY)
if [[ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
  env+=(
    -e GH_TOKEN -e GITHUB_TOKEN
    -e GIT_CONFIG_COUNT=2
    -e GIT_CONFIG_KEY_0=credential.https://github.com.helper -e GIT_CONFIG_VALUE_0=
    -e GIT_CONFIG_KEY_1=credential.https://github.com.helper
    -e 'GIT_CONFIG_VALUE_1=!f() { test "$1" = get || exit 0; t="${GH_TOKEN:-$GITHUB_TOKEN}"; test -n "$t" || exit 0; echo username=x-access-token; echo "password=$t"; }; f'
  )
fi

docker run --rm -u "$(id -u):$(id -g)" "${env[@]}" -v "$root:$root" -w "$PWD" \
  "$image" tacplus "$@"
