#!/usr/bin/env bash
# How a release's GitHub release is marked (.github/workflows/release.yml): `--latest` for the highest release,
# `--latest=false` for any other (a patch on an older line is never Latest), `--prerelease` for vX.Y.Z-pre.
#
# Usage:  ci/release-latest.sh vX.Y.Z[-pre]
#
# Run in the checkout with its tags fetched. Prints the gh release create flag. Tested by ci/release_test.sh.
set -euo pipefail

ref="$1"
if [[ "$ref" != v* || ! "${ref#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release-latest.sh: $ref is not vMAJOR.MINOR.PATCH" >&2
  exit 1
fi
if [[ -n "${BASH_REMATCH[1]}" ]]; then
  echo "--prerelease"
elif [[ "$(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)" == "$ref" ]]; then
  echo "--latest"
else
  echo "--latest=false"
fi
