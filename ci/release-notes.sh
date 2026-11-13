#!/usr/bin/env bash
# The notes of a GitHub release (.github/workflows/release.yml): the commits since the previous release.
#
# Usage:  ci/release-notes.sh vX.Y.Z[-pre]
#
# Run in the checkout with its tags fetched. The previous release is the highest vX.Y.Z below this one by
# version (pre-releases are not releases), so a patch on an older line lists what changed on that line.
# The first release lists every commit. Tested by ci/release_test.sh.
set -euo pipefail

ref="$1"
if [[ "$ref" != v* || ! "${ref#v}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release-notes.sh: $ref is not vMAJOR.MINOR.PATCH" >&2
  exit 1
fi
# This version's release: a pre-release's previous release can be its own X.Y.Z only once that is out,
# and then it sorts above the pre-release, so comparing X.Y.Z alone is enough.
this="v${BASH_REMATCH[1]}"

prev="$( { git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | grep -vxF "$this"; echo "$this"; } |
         sort -V | grep -xF -B1 "$this" | grep -vxF "$this" || true)"

if [[ -n "$prev" ]]; then
  echo "Changes since $prev:"
  range="$prev..$ref"
else
  echo "Changes:"
  range="$ref"
fi
echo
git log --no-merges --format='- %s (%h)' "$range"
