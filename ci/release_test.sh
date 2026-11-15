#!/usr/bin/env bash
# Tests of the release scripts (.github/workflows/release.yml): the image tags a release gets
# (release-tags.sh), whether its GitHub release is Latest (release-latest.sh) and its notes
# (release-notes.sh), each in a scratch repository with the tags given.
#
# Usage:  ci/release_test.sh
set -euo pipefail

ci="$(cd "$(dirname "$0")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
failures=0

check() { # name got want
  if [[ "$2" == "$3" ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: got [$2], want [$3]"
    failures=$((failures + 1))
  fi
}

# A fresh repository with one commit per tag given, each tag on its own commit, in that order.
repo() { # tag...
  rm -rf "$scratch/repo"
  git init -q "$scratch/repo"
  local t
  for t in "$@"; do
    git -C "$scratch/repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "before $t"
    git -C "$scratch/repo" tag "$t"
  done
}
in_repo() { (cd "$scratch/repo" && "$@"); }

# The first release: its own tag and the line's.
repo v0.1.0
check "first release: tags" "$(in_repo "$ci/release-tags.sh" v0.1.0)" "0.1.0 0.1"
check "first release: Latest" "$(in_repo "$ci/release-latest.sh" v0.1.0)" "--latest"
check "first release: notes list every commit" "$(in_repo "$ci/release-notes.sh" v0.1.0 | head -3)" \
  "Changes:

- before v0.1.0 ($(git -C "$scratch/repo" rev-parse --short v0.1.0))"

# A patch moves its line's tag.
repo v0.1.0 v0.1.1
check "patch: moves the line" "$(in_repo "$ci/release-tags.sh" v0.1.1)" "0.1.1 0.1"
check "patch: Latest" "$(in_repo "$ci/release-latest.sh" v0.1.1)" "--latest"
check "patch: notes since the previous release" "$(in_repo "$ci/release-notes.sh" v0.1.1 | head -1)" \
  "Changes since v0.1.0:"
check "patch: only its own commits" "$(in_repo "$ci/release-notes.sh" v0.1.1 | grep -c '^- ')" "1"

# A patch on an older line moves that line only, and is never Latest.
repo v0.1.0 v0.1.1 v0.2.0 v0.1.2
check "older line: its tag only" "$(in_repo "$ci/release-tags.sh" v0.1.2)" "0.1.2 0.1"
check "older line: not Latest" "$(in_repo "$ci/release-latest.sh" v0.1.2)" "--latest=false"
check "older line: notes since that line's last" "$(in_repo "$ci/release-notes.sh" v0.1.2 | head -1)" \
  "Changes since v0.1.1:"
check "newer line: its own line tag" "$(in_repo "$ci/release-tags.sh" v0.2.0)" "0.2.0 0.2"

# A release below its line's highest (re-published late) never moves the line tag back.
repo v0.1.0 v0.1.1 v0.1.2
check "not the line's highest: no line tag" "$(in_repo "$ci/release-tags.sh" v0.1.1)" "0.1.1"
check "not the highest: not Latest" "$(in_repo "$ci/release-latest.sh" v0.1.1)" "--latest=false"

# By version, not lexically: 0.1.10 is above 0.1.9, 0.10 above 0.9.
repo v0.1.9 v0.1.10
check "0.1.10 above 0.1.9: line tag" "$(in_repo "$ci/release-tags.sh" v0.1.10)" "0.1.10 0.1"
check "0.1.9 below 0.1.10: no line tag" "$(in_repo "$ci/release-tags.sh" v0.1.9)" "0.1.9"
check "0.1.10 notes since 0.1.9" "$(in_repo "$ci/release-notes.sh" v0.1.10 | head -1)" "Changes since v0.1.9:"
repo v0.9.0 v0.10.0
check "0.10.0 above 0.9.0: Latest" "$(in_repo "$ci/release-latest.sh" v0.10.0)" "--latest"
check "0.9.0 below 0.10.0: not Latest" "$(in_repo "$ci/release-latest.sh" v0.9.0)" "--latest=false"

# A pre-release is not a release: only its own tag, marked pre-release, and never a previous release.
repo v0.1.0 v0.2.0-rc.1 v0.2.0
check "pre-release: its own tag" "$(in_repo "$ci/release-tags.sh" v0.2.0-rc.1)" "0.2.0-rc.1"
check "pre-release: marked" "$(in_repo "$ci/release-latest.sh" v0.2.0-rc.1)" "--prerelease"
check "after a pre-release: notes since the last release" "$(in_repo "$ci/release-notes.sh" v0.2.0 | head -1)" \
  "Changes since v0.1.0:"

# Anything else is refused.
repo v0.1.0
for bad in 0.1.0 v0.1 v0.1.0.1 vX.Y.Z latest; do
  for s in release-tags.sh release-latest.sh release-notes.sh; do
    if in_repo "$ci/$s" "$bad" > /dev/null 2>&1; then
      check "$s refuses $bad" "accepted" "refused"
    else
      check "$s refuses $bad" "refused" "refused"
    fi
  done
done

if ((failures)); then
  echo "$failures failed"
  exit 1
fi
echo "all passed"
