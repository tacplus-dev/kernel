#!/usr/bin/env bash
# Checks .gitleaks.toml (#50): the repository scans clean, and a real private
# key or API token planted in a Java source is still reported. The planted
# secrets are generated here at run time, so no secret is ever in the tree.
# Needs gitleaks (8.30.1, the build's scanner) and openssl on PATH.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
config="$root/.gitleaks.toml"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

leaks() { # <dir>: the number of findings gitleaks reports in <dir>
  gitleaks dir "$1" --no-banner --config "$config" -f json -r "$work/report.json" >/dev/null 2>&1 || true
  python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' "$work/report.json"
}

fail=0
expect() { # <name> <want> <got>
  if [[ "$2" == "$3" ]]; then echo "ok: $1"; else echo "FAIL: $1: want $2 leaks, got $3" >&2; fail=1; fi
}

[[ -f "$config" ]] || { echo "FAIL: no $config" >&2; exit 1; }

expect "the repository scans clean" 0 "$(leaks "$root")"

# A PEM private key whose body is in the source.
mkdir "$work/key"
{
  echo 'class Planted {'
  echo '  static final String KEY = """'
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null
  echo '""";'
  echo '}'
} > "$work/key/Planted.java"
expect "a planted private key is reported" 1 "$(leaks "$work/key")"

# The same key inline after the header string literal, the shape the allowlist
# is closest to.
mkdir "$work/inline"
body="$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null | sed -n '2,$p' | sed '$d' | tr -d '\n')"
printf 'class Planted {\n  static final String KEY = "-----BEGIN PRIVATE KEY-----\\n"\n    + "%s"\n    + "\\n-----END PRIVATE KEY-----\\n";\n}\n' "$body" \
  > "$work/inline/Planted.java"
expect "a planted inline private key is reported" 1 "$(leaks "$work/inline")"

# A generic API token, next to a KeyType switch arm.
mkdir "$work/token"
token="$(openssl rand -hex 20)"
printf 'class Planted {\n  static final String API_KEY = "%s";\n}\n' "$token" > "$work/token/Planted.java"
expect "a planted API key is reported" 1 "$(leaks "$work/token")"

exit "$fail"
