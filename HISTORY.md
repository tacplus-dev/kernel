# History: kernel

Append-only: add entries at the end, never edit or remove one (CI enforces it). One line each:
`- <YYYY-MM-DD> <who: looper|agent|jody> <kind: issue|decision|release|deploy> <one line> (<links>)`

- 2026-10-27 looper issue Bouncy Castle 1.80 has CRITICAL advisories: bump bcprov/bcpkix/bcutil to 1.86 (#12, a6fb956)
- 2026-10-27 looper issue Jackson 2.17.0 (via opa) and 3.1.4 (via mcp) have HIGH advisories: pin jackson-bom 2.21.8 and 3.1.8 (#13, 8c86f18)
