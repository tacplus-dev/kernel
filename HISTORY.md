# History: kernel

Append-only: add entries at the end, never edit or remove one (CI enforces it). One line each:
`- <YYYY-MM-DD> <who: looper|agent|jody> <kind: issue|decision|release|deploy> <one line> (<links>)`

- 2026-10-27 looper issue Bouncy Castle 1.80 has CRITICAL advisories: bump bcprov/bcpkix/bcutil to 1.86 (#12, a6fb956)
- 2026-10-27 looper issue Jackson 2.17.0 (via opa) and 3.1.4 (via mcp) have HIGH advisories: pin jackson-bom 2.21.8 and 3.1.8 (#13, 8c86f18)
- 2026-10-27 looper issue Logback 1.5.29 has advisories: bump to 1.5.38 (#14, 2e1b3af)
- 2026-10-27 looper issue Hazelcast 5.5.0 has a CRITICAL advisory, fixed only in 5.7.0 (#15, 670d8df)
- 2026-10-27 looper issue Jetty 11.0.25 (via Javalin 6.7.0) has HIGH advisories; no fixed Jetty 11 on Maven Central (#16, 604be82)
- 2026-10-27 looper issue Base image distroless/java21-debian12 is behind the latest line (java25-debian13) (#17, b447775)
- 2026-10-27 looper issue DeleteTenant is complete: no new AT/ST, memberships removed (XIDs kept), nothing tenant-scoped left (#19, 7983b2f)
- 2026-10-28 looper issue Age out XIDs that have not signed in for about a year (#20, 52c48d4)
- 2026-10-28 looper issue Guava 33.5.0-android (via gRPC 1.79.0) has a HIGH advisory: pin guava 33.7.2 (#21, 62f7f66)
- 2026-10-28 looper issue Tenant-owned service identity carries the tid: spiffe://<td>/tenants/<tid>/services/<svc> (#23, 2288d36)
