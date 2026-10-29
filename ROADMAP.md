# Roadmap: kernel

Owned by Jody; changed only by an agent at Jody's request. Loopers propose in PROPOSALS.md.

## Now
The fleet's state host and token authority (Java, tacplus service). Unreleased; tacplus floor 2.4.
Built inside the fleet build from a manifest, not standalone. Ported from SeaBeam through `1672d4d4`; the private schematic kernel is not kept in sync.

## Next
- Sign-in and linking: binding step, kernel-owned pairwise mappings, account classification, proof age (#26)
- Tenant-owned service identity carries the tid: `spiffe://<td>/tenants/<tid>/services/<svc>` (#23; for tacplus-dev/gateway#3)
- Age out XIDs that have not signed in for about a year (#20)
- DeleteTenant is complete: no new AT/ST, memberships removed, XIDs kept, nothing tenant-scoped left (#19)
- Base image distroless/java21-debian12 to the latest line, java25-debian13 (#17)
- Jetty 11.0.25 (via Javalin 6.7.0) HIGH advisories (#16)
- Hazelcast 5.5.0 CRITICAL advisory, fixed in 5.7.0 (#15)
- Logback 1.5.29 to 1.5.38 (#14)
- Jackson HIGH advisories: pin jackson-bom 2.21.8 and 3.1.8 (#13)
- Bouncy Castle 1.80 to 1.86 (#12)
- `just verify`: the 66 generated proof harnesses fail to compile (#11)
- Work without SeaBeam: no gitlab.com/seabeam module paths, sources or registries (#10)
- Retire the `linked` claim (#4; landed in 5199fea, issue still open)

## Later
- Investigate and retire kmaker once kernel uses the member port (#29)
- Key-pair credentials for workloads that can't federate: tenant-managed CredPair keys, disabled after 90 days unused, configurable per tenant (#28)
- External workload identity: deployments as OIDC issuers trusted by GCP, Azure and AWS, for workloads only; users later (#27)
- Release: tag from v0.1.0 and publish the image (#7; blocked on tacplus-dev/looper#12)
- Move the identity graph to the people service (#2; blocked on tacplus-dev/people#1, tacplus-dev/tacplus#170)
- Stratum as identity's durable record; nothing new in kernel depends on Hazelcast (tacplus-dev/roadmap:decisions/platform-direction-2026-10-23.md, tacplus-dev/roadmap:decisions/stratum-per-tenant-2026-10-25.md)
- Remove Hazelcast from kernel; the Rust rewrite (README, tacplus-dev/roadmap:decisions/platform-direction-2026-10-23.md)
- Version-aware endpoint pools for canary, design needed (tacplus-dev/roadmap:decisions/fleets-and-canary-huddle-2026-10-22.md)

## Not doing
- The `linked` claim and tenant-user links: replaced by XIDs and request-named routing (#4, tacplus-dev/roadmap:decisions/identity-session-credential-2026-10-25.md, tacplus-dev/roadmap:decisions/tenant-routing-2026-10-26.md)
- SeaBeam's Accounts model (Account root, Accounts.CreateOrganization/GetMyAccount): SeaBeam's product surface; the XID-keyed Person replaces it (marked not applicable in the port, #9)
- `/people/<pid>` principals: devices belong to the XID (#18, tacplus-dev/tacplus#131)
