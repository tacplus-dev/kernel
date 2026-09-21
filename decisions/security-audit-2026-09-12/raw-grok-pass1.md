Launching a dedicated security review and starting a parallel correctness/quality pass on `server/src` and `codegen/src`.

● Security-review (requested model: grok-4.6) Kernel auth security review
  └ Agent started in background with agent_id: 1aaa7ab2-614a-468b-acc1-a0f70ef619...

● Todo added 3 items
  │ Running specialist security review
  │ Auditing correctness bugs
  └ Auditing anti-patterns and pattern drift

/ Search (glob)
  │ "**/*.{java,kt,proto,ts,js}" in
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src
  └ 42 files found

/ Search (glob)
  │ "**/*.{java,kt,proto}" in
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src
  └ 96 files found

Security review is running. I’ll inspect token, identity, and state-machine paths for correctness and pattern drift.

● Todo started correctness-audit

/ Search (grep)
  │ "TODO|FIXME|HACK|XXX" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src)
  └ No matches found

/ Search (grep)
  │ "synchronized|volatile|Atomic|Concurrent" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 52 lines found

/ Search (grep)
  │ "catch\s*\(" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 6 lines found

/ Search (grep)
  │ "TODO|FIXME|HACK|XXX" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src)
  └ 2 lines found

● Read TokenExchangeServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TokenExchangeServiceI
  │ mpl.java
  └ L1:200 (68 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L1:150 (150 lines read)

/ Search (grep)
  │ "catch\s*\([^)]+\)\s*\{\s*\}" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ No matches found

/ Search (grep)
  │ "printStackTrace|e\.getMessage\(\)|swallow|ignore" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 113 lines found

/ Search (grep)
  │ "catch\s*\([^)]+\)\s*\{[^}]*log\.(debug|warn|info|error)" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ No matches found

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L150:400 (251 lines read)

/ Search (grep)
  │ "namespace|chroot|tenant" in **/IdentityServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 83 lines found

/ Search (grep)
  │ "catch \(IllegalArgumentException ignored\)" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 17 lines found

/ Search (grep)
  │ "fail.?open|fail.?closed|if \(.* == null\)" in **/IdentityServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 39 lines found

/ Search (grep)
  │ "catch" in **/StateServer.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 19 lines found

/ Search (grep)
  │ "catch" in **/KernelPersistence.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 25 lines found

/ Search (grep)
  │ "catch" in **/CliTokenBrokerServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 32 lines found

/ Search (grep)
  │ "catch" in **/TenantAdminServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ No matches found

● Count lines in cluster Java files (shell)
  │ wc -l
  │ /Users/jody/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/ma
  │ in/java/com/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/*.java
  └ 26 lines…

● Read KernelPersistence.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/KernelPersistence.jav
  │ a
  └ 161 lines read

● Read CliTokenBrokerServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/CliTokenBrokerService
  │ Impl.java
  └ 353 lines read

● Read RateLimitInterceptor.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/RateLimitInterceptor.
  │ java
  └ 444 lines read

● Read FencedLockStateMachine.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/fencedlock/FencedLockStateMac
  │ hine.java
  └ 102 lines read

● Read KeyRotator.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/KeyRotator.java
  └ 1 line read

● Read RegistryAuthExemptions.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/main/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/RegistryAuthExemptions.java
  └ 100 lines read

● Read SecurityPolicyParser.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/main/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/SecurityPolicyParser.java
  └ 112 lines read

● Read TenantAdminServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TenantAdminServiceImp
  │ l.java
  └ L1:250 (250 lines read)

● Read TenantAdminServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TenantAdminServiceImp
  │ l.java
  └ L250:641 (392 lines read)

● Read KeyRotator.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/KeyRotator.java
  └ L1:250 (249 lines read)

/ Search (grep)
  │ "persistHook|persistState" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 22 lines found

/ Search (grep)
  │ "substring\(0,\s*8\)" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel)
  └ 19 lines found

● Read TlsCertServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TlsCertServiceImpl.ja
  │ va
  └ L1:220 (220 lines read)

● Read SecurityAuthenticatorGenerator.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/main/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/generator/SecurityAuthenticatorGenerator.java
  └ L1:200 (200 lines read)

● Read PersonalIdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/PersonalIdentityServi
  │ ceImpl.java
  └ 111 lines read

/ Search (grep)
  │ "^\t(public |private |static |@Override)" in **/IdentityServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 151 lines found

● Read BackendStoreServerGenerator.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/main/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/generator/BackendStoreServerGenerator.java
  └ L1:150 (104 lines read)

● Read TlsCertServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TlsCertServiceImpl.ja
  │ va
  └ L220:416 (197 lines read)

/ Search (grep)
  │ "bypass|NO_AUTH|self.?auth|TlsCert" in **/ClusterServer.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 36 lines found

/ Search (grep)
  │ "mintUserTokenInternal" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src)
  └ 6 lines found

● Read CliTokenBrokerServiceImplTest.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/test/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/CliTokenBrokerService
  │ ImplTest.java
  └ L1:100 (99 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L400:750 (351 lines read)

/ Search (grep)
  │ "createPersonalPrincipal|assertNotRevoked|assertGrantStillActive" in **/IdentityServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 11 lines found

/ Search (grep)
  │ "Tokenrequest\.TokenMintResponse mintUserTokenInternal" in **/IdentityServiceImpl.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 1 line found

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L2420:2550 (131 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L2920:3100 (181 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L3200:3350 (151 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L3580:3729 (150 lines read)

● Read ClusterServer.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/ClusterServer.java
  └ L1:200 (199 lines read)

● Read TokenReviewKubernetesTokenVerifier.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TokenReviewKubernetes
  │ TokenVerifier.java
  └ 363 lines read

● Read FencedLockOp.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/fencedlock/FencedLockOp.java
  └ 57 lines read

/ Search (grep)
  │ "serviceCaWriter|persistKernelState|callerInterceptor|RAW_AUTH" in **/ClusterServer.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main)
  └ 8 lines found

● Read ClusterServer.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/ClusterServer.java
  └ L500:650 (151 lines read)

● Read KeyRotator.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/KeyRotator.java
  └ L250:482 (233 lines read)

● Read ClusterServer.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/ClusterServer.java
  └ L980:1100 (121 lines read)

● Read RatisFencedLock.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/fencedlock/RatisFencedLock.ja
  │ va
  └ 164 lines read

● Read ClusterServer.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/ClusterServer.java
  └ L820:920 (101 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L1550:1750 (201 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L1880:2100 (221 lines read)

● Read StoreServerAuthorizationTest.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/test/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/StoreServerAuthorizationTest.java
  └ L1:80 (80 lines read)

● Read LocalJwkSource.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/LocalJwkSource.java
  └ 68 lines read

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L732:920 (188 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L2580:2750 (171 lines read)

● Read TemplateEngine.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/main/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/generator/TemplateEngine.java
  └ 49 lines read

● Read ProtoDescriptorParser.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src/main/java/c
  │ om/gitlab/secondstarcavalier/controlplane/codegen/ProtoDescriptorParser.java
  └ L1:120 (120 lines read)

● Read HazelcastMap.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/graphs/hazelcast/HazelcastMap
  │ .java
  └ L1:80 (80 lines read)

● Read FencedLockServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/FencedLockServiceImpl
  │ .java
  └ 52 lines read

/ Search (grep)
  │ "auth_disabled|NO_AUTH|skip" in **/ProtoDescriptorParser.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/codegen/src)
  └ 31 lines found

● Read SpiffeIds.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/SpiffeIds.java
  └ 81 lines read

● Read TenantAdminSelfLockoutTest.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/test/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/TenantAdminSelfLockou
  │ tTest.java
  └ L1:80 (80 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L2280:2420 (141 lines read)

/ Search (grep)
  │ "limit <= 0" in **/*.java
  │ (~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel)
  └ 1 line found

✔ Todo completed 2 items
  │ correctness-audit
  └ antipattern-drift

Security review is still running on `server/src` and `codegen/src`. Correctness/quality pass is drafted; I’ll merge both into the ranked report when the specialist finishes.

● Read (Security-review agent — Kernel auth security review)
  └ idle

✔ Todo completed security-review

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L1735:1820 (86 lines read)

● Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/secondstarcavalier/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ L3480:3575 (96 lines read)

## Security

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🔴 CRITICAL | IdentityServiceImpl.java | 2589 | MintX509Cert signs caller-supplied DNS/URI SANs; only appends the caller SPIFFE URI. Any service-token holder can mint a cluster-CA leaf for another service’s SPIFFE ID or arbitrary DNS names. | 9/10 |
| 2 | 🟠 HIGH | IdentityServiceImpl.java | 1764 | Workload SPIFFE paths miss `findDelegateBySubject`, so `authorized_services` is skipped and exchange takes the U2S arm — a `sub_type=service` token for any requested `aud`. | 8/10 |
| 3 | 🟠 HIGH | TlsCertServiceImpl.java | 242 | ManageCert binds `service_name` to the token but copies `init.instance_id` into a DNS SAN. A valid service token can obtain a leaf for `kernel` or another hostname. | 8/10 |
| 4 | 🟡 MEDIUM | IdentityServiceImpl.java | 3561 | MintClientToken honors `request.exp` with no lifetime ceiling (unlike other mint paths). A cred_pair proof can mint a C2S token that outlives rotation/expiry. | 9/10 |

## Correctness / anti-patterns / drift

| # | Severity | File | Lines | Defect | Failure |
|---|----------|------|-------|--------|---------|
| 5 | 🟠 HIGH | CliTokenBrokerServiceImpl.java | 163–250 | RegisterNonce prefers `delivery:` over the consumed marker; a losing CompleteNonce still mints and buffers. | Two CompleteNonce (or retry) for the same nonce can deliver a second user’s refresh token on reconnect. |
| 6 | 🟠 HIGH | KernelPersistence.java | 155–158 | `save()` logs and swallows all errors; writers still return success. | RevokeWorkload / RevokeGrant / CreatePersonalPrincipal “succeed”, then a restart resurrects revoked identities or drops registrations. |
| 7 | 🟠 HIGH | IdentityServiceImpl.java / TlsCertServiceImpl.java | 2628 / 362 | Two unsynchronized `getOrCreateIntermediateCa` copies. | Concurrent X509Mint + ManageCert for the same service overwrite CAs; leaves signed by the loser fail verify. |
| 8 | 🟡 MEDIUM | TenantAdminServiceImpl.java | 115–128 | DeleteTenant removes the row and projects, not nested tenants. | Delete `/tenants/acme` leaves `/tenants/acme/sub` alive and hidden from `listTenants("/")`. |
| 9 | 🟡 MEDIUM | TenantAdminServiceImpl.java | 70–90 | Nested create does not require a parent tenant; missing parent ⇒ unbounded ceiling. | Create `/tenants/acme/sub` without `/tenants/acme` skips ceiling inheritance. |
| 10 | 🟡 MEDIUM | CliTokenBrokerServiceImpl.java | 227 | CompleteNonce-before-register mints with `offlineAccess=false`. | Later RegisterNonce(offline=true) only replays the already-minted non-offline token. |
| 11 | 🟡 MEDIUM | CliTokenBrokerServiceImpl.java | 92 | `nonce.substring(0, 8)` with no length check. | Nonce shorter than 8 chars throws and kills the broker stream. |
| 12 | 🟡 MEDIUM | CliTokenBrokerServiceImpl.java | 210–240 | Nonce is `remove`d before mint; mint failure does not restore it. | Waiting oauth instance never gets local delivery; retry buffers instead of pushing the open stream. |
| 13 | 🟡 MEDIUM | TenantAdminServiceImpl.java | 538–554 | `jsonStringField("sub")` matches any `"sub…"` key via `indexOf`. | If `sub_type` is serialized before `sub`, self-lockout does not see the cred_pair id. |
| 14 | 🟡 MEDIUM | FencedLockStateMachine.java | 75–90 | Holds never expire; release is token-only. | Dead holder ⇒ lock stuck until someone presents that fencing token. |
| 15 | ⚪ LOW | CliTokenBrokerServiceImpl.java | 210–216 | `Thread.sleep` up to 5s on the gRPC callback thread. | Completing instance’s stream (and the shared executor) stall on IMap lag. |
| 16 | ⚪ LOW | PersonalIdentityServiceImpl.java | 41–47 | Comment says registration does not exist; `CreatePersonalPrincipal` does. | Stale contract for the C2S identity path. |
| 17 | ⚪ LOW | IdentityServiceImpl.java | 117–121 | `TOKEN_USE_OFFLINE` / `PARENT_SUB` hardcoded pending tacplus rebuild. | Drift from the “enum via Helpers” convention used everywhere else. |

Read-only — no files changed.

Follow-up:
1. Fix highest severity issues
2. Fix all issues
3. Commit a summary of findings (`SECURITY-REVIEW.md`)

Reply with 1, 2, or 3.

