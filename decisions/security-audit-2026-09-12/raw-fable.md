All three sub-audits are in and I've independently verified the top-ranked items. Here is the consolidated report.

## Kernel audit findings, ranked by severity

Paths are relative to `server/src/main/java/.../services/kernel/` and `codegen/src/main/...` unless noted.

**Critical**

1. **X509Mint signs whatever certificate request the caller sends.** `cluster/IdentityServiceImpl.java:2589-2602` only appends the caller's SPIFFE URI SAN; caller-supplied `uri_sans`, `dns_names`, `is_ca`, `path_len_constraint`, `key_usage` and `exp` pass straight into the generated signer, which honours all of them. Scenario: service `oauth` with any valid service token requests `uri_sans=["spiffe://<td>/system/services/kernel"]` and `exp` ten years out. It gets a root-chained cert that the mesh trust manager accepts as `kernel`, since it matches on any URI SAN. The newer ManageCert path at `cluster/TlsCertServiceImpl.java:288-296` builds the request server-side, so this is also pattern drift.

2. **Generated state servers with no computed policy are fail-open, and one is live.** `codegen/.../generator/BackendServiceServerGenerator.java:527-537` returns the `"*"` no-policy marker when a state root has no policy, and `SecurityAuthenticator.java.template:229-231` returns before any caller check for that marker. The generated `ServiceConfigStateStateServiceServer` has `GRAPH = "*"` and is registered at `cluster/ClusterServer.java:605`. Scenario: any `aud=kernel` token, including a user token, calls `ServiceConfigStateService/SetConfig` and replaces the cluster-wide OPA/TLS/logging config every service watches. The sibling store generator fails the build in this case; the service generator should too.

3. **A tenant admin can create a grandchild tenant with an unbounded ceiling.** `cluster/TenantAdminServiceImpl.java:351-365` returns null when the immediate parent has no tenant record, and line 96-101 then skips the ceiling check. Scenario: admin of `/tenants/acme` with a narrow ceiling creates `/tenants/acme/gap/evil` with `entitlements_ceiling` set to everything. The generated level-or-below check passes because the target is below `acme`. They then set cred_pairs with full grants on the new tenant and mint tokens carrying them via MintClientToken.

**High**

4. **ManageCert issues DNS SANs for a client-chosen hostname.** `cluster/TlsCertServiceImpl.java:242` stores `init.instance_id` unvalidated and line 295 adds it as a DNS SAN; the token's own `instance_id` claim is read at line 130 but never compared. Scenario: any service opens ManageCert with `instance_id="kernel"` or a gateway hostname and receives a root-chained cert hostname-verifying clients trust.

5. **MintToken exchange accepts any token class and extends lifetime without limit.** `cluster/IdentityServiceImpl.java:1701-1716` derives the new `exp` from the request up to `max_token_lifetime` with no ceiling from the input token's own `exp`, and nothing restricts `token_use` of the input to refresh. Lines 1791-1794 re-resolve entitlements from OPA only for refresh input, and lines 1841-1858 clone everything else. Scenario: any service holding a user's one-hour access or service token exchanges it with empty `aud` and gets a fresh 30-day token with the original stale entitlements, then repeats forever. A revoked OPA entitlement never takes effect and the refresh-token-as-root model is bypassed. The user-mint path at line 822-824 explicitly enforces "AT never outlives its parent", so this is drift too.

6. **SetLogLevel has no authorization.** `cluster/ClusterSetLogLevelHandler.java:56` replaces the generated method, which would have called `checkAccess` against the `Cluster` policy, with a handler that checks nothing beyond the outer authenticator. Scenario: any authenticated token sets the ROOT logger to `OFF`, silencing auth audit logs on the trust root.

7. **MintClientToken has no maximum lifetime.** `cluster/IdentityServiceImpl.java:3561-3569` only requires `exp > now`; every other mint path caps at `maxTokenLifetimeSeconds`. Scenario: a cred_pair holder mints a root-namespace admin token expiring in 2099. Rotating or expiring the cred_pair afterwards does not invalidate it.

8. **Tenant ceiling check ignores `data_grants` and `principal_scope`.** `cluster/TenantAdminServiceImpl.java:436-445` compares only `grants`, but line 3582 of `IdentityServiceImpl` stamps the whole `TokenEntitlements` verbatim into the token. Scenario: a tenant admin adds `principal_scope: PRINCIPAL_SCOPE_ANY` and arbitrary field-egress `data_grants` to a cred_pair regardless of what the parent ceiling allows.

**Medium**

9. **One failed state read publishes an empty JWKS fleet-wide.** `cluster/ClusterServer.java:322-334` swallows exceptions and returns an empty list. `cluster/LocalJwkSource.java:47-55` then clears the kernel Authorizer's cache, and `cluster/BackendServiceImpl.java:192-211` pushes an empty `Jwks` to every WatchJwks subscriber. Scenario: a Hazelcast partition migration timeout causes 10 to 20 seconds of `UNAUTHENTICATED` across the platform.

10. **Verifying-key retention is shorter than token lifetime.** `cluster/ClusterServer.java:362-364` sets retention to `max_token_lifetime` and `cluster/KeyRotator.java:408` sets key `exp = created + retention`, but a key signs until the next rotation tick, and offline tokens default to 90 days at `IdentityServiceImpl.java:173`. Scenario: an offline token becomes "unknown kid" after 30 days, and any max-lifetime token minted just before rotation outlives its key by up to a rotation interval. `VerifyingKeysGrowthTest` asserts the wrong arithmetic.

11. **Cert issuance never consults workload revocation.** `cluster/TlsCertServiceImpl.java:100-145` verifies the token once at stream open and then signs every renewal indefinitely; `IdentityServiceImpl.java:2570-2602` X509Mint never calls `assertNotRevoked`, unlike every token exchange. Scenario: a revoked workload keeps receiving fresh serving certs every half-lifetime.

12. **DeleteTenant orphans nested tenants and their credentials.** `cluster/TenantAdminServiceImpl.java:124-139` removes only the named tenant and its own config; nested `/tenants/acme/sub` records and configs survive. MintClientToken at line 3523 scans every `tenant_configs` entry, so the deleted subtree's cred_pairs keep minting tokens.

13. **FencedLock re-grant discloses another holder's fencing token.** `fencedlock/FencedLockStateMachine.java:72-82` re-grants on matching `holder_id`, and `cluster/FencedLockServiceImpl.java:32` ignores the verified caller; the RPC is `auth_services: ["*"]`. Scenario: a service that guesses a victim's holder id, which the proto suggests be its SPIFFE id plus a discriminator, acquires, releases, and steals the lock.

14. **Per-RPC auth exemptions drop their proto package.** `codegen/.../generator/GeneratorContext.java:293-314` collects exemptions from every parsed file and `SecurityAuthenticator.java.template:290-301` matches `Service/Rpc` only. The generated `NO_AUTH_METHODS` already contains `Mint/ListJwks`, `Auth/Authorize`, `Session/BrokerSession` from other services' packages. Latent today; adding an RPC with one of those names to a kernel proto ships it unauthenticated.

15. **Kernel's own Authorizer lags key rotation by up to 10 seconds.** `cluster/LocalJwkSource.java:31,61` polls every 10s and has no on-miss refresh, unlike the `waitForKeyByKid` retry the generated authenticator has. Scenario: a service bootstraps right after rotation, then calls TenantAdmin or FencedLock and is rejected with an unknown kid.

16. **`has_quorum` compares the live count to itself.** `cluster/ClusterStatePublisher.java:185` computes `coreCount >= coreCount / 2 + 1`, which is true for any count. An isolated node in a partition reports quorum.

17. **Configured log level is never applied.** `Bootstrap.java:46` calls `LogbackConfigurator.install(null)` after config is resolved, so `logger.level` in kernel config has no effect.

18. **FencedLock Raft log never snapshots.** `fencedlock/FencedLockStateMachine.java` does not override `takeSnapshot` and `fencedlock/RatisFencedLock.java` sets no purge properties, so the log grows forever and every restart replays it from index 0.

19. **Generated view `Watch` skips `checkAccess`.** `codegen/.../generator/BackendServiceServerGenerator.java:320-341` inlines the watch without the authorization call every other read fragment makes. Latent, since no kernel proto declares view sources yet.

**Low**

20. **Membership listener NPE window.** `cluster/ClusterServer.java:452-479` registers a listener that dereferences `clusterPublisher`, assigned only at line 582. A member change during startup throws on the Hazelcast event thread.

21. **CliTokenBroker blocks the stream thread.** `cluster/CliTokenBrokerServiceImpl.java:211-217` sleeps up to 5 seconds inside the bidi `onNext`, the exact pattern the authenticator's retry loop was hardened against.

22. **Log-stream observers collide on peer key.** `cluster/StateServer.java:22-30` overwrites an existing observer on `put` without completing it, and the old stream's cancel removes the newer observer.

23. **Audience literal drift.** `cluster/IdentityServiceImpl.java:3578` sets `"kernel"` while every other mint uses the proto package constant.

Items 1 through 8 are the ones I'd fix first; 1, 2, 4 and 6 are each a single-request compromise by any authenticated service. If a shareable page for the team would help, I can publish this as an artifact.
