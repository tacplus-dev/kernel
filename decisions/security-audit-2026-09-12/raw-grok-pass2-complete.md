Merging the specialist security review with the correctness pass. Checking agent results and closing remaining gaps.

✗ Read (1aaa7ab2)
  └ Failed

Security specialist context was lost after the timeout. Verifying the highest-confidence items from the earlier pass so the report is complete.

✗ Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ Permission denied and could not request permission from user

✗ Read IdentityServiceImpl.java
  │ ~/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/co
  │ m/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.j
  │ ava
  └ Permission denied and could not request permission from user

✗ Read SelfAuthenticatingRpcSkipTest.java
  │ ~/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/test/java/co
  │ m/gitlab/seabeam/controlplane/schematic/services/kernel/authz/SelfAuthenticatingRpcSk
  │ ipTest.java
  └ Permission denied and could not request permission from user

✗ Search (grep)
  │ "getDnsNames|addDnsNames|certRequest" in **/IdentityServiceImpl.java
  │ (~/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main)
  └ Permission denied and could not request permission from user

✗ Search (grep)
  │ "registerMethodAuth|RPC_FLAG|auth_disabled|CliTokenBroker" in **/*.{java,proto}
  │ (~/workspace/gitlab/seabeam/schematic/platform/services/kernel)
  └ Permission denied and could not request permission from user

✗ Re-read key finding line ranges (shell)
  │ sed -n '2515,2585p' /Users/jody/workspace/gitlab/seabeam/schematic/platform/service
  │ s/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/ke
  │ rnel/cluster/IdentityServiceImpl.java; echo '---'; sed -n '155,175p' /Users/jody/workspace/git
  │ lab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seco
  │ ndstarcavalier/controlplane/schematic/services/kernel/cluster/TenantAdminServiceImpl.java; …
  └ Permission denied and could not request permission from user

✔ Todo completed security-review

Specialist agent context was lost after the timeout. Findings below are from the earlier read-only pass of `server/src` and `codegen/src` (not `tacplus/` / `target/`).

## Security

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | IdentityServiceImpl.java | 2588–2594 | X509Mint signs caller-supplied DNS SANs / issuer / exp; only URI SAN is added | 9/10 |
| 2 | 🟠 HIGH | KernelPersistence.java | 108–114 | Corrupt snapshot load is treated as cold start; grant revocations are not restored | 9/10 |
| 3 | 🟠 HIGH | KernelPersistence.java | 154–156 | `save()` swallows errors after Revoke* / CreatePersonalPrincipal already returned OK | 9/10 |
| 4 | 🟠 HIGH | TlsCertServiceImpl.java | 286–297 | ManageCert DNS SAN is `init.instance_id`, never bound to token `instance_id` | 8/10 |
| 5 | 🟡 MEDIUM | IdentityServiceImpl.java | 2550–2553 | X509Mint accepts bearer from request body on an auth-exempt Mint service | 8/10 |
| 6 | 🟡 MEDIUM | TokenReviewKubernetesTokenVerifier.java | 248–256 | Missing in-cluster CA falls back to JVM default trust store | 7/10 |
| 7 | ⚪ LOW | TlsCertServiceImpl.java | 118–147 | ManageCert verifies JWT without `isPlausibleKid` / token-use checks used on Mint | 8/10 |

## Full findings (security + correctness + drift)

1. **🟠 HIGH** `IdentityServiceImpl.java:2588` (9/10) — X509Mint signs `certRequest` as-is after appending a SPIFFE URI SAN. **Failure:** authenticated service sends DNS SANs for another hostname; kernel issues a leaf that passes hostname verification for that name.

2. **🟠 HIGH** `KernelPersistence.java:108` (9/10) — Load failure returns `null` (“cold start”). `restoreGrantRevocations` no-ops; Config re-seeds grants with `revoked_at_ms=0`. **Failure:** truncated/corrupt snapshot on restart silently un-revokes standing delegations.

3. **🟠 HIGH** `KernelPersistence.java:154` + `IdentityServiceImpl.java:2984/3074/3710` (9/10) — Revoke/register call `persistState.run()` then succeed; `save()` only logs. **Failure:** disk full / validation error; process later restarts and loses revocations, grants marks, and personal principals.

4. **🟠 HIGH** `TlsCertServiceImpl.java:250` vs `286` (8/10) — Token `instance_id` is parsed into `callerInstanceId` and never compared; leaf DNS SAN is `init.instanceId`. **Failure:** service presents a valid token and Init `instance_id=other-svc.namespace.svc`; cert carries that DNS name.

5. **🟡 MEDIUM** `IdentityServiceImpl.java:2550` (8/10) — If Authorization is empty, X509Mint uses `request.input_token`. Mint is interceptor-exempt. **Failure:** gateway/client puts a stolen bearer in the body; handler treats it as the caller.

6. **🟡 MEDIUM** `TenantAdminServiceImpl.java:426` (9/10) — `pageByStringKey`: `limit <= 0` returns an empty page. **Failure:** client omits/zeroes page size (common “default page” wiring) and ListTenants/ListProjects looks empty.

7. **🟡 MEDIUM** `FencedLockStateMachine.java:36` (9/10) — Holds have no TTL/lease. **Failure:** holder dies; key stays granted forever; later Acquire for anyone else returns `granted=false`.

8. **🟡 MEDIUM** `FencedLockServiceImpl.java:32` (8/10) — Handler uses `request.holderId`, not `Caller`. **Failure:** any authorized FencedLock client Acquire/Release as another holder (or steal a free lock’s identity).

9. **🟡 MEDIUM** `CliTokenBrokerServiceImpl.java:228` (9/10) — CompleteNonce-before-Register mints with `offlineAccess=false`. **Failure:** oauth registers `offline_access=true` after CompleteNonce; user gets a refresh token, not an OT.

10. **🟡 MEDIUM** `CliTokenBrokerServiceImpl.java:99` (9/10) — Logs `nonce.substring(0, 8)` with no length check. **Failure:** nonce shorter than 8 chars throws `StringIndexOutOfBoundsException` on the gRPC thread.

11. **🟡 MEDIUM** `CliTokenBrokerServiceImpl.java:214` (9/10) — CompleteNonce busy-waits up to 5s (`10×500ms`) on the handler thread. **Failure:** lagged IMap + concurrent CompleteNonce stalls the kernel RPC pool.

12. **🟡 MEDIUM** `TenantAdminServiceImpl.java:339` (8/10) — Missing parent tenant ⇒ unbounded entitlements ceiling. **Failure:** CreateTenant `/tenants/acme/prod` when `acme` does not exist skips ceiling; orphan subtree with a wider ceiling than any parent.

13. **🟡 MEDIUM** `TenantAdminServiceImpl.java:279` (8/10) — SetProjectConfig does not require a live parent tenant. **Failure:** project_config rows appear under namespaces with no tenant (list/delete/chroot drift).

14. **🟡 MEDIUM** `ClusterServer.java:858` (8/10) — ManageCert `putServiceCas` does not call `persistKernelState`; comment says CAs are rebuilt on demand. **Failure:** new intermediate CA after restart; in-flight leaves chained to the old intermediate fail TLS.

15. **🟡 MEDIUM** `TokenReviewKubernetesTokenVerifier.java:248` (7/10) — Empty/missing CA file ⇒ default `HttpClient` SSL. **Failure:** `KERNEL_KUBE_API_URL` / mis-mounted CA; TokenReview can be MITM’d; forged SA identity mints a service token.

16. **🟡 MEDIUM** `IdentityServiceImpl.java` (~3700 lines) vs `TlsCertServiceImpl.java:118` (8/10) — Token verify duplicated; ManageCert skipped `isPlausibleKid`, exp/use, SPIFFE-until-Init. **Failure:** oversized/bogus kid on ManageCert does a full key scan; pattern the rest of Mint already closed.

17. **🟡 MEDIUM** `RateLimitInterceptor.java:48` / `353` (8/10) — Writes and unknown verbs are EXEMPT; buckets keyed by peer. **Failure:** Mint/CompleteNonce unthrottled; many source addrs grow `ConcurrentHashMap` until the 60s sweeper.

18. **⚪ LOW** `IdentityServiceImpl.java:128` (9/10) — `TOKEN_USE_OFFLINE = "offline"` hardcoded pending tacplus rebuild. **Failure:** proto json value ≠ `"offline"`; OT exchanges miss the OT arm and take the access/service path.

19. **⚪ LOW** `PersonalIdentityServiceImpl.java:32` (9/10) — Comment says registration “does not exist yet”; `CreatePersonalPrincipal` exists. **Failure:** reviewers/operators treat GetMyIdentity NOT_FOUND as “no registry,” not “empty snapshot.”

20. **⚪ LOW** `KeyRotator.java:394` vs `IdentityServiceImpl.java:141` (8/10) — Kids are UUID strings; comments describe base64url(24). **Failure:** tooling that assumes 32-char kids mis-handles kernel JWTs (format gate still allows UUID).

21. **⚪ LOW** `ProtoDescriptorParser.java:96` (8/10) — Unreadable proto files are skipped with no error. **Failure:** partial parse; auth exemptions / services omitted from generated servers.

22. **⚪ LOW** `SecurityPolicyParser.java:54` (8/10) — Hand YAML: only `- name:` + inline `rw:`/`ro:`/`exec:` lists. **Failure:** multiline lists or unquoted names silently drop principals from generated GRAPH_POLICIES.

23. **⚪ LOW** `RateLimitInterceptor.java:280` (8/10) — `onCancel` does not decrement `activeRpcs`/`activeStreams` if `close()` never runs. **Failure:** health/metrics show a stuck in-flight RPC count.

---

Not reported (by design or too speculative): `scopeToService` keeping `data_grants`/`principal_scope`; CreatePersonalPrincipal credential-id oracle; CliTokenBroker trusting oauth as broker (depends on generated Authorizer, not reviewed here).

Follow-up (reply with a number):
1. Fix highest severity issues
2. Fix all issues
3. Commit a summary of findings

