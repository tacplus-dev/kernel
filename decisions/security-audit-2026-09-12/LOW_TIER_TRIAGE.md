# Low-Tier Triage — kernel security audit 2026-09-12

Deduplicated across `CONSOLIDATED_REPORT.md`, `raw-codex.md`, `raw-fable.md`, `raw-grok-pass1.md`
and `raw-grok-pass2-complete.md`. Every item below was re-checked against the **current** working
tree (HEAD = `a163e83`), i.e. after the Critical/High/Medium fixes that landed today. Items already
fixed by that work, and tool claims that turned out not to be bugs, are listed in
[Dropped](#dropped--verified-not-a-bug-or-already-fixed) at the end rather than silently omitted.

Descriptions are my own reading of the code, not the tools' wording.

Paths are relative to
`server/src/main/java/com/gitlab/secondstarcavalier/controlplane/schematic/services/kernel/` and
`codegen/src/main/java/com/gitlab/secondstarcavalier/controlplane/codegen/` unless noted.

27 genuine items, grouped into 4 file-disjoint batches for parallel dispatch (see
[Batches](#dispatch-batches)). Within each batch items are ordered most- to least-worth-fixing.

---

## Batch 1 — identity / certificate core

Files: `cluster/IdentityServiceImpl.java`, `cluster/TlsCertServiceImpl.java`,
`cluster/KeyRotator.java`, `cluster/ServiceIntermediateCa.java`

### L1. MintClientToken's lifetime ceiling ignores the cred_pair's own `expires_at`
**Where:** `cluster/IdentityServiceImpl.java`, `mintClientToken` (~3646–3685).
**Bug:** `718b89a` added the `maxTokenLifetimeSeconds` ceiling, which closed the "token valid until
2099" hole. But the cred_pair's own `expires_at` is only used as a *pass/fail gate* on the
credential at mint time (~3647) — it is never used as a ceiling on the token's `exp`. A holder who
mints one second before the cred_pair expires still gets a token valid for the full 30-day
`max_token_lifetime`, so revoking/expiring the credential leaves up to 30 days of live access.
**Fix sketch:** in the `exp` computation, lower `maxExp` to `min(now + maxTokenLifetimeSeconds,
matched.getExpiresAt().getSeconds())` when the cred_pair carries a positive `expires_at`. Keep the
existing INVALID_ARGUMENT message shape so the two ceilings read the same to a caller.
**Shares files with:** L2, L3, L4, L5, L6, L7, L9.

### L2. Cred-pair and device proof JWTs have no anti-replay binding
**Where:** `cluster/IdentityServiceImpl.java`, `mintClientToken` (~3655–3661) and
`verifyDeviceProof` (688–722).
**Bug:** both paths do `TokenWrapper.parse` → `proof.verify(credential public key)` and nothing
else. `TokenWrapper.verify()` does enforce `exp` (this is the part Codex got wrong), so replay is
bounded by the proof's own expiry — but there is no `jti` seen-set, no server-issued challenge/nonce,
and no `aud` check tying the proof to kernel. Anyone who captures one proof can replay it verbatim
for fresh tokens/principal registrations until it expires, and nothing constrains how long a client
may set that expiry. Every kernel-*minted* token gets a fresh `jti` (`setJTI` at ~782, 975, 1498,
…); these client-minted proofs are the one credential class with no such handling.
**Fix sketch:** require `aud` on the proof and check it equals the kernel audience; cap the accepted
proof lifetime (e.g. 60s) independently of what the client asked for; keep a short-TTL `jti` seen-set
(Hazelcast IMap with TTL = the cap) and reject a repeat. Single shared helper used by both call
sites — the duplication between them is itself part of the problem.
**Shares files with:** L1, L3, L4, L5, L6, L7, L9.

### L3. MintClientToken stamps the audience as a string literal, not the proto package constant
**Where:** `cluster/IdentityServiceImpl.java:3693`, `mintClientToken`.
**Bug:** `.setAudience("kernel")`. Every other mint path in the file uses
`Kernel.getDescriptor().getPackage()` (779, 972, 1495, 2031, 2937, 2977). If the proto package is
ever renamed, C2S cred_pair tokens silently get an audience no authenticator accepts, and the
failure shows up as blanket UNAUTHENTICATED with nothing pointing at this line.
**Fix sketch:** replace the literal with `Kernel.getDescriptor().getPackage()`, matching the six
sibling call sites. Trivial; the only care needed is confirming no test asserts the literal.
**Shares files with:** L1, L2, L4, L5, L6, L7, L9.

### L4. Two claim constants are hardcoded strings pending a tacplus rebuild
**Where:** `cluster/IdentityServiceImpl.java:113` (`TOKEN_USE_OFFLINE = "offline"`) and `:123`
(`PARENT_SUB = "parent_sub"`).
**Bug:** every sibling constant is derived from the proto enum via `Helpers.tokenUseToString(...)` /
`Helpers.jwtPayloadTypeToString(...)`. These two are literals with TODOs saying tacplus has not been
rebuilt with `token.proto` commit `9acf59f`. If the enum's `(spec.json_return_value)` is anything
other than `"offline"`, offline tokens miss the OT arm of every exchange and silently take the
access/service path — a real authorization difference, not just cosmetics. This is exactly the
tacplus-duplication pattern the project forbids; it is Low only because it is currently correct.
**Fix sketch:** this one is *not* a code fix in kernel — rebuild tacplus with the renamed
`token.proto` enum values, then swap both literals for the `Helpers.*` calls and delete the TODOs.
Until the rebuild, add a static-init assertion that the generated enum's string equals the literal,
so drift fails at boot rather than at runtime.
**Shares files with:** L1, L2, L3, L5, L6, L7, L9.

### L5. Key-id format comment and regex describe a scheme kernel does not use
**Where:** `cluster/IdentityServiceImpl.java:129–137` (`KID_MAX_LENGTH`, `KID_FORMAT`,
`isPlausibleKid`) and `cluster/KeyRotator.java:420` (`newKey`).
**Bug:** the comment says "Production kids are base64url(24 bytes) = 32 chars of `[A-Za-z0-9_-]`
(see `generateRandomID`)". `KeyRotator` actually issues `UUID.randomUUID().toString()` — 36 chars
with dashes — and `generateRandomID` is not referenced anywhere in the rotator. Additionally
`KID_FORMAT` caps at `{1,512}` while `KID_MAX_LENGTH` defaults to 128 and is checked separately, so
the regex's own bound is dead. Nothing breaks today (UUIDs pass the permissive charset), but any
tooling or future tightening written against the stated format will mis-handle real kernel kids.
**Fix sketch:** decide which is canonical. Cheapest: correct the comment to describe UUID kids and
drop the `{1,512}` bound to `+` since `KID_MAX_LENGTH` already gates length. If the base64url(24)
scheme is actually wanted, change `KeyRotator.newKey` to emit it — but that is a format change
across live tokens, so treat it as its own item, not part of this cleanup.
**Shares files with:** L1, L2, L3, L4, L6, L7, L9.

### L6. `CreatePersonalPrincipal` cap and credential-uniqueness checks are a TOCTOU against the write
**Where:** `cluster/IdentityServiceImpl.java`, `createPersonalPrincipal` (3778–3818).
**Bug:** the registry-full check and the "one key, one person" credential scan both read
`principalMap.proto()`, then the method writes with `putPersonalPrincipals(randomUUID, ...)` — no
lock, no compare-and-set, and the key is fresh every time so nothing collides. Two concurrent
registrations of the same credential both see it absent and create two principals; `verifyDeviceProof`
then resolves whichever the iteration order yields first. That is precisely the "the person silently
becomes two people" outcome the code's own comment says is forbidden. The `MAX_PERSONAL_PRINCIPALS`
cap can likewise be overshot, which matters because the comment explains the cap exists to stop
`validateKernelDiskState` from failing every subsequent snapshot.
**Fix sketch:** serialize the read-check-write under a Hazelcast lock (or the FencedLock) keyed on
the principal registry, or add a credential-id → principal-id index map and use `putIfAbsent` on it
as the uniqueness gate before writing the principal row. Re-check the cap inside the critical section.
**Shares files with:** L1, L2, L3, L4, L5, L7, L9.

### L7. `mintClientToken` resolves a cred_pair id by first match across all tenants
**Where:** `cluster/IdentityServiceImpl.java`, `mintClientToken` (~3628–3640).
**Bug:** the lookup loops every `TenantConfigEntry` and every `CredPair` in it, breaking on the first
id match; the owning entry's `tenantName` then becomes the minted token's namespace. Nothing —
not `TenantAdminServiceImpl.updateTenantConfig`, not the proto — enforces that cred_pair ids are
unique across tenants. Two tenants that configure the same id make the winner depend on the
`tenant_configs` iteration order, and the loser's credential mints tokens scoped to somebody else's
namespace.
**Fix sketch:** either enforce global uniqueness on write (reject in `updateTenantConfig` if the id
already exists under a different tenant) or make this lookup collect all matches and refuse with
FAILED_PRECONDITION when there is more than one. Write-side enforcement is better but touches
`TenantAdminServiceImpl.java`, which would break batch disjointness — prefer the read-side refusal
here and file the write-side guard separately.
**Shares files with:** L1, L2, L3, L4, L5, L6, L9.

### L8. ManageCert's hand-rolled token verification is missing hardening the Mint path has
**Where:** `cluster/TlsCertServiceImpl.java`, `manageCert` (126–155).
**Bug:** ManageCert parses the raw bearer itself (the cluster interceptor deliberately bypasses this
service) and then linearly scans `verifyingKeysReader.get()` for a matching kid. Compared to
`IdentityServiceImpl.doX509Mint` (2543–2566) it is missing: (a) the `isPlausibleKid` fast-reject, so
an attacker-supplied oversized/garbage kid forces a full O(keys) scan per stream open — the exact
Phase 0.1 DoS gate `isPlausibleKid`'s javadoc says "every externally-influenced kid scan calls it";
and (b) any `token_use` / `sub_type` class check, so a non-service token whose `sub` happens to be a
SPIFFE URI reaches the stream. `token.verify()` does cover expiry, so this is hardening drift, not
an auth bypass. The key-lookup loop is also a verbatim copy of Mint's.
**Fix sketch:** make `IdentityServiceImpl.isPlausibleKid` package-visible (or move it to a shared
helper next to `SpiffeIds`) and call it before the scan; add the token-use/sub-type assertion Mint
makes. Better still, extract the parse → plausible-kid → key-lookup → verify sequence into one
shared method both call sites use, which also removes the copy.
**Shares files with:** L9.

### L9. Two independent `getOrCreateIntermediateCa` implementations race each other
**Where:** `cluster/IdentityServiceImpl.java:2732` and `cluster/TlsCertServiceImpl.java:417`
(helper: `cluster/ServiceIntermediateCa.java`).
**Bug:** both methods are `synchronized`, but on *different* instances, so the monitor buys nothing
across them. A concurrent `X509Mint` and `ManageCert` for the same service both read
`serviceCaReader.apply(serviceName)`, both miss, both generate a P-384 intermediate, and both write
via `caState.putServiceCas(serviceName, ...)`. The last write wins; the loser has already signed a
leaf chaining to an intermediate no longer in state, and that leaf fails chain verification for its
whole lifetime. The two bodies are otherwise near-identical copies — `TlsCertServiceImpl`'s comment
even says "same pattern as IdentityServiceImpl".
**Fix sketch:** move the whole get-or-create into `ServiceIntermediateCa` as a single static method
taking the reader/writer functions, and guard it with a cluster-wide lock keyed on the service name
(the FencedLock or a Hazelcast lock) rather than a JVM monitor — the race is also cross-node, since
two kernel pods can be handling the two RPCs. Both call sites then delegate. Keep the fix inside
`ServiceIntermediateCa.java` so it does not reach into `ClusterServer.java` (where the two
`putServiceCas` lambdas live, at 781 and 854) and collide with Batch 2.
**Shares files with:** L1–L8.

---

## Batch 2 — cluster runtime

Files: `cluster/ClusterServer.java`, `cluster/StateServer.java`, `cluster/LocalJwkSource.java`,
`cluster/RateLimitInterceptor.java`

### L10. Membership listener dereferences `clusterPublisher` before the field is assigned
**Where:** `cluster/ClusterServer.java`, constructor — listener registered at ~440–463, calling
`clusterPublisher.onMembershipChange()` at 450 and 461; the field is assigned at 566.
**Bug:** the Hazelcast membership listener is registered ~120 lines before `this.clusterPublisher`
is set. A member join or leave landing in that window runs on the Hazelcast event thread and NPEs.
Startup is exactly when membership events are most likely (the node is joining), and the throw
happens on Hazelcast's thread, so the constructor completes and the node comes up looking healthy
while the publisher never sees that event.
**Fix sketch:** move the `addMembershipListener` call below the `clusterPublisher` assignment, or
null-guard both call sites (`if (clusterPublisher != null)`) and re-publish once at
`clusterPublisher.start()`. Moving the registration is cleaner — check nothing between 463 and 566
depends on the listener already being attached.
**Shares files with:** L11, L12.

### L11. Tenant snapshot restore indexes tenant records by leaf name, so same-named tenants collide
**Where:** `cluster/ClusterServer.java` ~1194–1206, in the disk-snapshot rehydration.
**Bug:** `byLeaf.put(t.getName(), t)` builds the index, and `Kernel.Tenant` is written with
`.setName(leaf)` (`TenantAdminServiceImpl.java:107`) — the leaf segment only, not the full
namespace. `/tenants/acme/prod` and `/tenants/beta/prod` therefore overwrite each other in the map,
and the reconstruction loop hands both full-path keys whichever record survived. After a restart one
namespace carries the other tenant's `status` and `constraints.entitlements_ceiling` — a ceiling
widening or a wrongly-active tenant, silently, only on restart.
**Fix sketch:** the snapshot already carries full-path keys in `tenant_configs` and
`project_configs`; the `Tenant` record is what lacks the path. Either persist the full namespace
alongside each tenant in the snapshot and index on that, or match each full-path key to its tenant
by comparing full paths rather than leaves. If the snapshot format changes, keep a leaf-based
fallback for snapshots written by the old code and log when it fires.
**Shares files with:** L10, L12.

### L12. Snapshot rehydration fails *open* on a partial restore, while `load()` was hardened to fail closed
**Where:** `cluster/ClusterServer.java` — the rehydrate block ending ~1209–1212, and
`restorePersonalPrincipals` ~1123–1131.
**Bug:** `deffa45` deliberately made `KernelPersistence.load()` refuse to boot when a snapshot exists
but cannot be read ("refusing to come up as a cold start"). The rehydration that *consumes* that
snapshot did not get the same treatment: each loop is wrapped in one try/catch that logs
"Failed to fully rehydrate kernel snapshot (continuing)" and lets the node start. One malformed
tenant, CA or revocation row aborts the rest of the loop, so kernel boots with an arbitrary prefix
of the snapshot applied — e.g. revocations restored but tenants not, or vice versa. That is the
same silent-partial-state class the load hardening closed, one layer up.
**Fix sketch:** make rehydration all-or-nothing at the same severity as `load()`: let the exception
propagate and refuse to start, or restore into staging collections and swap them in only after every
row applied. At minimum log at ERROR with the failing key and mark the node NOT_SERVING instead of
SERVING, so a partial restore is visible rather than logged and forgotten.
**Shares files with:** L10, L11.

### L13. Log-stream observers overwrite each other on the peer key; the stale cancel unregisters the new one
**Where:** `cluster/StateServer.java`, `addLogObserver` / `removeLogObserver` (23–30).
**Bug:** `logObservers.put(peer, observer)` replaces any existing entry without calling
`onCompleted()`/`onError()` on the displaced stream — that client hangs until its own deadline.
Worse, `removeLogObserver(peer)` is keyed only on the peer address, so when the *old* stream is
finally cancelled it removes the *new* stream's entry, and the live client silently stops receiving
log messages. Peer address is not unique per stream: two streams from the same pod, or a reconnect
before the old cancel lands, both hit this.
**Fix sketch:** key the map on a per-stream token (a UUID handed back by `addLogObserver` and passed
to `removeLogObserver`), or keep a `Map<String, List<StreamObserver>>` and remove by identity. Either
way, complete the displaced observer explicitly if you keep last-writer-wins.
**Shares files with:** none.

### L14. Kernel's own Authorizer lags key rotation by up to 10 seconds with no on-miss refresh
**Where:** `cluster/LocalJwkSource.java` (`REFRESH_SECONDS = 10`, `start`).
**Bug:** the source pushes keys at start and then on a fixed 10s schedule. There is no
refresh-on-miss path, unlike the generated authenticator's `waitForKeyByKid` retry that every other
consumer gets. A token minted with a key published seconds ago is rejected as "unknown kid" by
kernel's own Authorizer until the next tick — so an RPC to TenantAdmin or FencedLock immediately
after a rotation fails for up to 10s, and the caller sees UNAUTHENTICATED rather than a retryable
status.
**Fix sketch:** expose a `refreshNow()` on the source and have the sink call it once on a kid miss
before rejecting (with a short single-flight guard so a bogus kid cannot force a refresh per
request). Keep the periodic push as the backstop. Do *not* copy the interceptor's blocking
sleep/retry loop — `isPlausibleKid`'s javadoc says that retry lives exclusively on the cross-kernel
propagation path.
**Shares files with:** none.

### L15. `onCancel` never decrements the in-flight counters it was written to catch
**Where:** `cluster/RateLimitInterceptor.java`, `trackActiveCall` (226–257).
**Bug:** the interceptor increments `activeRpcs`/`activeStreams` on call start and decrements in the
wrapped `close()`. It then wraps the listener with the comment "Also wrap the listener to catch
cancellations" — but the `onCancel()` override does nothing except `super.onCancel()`. gRPC does not
guarantee `close()` runs on a client cancellation or a transport drop, so every such call leaks a
count permanently. `getActiveRpcs()`/`getActiveStreams()` feed health and metrics, so the reported
in-flight count drifts upward forever and never returns to zero on an idle node.
**Fix sketch:** hoist the `closed` flag out of the `SimpleForwardingServerCall` into an
`AtomicBoolean` shared with the listener, and have both `close()` and `onCancel()` decrement through
it exactly once. If nothing else ends up needing the listener wrapper, the alternative is to delete
it and do the decrement in a `Context` cancellation callback instead — but the shared-flag version is
the smaller change.
**Shares files with:** none.

---

## Batch 3 — tenant admin, CLI broker, fenced lock

Files: `cluster/TenantAdminServiceImpl.java`, `cluster/CliTokenBrokerServiceImpl.java`,
`fencedlock/FencedLockStateMachine.java`, `fencedlock/RatisFencedLock.java`

### L16. `pageByStringKey` returns an empty page when `limit <= 0` instead of applying a default
**Where:** `cluster/TenantAdminServiceImpl.java`, `pageByStringKey` (450–460); reached from
`listTenants` (193) and `listProjects` (325).
**Bug:** `limit <= 0` — which is what a client sends when it omits `page.limit`, the common
"just give me the default page" wiring — returns an empty item list with `total` set to the real
count. A caller sees "0 tenants, total 12" and has no cursor to page with. Nothing else in the file
supplies a default.
**Fix sketch:** substitute a `DEFAULT_PAGE_LIMIT` constant when `limit <= 0` (and cap an
unreasonably large requested limit at a `MAX_PAGE_LIMIT` while you are there). Both list RPCs get the
fix for free since they share this helper.
**Shares files with:** L17, L18.

### L17. `SetProjectConfig` writes a project row without requiring a live parent tenant
**Where:** `cluster/TenantAdminServiceImpl.java`, `updateProjectConfig` (271–287).
**Bug:** `636378e` closed the analogous gap for `CreateTenant` (a missing immediate parent now
throws NOT_FOUND). The project path never got the same check: `updateProjectConfig` validates only
that `project_namespace` and `config` are present, then writes. A project config row can be created
under a namespace with no tenant record — an orphan that `listProjects` will happily return (it
filters on `isImmediateChild`, not on tenant existence) and that survives `DeleteTenant`, which after
`4d1c690` refuses on nested *tenants* but says nothing about nested projects.
**Fix sketch:** mirror `createTenant`'s parent check — derive the parent namespace from
`project_namespace` and require `configMap.getTenants(parent)` to exist and be ACTIVE, else
NOT_FOUND. Then decide whether `DeleteTenant`'s nested check should also refuse on surviving project
configs; if so, extend the same FAILED_PRECONDITION message.
**Shares files with:** L16, L18.

### L18. Self-lockout guard resolves the caller's cred_pair id with a hand-rolled JSON scan
**Where:** `cluster/TenantAdminServiceImpl.java`, `jsonStringField` (622–640), used by
`callerCredPairId` (589–595).
**Bug:** `jsonStringField` finds `"<field>"`, then the next `:`, then the next two `"`. It does not
handle escaped quotes, does not distinguish a top-level key from the same text appearing inside a
nested object or a string *value*, and cannot tell an absent claim from a malformed one — all three
return a wrong-or-null answer with no error. This feeds the invariant-3 self-lockout guard, so a
token payload whose claims happen to contain the text `"sub"` (a claim value carrying JSON, which
`buildClaimsStruct` in `IdentityServiceImpl` shows is a real shape here) can make the guard read the
wrong subject and skip the check.
*(Note: Grok claimed `"sub_type"` would false-match `"sub"`. It does not — the needle includes the
closing quote. That specific claim is wrong; the underlying fragility above is real.)*
**Fix sketch:** parse the payload with the JSON library already on the classpath (`com.google.gson`
is imported in `IdentityServiceImpl`) and read top-level fields from the parsed object, or — better
— take the claims from the verified `Caller`/`TokenWrapper` accessors instead of re-parsing the raw
payload string at all. Delete `jsonStringField` once nothing calls it.
**Shares files with:** L16, L17.

### L19. `nonce.substring(0, 8)` is called ~15 times with no length check
**Where:** `cluster/CliTokenBrokerServiceImpl.java` — line 99 and roughly a dozen more log sites
throughout `brokerStream` and `queueTokenDelivery`.
**Bug:** the nonce is client-supplied and the truncation is purely for log hygiene, but a nonce
shorter than 8 characters throws `StringIndexOutOfBoundsException`. Several of these sites are on the
gRPC handling thread inside `onNext`, and at least one (line 99) is inside the mint-failure `catch`,
so the exception replaces a handled error with an unhandled one and kills the broker stream. This
survived `953cbc3` (which only reworked the busy-wait).
**Fix sketch:** one private `shortNonce(String)` helper that returns
`n == null ? "" : n.substring(0, Math.min(8, n.length()))`, and replace every call site. Separately,
reject a nonce below a minimum length at the top of `REGISTER_NONCE`/`COMPLETE_NONCE` — a 3-character
nonce is not a credential worth brokering.
**Shares files with:** L20, L21.

### L20. CompleteNonce-before-Register hardcodes `offlineAccess = false`, and the later registration only replays it
**Where:** `cluster/CliTokenBrokerServiceImpl.java`, `completeWithRegistration` entry==null branch
(~250–262), plus the buffered-replay branch of `REGISTER_NONCE` (~189–206).
**Bug:** when the completion arrives before any registration, the mint is forced to
`mintRefreshToken(complete, nonce, false)` because no registration has yet said whether the client
asked for offline access. The token is buffered under `delivery:<nonce>` and the nonce is marked
consumed. A `RegisterNonce` that then arrives with `offline_access = true` hits the buffered-replay
branch, hands back the already-minted non-offline token, and never re-mints. The user asked for an
offline token and silently gets an ordinary refresh token; the CLI's long-lived session then expires
early with no error anywhere.
**Fix sketch:** don't mint in the no-registration case. Buffer the `CompleteNonce` *request* (subject
+ claims) instead of a minted token, and mint at registration time when `offline_access` is known.
That also removes L21's "minted and discarded" case. If buffering the request is too large a change,
the fallback is to fail the replay when the registration's `offline_access` disagrees with what the
buffered token was minted as, so the client retries rather than silently downgrading.
**Shares files with:** L19, L21.

### L21. A token can be minted and then silently dropped when buffering is refused
**Where:** `cluster/CliTokenBrokerServiceImpl.java`, `completeWithRegistration` (~250–303) and
`queueTokenDelivery` (306–338).
**Bug:** both delivery paths mint first and buffer second. `queueTokenDelivery` can legitimately
return false — lock busy, `MAX_BUFFERED_DELIVERIES` reached, or an existing entry it refuses to
replace — and the caller just falls through without marking the nonce consumed. A valid refresh token
for a real user has been signed and is now unreferenced: never delivered, never revoked, and live
until its own expiry. Related: `handleCompleteNonce` does `nonceMap.remove(nonce)` before minting and
never restores the registration if the mint returns null, so the waiting oauth instance is stranded
with no entry to retry against.
**Fix sketch:** reorder so the delivery slot is reserved (`putIfAbsent` a placeholder, or take the
cap lock) *before* minting, and mint into the reserved slot — release the slot if the mint fails. For
the removed-registration case, restore the entry with `putIfAbsent` when `mintRefreshToken` returns
null so a retry can find it. Overlaps L20's fix: buffering the request rather than the token makes
both disappear, so sequence them together.
**Shares files with:** L19, L20.

### L22. The FencedLock Raft log never snapshots, so it grows forever and every restart replays from index 0
**Where:** `fencedlock/FencedLockStateMachine.java` (no `takeSnapshot` override on `BaseStateMachine`)
and `fencedlock/RatisFencedLock.java` (~85–115: `RaftProperties` sets only `setStorageDir`, no
snapshot-trigger or log-purge keys).
**Bug:** with no snapshot ever taken, Ratis has no purge point, so the segment log accumulates every
Acquire/Release for the life of the cluster. Disk grows unbounded and node startup time grows linearly
with total lock traffic — a slow-motion availability problem on the service that gates cluster
leadership. The state itself is tiny (`Map<String, Hold>`), so this is purely unimplemented plumbing.
**Fix sketch:** implement `takeSnapshot()` to serialize the `holds` map plus the last-applied
term/index to the state machine's snapshot dir, and `initialize`/`reinitialize` to load it back; then
set `RaftServerConfigKeys.Snapshot.setAutoTriggerEnabled` and a trigger threshold, plus
`RaftServerConfigKeys.Log.setPurgeUptoSnapshotIndex`, in `RatisFencedLock`. Note the existing
`RELEASE_UNVERIFIED` opcode exists to replay pre-hardening entries — confirm a snapshot taken after
`7018e4c` does not strand that compatibility path.
**Shares files with:** L23.

### L23. A hold has no lease, so a dead holder wedges its key permanently
**Where:** `fencedlock/FencedLockStateMachine.java` — the `Hold` record (44) and `applyAcquire`
(84–95).
**Bug:** `Hold` carries only `holderId` and `fencingToken`; there is no expiry and nothing sweeps.
`applyAcquire` refuses any other holder while a hold exists, and `applyRelease` requires both the
holder identity and the exact granted token. A holder that crashes without releasing leaves the key
held forever — no operator path short of restarting the Raft group or replaying a crafted release.
*Lower confidence than the rest of this batch:* a fencing lock is legitimately allowed to be
lease-free, with the resource owner doing the fencing on the monotonic token. Confirm the intended
contract before changing behaviour.
**Fix sketch:** if a lease is wanted, add an `expiresAtMs` to `Hold` set from the Raft-applied
timestamp, have `applyAcquire` treat an expired hold as absent (issuing a *new*, higher token so
fencing still works), and add a renew opcode for live holders. If a lease is *not* wanted, document
that in the class javadoc and add an explicit admin force-release opcode instead — the current state
is neither.
**Shares files with:** L22.

---

## Batch 4 — codegen

Files: `generator/GeneratorContext.java`, `codegen/src/main/resources/templates/SecurityAuthenticator.java.template`,
`generator/BackendServiceServerGenerator.java`, `ProtoDescriptorParser.java`, `SecurityPolicyParser.java`

### L24. Auth exemptions are collected across every parsed proto and matched without the package
**Where:** `generator/GeneratorContext.java`, `getNoAuthServiceNames` (293–314); consumed by
`generator/SecurityAuthenticatorGenerator.java:40–41` (`buildNoAuthSet`) and matched by
`templates/SecurityAuthenticator.java.template`, `isNoAuthMethod` (290–301).
**Bug:** the collector walks `parser.getAllFiles()` — every proto in the build, not just the ones
belonging to the service being generated — and records exemptions as bare `ServiceName` or
`ServiceName/RpcName`, dropping the proto package. `isNoAuthMethod` then strips the package off the
incoming method too (`service.substring(service.lastIndexOf('.') + 1)`) before comparing. So an
`auth_disabled` RPC declared in *any* proto exempts an identically-named RPC in *every* package. The
generated `NO_AUTH_METHODS` already carries `Mint/ListJwks`, `Auth/Authorize` and
`Session/BrokerSession` from other services' packages. Latent today — no kernel proto reuses those
names — and it ships an unauthenticated RPC the moment one does. Note the template's javadoc already
worries about substring collisions and fixed *that*; this is the package axis, still open.
**Fix sketch:** qualify the entries with the proto package on both sides — emit
`pkg.Service/Rpc` from `getNoAuthServiceNames` and compare against the full `fullMethodName` in
`isNoAuthMethod` instead of the simple name. Keep the existing exact-equality (never substring)
property. Regenerate and diff `NO_AUTH_METHODS` to confirm nothing that *should* be exempt drops off.
**Shares files with:** none (within this list).

### L25. Generated view `Watch` RPCs emit no `checkAccess` call
**Where:** `generator/BackendServiceServerGenerator.java`, the view-RPC emitter (312–341).
**Bug:** the emitted `watch<View>` body goes `NamespaceScope.current()` → build snapshot → `onNext`
→ register watcher, with no `checkAccess(...)` — while the equivalent hand-written fragment
`templates/fragments/server_collection_watch.java.template:6` does call
`checkAccess(field, OperationType.READ)`, as does every other read fragment. Compounding it, view
servers deliberately pass `SecurityAuthenticator.NO_POLICY_GRAPH` (see
`templates/ViewServer.java.template:59,85` and the javadoc at `BackendServiceServerGenerator.java:520–528`),
so a view is unauthorized by construction. That is defensible while a view is a read-only merge of
already-scoped sources, but nothing at build time enforces that property. Latent: no kernel proto
declares view sources yet. `93a0bfd` closed the sibling fail-open for write-capable *state* roots;
the view path was explicitly left as the exception.
**Fix sketch:** emit the same `checkAccess(..., OperationType.READ)` the collection-watch fragment
emits, so a view inherits its source's policy rather than none. If views must stay policy-free, add a
build-time assertion that every view's source collections are themselves namespace-scoped, and make
the javadoc say that is the invariant being relied on.
**Shares files with:** none.

### L26. `ProtoDescriptorParser` silently drops any proto it cannot read
**Where:** `ProtoDescriptorParser.java` ~98–100: `catch (IOException e) { // Skip files that can't be read }`.
**Bug:** an empty catch with no log and no rethrow. A proto that fails to read — permissions, a
truncated file, an encoding problem — vanishes from the descriptor set, and codegen proceeds against
a partial model. The services in that file get no server generated, and its `auth_disabled`
exemptions and security policies simply are not there. The build succeeds and the missing pieces show
up as a runtime 404 or, worse, as a policy that silently never applied.
**Fix sketch:** rethrow as an unchecked exception naming the file so the build fails, which is the
same fail-closed stance `BackendServiceServerGenerator.graphKey` now takes for a missing policy. If
some callers genuinely need to tolerate unreadable files, log at ERROR with the path and accumulate
the failures for the caller to decide on — but silence is not an option on a path that feeds auth.
**Shares files with:** none.

### L27. `SecurityPolicyParser` silently drops block-style YAML lists
**Where:** `SecurityPolicyParser.java`, `parse` (29–76) and `parseInlineList` (91–110).
**Bug:** the hand-rolled line parser only understands `- name:` followed by *inline* `rw:`/`ro:`/
`exec:` lists on a single line. A block sequence —
```yaml
rw:
  - "service:snoopy"
```
— leaves `rw:` parsing to `parseInlineList("")`, which returns an empty list, and the `- "service:snoopy"`
lines that follow start with `- ` but not `- name:`, so they are skipped entirely. The result is a
policy with no principals, emitted into `GRAPH_POLICIES` with no warning. That direction fails
*closed* (nobody is authorized), so it is a silent breakage rather than a hole — but it is silent,
and the file's own javadoc leans on "the format is simple and machine-generated" as the justification
for not using a YAML library. `extractQuotedValue` likewise returns an unquoted name verbatim,
trailing comment included.
**Fix sketch:** either use a real YAML parser (SnakeYAML, if it is already an acceptable codegen
dependency) or — smaller — teach the parser the block-sequence form and make anything it cannot
classify a hard error naming the line, so a format it does not understand fails the build instead of
producing an empty policy. Add a check that a parsed policy with zero principals in all three lists
is intentional rather than a parse miss.
**Shares files with:** none.

---

## Dispatch batches

Batches are file-disjoint — no two batches touch the same file — so all four can run concurrently in
the shared checkout without the collisions that hit the Medium tier today (see `4e1c23a`, which had
to re-dispatch three items after a dirty-tree collision).

| Batch | Items | Files owned |
|---|---|---|
| **1 — identity / cert core** | L1–L9 | `cluster/IdentityServiceImpl.java`, `cluster/TlsCertServiceImpl.java`, `cluster/KeyRotator.java`, `cluster/ServiceIntermediateCa.java` |
| **2 — cluster runtime** | L10–L15 | `cluster/ClusterServer.java`, `cluster/StateServer.java`, `cluster/LocalJwkSource.java`, `cluster/RateLimitInterceptor.java` |
| **3 — tenant / broker / lock** | L16–L23 | `cluster/TenantAdminServiceImpl.java`, `cluster/CliTokenBrokerServiceImpl.java`, `fencedlock/FencedLockStateMachine.java`, `fencedlock/RatisFencedLock.java` |
| **4 — codegen** | L24–L27 | `generator/GeneratorContext.java`, `templates/SecurityAuthenticator.java.template`, `generator/BackendServiceServerGenerator.java`, `ProtoDescriptorParser.java`, `SecurityPolicyParser.java` |

Notes for the dispatcher:

- **Batch 1 is the only internally-coupled one.** L8 and L9 both touch `TlsCertServiceImpl.java`, and
  L9 also touches `IdentityServiceImpl.java`, so batch 1 cannot itself be split by file. If it needs
  splitting for size, split it sequentially (L1–L7 first, then L8+L9) rather than in parallel.
- **L9's fix must stay inside `ServiceIntermediateCa.java`.** The two `putServiceCas` writer lambdas
  live in `ClusterServer.java:781` and `:854`, which batch 2 owns. Centralizing in the existing shared
  helper keeps the batches disjoint; a fix that reaches into `ClusterServer` will collide.
- **L7's better fix is write-side** (reject duplicate cred_pair ids in
  `TenantAdminServiceImpl.updateTenantConfig`), which belongs to batch 3's files. Do the read-side
  refusal in batch 1 as specified and file the write-side guard as a follow-up, or move both into
  batch 3 — don't do both halves in parallel.
- **L20 and L21 overlap.** Buffering the CompleteNonce *request* instead of a minted token resolves
  both; sequence them as one change, not two.
- **L4 is not a kernel code change** — it is blocked on a tacplus rebuild. Dispatch it as the
  static-init assertion only, or hold it until the rebuild lands.
- **Test tier is dirty before you start:** `IdentityServiceImplTest.serviceScopedEventBusAudienceTokenKeepsRoutingAliasedContractGrant`
  and `SelfAuthenticatingRpcSkipTest.selfAuthenticatingRpcsPassUnauthenticated` already fail on HEAD
  and are not audit findings. Batch 1 touches `IdentityServiceImpl`; don't let its dispatch chase
  that first failure.

---

## Dropped — verified not a bug, or already fixed

Checked against the current tree and deliberately excluded.

**Already fixed by today's Critical/High/Medium work:**

| Tool claim | Fixed by |
|---|---|
| X509Mint signs caller-supplied SANs / `is_ca` / `exp` (all 3 tools) | `1ed43cd` — `doX509Mint` now builds the cert request from kernel's own verified view; nothing identity- or constraint-bearing is carried over |
| Fail-open generated state server on the `"*"` no-policy marker (Fable #2) | `93a0bfd` — `BackendServiceServerGenerator.graphKey` now throws on a missing policy |
| `SetLogLevel` unauthorized (Fable #6) | `b5c8f31` |
| FencedLock holder identity taken from the request (Fable #13, Grok p2 #8) | `7018e4c` — `applyAcquire`/`applyRelease` now use the verified caller; the javadoc says so explicitly |
| ManageCert DNS SAN not bound to the token's `instance_id` (Fable #4, Grok #3/#4) | `dab46f8` |
| Cert issuance ignores workload revocation (Fable #11) | `9b2ba2e` — `TlsCertServiceImpl` now calls `assertNotRevoked` on every renewal (line ~275) |
| `MintClientToken` has no lifetime ceiling (Fable #7, Codex #10, Grok #4) | `718b89a` — ceiling present at ~3671. *Residual gap tracked as L1.* |
| `KernelPersistence.save()` swallows failures / corrupt load treated as cold start (Grok #2/#3, Codex #12) | `deffa45` — both now throw; the class javadoc states it. *Rehydration side tracked as L12.* |
| Tenant ceiling skipped for a missing parent (Fable #3, Grok #9/#12) | `636378e`. *Project-config equivalent still open as L17.* |
| Ceiling ignores `data_grants` / `principal_scope` (Fable #8) | `4d1c690` |
| `DeleteTenant` orphans nested tenants (Fable #12, Grok #8) | `4d1c690` |
| `has_quorum` compares the live count to itself (Fable #16) | `24ec6d0` — now `coreCount >= configuredMembers / 2 + 1` |
| Configured log level never applied at boot (Fable #17) | `aa97697` |
| CliTokenBroker busy-waits on the gRPC thread (Fable #21, Grok #11/#15) | `953cbc3` — replaced with a parked `CompletableFuture` + entry listener |
| Verifying-key retention shorter than max token lifetime (Fable #10) | `a163e83` |
| Empty JWKS pushed fleet-wide on one failed read (Fable #9) | `a163e83` |
| K8s CA fallback to the JVM default trust store (Grok #6/#15) | `d71b738` |
| Mint/CompleteNonce unthrottled (Grok #17) | `2aaa781` — `rateLimiter.registerServices` now called for the Mint definition |

**Not a bug:**

- **Codex #1, #2, #5, #6, #7, #8 — "never validates token expiration".** Already called out in the
  consolidated report's corrections. `TokenWrapper.verify()` enforces `exp`; every cited call site
  goes through it. Confirmed again while reading `doX509Mint` and `manageCert`.
- **Grok p1 #13 — `jsonStringField("sub")` matches `"sub_type"` via `indexOf`.** False. The needle is
  `"sub"` *including the closing quote*, which cannot match `"sub_type"`. The helper is fragile for
  other reasons, tracked as L18.
- **Grok p2 #5 — X509Mint accepts a bearer from the request body.** Real behaviour
  (`IdentityServiceImpl.java:2528–2530`) but intentional and documented: the `input_token` fallback
  exists for gateway-mediated calls, and the token is fully verified through the same path as a
  header-borne one. Not an authentication bypass.
- **Grok p2 #14 — `putServiceCas` does not call `persistKernelState`.** Deliberate, with the reasoning
  in the comment at `ClusterServer.java:783` and `:856` (service CAs are rebuilt on demand at startup,
  kept off the persistence hot path). The *real* problem in this area is the create race, tracked as L9.
- **Grok p1 #5 — a losing CompleteNonce still mints and delivers a second user's token.** The
  `putIfAbsent` guard in `queueTokenDelivery` and the `containsKey(DELIVERY_PREFIX + nonce)` check at
  the top of `completeWithRegistration` make a double delivery unreachable. The residual issue is that
  the losing mint is discarded rather than prevented — tracked as L21.
- **Grok p1 #16 / p2 #19 — `PersonalIdentityServiceImpl` javadoc says registration "does not exist
  yet".** The claim is accurate (`createPersonalPrincipal` exists at `IdentityServiceImpl.java:3744`,
  so the comment is stale), but it is a comment-only correction with no behavioural consequence.
  Worth folding into whatever change next touches that file rather than dispatching.
