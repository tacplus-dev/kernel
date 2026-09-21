# kernel Security & Quality Audit — Consolidated Report
2026-09-12 — multimodal review: Fable 5.1 (Claude), Codex CLI (GPT), Grok 4.6 (via GitHub Copilot CLI)
Scope: `server/src` (89 Java files, main implementation) + `codegen/src` (35 files, kernel-specific
codegen). `tacplus/` (nested copy of the already-audited tacplus repo) and all `target/` excluded.

**Kernel is the platform's auth/identity root** — token minting, verification, service delegates,
tenant state chrooting, certificate issuance. Everything else trusts it. These findings apply to
the code currently running in the live `kernel-0/1/2` pods.

Items marked **[VERIFIED]** were personally re-checked against source (read the actual function,
not just trusted the tool's claim). Everything else is tool-reported and not independently
line-verified by me, though several have 2-4-way cross-model agreement noted explicitly.

---

## Critical — fix first, these are live exploitable paths today

### 1. Certificate identity injection via X509Mint [VERIFIED — found independently by all 3 tools]
**File:** `IdentityServiceImpl.java`, `doX509Mint`, ~lines 2503-2620
Kernel authenticates the caller's own bearer token, then builds the signed certificate from
`request.getCertRequest().toBuilder().addUriSans(spiffeId).build()` — this **copies over every
field the caller already put in their request** (DNS SANs, additional URI SANs, `is_ca`,
`path_len_constraint`, `key_usage`, `exp`) and merely appends the one verified SPIFFE URI on top.
Nothing strips or rejects caller-supplied SANs/flags before signing.

**Concrete exploit:** any service holding its own valid, legitimate token calls X509Mint with a
`certRequest` that already sets `uri_sans: ["spiffe://<trust-domain>/system/services/kernel"]` (or
any other service's identity) and a far-future `exp`. Kernel signs a cert containing *both* the
caller's real identity and the injected one, root-chained, accepted by any mesh peer that matches
on URI SAN.

**I read the entire function start-to-finish; there is no SAN-stripping or validation code
anywhere in it.** This is not a maybe.

### 2. Same function: certificate lifetime has no ceiling [VERIFIED]
**File:** `IdentityServiceImpl.java` ~line 2593, same function as #1
The requested `exp` is signed as-is. This is a genuine inconsistency, not just an oversight — the
same file caps *token* lifetime against `maxTokenLifetimeSeconds`/`offlineTokenLifetimeSeconds` in
five separate places (lines ~759, 1475, 1702, 2002, 2257). The certificate path is the one place
that established pattern was dropped. A caller can mint a cert valid for years off a short-lived
token.

### 3. `SetLogLevel` has zero authorization [VERIFIED]
**File:** `ClusterSetLogLevelHandler.java`
The generated stub for this RPC is intentionally hand-replaced (it's a `(spec.command)` requiring
custom logic) — but the replacement (`handleSetLogLevel`) goes straight from parsing the request to
calling Logback, with no `checkAccess`/entitlement check anywhere in its body. Any authenticated
caller (not necessarily one entitled to cluster administration) can set the root logger to `OFF`,
silencing kernel's own auth audit logs.

### 4. Fail-open generated state server, one instance live (Fable, not personally verified — check before trusting)
**Files:** `codegen/.../generator/BackendServiceServerGenerator.java:527-537`,
`SecurityAuthenticator.java.template:229-231`, `ClusterServer.java:605`
Claim: when a state root has no computed policy, the generator emits a `"*"` no-policy marker, and
the generated authenticator treats that marker as "skip the caller check" rather than fail closed.
`ServiceConfigStateStateServiceServer` allegedly has this and is registered live — meaning any
`aud=kernel` token (including a plain user token) could call `SetConfig` and rewrite the
cluster-wide OPA/TLS/logging config every service watches. **I have not personally traced this one
end-to-end — given the severity if true, this should be the very first thing verified before
anything else on this list, ahead of even #1/#2.**

---

## High

- **Tenant ceiling escalation via grandchild tenant creation** (Fable + Grok, cross-confirmed) —
  `TenantAdminServiceImpl.java` ~339-365: creating a tenant under a *non-existent* parent skips the
  entitlements-ceiling check entirely, letting a narrowly-scoped tenant admin create a subtree with
  unlimited entitlements.
- **`MintClientToken` has no maximum lifetime** (Fable) — `IdentityServiceImpl.java:3561-3569`;
  every other mint path caps lifetime, this one only checks `exp > now`.
- **MintToken exchange doesn't cap new token lifetime against the input token's own expiry, and
  re-derives entitlements only for refresh-class inputs** (Fable) — `IdentityServiceImpl.java:1701-1716`;
  potential path to indefinitely-renewable access with stale entitlements (revocation doesn't take
  effect).
- **FencedLock: holder identity taken from the request, not the verified caller** (Fable + Grok,
  cross-confirmed) — `FencedLockServiceImpl.java:32`, `FencedLockStateMachine.java:72-82`; a caller
  who knows/guesses another holder's id can acquire/release/steal their lock. `auth_services: ["*"]`
  makes this reachable by any authenticated service.
- **ManageCert DNS SAN never checked against the token's own `instance_id` claim** (Fable + Grok,
  cross-confirmed) — `TlsCertServiceImpl.java` ~242-297; a service can request a cert hostname-valid
  for a different service's name.
- **Kernel persistence swallows write failures after already returning success to the caller**
  (Grok) — `KernelPersistence.java:154` + several `IdentityServiceImpl.java` call sites: Revoke/
  CreatePersonalPrincipal report OK to the caller, then `save()` failure is only logged. A disk
  issue followed by a restart silently loses revocations and grants.
- **Corrupt/truncated snapshot on restart is treated as cold start, silently un-revoking standing
  grants** (Grok) — `KernelPersistence.java:108-114`.

## Medium
- Tenant ceiling check ignores `data_grants`/`principal_scope` fields entirely, only compares
  `grants` (Fable).
- K8s token verifier falls back to the JVM default trust store if the in-cluster CA file is
  missing — MITM risk on TokenReview (Grok, `TokenReviewKubernetesTokenVerifier.java:248-256`).
- Rate limiting exempts writes and unknown verbs, so `Mint`/`CompleteNonce` are unthrottled (Grok,
  `RateLimitInterceptor.java`).
- Verifying-key retention window shorter than max token/offline-token lifetime — tokens can outlive
  their signing key (Fable, `ClusterServer.java`/`KeyRotator.java`).
- Cert issuance never checks workload revocation on renewal, unlike every token exchange (Fable,
  `TlsCertServiceImpl.java` vs `IdentityServiceImpl.java`).
- `DeleteTenant` orphans nested tenants and their credentials, which keep minting tokens (Fable,
  `TenantAdminServiceImpl.java:124-139`).
- A single failed state read can push an empty JWKS fleet-wide, causing 10-20s of platform-wide
  `UNAUTHENTICATED` (Fable, `ClusterServer.java`/`LocalJwkSource.java`/`BackendServiceImpl.java`).
- `has_quorum` compares live node count to itself (`coreCount >= coreCount/2 + 1`, always true) —
  an isolated/partitioned node reports quorum (Fable, `ClusterStatePublisher.java:185`).
- Configured log level is never applied at boot — `LogbackConfigurator.install(null)` (Fable,
  `Bootstrap.java:46`).
- CliTokenBroker busy-waits up to 5s inside a bidi stream handler, blocking the gRPC thread (Fable +
  Grok, cross-confirmed).

## Low / correctness / pattern drift
~15 more items across both tools — hardcoded token-use constant pending a tacplus rebuild, unbounded
Raft log growth (no snapshot), a membership-listener NPE window at startup, log-stream observer
collision on peer key, audience-string literal drift, a few silent-skip parsing bugs, page-limit
edge case (`limit<=0` returns empty rather than default), duplicated token-verification logic
between Mint and ManageCert with ManageCert missing some of Mint's hardening. Full detail in the
raw per-tool files.

---

## Corrections to tool claims (don't act on these as stated)
Codex separately claimed kernel "never validates token expiration" in several spots
(`exchangeKernelToken`, the shared `verifiedCallerToken` helper, a generated state-plane
authenticator). **I checked — this is false.** Expiry checking is built into the shared
`TokenWrapper.verify()` method every one of those call sites uses (rejects missing `exp`, rejects
expired past a clock-skew tolerance) — Codex didn't trace into that method's actual implementation.
Ignore those specific line items from Codex's report.

## Recommended next step
Given severity, I'd triage in this order: **verify #4 first** (fail-open state config RPC — highest
potential blast radius if real, unverified by me), then fix #1/#2/#3 (all cheap, scoped, and I've
personally confirmed all three). The High-tier tenant/FencedLock/cert items after that. This is
running in production right now — worth moving faster than the tacplus generator fixes.

## Raw per-tool output
- Codex: `codex.out.md` (15 findings)
- Fable 5.1: `fable.out.md` (23 findings, explicitly cross-verified its own top items internally)
- Grok 4.6: `grok.out.md` (first pass, cut short again by Copilot CLI's internal timeout) +
  `grok2.out.md` (completed continuation, 23 findings — note: lost its earlier file-read
  permissions on resume and worked partly from memory of the first pass, slightly lower confidence
  on anything not cross-checked elsewhere)
