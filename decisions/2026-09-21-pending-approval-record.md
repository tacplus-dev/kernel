# The pending-approval record: device-only approvals, the platform half

Slice owner: schematic looper (kernel + platform proto), 2026-09-21.
Authority: `looper/schematic/decisions/identity-people-tenant-devices-private-2026-09-21.md`
§5, building on §1 (`2026-09-21-people-tenant-bootstrap.md`), §2
(`2026-09-21-tenant-user-links.md`) and §3
(`platform/services/personalauth/decisions/2026-09-21-device-webauthn-link.md`).

Scope: **the pending-approval record and its verification API, and only that.**
tacplus's generated `(spec.rpc).requires_device` check is tacplus's own backlog
item 3 and is NOT here — what is here is the primitive it calls into, filed to
`tacplus/looper/inbox.md` with the exact call shape. No product flow (Scotty's
propose UI, the phone prompt) is here either, and App Attest / Play Integrity
remain out of scope exactly as in §3: WebAuthn only.

---

## Headline: the record answers "what was approved", and that is the whole design

§5's sentence that decides everything else is *"the generated check … must verify
**what** was approved"*. A record saying "person X tapped yes at 18:42" is not an
approval of anything; it is a permission slip for a shape of call. So the record
pins one RPC and one exact request, the device's signature covers both, and the
approval is burned on use. Every other decision below falls out of that.

The three things a pending approval is:

| | |
| --- | --- |
| **who** | `person_user_key` — `"/tenants/people\|<person SPIFFE sub>"`, §2's `TenantUserLinks.user_key` form |
| **what** | `rpc_method` (`"pkg.Service/Method"`) + `request_hash` (SHA-256, 32 bytes) |
| **how long** | `expires_at_ms`, kernel's from a capped TTL; `consumed_at_ms`, single-use |

## What was built

### Proto (`platform/proto/services/kernel.proto`)

- **`message PendingApproval`** — the record above.
- **`PrincipalState.pending_approvals = 4`** — the registry, keyed by
  `approval_id`. The one collection in that boundary with **no
  `(spec.persistence)`** and no `KernelDiskState` field; see "Storage" below.
- **`PersonalIdentity.CreatePendingApproval`** + its two messages — the
  proposer's path (C2S, `RPC_PRINCIPAL_USER`, `RPC_FLAG_AUTH_ANY_USER`,
  `RPC_EXPOSURE_EXTERNAL`).
- **`Mint.BrokerPendingApproval`** + its two messages — the verification path
  (S2S, `RPC_PRINCIPAL_SERVICE`, `auth_services: ["*"]`).

### Kernel

- **`WebauthnProof.approvalBinding(approvalId, rpcMethod, requestHash)`** — the
  challenge a device must sign. Same construction as §3's `loginBinding`
  (base64url(SHA-256(fields joined by 0x1f))), which was factored into one
  private `binding(byte[]...)` both call rather than copied; a domain tag
  (`schematic-pending-approval`) makes an approval binding and a login binding
  incapable of colliding.
- **`IdentityServiceImpl`** — `brokerPendingApproval` / `doBrokerPendingApproval`
  / `verifyApprovingDevice` / `DeviceApprover`, the static
  `personUserKey(PrincipalMap, namespace, subject)` both services use, and
  `PENDING_APPROVAL_LOCK`.
- **`PersonalIdentityServiceImpl`** — `createPendingApproval` and `sweepExpired`,
  plus the four constants that bound it (TTL default/ceiling, the SHA-256 length,
  the per-person live cap). No constructor change: person resolution needs only
  the link registry it already holds.
- **`PendingApprovalTest`** (new) — 17 tests.

### personalauth

One arm added to the test-only `CapturingMint` fake in `src/device.rs`
(`broker_pending_approval` → `unimplemented!`), because a new `kernel.Mint` RPC
is a compile error in the one other crate that implements that trait. Exactly the
kind of change §3 had to make, for exactly the same reason. No design change.

## The decisions the dispatch asked to be made rather than guessed

### 1. How an RPC is named: `"pkg.Service/Method"`, not a new scheme

Two existing conventions could have been used, and one of them is not available
to the caller: tacplus's entitlement grant names (`KERNEL_MINT_MINT_USER_TOKEN`)
and the qualified method key. The check that will call this has a gRPC
`MethodDescriptor` in hand and nothing else, and two things in the tree already
key on exactly that string:

- tacplus's generated authorizers — `_qualified_method_key(full_method)`, whose
  own comment states the key is `"pkg.Service/Method"` and never the bare name;
- kernel's own `RateLimitInterceptor`, which buckets on
  `call.getMethodDescriptor().getFullMethodName()`.

So `rpc_method` is gRPC's full method name without its leading slash. Nothing new
was invented, and the one risk — tacplus preferring grant names — is a one-line
change here and is asked explicitly in the note to their inbox, because a
mismatch is a feature that passes every test on both sides and never works once.

### 2. The creation path reuses an existing RPC surface (and one is a new RPC on it)

The dispatch asked whether creation should be a new kernel RPC or reuse an
existing mechanism. It is **a new RPC on the existing `PersonalIdentity`
service**, which is reuse of everything that matters and a new method for the one
thing that does not exist:

- No existing RPC can carry it. `CreateTenantUserLink` proves a link;
  `MintUserToken` mints a token; neither has a place to put "and also remember
  this pending consent", and overloading either would make one call do two
  unrelated things with two different callers.
- `PersonalIdentity` is exactly the right host. Its charter is already *"the
  caller's own identity, resolved from the verified token, with no field pointing
  at somebody else"* — `GetMyIdentity` takes no argument and
  `RevokeTenantUserLink` reads the owner off the token. `CreatePendingApproval`
  is the same shape: the person is the caller's, through the link registry. It is
  C2S with `auth_any_user`, so a browser, Scotty holding a delegated token, and
  the device itself can all propose — which is §5's UX ("a browser or Scotty
  *proposes*") with no new surface.
- No new service, no new authenticate-func, no new wiring in `ClusterServer`: the
  generated `PersonalIdentity` wrapper is already registered and already
  token-only authenticated for precisely these callers.

**Proposing is deliberately unprivileged.** The row authorizes nothing — it is
the thing a signature is checked against — so a proposer needs no right beyond
being the user. What bounds it is the per-person live cap (16) and the TTL, not a
permission.

### 3. Verification lives on `Mint`, and the verb is `Broker`

The caller of the verification API is a *service*: tacplus's generated check,
running inside whatever service declared the RPC. That is S2S and it must be
reachable from **every** service, since any service may declare a
`requires_device` RPC.

`Mint` is where that is free. Kernel is the fleet's `token_minter`, so every
service already has a generated `Mint` client (`MintGrpcClient` in Java,
`mint_client()` in Rust — verified by reading eventbus's and personalauth's
generated trees). A dedicated `DeviceApproval` service would have been defensible
— `FencedLock` and `CliTokenBroker` are small s2s services of their own — but it
would make tacplus's generated check carry a new client, a new route and new
deployment wiring into every service that uses the annotation, for a separation
that means nothing: `Mint` already holds `CreatePersonalPrincipal` and
`CreateTenantUserLink`, i.e. it is kernel's S2S identity surface and not narrowly
a token factory.

**The verb is `Broker`.** `Authorize` was the instinct and is wrong: tacplus's
closed verb registry defines it as *"Make an authorization decision (**no state
change**)"* with `Access=READ`, and this RPC burns the record. `Broker` is
*"Coordinate a mediated exchange between two parties… owns matching, relay, or
completion semantics"*, and the in-tree precedent is exact —
`Mint.BrokerDelegateOfflineToken` looks one single-use record up by its opaque
id, verifies the presenter, burns it, and releases the result. This does the same
four things. (Both `Create` and `Broker` passed the generator's classifier on the
first run; unlike §2's `LinkTenantUsers`, nothing had to be renamed.)

### 4. Storage: kernel state, not stratum, and not the disk snapshot

The dispatch asked whether stratum's record lifecycle
(`idle_seconds`/`deleted_max_age_seconds`) fits. It does not, and the reason is
not preference:

- **Stratum's lifecycle governs stratum-stored `(spec.record)` rows.** None of
  kernel's registries are stratum records — `Person`, `PersonalPrincipal`,
  `TenantUserLinks` are all `PrincipalState` collections, kernel-only and
  unexported. Putting the approval in stratum would make it a record type with
  an egress surface, and would put the platform's approval check behind a second
  service's availability. The check is kernel's: kernel holds the credential and
  the link table it must be verified against.
- **So it goes where the comparable state already is:** `PrincipalState`, the
  boundary §1 put `Person` in and §2 put `TenantUserLinks` in, for the reason
  both give — a boundary of its own would mean another constructor parameter and
  its construction sites for a separation that means nothing.
- **But NOT in `KernelDiskState`, and no `(spec.persistence)`.** This is the one
  collection in the boundary that is deliberately ephemeral, and it follows
  `KernelDiskState`'s own stated rule: *"Ephemeral, rebuilt-at-runtime state … is
  deliberately NOT snapshotted; only state that must survive a restart is."* A
  link is snapshotted because it is proved once by live credentials, can never be
  re-derived, and **losing it fails silently** (a `linked` claim that stops
  appearing). An approval lives ≤10 minutes and **losing it fails closed**: the
  id is not found, the RPC is refused, the person taps again. Persisting it would
  buy nothing and put churn into the snapshot that carries the signing keys.

### 5. Cleanup: a sweep on the creation path

Creation is the only path that grows the collection, so `createPendingApproval`
sweeps every row whose expiry has passed before writing its own, under the same
lock. That keeps the registry proportional to the approvals actually outstanding
in one TTL window, with no scheduler to own and nothing to fail quietly if one
stopped running. Two details are deliberate:

- **An expired row is deleted, not marked.** The tree's "mark, never delete" rule
  is about withdrawn authority that must remain auditable; there is nothing to
  audit in "nobody tapped it", and the audit that matters — a tap that was
  accepted — belongs to the RPC the approval let through, which is the guarded
  service's own record.
- **A consumed row is kept until it expires.** That is what lets a replay inside
  the window be refused as ALREADY USED rather than as an unknown id.

The per-person live cap (16) is the bound that matters: any user token reaches
this RPC, so without it one caller could fill the registry. There is no separate
collection-total refusal, unlike `MAX_PERSONAL_PRINCIPALS` — that check exists
because an over-cap collection silently breaks the disk snapshot, and this
collection is not in the snapshot.

## The two checks §5 exists for, and what refuses what

`BrokerPendingApproval`, in order, all under one lock (verify-then-consume with a
gap in the middle is not single-use):

1. record exists → else `NOT_FOUND`, non-enumerating;
2. not consumed → else `PERMISSION_DENIED`;
3. not expired → checked on consumption, not merely swept, so a row the sweep has
   not reached is still dead;
4. `rpc_method` equals the record's;
5. **`request_hash` equals the record's** — the exact-request pin;
6. the served caller resolves to the record's person;
7. the assertion verifies against the **stored** credential, over
   `approvalBinding(approval_id, live rpc_method, live request_hash)`;
8. **that credential's `/people/<pid>` principal holds a LIVE `TenantUserLink` to
   that person** — the device-link check;
9. burn, and return who approved and with what.

**Why the stored key only.** A first device→person link has a bootstrap moment
where the request's copy of the key is the only thing to check against (§3's
`deviceCredential`). An approval has no such moment — an approving device is by
definition already registered and linked — so no key travels in the request and
the proto carries no field for one. Steps 4/5 are then *belt and braces with* step
7: the live method and hash are compared to the record AND are inside the
challenge the device signed, so a same-shaped-but-different request fails twice
over. The mutation run below confirms both halves independently refuse it.

**Why step 6 exists.** The guarded service reports which of its own users it is
serving. It is already trusted with that (it is serving the request), but without
the check a service could spend an approval one of its users proposed on a call it
is serving for another. It costs one keyed read.

## Generated code used, none hand-rolled

| Need | Generated thing used |
| --- | --- |
| Approval row read/write/delete | `PrincipalMap.getPendingApprovals` / `putPendingApprovals` / `deletePendingApprovals` / `proto()` |
| Validation on every write | `Helpers.validatePendingApproval`, inside `putPendingApprovals`; `Helpers.validate*Request/Response` in the wrappers |
| RPC surfaces | the generated `Mint.MintHandler` and `PersonalIdentity.PersonalIdentityHandler` interfaces and their registered wrappers |
| Caller's verified claims | `Caller.getNamespace()` / `getSubject()` |
| Public key → `java.security.PublicKey` | `ImmutableJwk.from(jwk).getPublicKey()` (via §3's `WebauthnProof`) |
| SPIFFE subject construction | `Spiffe.userSpiffeId`, `Spiffe.PEOPLE_SEGMENT` |
| Link lookups | §2's `PrincipalMap.getTenantUserLinks`, unchanged |

No gRPC client, server wrapper, state accessor, auth interceptor, claim encoder or
token construction was written by hand, and no new dependency was added: the
signature check is §3's `WebauthnProof` and therefore the JDK's own `Signature`.

## Verification

Generation: `tacplus build --tag latest --src <local platform/proto> --src
<local scotty/backend/proto>`, with a `tacplus` binary built from the local
tacplus repo HEAD into scratch space (the installed v1.2.248 is still too old)
and the pinned protoc from kernel's `justfile generate`
(`target/protoc/bin/protoc`, libprotoc 36.2). Both kernel and personalauth were
regenerated. **The tacplus repo was not modified.**

`mvn -B -pl server -am -Dtest=PendingApprovalTest test`:

```
Tests run: 17, Failures: 0, Errors: 0, Skipped: 0
```

Full kernel suite, `mvn -B install`:

- **Before (§3's post-slice count):** `Tests run: 350, Failures: 1, Errors: 1, Skipped: 0`
- **After:** `Tests run: 367, Failures: 1, Errors: 1, Skipped: 0`

+17, exactly this slice's tests, and the same two pre-existing source-set
artifacts with unchanged messages:

- `IdentityServiceImplTest.serviceScopedEventBusAudienceTokenKeepsRoutingAliasedContractGrant`
  — "generated grant catalog is missing
  TASKS_DELEGATION_PROBE_BUS_STATE_SERVICE_PUBLISH_TO_STREAM".
- `SelfAuthenticatingRpcSkipTest.selfAuthenticatingRpcsPassUnauthenticated`
  — `UNAUTHENTICATED: missing authorization header`.

The build therefore reports `BUILD FAILURE` on those two, as it did before this
slice. (Note for the next kernel dispatch: the "`mvn test` doesn't compile at all
right now for anyone" entry in the looper's state.md is stale — the llmproxy/proto
drift it described is gone, and the suite compiles and runs.)

personalauth, `cargo test`: `8 passed; 0 failed` — the same count as §3, with the
fake's new arm.

**The two tests the dispatch asked for, and proof they are meaningful.** Passing
tests prove nothing about a check that might not exist, so both were
mutation-tested: with the hash comparison deleted AND the device-link refusal
replaced by an accept, the suite fails exactly three tests and no others —

```
[ERROR] PendingApprovalTest.anApprovalCannotBeSpentOnASameShapedDifferentRequest:228
        device approval refused: the assertion's challenge does not name the presented login
        ==> expected: <true> but was: <false>
[ERROR] PendingApprovalTest.aDeviceLinkedToSomebodyElseCannotApprove:273
        Expected ProtoException to be thrown, but nothing was thrown.
[ERROR] PendingApprovalTest.anUnlinkedDeviceCannotApprove:303
        Expected ProtoException to be thrown, but nothing was thrown.
```

That output says two useful things at once. The link check is load-bearing: with
it gone, any registered device's valid signature approves anybody's request. And
the exact-request pin is defended twice: with the hash comparison gone the request
is *still* refused, by the challenge binding, which is why that test asserts on
the refusal MESSAGE and not only on the code. Both were restored immediately; the
run above is the restored tree.

What the 17 tests prove:

1. A person proposes, their linked device taps, kernel names who approved and
   with which device, and burns the record.
2. Two approvals of the same request have different challenges, and an assertion
   over the other one's challenge is refused.
3. A tampered signature approves nothing.
4. **An approval for one request cannot be spent on a same-shaped different one
   — and the approved request still goes through afterwards**, which is what
   proves the refusal was about the hash and not about a stale assertion.
5. An approval for one RPC cannot be spent on another.
6. **A device linked to a DIFFERENT person cannot approve**, though its assertion
   is perfectly valid.
7. An unlinked device cannot approve, and unlinking does not revoke its
   credential.
8. An unregistered device cannot approve.
9. Another person's call cannot spend this person's approval.
10. An approval is single-use.
11. An expired approval cannot be consumed, even before the sweep reaches it.
12. An unknown id is `NOT_FOUND`.
13. Creating an approval sweeps the expired ones.
14. A week-long requested TTL comes back as the ceiling.
15. The device itself may propose and resolves to the same person through its own
    link edge.
16. A caller with no linked person cannot propose at all.
17. A `request_hash` that is not a 32-byte digest is refused.

The setup is the real §3 ceremony throughout — a passkey and an Apple login whose
nonce is that key's thumbprint, through `CreateTenantUserLink` — not a seeded link
table, because a seeded table would pass against a check that resolved a device
the wrong way.

## Open questions, and the defaults taken

1. **~~Nothing checks the WebAuthn relying party, and it costs more here than in
   §3.~~ RESOLVED — see "RP ID / origin check landed" at the end of this doc.**
   Jody ruled the same day that this is not a question; the check is now enforced
   in both flows and the default recorded below no longer holds. The paragraph is
   kept as written because it is the reasoning the ruling acted on. §3 left this
   open and named §5 as where to revisit it ("§5 needs RP
   configuration anyway"); §5 does not fix it, because the platform still has no
   relying-party configuration and a constant compiled into kernel would lock out
   every deployment whose origin differs. **The cost is genuinely higher here.**
   In §3 an assertion obtained by a hostile relying party is useless without an
   id_token whose nonce is that key's thumbprint — two halves, attacker holds
   one. An approval has no second half: the challenge is all the device signs,
   and the origin check is exactly what WebAuthn uses to stop a phishing page
   from collecting a signature over a challenge it was handed. The attacker must
   still learn a live `approval_id` and its challenge, which are returned only to
   the proposer's own session and dead in ≤10 minutes — so this is not
   "approvals are forgeable", it is "WebAuthn's one anti-phishing control is
   off". **Default taken:** not checked, matching §3; the approval binding does
   the work the challenge is there to do. The fix is four lines in
   `WebauthnProof.verify` once an RP ID exists in per-deployment config, next to
   the oauth provider config the `people` tenant already has — which needs the
   product's real domains, so it is raised in the looper's `inbox.md` rather than
   defaulted to a guess.
2. **Single-use is single-use PER NODE.** `PENDING_APPROVAL_LOCK` is node-local,
   the same limitation and the same absent cluster CAS §1/§2/§3 all record. The
   consequence is sharper than it was for links, where two concurrent proofs
   write the same rows: two kernel nodes serving two copies of the same guarded
   request could each consume the same approval once. Kernel embeds a Ratis
   `FencedLock` that could close this properly. **Default taken:** node-local,
   documented, and raised — worth doing if any product puts a money-shaped RPC
   behind `requires_device`.
3. **The request-hash canonicalisation rule is tacplus's, and kernel cannot
   enforce it.** Kernel compares 32 opaque bytes and never re-derives them, which
   is what stops kernel from silently disagreeing with either side — but the
   proposer and the generated check must produce the same bytes for the same
   request in whatever languages they are written in, and proto serialisation is
   not canonical. **Default taken:** kernel imposes only the length. Asked of
   tacplus explicitly, along with a request that they generate the
   proposer-side hash helper too rather than leave every product to hand-roll it.
4. **How the approval id and assertion reach the guarded service is undecided,
   and deliberately so.** Metadata headers or annotation-added request fields are
   both fine; kernel does not see the transport. The one constraint, stated to
   tacplus: whatever carries them must not be inside the bytes that get hashed.
5. **An ordinary tenant user proposing is untested.** `personUserKey` resolves a
   non-`people` caller through their live link into `/tenants/people`, and the
   `/people/<pid>` device arm exercises exactly that branch — but a
   drpepper-user-linked-to-a-person proposer is not tested, because that needs a
   second OPA-keyed fixture the harness does not have (the same gap §2 recorded
   for two-ordinary-tenant links). The code has no people-specific branch on that
   path.
6. **A person linked to two `people` identities cannot approve anything.**
   `personUserKey` returns nothing when a caller resolves to more than one
   person, and the refusal is the same as "no person at all" so it enumerates
   nothing. That state should not exist (one provider identity = one person, §1),
   and picking one would be guessing which human approved. Stated so the absence
   is not read as an oversight.
7. **No read surface.** Nothing lists a person's pending approvals. The product
   prompt is pushed by whatever proposes (it has the id and the challenge in
   hand), so nothing needs one yet, and a speculative list over a registry this
   sensitive is a surface to defend for no caller. Named, not built.

## Follow-ons (named, not built)

- **The generated `requires_device` check** — tacplus's item 3, now unblocked;
  the call shape is in their inbox.
- ~~**Relying-party configuration** — open question 1, and it unblocks §3's open
  question 2 at the same time.~~ Built; see "RP ID / origin check landed" below.
- **Cluster-wide single-use via `FencedLock`** — open question 2.
- **`PersonalPrincipal` vs `Person`** — §3 asked whether a device should be a
  credential ON the `Person` row rather than its own `/people/<pid>` principal,
  and flagged §5 as the thing that might want person→devices as a keyed lookup.
  It does not: verification goes device→person (resolve the credential, then read
  that device's own link row), which is one keyed read and needs no index. So §5
  does not reopen it, and the question stands where §3 left it.

---

## RP ID / origin check landed

**Supersedes open question 1 above.** Jody ruled on 2026-09-21 23:00 MDT (schematic
looper `inbox.md`): *"not a question — enforce it. The pending-approval signature
MUST verify `rpIdHash` and `origin` against the configured relying party; an
approval with no second half cannot skip WebAuthn's anti-phishing control. Same
check in §3 while you are there."* Question 1's "default taken: not checked" no
longer holds, and §3's open question 2 (`platform/services/personalauth/decisions/
2026-09-21-device-webauthn-link.md`) is closed by the same change. The class
javadoc's "What is deliberately NOT checked, and why" section is gone.

### What was built

`WebauthnProof.RelyingParty` — a nested value holding `SHA-256(rpId)` and the set
of allowed origins, and one private `check(authenticatorData, origin)` that
`verify` calls. Both flows go through the one `verify`, so §3's link proof and
§5's approval get the same check from the same four lines; there is no second
code path that could drift.

The check is two comparisons, and they are not redundant:

- `authenticatorData[0:32]` must equal `SHA-256(rpId)`. This is the
  **authenticator's** statement of which domain it unlocked the key for, and no
  page can change it.
- `clientDataJSON.origin` must be one of the configured origins, compared for
  exact string equality. This is the **browser's** statement of which page asked,
  and it is what catches a look-alike or a subdomain serving the same RP ID.

It runs after the challenge binding and before the signature, so an assertion from
a hostile relying party is refused on the ground that names what is actually wrong
with it rather than on a generic signature failure.

### The config shape, and why

**Two environment variables, `KERNEL_WEBAUTHN_RP_ID` and
`KERNEL_WEBAUTHN_ORIGINS`** (the latter comma-separated), read once in
`ClusterServer.webauthnRelyingParty()` and injected into `IdentityServiceImpl` as
a constructor parameter.

The instinct was a `Kernel.Config` field beside `people_idp_credentials`, which is
where `PeopleTenant`'s per-deployment values live and which tacplus would have
given an env-var binding (`PROTO_CONFIG_*`) and validation for free. That is
probably where it belongs long-term. It was **not** done here for one reason: the
`Config` message lives in `platform/proto/services/kernel.proto`, outside this
slice's write boundary, and adding a field means regenerating every language's
tacplus output for a change that is otherwise pure application logic in one file.

So the mechanism chosen is the one kernel **already** uses for per-deployment
values the bundle has no field for: a hand-read `KERNEL_*` environment variable,
exactly as `KERNEL_K8S_TOKEN_AUDIENCE`, `KERNEL_KUBE_API_URL` and
`KERNEL_KUBE_TOKEN_FILE` are read today. Nothing new was invented, and the
`KERNEL_` prefix does not collide with the `PROTO_CONFIG_` namespace tacplus
generates. **Follow-on, named not built:** move these two onto `Config` when the
proto is next opened, at which point `RelyingParty.of(...)` is the only call site
that changes.

Three judgment calls the ruling did not need to specify, made here and recorded:

1. **Global, not per-tenant.** The relying party is the deployment's own web
   domain — the page a passkey ceremony runs on — not a property of the tenant the
   person belongs to. The `people` tenant is the only tenant these flows touch at
   all, and it is reserved and fleet-wide, so a per-tenant knob would have exactly
   one value forever.
2. **Exact origin match against a list, no patterns.** A wildcard is how origin
   checks get quietly widened to something that matches an attacker's host. A list
   covers the real case (apex plus a staging host) and a deployment that needs
   more adds more.
3. **Both variables or neither.** An RP ID with no origins would check one half of
   WebAuthn's anti-phishing pair and silently skip the other, which is the state
   this change exists to end. Either missing or blank yields
   `RelyingParty.NONE`.

### Fail closed, and what that costs

`RelyingParty.NONE` — no configuration — is **not** "skip the check": it refuses
every assertion, with `no WebAuthn relying party is configured to check against`.
There is no compiled-in default because there is no domain that is right for two
deployments, and a wrong RP ID that is checked is worse than one that is absent.

The `IdentityServiceImpl` constructor parameter is `@Nullable` and null means
`NONE`, so every one of the 18 test wirings that does not do WebAuthn now gets the
fail-closed relying party by default. A deployment that runs the device flows must
set both variables; one that does not is unaffected, because nothing else reaches
this code. `ClusterServer` logs at INFO when nothing is configured, so an operator
who meant to run the flows can see why every tap is being refused.

### Test evidence

Six new tests, three per flow, in the two files that already own these ceremonies.
Both `Passkey` fixtures gained an `assertFor(challenge, rpId, origin)` overload —
the existing `assertFor(challenge)` now delegates to it with the test deployment's
own values (`example.test` / `https://example.test`, which is what the fixtures
already baked in), so every pre-existing test is unchanged in behaviour.

`DeviceWebauthnLinkTest` (§3), 15 → 19:

- `anAssertionProducedForAnotherRelyingPartyLinksNothing` — real key, real
  signature, nonce IS the thumbprint, challenge names this exact login; only
  `rpIdHash` names `attacker.test`. `PERMISSION_DENIED`, nothing written.
- `anAssertionCollectedFromAnotherOriginLinksNothing` — the deployment's own RP
  ID, so the authenticator is satisfied, but `origin` is
  `https://phish.example.test`.
- `anUnconfiguredRelyingPartyRefusesAPerfectlyGoodAssertion` — the same assertion
  verifies against the configured relying party and is refused by
  `RelyingParty.NONE`. This is the fail-closed proof.
- `halfAnEnvironmentConfiguresNoRelyingParty` — RP ID alone, origins alone, a
  blank RP ID and an empty environment all yield an unconfigured relying party.

`PendingApprovalTest` (§5), 17 → 19:

- `anAssertionProducedForAnotherRelyingPartyApprovesNothing` — genuine assertion
  over this approval's own challenge, wrong RP ID. `PERMISSION_DENIED`, and the
  approval is **not** burned.
- `anAssertionCollectedFromAnotherOriginApprovesNothing` — wrong origin, refused,
  and then the real page's tap still succeeds, which is what proves the refusal
  was about the origin and not about a spent approval.

**Mutation run, because passing tests prove nothing about a check that might not
exist.** With `RelyingParty.check` replaced by an immediate `return`, exactly five
tests fail and no others:

```
[ERROR]   DeviceWebauthnLinkTest.anAssertionCollectedFromAnotherOriginLinksNothing:286 Expected ProtoException to be thrown, but nothing was thrown.
[ERROR]   DeviceWebauthnLinkTest.anAssertionProducedForAnotherRelyingPartyLinksNothing:262 Expected ProtoException to be thrown, but nothing was thrown.
[ERROR]   DeviceWebauthnLinkTest.anUnconfiguredRelyingPartyRefusesAPerfectlyGoodAssertion:313 Expected WebauthnProof.Invalid to be thrown, but nothing was thrown.
[ERROR]   PendingApprovalTest.anAssertionCollectedFromAnotherOriginApprovesNothing:296 Expected ProtoException to be thrown, but nothing was thrown.
[ERROR]   PendingApprovalTest.anAssertionProducedForAnotherRelyingPartyApprovesNothing:277 Expected ProtoException to be thrown, but nothing was thrown.
```

The sixth new test passes under the mutation, correctly: it tests how the
environment is parsed, not what the check does. The check was restored
immediately; the run below is the restored tree.

Full kernel suite, `mvn -B install`, on the same tree before and after:

- **Before:** `Tests run: 367, Failures: 1, Errors: 1, Skipped: 0`
- **After:** `Tests run: 373, Failures: 1, Errors: 1, Skipped: 0`

+6, exactly this change's tests, with the same two pre-existing source-set
artifacts and unchanged messages —
`IdentityServiceImplTest.serviceScopedEventBusAudienceTokenKeepsRoutingAliasedContractGrant`
("generated grant catalog is missing
TASKS_DELEGATION_PROBE_BUS_STATE_SERVICE_PUBLISH_TO_STREAM") and
`SelfAuthenticatingRpcSkipTest.selfAuthenticatingRpcsPassUnauthenticated`
(`UNAUTHENTICATED: missing authorization header`). The build therefore still
reports `BUILD FAILURE` on those two, as it did before this change.

No proto change, no regeneration, no new dependency: the check is a `MessageDigest`
and an `Arrays.equals`.
