# Tenant-user ↔ tenant-user links: store, prove, and the `linked` claim at mint

**SUPERSEDED 2026-10-27** by kernel#4 (Jody, 2026-10-26: retire the `linked` claim). XIDs (one
person, `spiffe://<td>/users/<xid>`) and request-named routing (tacplus#170) replace it: who the
caller is comes from the person, which tenant a call is for from the request, and whether it is
allowed is policy at the target. Kernel no longer stamps `linked`, and the link registry, the
tenant-user arm of `CreateTenantUserLink` and `RevokeTenantUserLink` are gone. Devices moved onto
the XID in kernel#18. See IDENTITY.md, "2026-10-27 — The `linked` claim is retired (#4)". Left below
for historical record.

Slice owner: schematic looper (kernel + platform proto), 2026-09-21.
Authority: `looper/schematic/decisions/identity-people-tenant-devices-private-2026-09-21.md`
§2, plus tacplus's 2026-09-21 13:48 MDT inbox note pinning the claim's shape.

Scope: §2 of that doc's schematic work split, and only that. Device-bound linking
(§3), `(spec.record).private` (§4), `requires_device` (§5) and Scotty's product
work (§6) are explicitly NOT here. Neither is the admin re-key flow — see
"Follow-ons" below.

Builds directly on §1 (`2026-09-21-people-tenant-bootstrap.md`): the `people`
side of a link resolves through the same `PeopleTenant` derivation and the same
`findOrCreatePerson` the people mint arm uses.

---

## Headline: the claim carries a NAMESPACE, and the dispatch brief said otherwise

The dispatch for this slice said the `linked` claim is
`/tenants/<other>/users/<u>` — "namespace-shaped, NOT a bare user path". So does
the decision doc's own §2 example. **Both are wrong, and tacplus said so first.**

tacplus's 2026-09-21 13:48 MDT inbox message: their generated namespace backstop
compares the claim against `(spec.store_namespace)`, which holds a NAMESPACE
(`/tenants/people`), not a user path, and the comparison is deliberately plain
equality with no path parsing. They are minting and reading it as a namespace and
asked kernel to match.

The generated Java chassis, regenerated here, settles it beyond the prose:

```java
// chassis/token/TokenWrapper.java
/** Returns the linked namespaces as a list (comma-delimited in payload). */
public List<String> getLinked() { ... }
public TokenWrapper setLinked(List<String> linked) { ... }

// chassis/servicemanager/Caller.java
/** ... additional NAMESPACES this token's caller is linked to, beyond
  * getNamespace(). The generated namespace backstop accepts a row whose
  * namespace matches getNamespace() OR any entry here. */
```

So: **kernel mints `linked: /tenants/people`**, through the generated
`TokenWrapper.setLinked(List<String>)`, and a user path appears nowhere in the
claim. Minting it the doc's way would have produced a claim the backstop can
never accept — a silent, total failure of the read path the whole §2 exists to
unblock.

Confirmed tacplus's half is landed rather than re-deriving it: `JwtPayloadType`
carries `JWT_PAYLOAD_TYPE_LINKED = 29` with `json_return_value = "linked"`,
`Helpers.jwtPayloadTypeValidValues()` includes it, `Auth.callerLinked()` and
`Caller.getLinked()` exist. Nothing in tacplus was touched by this slice.

## What was built

### 1. The link record

`PrincipalState.tenant_user_links`, a new collection in the boundary §1 already
put `Person` in — kernel's own registry of which identities exist, `label:
["kernel"]` and unexported. A link is identity, not user data, so this is where
"kernel out of the user game" says it goes. A boundary of its own would have
meant another `IdentityServiceImpl` constructor parameter and its sixteen
construction sites for no separation that means anything — the same call §1 made
for `Person`, for the same reason.

```proto
message TenantUserLink {          // one edge OUT of a linked user
  string peer_namespace = 1;      // what the `linked` claim carries
  string peer_subject   = 2;      // the peer's `sub` as kernel mints it
  int64  created_at_ms  = 3;
}
message TenantUserLinks {         // one user's edges
  string user_key = 1 [(spec.indexed) = true];
  repeated TenantUserLink links = 2 [(spec.assert_max_size) = 64];
}
```

**Both directions are written.** Linking A and B writes A's row and B's row.
That is a denormalised index, and it is deliberate: the brief requires
bidirectional lookup to be cheap because it is read on *every* mint, and the
generated `PrincipalMap` gives exactly one cheap primitive —
`getTenantUserLinks(key)`, an O(1) read off a keyed convergent map. One row per
pair would have meant scanning the whole registry per mint for a row that happens
to mention the caller. Two writes on a rare path beat a scan on a hot one.

**The key is `"<namespace>|<sub>"`** — the exact pair kernel mints. Not a derived
user path, because an ordinary tenant's `sub` is whatever its IdP broker supplies
(`alice@example.com` today, as `PeopleTenantMintTest` pins) and is not required
to be a SPIFFE id, so there is no path to derive. The namespace half is what
keeps two tenants' identically-named users apart. Neither a namespace nor a
SPIFFE id may contain `|`, so the pair is never ambiguous.

Carried in `KernelDiskState.tenant_user_links` and restored by
`ClusterServer.restoreTenantUserLinks` at boot, fail-closed next to
`restorePeople`. This matters *more* than it does for `Person`: a link is proved
once, by two live IdP logins sharing a nonce, and nothing kernel holds can
re-derive it. A dropped snapshot silently unlinks everybody, and the only symptom
is a `linked` claim that stops appearing.

### 2. The RPC: `Mint.CreateTenantUserLink`

On `Mint`, next to `CreatePersonalPrincipal`, with the same options
(`principal: RPC_PRINCIPAL_SERVICE, auth_services: ["*"]`) and for the same
stated reason: who may attest a human login is per-delegate runtime config
(`Delegate.auth_broker_kinds`), checked in the handler, not a compile-time
literal in the proto.

**Named `CreateTenantUserLink`, not `LinkTenantUsers`.** tacplus classifies every
RPC verb against a closed registry and refused `Link`:

```
Mint.LinkTenantUsers: method "LinkTenantUsers" uses verb "Link" which is not in
the closed verb registry; add it (fold test → registry) or rename
```

`Create` is in the registry and fits exactly — "Bring a new resource into
existence… NOT Mint; creates durable resource state" — which is precisely what
this does, and it is the verb the neighbouring `CreatePersonalPrincipal` already
uses for the same kind of thing. Renamed rather than reported as a generator gap,
because this is the registry working as designed, not a hole in it.

The request is two `TenantUserLinkSide`s, each one IdP login the calling broker
has just verified: the `origin_*` claims (issuer, subject, nonce) plus a
`subject` used only on an ordinary-tenant side.

**The proof is the shared nonce.** Both sides must carry `origin_nonce`, and the
two must be equal. That is the client having generated one value and sent it into
both logins, so both id_tokens were obtained together by somebody holding both
accounts. Missing nonce → `UNAUTHENTICATED`; mismatched → `PERMISSION_DENIED`.
Without it a token stolen for one side could be replayed alone against a login the
attacker *does* control, and the result would be a link to somebody else's
account — which is the whole of what a link authorizes.

**Neither side's namespace comes from the request.** This is the 2026-09-08
"the IdP binds the tenant, not the caller" ruling carried into §2:

- A **people side** is recognised by its issuer being one of `PeopleTenant`'s two
  fixed ones, and its namespace and user id are derived from the verified claims
  exactly as `mintPersonToken` derives them. `request.subject` is ignored, as it
  is on the mint's people arm.
- **Only the people tenant's own broker may attest a people side.** Same gate
  `doMintUserToken` uses to reach the people arm — the delegate's own
  `tenant_namespace`. Without it, any delegate trusted to broker *some* tenant's
  IdP could name an Apple subject and link itself to a person it never
  authenticated. This is the one non-obvious security check in the slice and it
  has its own test.
- **Any other side** gets its namespace from OPA, evaluated on that side's own
  verified claims — the same authority that names it at mint. So the broker names
  neither tenant, and through neither can it name whose account is being linked.

Both sides landing in one namespace is `INVALID_ARGUMENT`: a link joins two
tenants, and the claim that would result names the namespace the token already
carries.

Re-proving an existing link is idempotent — the same two logins presented again
are the same fact, so the edge and its `created_at_ms` are left alone.

The registry write is under a node-local `linkRegistryLock`, the same shape and
the same limitation as `findOrCreatePerson`'s: no cluster CAS is available to
these services. The consequence here is mild — two concurrent proofs of the same
link write the same two keys, so nothing duplicates.

### 3. The claim at mint

`mintUserTokenInternal`, one keyed read, right after the namespace is resolved
and *before* the broker's relayed claims are copied in — so a broker that puts a
`linked` key in its claim struct cannot name a namespace the registry does not.
Both arms get it: the people arm and the ordinary tenant arm are the same code
path here, which is what makes the link symmetric.

The access token is cloned from the refresh token by `mintAccessFromRefresh`, so
the claim reaches the token services actually present with no second write.
Pinned by a test.

Duplicate peer namespaces are collapsed: the claim names subtrees and the
backstop compares it to one, so two links into the same tenant are one entry.

## Generated code used, none hand-rolled

| Need | Generated thing used |
| --- | --- |
| Link row read/write | `PrincipalMap.getTenantUserLinks` / `putTenantUserLinks` / `proto()` |
| Validation on every write | `Helpers.validateTenantUserLinks`, inside `putTenantUserLinks` |
| The `linked` claim | `TokenWrapper.setLinked(List<String>)` / `getLinked()` |
| RPC surface | the generated `Mint.MintHandler` interface `IdentityServiceImpl` already implements, and its generated wrapper |
| Caller authentication | `verifiedCallerToken` → the existing chassis token path |
| Person derivation on a people side | `PeopleTenant.userId` / `Spiffe.userSpiffeId`, unchanged from §1 |

No gRPC client, server wrapper, state accessor, auth interceptor, claim encoder
or token construction was written by hand.

## Files changed

**`platform/proto/services/kernel.proto`**
- `message TenantUserLink`, `message TenantUserLinks` — the record.
- `PrincipalState.tenant_user_links = 3`, `KernelDiskState.tenant_user_links = 12`.
- `Mint.CreateTenantUserLink` + `TenantUserLinkSide`,
  `CreateTenantUserLinkRequest`, `CreateTenantUserLinkResponse`.

**`.../kernel/cluster/IdentityServiceImpl.java`**
- `createTenantUserLink` / `doCreateTenantUserLink` / `resolveLinkSide` /
  `recordLink` / `LinkedUser` / `linkKey` — the RPC.
- `linkedNamespaces`, and its one call site inside `mintUserTokenInternal`.
- `linkRegistryLock`, `MAX_LINKS_PER_USER`, `LINK_KEY_SEPARATOR`.

**`.../kernel/cluster/ClusterServer.java`** — `restoreTenantUserLinks`, and its
call next to `restorePeople`.

**`.../kernel/cluster/KernelPersistence.java`** — one line: the link rows join
`people` in the snapshot the existing `principalStateReader` already supplies. No
signature change.

**`.../kernel/cluster/TenantUserLinkTest.java`** (new) — 9 tests.

No adjacent code was refactored; `PeopleTenant.java` and the people mint arm are
untouched.

## Verification

Generation: `tacplus build --tag latest --src platform/proto --src
scotty/backend/proto`, with a `tacplus` binary built from the local tacplus repo
HEAD into scratch space (the installed v1.2.248 is still too old) and the pinned
protoc toolchain from `justfile generate` — the same procedure and the same two
environment caveats §1 recorded. The tacplus repo was not modified.

`mvn -pl server -am -Dtest=TenantUserLinkTest -Dsurefire.failIfNoSpecifiedTests=false test`:

```
Tests run: 9, Failures: 0, Errors: 0, Skipped: 0
```

Full suite, `mvn -B install` at `platform/services/kernel`:

- **Before (§1's post-unblock count):** `Tests run: 326, Failures: 1, Errors: 1, Skipped: 0`
- **After:** `Tests run: 335, Failures: 1, Errors: 1, Skipped: 0`

+9, which is exactly this slice's tests, and the same two pre-existing
source-set artifacts, unchanged and with unchanged messages:

- `IdentityServiceImplTest.serviceScopedEventBusAudienceTokenKeepsRoutingAliasedContractGrant`
  — "generated grant catalog is missing
  TASKS_DELEGATION_PROBE_BUS_STATE_SERVICE_PUBLISH_TO_STREAM".
- `SelfAuthenticatingRpcSkipTest.selfAuthenticatingRpcsPassUnauthenticated`
  — `UNAUTHENTICATED: missing authorization header`.

The build therefore reports `BUILD FAILURE` on those two, as it did before this
slice. Nothing else moved.

What the 9 tests actually prove:

1. Two logins sharing a nonce create the link, in both directions, with one
   agreed `created_at_ms`, and create the person if nobody had seen them.
2. Mismatched nonces are refused (`PERMISSION_DENIED`).
3. A missing nonce on either side is refused (`UNAUTHENTICATED`).
4. A broker outside the people tenant cannot attest a people side.
5. Re-linking is idempotent.
6. Both sides in one tenant is refused.
7. After a link, **either** side's mint carries the other's namespace as
   `linked`, in namespace form, on the refresh token AND the cloned access token.
8. An unlinked user's mint carries no `linked` claim at all.
9. A link survives a real snapshot + real boot-time restore, both directions.

## Open questions, and the defaults taken

1. **Which broker actually holds both id_tokens?** The design says "both
   credentials in one request", and kernel requires the people tenant's own
   broker for a people side. In the real flow — jody signed into drpepper's
   webapp, tapping "link my Apple account" — that means the people tenant's oauth
   instance has to verify the drpepper id_token too, or drpepper's oauth has to
   hand it over. That is an oauth/product routing question, not a kernel one, and
   it is the same unanswered "how does a browser reach a tenant-owned broker
   pre-token" §1 flagged. **Default taken:** kernel accepts whichever single
   registered IdP-broker delegate presents both, subject to the people-side gate
   above. Nothing here assumes a route. Raised in inbox.md.
2. **Nonce freshness and single-use.** Kernel checks that the two nonces are
   equal, not that either is fresh or unused. Freshness is the IdP's job (the
   provider echoes the nonce into a token with its own `iat`/`exp`, which the
   broker verified), and single-use would need a seen-nonce set like
   `seenProofJtis`. **Default taken:** equality only. The replay this slice must
   stop is *one* side being replayed alone, and the shared nonce stops that;
   replaying *both* sides together re-proves the same link, which is idempotent.
   Raised in inbox.md as the thing to revisit if a nonce ever becomes long-lived.
3. **No `revoked_at_ms` on `TenantUserLink`.** Its neighbours
   (`TenantMembership`, `PersonalCredential`, `Grant`) all mark rather than
   delete, so this is a deliberate omission, not an oversight: unlink is not in
   this slice, nothing would write the field, and a read-side `!= 0` check with
   no writer is untestable dead code. Adding it later is an additive proto field
   with no migration. Stated so the next slice does not read the absence as a
   ruling that links are irrevocable.
4. **The trust domain is inside a people-side key.** A people user's `sub` is a
   full SPIFFE id, so `/tenants/people|spiffe://<td>/...` embeds `<td>`. An
   ordinary tenant's key does not. Changing the fleet's trust domain would
   therefore orphan the people half of every link — silently, since the only
   symptom is a missing claim. Not fixed here: a td change is already a
   fleet re-identity event, and every alternative key needed a derivation that
   an arbitrary broker-supplied `sub` does not support. Flagged, not worked
   around.
5. **Cross-tenant links between two ordinary tenants.** The mechanism is generic
   and two non-`people` sides work — both namespaces come from OPA — but nothing
   tests that combination, because a second ordinary tenant needs a second fake
   OPA answer keyed on claims, which the existing harness does not do. The
   people↔tenant path is what §2's first use needs, and the code has no
   people-specific branch on the ordinary side.

## Follow-ons (named, not built)

- **Admin re-key.** §2's "re-keying an IdP is an admin operation that updates
  links, never an identity reset". Nothing here forecloses it: `peer_subject` is
  stored alongside `peer_namespace` precisely so the edges naming one user can be
  found and rewritten, and both directions are already materialised so a re-key
  knows every row it must touch. It needs `revoked_at_ms` (open question 3), an
  unlink, and a `TenantAdmin` surface — none of which is this slice.
- **§3 device-bound linking** reuses this record with a different proof (device
  signature + nonce-bound IdP token instead of two IdP tokens). `resolveLinkSide`
  is where a device side would resolve; `recordLink` and the claim need no change.
