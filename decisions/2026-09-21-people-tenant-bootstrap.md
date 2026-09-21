# The reserved `people` tenant: bootstrap, and person creation on first IdP login

Slice owner: schematic looper (kernel + platform proto), 2026-09-21.
Authority: `looper/schematic/decisions/identity-people-tenant-devices-private-2026-09-21.md`
§1, plus Jody's 2026-09-08 `namespaceFromOpaOrRoot` ruling (inbox.md, "the IdP binds the
tenant, not OPA").

Scope: §1 of that doc's schematic work split, and only that. Tenant-user ↔ tenant-user
links (§2), device credentials (§3), `(spec.record).private` (§4) and device-only
approvals (§5) are explicitly NOT here.

---

## Headline: one hard blocker, upstream in tacplus

**`/tenants/people` is not a constructible namespace today.** The generated
`Spiffe` chassis keeps `people` in its `RESERVED_TAGS` set (a leftover of the
`/people/<principal_id>` root this decision doc supersedes), and
`validateNamespaceSegments` refuses a reserved tag in the tenant-name position:

```
Spiffe.userSpiffeId(td, "/tenants/people", "apple.001672…")
  -> IllegalArgumentException: spiffe: reserved tag "people" cannot be a tenant name
Spiffe.tenantSpiffeId(td, "people")
  -> IllegalArgumentException: spiffe: "people" is a reserved tag and cannot be an identifier segment
```

This blocks more than user subjects: the `people` tenant's own oauth **delegate**
cannot have a SPIFFE identity either (`spiffe://<td>/tenants/people/services/oauth`
is rejected by the same check), so nothing can even authenticate into the people
arm of the mint.

This is exactly the tacplus work-split item the decision doc already lists —
"`people` as a reserved tenant name in the grammar validators if any tag list
needs it". It is a generator change, so per the standing rule it is reported
here rather than worked around: hand-building the SPIFFE strings in kernel (or in
the tests) would be duplicating generated code, which this fleet forbids.

**What tacplus needs to do:** stop treating `people` as reserved in the
tenant-name position — the `/people/<pid>` namespace root it was reserved for is
what this decision doc rejects. Whether the tag disappears entirely or only from
the `TENANTS_SEGMENT` branch of `validateNamespaceSegments` is tacplus's call;
kernel only needs `/tenants/people` to normalise.

Consequence for this slice: the wiring is written and compiles, and every piece
of it that does not have to construct that namespace is implemented and tested.
Three tests that must reach the people arm end to end are `@Disabled` with that
reason, on a shared constant; deleting the annotations should be the whole of the
follow-up.

---

## What bootstraps `people`, with Apple and Google

`people` is a **reserved tenant**. That is the one deliberate special case, and
it is stated in three places rather than hidden: the proto comment block above
`PeopleIdpProvider`, the class javadoc on `PeopleTenant`, and
`TenantAdminServiceImpl.rejectReserved`.

Reserved means exactly three things:

1. **The platform knows it exists ahead of time.** `ClusterServer` calls
   `PeopleTenant.seed(...)` at every boot, next to `seedRootCredPairs` and for
   the same reason: after the disk snapshot is rehydrated, so the bundle stays
   authoritative for what it declares while the tenant's `created_at` survives a
   restart. No operator creates it.
2. **Its IdP set is fixed.** `PeopleIdpProvider` is a closed enum — Apple,
   Google. `Config.people_idp_credentials` supplies only `client_id` /
   `client_secret`; kernel adds the issuer URL from `PeopleTenant`'s own table.
   There is no field a deployment could point at a third issuer, and the mint
   re-checks the verified `origin_iss` against the same table, so a
   misconfigured broker mints nothing rather than minting a person keyed to an
   unrecognised issuer.
3. **It has no admin.** Nothing seeds a cred_pair into its `TenantConfig`, and
   `TenantAdmin.CreateTenant` / `DeleteTenant` / `SetTenantConfig` all refuse the
   namespace. The refusal has to live in the handler, not the authorizer: a
   root-entitled caller passes the generated level-or-below check for every
   namespace, so without it "no admin" would be an intention rather than a fact.

Everything else is an ordinary tenant. In particular the providers are written
into the tenant's existing `oauth.OAuthTenantConfig` slice — the same per-tenant
config slice drpepper and sprite use — so **oauth needs no code change** to learn
the people tenant's IdPs. `OAuthTenantConfig` needed no variation for a reserved
tenant; it is a plain instance of the existing shape.

The oauth slice is **replaced**, not merged, on each seed. It is the fixed IdP
set: a provider dropped from the bundle must disappear from the tenant, and
there is no admin surface through which anyone could delete it afterwards.

## How person creation / lookup works

`Mint.MintUserToken`, `AUTH_BROKER_KIND_IDP` arm. The arm is selected by the
**minting delegate's own `tenant_namespace`** — `/tenants/people` takes the
people path, anything else is unchanged. That is the 2026-09-08 ruling applied to
this slice: the namespace is stamped from the delegate's identity, which the K8s
SA / cloud identity matcher proves, and never from OPA output. A people-tenant
delegate mints into `/tenants/people`, nothing else.

On that arm (`IdentityServiceImpl.mintPersonToken`):

1. Read `origin_iss` and `origin_sub` from `request.claims` — the IdP's own
   issuer and subject, which oauth copies verbatim out of the id_token it
   verified (`oauth/src/auth.rs`, `build_claims_struct` prefixes well-known JWT
   claims with `origin_`). Absent either, `UNAUTHENTICATED`.
2. Map the issuer to a `PeopleIdpProvider`. Not one of the two, `PERMISSION_DENIED`.
3. Derive `<u>` (below).
4. Find-or-create the `Person` row keyed by `<u>`, under a node-local lock
   (`personRegistryLock`), the same read-check-write shape
   `CreatePersonalPrincipal` uses and for the same reason. A disabled person is
   refused; a person past the registry cap is refused.
5. Mint through the existing `mintUserTokenInternal` with
   `subject = Spiffe.userSpiffeId(td, "/tenants/people", <u>)` and
   `stampedNamespace = "/tenants/people"`.

`request.subject` is **ignored** on this arm, deliberately, exactly as the device
arm ignores it: everything identifying comes out of the verified claims, so there
is no field a broker could point at somebody else's person.

Claims ARE relayed into OPA here (unlike the device arm, which synthesises them):
on this path the broker really did attest the login, so OPA is entitled to see
what it attested. OPA remains the sole entitlement authority; it just does not
get to name the subtree kernel already resolved.

## How the user id is derived

`<u>` = `"<provider>.<provider's own sub>"` — `apple.001672.9c4f…`,
`google.110169484474386276334`.

- No hash of our own. The provider's subject is already stable and unique within
  that provider, so the same human lands on the same row from any device with no
  lookup table to keep consistent.
- Neither provider token contains a `.`, so the first dot is an unambiguous
  delimiter and the pair is recoverable from the id.
- **One provider identity = one person.** The same subject string under Apple and
  under Google is two people, and a test pins that.
- A subject that does not fit the SPIFFE segment grammar goes through the
  generated `Spiffe.opaqueSegment(kind, value)` — the decision doc's
  `opaque_segment`, which tacplus already emits — with the provider token as its
  `kind`, so one provider's subject can never collide with another's. Neither
  provider emits such a subject today (Apple's are dotted hex, Google's decimal);
  the branch exists so that one which did would still resolve to one stable
  person rather than refusing the login. `Spiffe.normalizeSegment` is the grammar
  oracle rather than a regex of our own, so the id and the path it becomes can
  never disagree about what a legal segment is.
- The `Person` row keeps `provider` and `provider_subject` as fields, which is
  also what `opaqueSegment`'s contract requires ("callers must preserve the
  original external value").

## Where the row lives

`PrincipalState.people`, not a state root of its own. That boundary is already
kernel's registry of which humans exist — kernel-only, unexported, persisted —
and it is already injected into `IdentityServiceImpl` as `principalMap`.
`PersonalPrincipal` in the same boundary is the superseded `/people/<pid>` shape
and goes away with the device slice (§3); `Person` is what remains. A second
boundary would have meant a new constructor parameter on `IdentityServiceImpl`
and its sixteen construction sites for no separation that means anything.

Rows are carried in `KernelDiskState.people` and restored by
`ClusterServer.restorePeople` at boot, fail-closed like its
`restorePersonalPrincipals` neighbour. This matters more than it looks: a person
is created once and found thereafter, so a dropped snapshot would not merely
forget them — it would silently re-create them with a fresh `created_at_ms` on
their next login.

## Generated code used, none hand-rolled

Every piece of plumbing below is tacplus's, used as generated:

| Need | Generated thing used |
| --- | --- |
| Person row read/write | `PrincipalMap.getPeople` / `putPeople` / `proto()` (from `PrincipalState`) |
| Tenant + tenant config read/write | `ConfigMap.getTenants` / `putTenants` / `getTenantConfigs` / `putTenantConfigs` |
| SPIFFE subject construction | `Spiffe.userSpiffeId`, `Spiffe.normalizeSegment`, `Spiffe.opaqueSegment`, `Spiffe.TENANTS_SEGMENT` |
| Tenant admin RPC surface | `TenantAdmin.TenantAdminHandler` (the generated handler interface `TenantAdminServiceImpl` already implements) |
| Mint RPC surface | the existing `Mint` handler `IdentityServiceImpl` already implements |
| Validation on every write | the generated `Helpers.validatePerson`, invoked inside `putPeople` |
| Per-tenant oauth config shape | `oauth.OAuthTenantConfig` / `OAuthProvider` via the generated `TenantConfig` slice |

No gRPC client, server wrapper, state accessor, auth interceptor or token
construction was written by hand.

## Files changed, and why

**`platform/proto/services/kernel.proto`**
- `Config.people_idp_credentials = 38` — the only deployment-supplied part of the
  reserved tenant's IdP config.
- `enum PeopleIdpProvider`, `message PeopleIdpCredential` — the closed provider
  set, which is what makes "the IdP set is fixed" a property of the type.
- `message Person` — the user row: derived id, provider, the provider's raw
  subject, created/disabled clocks.
- `PrincipalState.people = 2` — where those rows live.
- `KernelDiskState.people = 11` — so they survive a restart.

**`.../kernel/cluster/PeopleTenant.java`** (new)
- The reserved tenant's constants, the fixed issuer table, the `<u>` derivation,
  and the boot seed. One small class because three call sites need it
  (`ClusterServer` seeds, `IdentityServiceImpl` derives, `TenantAdminServiceImpl`
  refuses) — not an abstraction, a shared constant table.

**`.../kernel/cluster/IdentityServiceImpl.java`**
- `doMintUserToken`: keep the `Delegate` `requireBrokerDelegate` already returns,
  and dispatch to the people arm when its `tenant_namespace` is `/tenants/people`.
- `mintPersonToken`, `findOrCreatePerson`, `claimString`, `personRegistryLock`,
  `MAX_PEOPLE` — the arm itself. `findOrCreatePerson` is package-private so the
  create/find behaviour can be proven while the mint around it is blocked.

**`.../kernel/cluster/ClusterServer.java`**
- Seed the reserved tenant at boot, next to `seedRootCredPairs`.
- `restorePeople`, called next to `restorePersonalPrincipals`. Separate because
  that method returns early on an empty principal list and the two collections
  are independently populated.
- The snapshot reader now hands `KernelPersistence` the whole `PrincipalState`
  rather than just its personal-principal list.

**`.../kernel/cluster/KernelPersistence.java`**
- `personalPrincipalsReader` (a `Supplier<List<PersonalPrincipal>>`) becomes
  `principalStateReader` (a `Supplier<PrincipalState>`), mirroring the existing
  `configStateReader`, and `save()` carries both collections. A ninth constructor
  parameter would have touched all eleven construction sites; this touched the
  three that pass a real supplier.

**`.../kernel/cluster/TenantAdminServiceImpl.java`**
- `rejectReserved(ns)` on `createTenant`, `deleteTenant`, `updateTenantConfig`.

**`.../kernel/cluster/PeopleTenantMintTest.java`** (new), plus a two-line
signature fix in `DevicePrincipalTest` and `KernelPersistencePersonalPrincipalTest`
for the `KernelPersistence` reader type.

## Open questions, and the defaults taken

1. **How does a browser reach the people tenant's oauth instance before it has a
   token?** Jody's 2026-09-08 ruling already flags this for tenant-owned brokers
   generally ("login is pre-token by definition… reaching a tenant-owned broker
   needs a pre-auth tenant selector (hostname or path prefix)"). It is not
   specific to `people` and is not resolved here. Default taken: nothing in this
   slice assumes an answer — the arm is selected by the delegate's own identity,
   whatever route reached it.
2. **Scopes requested from Apple and Google.** The doc does not say. Default
   taken: `openid email` for both — `openid` is what makes the response an
   id_token at all, `email` is what lets a person recognise which account they
   used. The `sub` this tenant keys people on is in every id_token regardless, so
   nothing here depends on the choice.
3. **The `people` tenant has no `Constraints`.** `CreateTenant` would normally
   validate an entitlements ceiling against the parent's. The seed writes none —
   a tenant with no admin has nobody to constrain, and an unset ceiling is what
   every unconstrained tenant already carries. Revisit if §2's links make a
   person's token carry entitlements in their own right.
4. **The device path still mints `/people/<pid>`.** That is the shape §1
   supersedes, but migrating it is §3 work and touching it here would have
   changed a live login path for no gain in this slice. `PersonalPrincipal` and
   `Person` coexist in `PrincipalState` until then, and the proto comments say so.
5. **The find-or-create lock is node-local.** Same limitation, same reason, as
   `CreatePersonalPrincipal`'s: no cluster CAS is available to these services.
   The consequence here is milder than there — two concurrent first logins write
   the same key, so nothing duplicates; the loser would only reset `created_at_ms`.

## Verification

Built and tested with the merged proto source set tacplus itself prescribes
(`--src platform/proto --src scotty/backend/proto`). Two notes on the environment,
neither caused by this slice:

- The installed `tacplus` binary (v1.2.248) predates `spec.ResidencyPolicy.idle_seconds`,
  which the current `platform/proto` uses, so generation was run with a tacplus
  built from the local tacplus repo HEAD into the scratchpad. The tacplus repo
  was not modified.
- Generating kernel standalone now fails the residency/trait check
  ("no `(spec.trait)` hosts a record query plane"); the error message itself
  prescribes the merged application+platform build, hence the second `--src`.
  `testapp/proto` cannot be the application source — it still uses the retired
  `(spec.record).retention`.

Full suite, `mvn -B install` at `platform/services/kernel`:

- **Baseline (before any change):** `Tests run: 313, Failures: 1, Errors: 1, Skipped: 0`
- **After:** `Tests run: 326, Failures: 1, Errors: 1, Skipped: 3` — the same two
  failures, unchanged, plus this slice's 13 new tests (3 of them skipped on the
  tacplus blocker). Both pre-existing failures are source-set artifacts of the
  local generation described above, not code:
  - `IdentityServiceImplTest.serviceScopedEventBusAudienceTokenKeepsRoutingAliasedContractGrant`
    — wants `testapp/services/tasks` in the generated grant catalog, which the
    merged source set above cannot include.
  - `SelfAuthenticatingRpcSkipTest.selfAuthenticatingRpcsPassUnauthenticated`
    — same source-set artifact.

`PeopleTenantMintTest`: `Tests run: 13, Failures: 0, Errors: 0, Skipped: 3` — the
three skips being the tacplus blocker above.
