# Identity and Token Architecture

## Authority Boundaries

The identity system has a small number of distinct authorities. Keeping them
separate is what makes the trust model auditable.

1. **The operator deploys.** It provisions clusters and workloads and is the
   only component that wires environment-specific verifiers (e.g. the live
   Kubernetes token verifier — see below). The operator does not mint identity.
2. **kmaker makes kernels only.** kmaker signs kernel certificates
   (`MintKernelCert`) bound to verified pod facts. It is the certificate
   authority for *kernels*; it does not mint Schematic tokens or ordinary service
   identities.
3. **Kernel mints Schematic tokens and ordinary service certs.** Kernel is the
   signing authority for all S2S/C2S tokens and for ordinary service TLS
   certificates (the SPIFFE-keyed leaf+intermediate chain issued from
   `TokenMint` when the caller's `sub` is a SPIFFE URI).
4. **Kubernetes tokens, `cloud_proof`, and kernel-signed `input_token`s are
   layered delegate proofs.** They are *inputs* a service presents to the
   kernel to prove which delegate it is. They are never themselves Schematic
   identity; the kernel resolves them to a registered delegate and then mints
   its own tokens. A presented credential's facts (e.g. a verified pod's SA)
   are cross-checked, never trusted verbatim.

> Field names/numbers settled in Phase 2 are authoritative:
> `MintServiceTokenRequest` accepts flat credential fields:
> `input_token = 1`, `cloud_proof = 2`, `kubernetes_token = 8`, and
> `Delegate.kubernetes_service_accounts = 5` (repeated
> `KubernetesServiceAccountMatcher`). The kernel-side cert RPC keeps its
> existing name `MintKernelCert` (it is not being renamed to `SignKernelCert`).

## S2S (Service-to-Service) Tokens

### Bootstrap

Schematic configures a **delegate** for each service. In Kubernetes, each delegate
is matched to one or more service accounts through
`Delegate.kubernetes_service_accounts`. Each delegate entry specifies which
services the delegate may mint tokens for. Currently each service can only mint
for itself.

### Service Startup

1. The service reads its projected Kubernetes service-account token.
2. The service sends this JWT as `kubernetes_token` to kernel's `TokenMint` RPC.
3. Kernel verifies the token, maps the verified `(namespace, service_account)`
   to a registered delegate, and mints a **refresh token** and **access token**:
   - `sub: "<service_name>"`
   - `aud: "kernel"`
   - `sub_type: "service"`
   - `token_use: "refresh"` / `"access"`

### Ongoing Token Lifecycle

- The service holds the **refresh token** in memory and uses it only to obtain new access tokens.
- The **access token** (`aud: "kernel"`) is used for kernel RPCs.
- When the service needs to call another service, it exchanges its refresh token with kernel for a new access token with `aud: "<target_service>"`.
- Kernel checks that the delegate is authorized to mint for the requested `aud` (based on the delegate's `authorized_services` list).

### Destination Service Validation

The **destination service** (not kernel) is responsible for validating inbound S2S requests. It must check:

1. The token is an S2S token (`sub_type: "service"`).
2. The `aud` matches the destination service's own name.
3. The `sub` (principal) is authorized to call the destination service.

Kernel does not decide whether a service may talk to another service at request time. That policy is enforced by the destination service.

### Signing Authority

All S2S tokens are signed by kernel and kernel only. There is no fallthrough to
external IdP resolution for S2S flows. A service bootstrap request must resolve
to a configured delegate through `kubernetes_token` or `cloud_proof`.

### Credential Layering (Phase 2)

`MintServiceTokenRequest` carries **exactly one** credential proof:

- **`input_token` (= 1)** — a kernel-signed refresh/access token used for
  exchange. It is no longer a service bootstrap credential.
- **`cloud_proof` (= 2)** — a cloud-native identity proof (AWS STS / GCP /
  Azure). **Stub:** the mint path routes this to an explicit
  `UNIMPLEMENTED` rather than silently accepting it.
- **`kubernetes_token` (= 8)** — a projected Kubernetes service-account JWT.
  The kernel structurally checks the token, hands it to a swappable
  `KubernetesTokenVerifier` seam, then maps the verified `(namespace,
  service_account)` to a delegate via that delegate's
  `kubernetes_service_accounts` matchers (`Delegate.kubernetes_service_accounts
  = 5`).

The mint path counts the flat fields and rejects any request that sets more
than one proof, so raw clients cannot smuggle multiple proofs.

Whichever credential is used, if the request also carries a `continuity_token`
the kernel cross-checks it against the **resolved delegate's canonical SPIFFE
id** — i.e. the identity the prior refresh token actually carries — not against
anything derived from the presented credential. This binds continuity to the
delegate the kernel resolved, not to attacker-controlled token contents.

**Kubernetes path is live for Kubernetes deployments.** Operator projects the
kernel-audience service-account token, kernel verifies it through its
`KubernetesTokenVerifier`, and delegate matchers bind the verified pod identity
to a Schematic service identity.

## C2S (Client-to-Service) Tokens

Every service is declared as either `service_s2s` or `service_c2s`. C2S services accept tokens from end users (humans, agents). S2S services only accept tokens from other services.

### OAuth Authentication (Current Model)

The only client authentication method currently supported is OAuth via an external Identity Provider (e.g., Google, Okta).

1. The user obtains an **OAuth token** from an external IdP (via browser-based OIDC flow through fleetwood).
2. The **OAuth service** validates this token using the IdP's **publicly accessible JWKs**. OAuth is the one and only service that validates tokens not issued by kernel.
3. OAuth maps the public IdP claims (email, name, etc.) into the new token request.
4. OAuth executes an **OPA policy** to assign zero or more **profiles** (comma-separated) to the token. Profiles determine what the user is authorized to do.
5. OAuth sends a **delegation mint request** to kernel, authenticating with its own S2S bearer token. The request includes:
   - The user's subject
   - The mapped claims
   - The assigned profiles
   - The token is marked as `sub_type: "user"`
6. Kernel validates the OAuth service's S2S bearer token and extracts the caller's identity.
7. Kernel mints a **refresh token** and **access token** for the user:
   - `sub: "<user_subject>"`
   - `aud: "kernel"`
   - `sub_type: "user"`
   - `azp: "oauth"` (the identity of the on-behalf-of service; could also be `"fleetwood"` or others in the future)
   - `profiles: "<assigned_profiles>"`
8. The refresh and access tokens are returned to the client.

### Client Token Lifecycle

- The client holds the **refresh token** and uses it only to obtain new refresh tokens.
- When the client wants to call a service, it exchanges its token for a **service token** with `aud: "<target_service>"`.

### Client-facing mint RPCs

A mint RPC whose caller is a person is declared `(spec.service_c2s)` on kernel and reached through the gateway's ordinary generic routing. There is no hand-written proxy code for it: the route exists because kernel declares the surface.

The shape, as `kernel.UserMint` implements it (token-management decision item 7):

- The RPC lives on a C2S service block of its own. A service declares exactly one caller surface — tacplus refuses `(spec.service_c2s)` and `(spec.service_s2s)` on the same service — so the S2S `kernel.Mint` keeps the service-called mints and the C2S block carries the client-called ones. Both are served by the same `IdentityServiceImpl`.
- It is marked `RPC_FLAG_AUTH_ANY_USER`, so the gateway verifies the caller's token (signature, expiry, `aud: kernel`, `sub_type: user`) and proxies the call straight to kernel.
- Kernel extracts the user's identity from that bearer token, validates it, and mints against the caller's own authority.
- tacplus emits the gateway route — gRPC `/kernel.UserMint/<Rpc>` and REST `/kernel/UserMint/<Rpc>` — from the annotation alone.

**Still on the old shape:** the C2S *token exchange* (`gateway.Mint/MintToken`, and `MintX509Cert` beside it) is still hand-written proxy code in `platform/services/gateway/src/mint.rs`. It is not a leftover that can simply be deleted: gateway's OIDC discovery document advertises `<issuer>/gateway/TokenMint` as the `token_endpoint`, and kernel's own `kernel.Mint/MintToken` is proxy-routable over gRPC but carries no REST path (it is a self-authenticating S2S method, so tacplus emits an auth-only proxy entry with no HTTP route). Moving the exchange onto the shape above means declaring it C2S on kernel first; until then the front stays.

### Destination Service Validation (C2S)

The destination service must check:

1. The token is a C2S token (`sub_type: "user"`).
2. The `aud` matches the destination service's own name.
3. The user's **profiles** authorize the requested operation (entitlement check).

## Token Hierarchy Summary

```
S2S Bootstrap:
  kubernetes_token → kernel.TokenMint → refresh(aud:kernel) + access(aud:kernel)
  refresh(aud:kernel) → kernel.TokenMint(aud:X) → service(aud:X)

C2S Bootstrap:
  IdP OAuth token → oauth.validate → kernel.MintUserToken(S2S bearer, claims)
    → OPA EvalEntitlement → refresh(aud:kernel, sub_type:user, azp:oauth) + access(aud:kernel)

C2S Token Exchange:
  access(aud:kernel) → kernel.TokenExchange(aud:X) → service(aud:X, sub_type:user)
```

## Key Invariants

1. **All Schematic tokens in the system are signed by kernel.** The exceptions are the *layered delegate proofs* a service presents to bootstrap or exchange an S2S token — a `kubernetes_token`, a `cloud_proof`, or a kernel-signed `input_token` — which kernel verifies, resolves to a delegate, and discards. They are never re-emitted as Schematic identity.
2. **Only OAuth (and fleetwood) validate external IdP tokens.** No other service ever sees or validates non-kernel tokens.
3. **Destination services enforce access policy**, not kernel. Kernel mints tokens; destinations decide who may call them.
4. **`azp` records who brokered the token.** For S2S: the delegate name. For C2S: the on-behalf-of service (oauth, fleetwood, etc.).
5. **`sub_type` is the trust boundary.** Services declared `service_s2s` must reject `sub_type: "user"` tokens. Services declared `service_c2s` accept user tokens and enforce profile-based entitlements.

## 2026-10-25 — Identity decision record, step 1: the XID-keyed person

Implements step 1 of `identity-session-credential-2026-10-25` (schematic roadmap). Log kept
here so the parent session can follow without asking.

### What changed

- **A human is `spiffe://<td>/users/<xid>`.** `Person` is keyed by a kernel-minted XID (128
  random bits, lower-case hex, a legal SPIFFE segment as minted). The provider-keyed
  `/tenants/people/users/<provider>.<sub>` row is gone: `Person.provider`/`provider_subject`
  are reserved field numbers, replaced by `Person.links` (`IdentityLink{idp_id,
  provider_subject}`) and `Person.memberships` (`PersonMembership{tenant_namespace}`).
  `Person.generation` is declared for step 2's sign-out-everywhere.
- **The link index.** `PrincipalState.identity_links` (`IdentityLinkRow{link_key =
  "<idp_id>|<sub>", xid}`) is one keyed read from a verified `(idp_id, sub)` to the XID. It is
  written with the Person at first login and is what every login reads; step 2's "the link
  still exists" check reads the same row. Both collections ride the disk snapshot
  (`KernelDiskState.identity_links = 13`) and are restored together, fail-closed, because a
  person whose row or link does not come back is minted a NEW XID on their next login.
- **First login.** `IdentityServiceImpl.resolveOrCreatePerson(idpId, sub)` (replaces
  `findOrCreatePerson`): index hit → the Person (refused if disabled); miss → mint XID, write
  the Person with that link and its `people` membership, write the index row, snapshot. The
  sign-ups kill switch still refuses only the create half.
- **Which logins are people.** The IdP mint arm now forks on the verified `origin_iss`, not on
  the broker's `tenant_namespace`: an issuer in `PeopleTenant`'s fixed table (Google, Apple)
  is a person; anything else is the untouched ordinary tenant login (`request.subject`,
  namespace from OPA). The same holds for a `people` side of `CreateTenantUserLink`. The old
  gate "only a `/tenants/people`-rooted broker may attest a people login" is removed: the
  fleet runs ONE oauth instance, rooted at `/system`, and it brokers every login. This is
  the shape that lets seatrials' Google sign-in mint without a second oauth.
- **Org + people.** The people arm asks OPA once. If the claim matchers route the login to a
  tenant, the token minted is that tenant's (`sub=/users/<xid>`, `namespace=/tenants/<t>`)
  and the org membership is recorded on the Person the FIRST time (a write at first org
  login; later logins read it and write nothing). A revoked org membership refuses the org
  token. If nothing routes the login, the token is `people`'s. Subject is the XID either way.
- `PeopleTenant.idpId(provider)` (`apple`, `google`) replaces the derived `userId`.
  `SpiffeIds.userSubject(td, xid)` builds the subject.

### What the record left open and what was decided here

- **`idp_id` for tenant IdPs.** The record defines links as `(idp_id, provider_subject)`
  and the 10-21 huddle (item 24) wants registered IdP records with immutable ids; none exist.
  Decided: only the fixed people providers carry an `idp_id` today, so only Google/Apple
  logins become XIDs; a tenant-IdP login stays on the legacy path until IdP records exist.
  Seatrials has only Google, so nothing is lost on the proof fleet.
- **Org membership is a record, written once.** The record says "a login … writes nothing"
  and also "the membership still exists" is read at mint. Reconciled as: the first login
  into each tenant writes its membership; every later login reads. Nothing revokes one yet
  (no surface); the flag is honoured so the surface can be added without touching the mint.
- **No `/users` root in tacplus's Spiffe helper.** The record says tacplus v2.2.0 carries
  `/users/<xid>`; the generated `Spiffe` (pinned 03fccf6 and the registry-and-floor
  template) does not — `parseSpiffeId("spiffe://td/users/x")` throws. Not needed: the
  generated authenticator and the gateway read a user token's `namespace` claim and treat
  its `sub` as opaque, and kernel builds the subject with `Spiffe.userSpiffeId(td, "/",
  xid)`. Flagged, not fixed, in tacplus.
- **The token returned at login** is still refresh + access (`TokenMintResponse`), with the
  new subject. Step 2 puts the session credential in the long-lived slot.
- Device links (`PersonalPrincipal`, `/people/<pid>`) and `TenantUserLink` are untouched
  except that their people side now resolves to the XID; they move in step 4.

### Proof

- Kernel: `PeopleTenantMintTest` (XID minted once, resolved on repeat, distinct links are
  distinct people, `/system` broker mints the `people` token for a Google login no tenant
  routes, org routing mints the org token and records the membership once, revoked
  membership refuses, restart round trip of Person + link). `TenantUserLinkTest`,
  `DeviceWebauthnLinkTest`, `PendingApprovalTest` updated to find the person through the
  link index.
- Seatrials: see the next dated entry once the kernel image is rolled.

## 2026-10-25 — Identity decision record, step 2: the session credential

### What changed

- **Mint (login) returns a session credential plus the first access token.** The people arm
  now mints a kernel-signed credential into `TokenMintResponse.refresh_token` and the first AT
  into `access_token`, so oauth, the gateway and the webapp see the same wire shape as before.
  The credential is refresh-class (offline-class when the broker asked for `offline_access`),
  `sub=/users/<xid>`, `namespace=/tenants/people` (the default tenant; a signed user token must
  carry one, and it never selects what the credential mints), and the two claims that make it a
  credential: `xid_gen` (the per-XID generation) and `proofs` (JSON array of
  `{idp_id, sub, auth_time, exp, tenants, claims}`). `SessionCredential.java` holds the shape.
- **A proof's `tenants` is fixed at login.** An org login the claim matchers routed vouches
  `[org, people]`; a personal login vouches `[people]`. Never re-derived at the exchange, so a
  later matcher change cannot widen a session already out. `claims` are the IdP claims the
  broker relayed, replayed into OPA for entitlements at every mint from that proof.
- **The per-tenant exchange is `Mint.MintToken` with `input_token=<credential>` and
  `tenant_namespace=/tenants/<t>`** (no tenant means `people`). Kernel: signature → the person
  exists, is not disabled, and the credential's generation is theirs → a live proof vouches
  `<t>` whose link row still maps to this XID → the membership of `<t>` exists and is not
  revoked → AT (`sub=/users/<xid>`, `namespace=/tenants/<t>`, exp ≤ min(request, access
  lifetime, proof exp, credential exp), entitlements from OPA on the proof's claims,
  `parent_jti` the credential's, `linked` as the legacy mint stamped it). Otherwise
  `PERMISSION_DENIED` — the step-up ("no live proof vouches for <t>: sign in with that tenant's
  identity provider") for a missing proof or membership, one indistinct refusal for a dead
  person/generation. `service_auds` works as on every other exchange; `offline_access` hands
  the same credential back (a credential is not renewed: a proof lives on its IdP's policy, a
  new login is what extends a session).
- **Merge and Unmerge are kernel.proto RPCs on the C2S `UserMint` service**, callable with any
  live AT of the same person as bearer; the credentials travel in the body and are verified by
  signature, never looked up. `MergeCredentials(credentials[])`: same XID required (two people
  is Link, a write), current generation required, proofs unioned and deduplicated by
  `(idp_id, sub)` keeping the fresher `auth_time`, re-signed with exp = the latest proof's.
  `RevokeCredentialProof(credential, idp_id, sub)` is the record's Unmerge under a registered
  verb ("Unmerge" is not in tacplus's closed verb registry; adding it would have meant a
  tacplus change AND a new tacplus image pin): drops the proof, re-signs, returns no
  credential when the last proof is dropped, `NOT_FOUND` for a proof the credential does not
  carry. Both stateless.
- **Shape, not `token_use`, selects the arm.** `SessionCredential.isCredential` requires both
  `xid_gen` and `proofs`. A legacy single-namespace refresh token never enters the credential
  arm (with a tenant named it is refused as it always was, INVALID_ARGUMENT; without one it
  exchanges the legacy way); a credential never reaches the legacy clone path (its AT carries
  none of the credential's claims and the generation check is made). One test per direction.
- No sys-proto change was needed: the credential rides the existing `refresh_token` slot and
  `TokenMintRequest.tenant_namespace`; Merge/Unmerge are kernel's own policy RPCs.

### Decided here (record silent)

- Proof `exp` = the login's requested `exp` if given, else kernel's refresh lifetime (offline
  lifetime with `offline_access`), under the same ceilings the legacy refresh token had. No
  tenant configures a max proof age yet. `auth_time` = `origin_auth_time`, else `origin_iat`,
  else now.
- The first AT at login is the routed org's when there is one, else `people`'s.
- Sign-out-everywhere, Link, Unlink and Delete account are later surfaces; step 2 only
  checks `Person.generation`.
- Project scoping (`authorized_projects`/`default_project`, v3) and `Delegate.custom_claims` are
  not stamped on credential-minted ATs; they were IdP-session features of the legacy refresh
  token and nothing on seatrials uses them.

### Proof

- Kernel: `SessionCredentialTest` — personal proof yields people only; org proof yields
  org + people and not a second org; tenants fixed at login; Merge unions, dedupes keeping
  the fresher, refuses two people and another person's bearer; Unmerge drops a proof, the last
  one signs out, unknown proof NOT_FOUND, the link remains; expired proof no longer mints
  while the personal one still does; link removed → no mint; membership revoked → no org
  token, people untouched; generation bump fails every outstanding credential and Merge;
  disabled person mints nothing; legacy refresh is never a proof set; a credential never takes
  the legacy path. Step 1 tests updated for the credential in the refresh slot.
- Seatrials: see the next dated entry once the kernel image is rolled.

### Seatrials proof (2026-10-25 23:53 UTC, kernel 28ae372)

One Google sign-in by Jody at https://seatrials.tacplus.dev through the fleet's single
`/system` oauth, with no claim matcher routing it, produced in kernel-0's log:

- `Created person: xid=f6ce7fb592d3bb13ae34639b1cc9e35c idp_id=google` (step 1: XID minted,
  link and `people` membership written);
- `Mint: credential for xid=f6ce7fb5… vouching [/tenants/people] via google, first AT in
  /tenants/people` (step 2: the login is a credential with one personal proof plus the first AT);
- `MintToken (session credential): xid=f6ce7fb5…, tenant=/tenants/people, via=google` (the
  webapp's own exchange of the credential took the credential arm and minted the people AT).

Before this change the same sign-in failed at MintUserToken with "entitlements policy returned
no namespace for this caller".

## 2026-10-26 — Microsoft is a people provider; adding a sign-in (Link)

Jody, directly: Microsoft logins get an XID, a signed-in person can add the other providers'
sign-ins to the same account (to test multi-login), and the sign-in buttons carry the
providers' logos. This settles the record's open "Microsoft" item and pulls in the part of
step 4 multi-login needs.

- **Microsoft.** `PeopleIdpProvider.MICROSOFT`; issuer `https://login.microsoftonline.com/<tid>/v2.0`
  (one per directory, the consumer directory included). Link key `microsoft|<tid>:<oid>`, per
  the 10-21 huddle's claim table (item 23): `sub` is pairwise per app registration and is not
  the key; `tid` must be the directory the issuer names. A Microsoft login without `oid`
  (oauth relays `tid`/`oid` verbatim; the seatrials scopes include `profile`) mints nothing.
  An Entra work account follows the same trust rule as Google Workspace: routed by a claim
  matcher it is an org proof, otherwise a personal one.
- **Adding a sign-in = the record's Link, as `UserMint.MergePeople`** (tacplus's closed verb
  registry has no "Link"). The console runs the provider flow again; that login mints its own
  credential (a fresh XID if the identity is new); the console presents both credentials. The
  older XID survives (huddle item 13); the other's links and memberships move to it, its index
  rows are repointed, and it is tombstoned (`Person.merged_into_xid`), after which its own
  credentials mint nothing. The response is the survivor's credential with both proofs. Two
  credentials of one person are just merged (no write).
- **Warning path.** A proof now records `first` when its login created the XID. The absorbed
  person may be folded in without `confirm` only when it is exactly that: one link, its proof
  `first`, no membership beyond `people`. Otherwise FAILED_PRECONDITION until `confirm`; the
  console shows "Merge the accounts / Cancel".
- Not done: device links (`TenantUserLink`/`PersonalPrincipal`) of an absorbed person are not
  moved; Unlink and Delete account are still open.

## 2026-10-26 — Step 4's kernel surface; the identity graph behind the people service's contract

Jody approved steps 3 and 4 (relayed by the hub, 2026-10-25 evening) and, in the Stratum huddle
(`schematic/roadmap/stratum-per-tenant-2026-10-25.md`), moved the identity graph to a people service
in the `people` tenant, on that tenant's Stratum.

- **`IdentityGraph`** is that service's contract: resolve-or-create a login's person, add a
  membership, read a person and a link, Link (merge), Unlink, delete account, bump the generation.
  **`KernelIdentityGraph`** implements it on kernel's `PrincipalState` as the interim backend (the
  10-23 rule "behind an interface shaped like the Stratum operations, so the switch is a backend
  swap"). IdentityServiceImpl no longer touches people or link rows directly; switching to the
  people service is replacing that one class.
- **Step 4 RPCs on `UserMint`**, all authenticated by the caller's own access token and, for the
  writes, the caller's own session credential:
  - `GetLinkedAccounts` — the caller's links and memberships (the linked-accounts screen).
  - `DeleteIdentityLink` — the record's Unlink; refused for a sign-in whose proof the presenting
    credential carries, so the last link can never be unlinked. The next login with an unlinked
    sign-in starts a new person.
  - `DeleteAccount` — warned and two-step: without `confirm`, FAILED_PRECONDITION saying what goes;
    with it, every link revoked, the generation bumped, the person tombstoned (`deleted_at_ms`), the
    XID never reused.
  - `RevokeSessions` — sign out everywhere: one generation bump; every outstanding credential,
    the caller's own included, fails at its next mint.
  Names follow tacplus's closed verb registry (no "Unlink"; List requires paging).
- Tests: `SessionCredentialTest` (30), including Unlink of the in-use sign-in refused, delete
  account warned then tombstoned, sign-out-everywhere killing two credentials, and another
  person's bearer refused for every write.
- Not yet on seatrials; the console screens for these (gateway) and step 3's claim matchers
  (fleet-seatrials) go to their repos' loopers as issues.

### Seatrials (2026-10-26)

Kernel 77f7c24 and the gateway rebuilt against it are live on seatrials (fleet 3d2ec3a; only kernel and the
gateway restarted, letsencrypt untouched). Kernel registers `UserMint/GetLinkedAccounts`,
`DeleteIdentityLink`, `DeleteAccount`, `RevokeSessions`; through the gateway an anonymous call is refused
(401) and an unknown method is not found (404). The gateway kept its Let's Encrypt certificate across the
kernel restart (letsencrypt 2c60a0d re-mirrors it when the kernel Watch reconnects). The console screens for
these RPCs are gateway#2.

## 2026-10-27 — Sign out of one provider (#6)

Jody, testing seatrials (2026-10-26): the sign-in page lists the session's sign-ins and each offers
"Sign out" for that provider. That is the record's Unmerge, which kernel already had as
`UserMint.RevokeCredentialProof`; it is extended rather than joined by a second RPC doing the same thing.

- **Named by provider.** `provider_subject` is no longer required: `idp_id` alone drops every proof of
  that provider the credential carries (two Google sign-ins in one session both go); with
  `provider_subject` set it drops that one sign-in, as before. A provider the credential carries no proof
  of — unknown, or simply not signed in — is `NOT_FOUND`.
- **Credential and access token back.** The response now carries `access_token` beside the re-signed
  credential, minted by the same exchange as `Mint.MintToken`: in the bearer's tenant when a remaining
  proof still activates it (live, vouches it, link still this person's, membership not revoked), else
  `people`. Tenants only the dropped proof vouched are no longer active; reaching them again is the
  ordinary step-up. Dropping the last proof ends the session: neither field is set.
- **Still stateless.** Nothing on the person changes, so the credential the client held before the call
  still carries the dropped proof until it expires; the client discards it, as it discards a credential
  on a full sign-out. Killing every outstanding credential is `RevokeSessions`; removing the link is
  `DeleteIdentityLink`.
- Tests (`SessionCredentialTest`): one of two providers dropped (the other's tenants only; the AT stays
  in acme when the remaining proof vouches it, falls to `people` when it does not, and acme is a step-up
  again), the last dropped (no credential, no AT), an unknown or absent provider refused, a provider's
  every proof dropped by `idp_id` alone.

## 2026-10-27 — Relayed claims never carry the names kernel synthesizes (#9)

Ported from SeaBeam a19d59a ("kernel owns the synthesized claim names"), in this repo's shape. Kernel hands OPA
claim sets it builds itself on two paths (the device arm and the personal-principal tenant exchange):
`principal_id`, `tenant_namespace`, `proof_kind`, `customer`. oauth relays any non-well-known IdP claim under its
own name, so a tenant IdP could put one of those names in its id_token and have it read as kernel's.

- Every relayed claim set loses those four names before OPA sees it: the people arm (so the proof, and every
  access token minted from it, never carries them either), the ordinary tenant login, a link's tenant side, and
  the CLI token broker. `IdentityServiceImpl.SYNTHESIZED_CLAIMS` is the list.
- Not ported from that commit: `owner` (kernel does not synthesize it here) and handing OPA `principal_id = <xid>`
  at login (the per-tenant exchange here replays the proof's claims and synthesizes nothing).
- Tests: `SessionCredentialTest` (people login: OPA at login and exchange, the proof, both access tokens; tenant
  login; CLI broker), `TenantUserLinkTest` (link side). Each failed before the change.

## 2026-10-27 — Devices belong to the XID; the `/people/<pid>` principal is retired (#18)

tacplus 2.4 retired the `/people/<pid>` SPIFFE root (tacplus#131): a person is `spiffe://<td>/users/<xid>`. Kernel's
device principal moves onto the person, which is step 4's device half and answers #4's open question for approvals.

### What changed

- **A device is a credential of the XID.** `Person.devices` (repeated `PersonalCredential`, at most 16) holds a
  person's device keys. One key belongs to at most one person. `PrincipalState.personal_principals` is gone.
- **Enrolment** is `Mint.CreateTenantUserLink` with a device side beside a people-provider login, bound exactly as
  §3 bound it: the id_token's `nonce` is the key's thumbprint, and the WebAuthn assertion's challenge names that
  login. The credential goes onto the XID the login resolves to (created on first sight, as any login creates
  one). No link edge is written; the response's two keys are both the person's. A key already on another
  person's XID is refused before anything is written, the login's person included (moving a key between people is
  a merge). Re-enrolling the same key on the same person changes nothing, and a revoked key cannot be re-enrolled.
- **The device token (the cred_pair mint)** is `MintUserToken` with `AUTH_BROKER_KIND_DEVICE`, a JWT signed by an
  enrolled key: `sub = /users/<xid>`, `namespace = /tenants/people` (the people tenant's token, like every personal
  token), `device = <credential_id>`, and `xid_gen` (the person's generation). `device` joins the synthesized claim
  names stripped from every relayed claim set, so no IdP login can pass for a device token. The exchange re-checks
  a device token on every use: the credential must still be enrolled and unrevoked on the live person its `sub`
  names, at that generation. So removing the device, deleting the account and signing out everywhere all reach a
  device token that is already out.
- **Approvals check the XID directly.** The person is the caller's `sub` when it is an XID, in whichever tenant
  (`personUserKey` is `/tenants/people|<sub>` as before). The approving credential must be on that XID's
  `devices`. No `TenantUserLink` is read. `BrokerPendingApprovalResponse.device_namespace` (3) becomes
  `device_credential_id` (3).
- **Removing a device** is the new `UserMint.RevokeDeviceCredential(credential, credential_id)`: the caller's own
  session credential, no proof from the device (a device is most often removed because it is lost). The credential
  is marked revoked, never deleted. `GetLinkedAccounts` now lists `devices`. MergePeople moves the absorbed person's
  devices to the survivor. DeleteAccount clears them.
- **Retired with the principal:** `Mint.CreatePersonalPrincipal` (device-first registration);
  `PersonalIdentity.GetMyIdentity`; the personal-principal tenant exchange (`MintToken` with `tenant_namespace` on a
  `/people` token) together with `TenantMembership` and `MembershipProofKind`. `PersonalPrincipal` survives only as
  the shape of `KernelDiskState.personal_principals` (10), so that an old snapshot can be read once.

### Decided here

- **No device-first XID.** Only a personal IdP login mints an XID. A self-asserted key alone may not (identity graph
  huddle 2026-10-21, items 3 and 17), and device attestation, the one other anchor, is deferred (platform
  direction 2026-10-23). So enrolment needs the person's login, and `CreatePersonalPrincipal` has no XID to
  register onto. Nothing in the fleet called it.
- **A device token is the people tenant's token**, `namespace = /tenants/people`, not a `/users/<xid>` namespace:
  the authorizer's single-namespace model is unchanged (step 1). A tenant token needs a live proof from that
  tenant's IdP (step 2). The `/people` exchange that minted one from a membership record alone does not survive.

### Migration (one-time, at boot)

`ClusterServer.migratePersonalPrincipals` runs after the people and the links are restored. A device principal
whose live link edges into `/tenants/people` name exactly one live person (following a merge redirect) moves onto
that XID: every credential, with its key, label and revocation mark. A credential some person already holds is not
copied. Every other principal is dropped: no live link, links to two people, a deleted person, or a disabled
principal. Its memberships are dropped either way. Every `TenantUserLinks` edge naming `/people/...` is removed,
both directions. The boot log line counts what moved and what was dropped: `Migrated N /people device principal(s)
(C credential(s)) onto their XIDs; dropped K with no live link to exactly one person; removed E device link
edge(s)`. Nothing is written back by the migration itself. Until the next identity write, the old snapshot still
holds the rows, and replaying it gives the same result. The next snapshot carries no `personal_principals`. It
fails closed, like the restores around it.

How many are dropped on seatrials is that log line's to say once the image rolls (no deploy here). The expected
count is zero rows of either kind: the fleet runs no device broker, and nothing there ever called
`CreatePersonalPrincipal` or linked a device.

### Proof

- Kernel: `DevicePrincipalTest` (the device token is the person's with the `device` claim; two devices, one
  subject; only a device broker relays a proof; revoked, unknown and deleted-person keys get one refusal; a key
  cannot mint for another person; a device token already out stops when its device is revoked, the person signs
  out everywhere, or the account is deleted; a device token cannot name a tenant; a relayed `device` claim never
  reaches a token). `DeviceWebauthnLinkTest` (enrolment onto the XID and every binding refusal writing nothing;
  another person's device refused; the linked-accounts view; RevokeDeviceCredential end to end).
  `PendingApprovalTest` (approval by a device of the XID; another person's device and a revoked device refused;
  the person's token in any tenant proposes as them; a tenant user, including `/tenants/t/users/<xid>`, cannot).
  `PersonalPrincipalMigrationTest` (linked principal migrated with its marks and edges removed; the five drop
  cases counted; merge redirect followed; no double copy; restart round trip with no `personal_principals`
  written; fail-closed). Mutation-checked: disabling the approval ownership check, the cross-person enrolment
  refusal, the `device` strip or the exchange re-check fails exactly the test written for it.
- Gates on tacplus 2.4 (kernel#1's floor). See the issue for how they were run before that floor is on main.

## 2026-10-27 — Tenant ids (#3)

A tenant's Kubernetes namespace cannot be renamed, so it is named by an immutable, fixed-size id rather than the
tenant's name: `tac-<deployment>` for the platform services, `tac-<deployment>-<tid>` for each tenant (Jody,
2026-10-26). SPIFFE paths and grants still name the tenant; moving them to the tid is not part of this.

### What changed

- **`Tenant.tid`**: exactly 8 of `[0-9a-z]`, minted once, immutable, never reused. `CreateTenant` mints it and
  returns it on the `Tenant`; `ListTenants` and the record carry it.
- **Unique by insert-if-absent.** `ConfigState.tenant_ids` (`TenantIdRow`, keyed by tid) holds every tid ever
  issued. Minting draws a random tid and inserts its row only if absent (`TenantIds.mint`); a taken one is just
  another draw. `DeleteTenant` tombstones the row (`tombstoned_at_ms`) and never deletes it, so a deleted tenant's
  tid is never issued again. The rows ride the disk snapshot (`KernelDiskState.tenant_ids`).
- **Reserved range.** Every all-digit tid is the platform's. `people` is `00000001` and `restore` is `00000002`, the
  same in every deployment. A minted tid is a letter then 7 of `[0-9a-z]` (about 41 bits), so it never falls in
  that range.
- **The `restore` tenant** (`RestoreTenant`) hosts redo (tacplus-dev/redo#1) and has no human members. It is seeded
  at every boot as `people` is, and `TenantAdmin` refuses to create, reconfigure or delete it.
- **Bootstrap tenants.** `Config.tenants` (`BootstrapTenant{name, tid}`) lists the tenants the deployment renders
  before kernel starts. Kernel seeds each at every boot as `/tenants/<name>`: under the listed tid as given, or a
  minted one when it lists none (kept from then on through the snapshot). A tenant that already exists keeps its
  record; a listed tid that differs from the record's is refused, and so is one that is malformed, all digits,
  tombstoned or another tenant's. Each entry is seeded on its own; the boot log names every refused one.
- **Backfill.** A tenant record written before tids gets one minted at boot (`TenantIds.backfill`), with a
  compare-and-set on the record, so of two kernels booting at once one tid lands and the other is tombstoned.
- Kubernetes service-account matchers are unchanged: they already name a namespace. A test shows a tenant-owned
  instance matched in its tenant's own `tac-<deployment>-<tid>`.

### Decided here (issue silent)

- **The bootstrap list is a new `kernel.Config.tenants`.** Kernel's Config had no tenant list. operator.yaml's
  `tenants` (bare names) are rendered into per-tenant pods and delegates but were never kernel records. The
  operator rendering `Config.tenants`, with the tids it names namespaces by, is the operator's side and is not
  done here.
- **A bootstrap tid may not be all digits.** The reserved range is the platform's, and kernel seeds the platform's
  tenants itself.
- **A refused bootstrap entry does not stop kernel.** It is logged at error with the reason, like the other boot
  seeds, and the remaining entries are still seeded.

### Proof

- `TenantIdTest`: format (10 000 mints match `^[a-z][0-9a-z]{7}$`, none in the reserved range); uniqueness (a taken
  draw is skipped, a held tid cannot be claimed, 200 tenants get 200 tids); immutability (a bootstrap entry cannot
  change a tid; tid and tombstones survive a restart; delete-then-recreate gets a new tid, and the old one cannot be
  drawn or claimed); reserved (`people` is `00000001`, `restore` is `00000002`, both survive a restart, `restore`
  cannot be deleted, created or reconfigured); the seeded case (a listed tid is seeded as given and kept on every
  boot, a missing one is minted once, reserved/malformed/another tenant's/reserved-name entries are refused while
  the rest are seeded, a record from before tids takes the listed tid); backfill.
  `MintServiceTokenKubernetesTest.aTenantOwnedInstanceIsMatchedInItsTenantsOwnNamespace`.

## 2026-10-27 — The `linked` claim is retired (#4)

Jody, 2026-10-26: retire the `linked` claim. XIDs (one person, `spiffe://<td>/users/<xid>`) and
request-named routing (tacplus#170) replace it. Who the caller is comes from the person, which tenant a
call is for comes from the request, and whether it is allowed is policy at the target. A token that widens
its own namespaces is the thing being removed. The tacplus side, the generated backstop that accepts
`linked` namespaces, is tacplus-dev/tacplus#171.

### What changed

- **No token kernel mints carries `linked`.** The session credential's access tokens
  (`accessTokenFromProof`) and the legacy user mint (`mintUserTokenInternal`, the device token included)
  no longer stamp it, and `linkedNamespaces` is gone. A relayed `linked` claim was already dropped,
  because `linked` is a platform claim name (`JWT_PAYLOAD_TYPE_LINKED`). A test now covers that.
- **The tenant-user link registry is retired.** `PrincipalState.tenant_user_links` (3) is reserved and
  is no longer restored (`ClusterServer.restoreTenantUserLinks` is gone) or written to the snapshot.
  `PersonalIdentity.RevokeTenantUserLink` and its messages are gone. `CreateTenantUserLink` now only enrols
  a device. A request with no device side is refused with `INVALID_ARGUMENT` before either side is
  resolved, so it writes nothing, not even a person. The nonce-pair proof, the OPA-named tenant side and
  the per-user link cap went with it.
- **An old snapshot still boots.** `TenantUserLink`/`TenantUserLinks` survive only as the shape of
  `KernelDiskState.tenant_user_links` (12), the same way `PersonalPrincipal` survives for field 10.
  `migratePersonalPrincipals` reads the device edges straight from the snapshot to find each pre-#18
  principal's person. It no longer reads them from live state. Every other edge is ignored. The boot log
  counts the ignored rows (`Ignored N retired tenant-user link row(s) in the disk snapshot (kernel#4)`).
  The next snapshot written carries none.

### Decided here

- **#4's open question was already answered by #18.** Device approvals check the approving credential
  against `Person.devices` of the XID the approval names. `personUserKey` reads no link, and the
  `/people/<pid>` principal is gone. Nothing but the `linked` claim and the #18 migration read the link
  records, so they go.
- **The RPC keeps its name.** `CreateTenantUserLink` is the device broker's enrolment call. Renaming it
  would break that caller's contract for no behavioural gain. `TenantUserLinkSide.subject` and
  `CreateTenantUserLinkRequest.trace_id` are now ignored but not reserved, so a broker that still sets
  them keeps compiling.
- **Field 12 stays readable rather than reserved.** Reserving it would make the #18 migration drop every
  pre-#18 device principal, because their edges are the only record of whose devices they were. The
  expected count on seatrials is zero rows either way (see #18), but keeping the field readable costs
  nothing.

### Proof

- `TenantUserLinkTest`: a person with an enrolled device and tenant links in both directions, booted
  from a pre-#4 snapshot, mints tenant refresh and access tokens and the people session credential and
  access token. None of them carries `linked`. A relayed `linked` claim never reaches a token. Two IdP
  logins are refused and write nothing. The next snapshot holds no link rows and the same person with the
  same device. The first and third of these failed before the change.
- `PersonalPrincipalMigrationTest`: the migration finds the person through the snapshot's edges, counts
  them as ignored, and writes none back. `DeviceWebauthnLinkTest`, `DevicePrincipalTest` and
  `PendingApprovalTest` (enrolment, device tokens, approvals) pass unchanged apart from the removed
  registry assertions.
- Gates on tacplus 2.4.

## 2026-10-27 — Deleting a tenant is complete for what kernel owns (#19)

Jody, 2026-10-27 (tacplus-dev/roadmap decisions/tenant-deletion-2026-10-27.md): deleting a tenant is destructive
and complete. Nothing it owned is left orphaned, the people stay, and the tenant can no longer mint access or
service tokens. Tokens already issued are not chased. This entry covers kernel's part; Stratum data and the
Kubernetes namespace belong to the restore tenant, the operator and nsproxy.

### What changed

- **A deleted tenant mints nothing.** A tenant is deleted when its tid is tombstoned and no live tenant record holds
  its namespace (`TenantIds.deletedTenantOf`). Every token kernel signs carries the namespace it is for, so the check
  sits at the signature (`IdentityServiceImpl.signLive`): every mint path is refused with `PERMISSION_DENIED`
  ("tenant /tenants/<t> was deleted: it mints no tokens"), and so is any path added later. That covers the
  session-credential exchange, a people login routed into the tenant, a tenant IdP login, the refresh-to-access and
  access-to-service exchanges, the Kubernetes and cloud-proof service mints, delegated (grant) and delegate offline
  tokens, workloads, cred-pair client tokens and external service tokens. Three paths sign without going through it
  and check on their own: `MintExternalToken` (the user token's namespace), `X509Mint` (the subject's) and
  ManageCert, which checks on every CSR so a stream that is already open stops renewing.
- **A login routed into a deleted tenant writes nothing.** A claim matcher left behind in policy creates no person
  and no membership: the check runs before `IdentityGraph.resolveOrCreate`.
- **Memberships are removed; the people stay.** `IdentityGraph.removeTenantMemberships` removes the tenant's
  membership from every person, tombstoned people included, and keeps the person, their XID, links, devices and
  other memberships. It is part of the people service's contract, so it carries over when the graph moves.
- **The rest of the tenant goes.** `DeleteTenant` first removes the records and tombstones the tid, so nothing mints
  into the tenant from then on. It then runs the purge (`IdentityServiceImpl.purgeDeletedTenant`) and logs one line
  for each kind of state:

  | Found | Done |
  |---|---|
  | Tenant record, `tenant_config`, project configs | Deleted (as before) |
  | The tid's `TenantIdRow` | Kept, tombstoned (#3): the one row left that names the tenant |
  | `Person.memberships` of the tenant | Removed from every person |
  | `PendingApproval`s naming it | Deleted. An approval is keyed to the person (`/tenants/people\|<sub>`), so there are none |
  | Grants whose delegate is the tenant's | Revoked. They come from `Config.grants`; the revocation rides the snapshot, so they stay revoked when the boot reseeds them |
  | Workload localities of the tenant's services | Deleted |
  | Workload revocations of the tenant's workloads | Kept. They are a deny list, and dropping one would un-revoke the workload if a tenant of the same name came back |
  | Withheld delegate offline tokens for it | Dropped, so no code redeems one |
  | Delegates and their Kubernetes service-account matchers for it | Counted only. They are `Config.delegates`, the deployment's; every mint through one is refused |

### Decided here (issue silent)

- **"Removed" means removed.** `PersonMembership.revoked_at_ms` marks and never deletes, but the issue asks for no
  trace of the tenant in kernel state, so the membership row goes. The tid tombstone is the record that the tenant
  existed.
- **A tenant created again under the same name mints.** It is a new tenant with a new tid. The refusal belongs to the
  deleted tenant, not to the name. Kernel cannot tell the two tenants' tokens apart until SPIFFE paths and grants
  name the tid (#3 left that out); see PROPOSALS.md.
- **A namespace kernel has no record of is not deleted.** Delegates may name a tenant kernel never recorded (the
  operator's tenants, before it renders `Config.tenants`). Only a tombstone makes a tenant deleted, so those still
  mint.
- **The session exchange's refusal keeps its one shape.** With the membership gone, it answers "no live proof
  vouches for ..." as for any other miss, so the exchange cannot be used to probe which tenants a person belonged to.

### Proof

- `TenantDeletionTest`: for a person routed into acme, acme's Kubernetes-matched `docmanager` and two grants, every
  mint path into acme that worked before `DeleteTenant` is refused after it, and people and beta still mint. The
  paths are the exchange, a people login, a tenant IdP login, RT to AT, the Kubernetes mint, AT to ST, both grants
  and X509Mint. The person keeps their XID and links, and loses only the acme membership. A login routed into acme
  writes no membership back. A walk of `PrincipalState` and `ConfigState` finds acme only in its tombstoned tid, and
  beta's rows are unchanged. Localities are deleted, revocations kept, acme's grant is revoked and the /system one
  is not. Withheld offline tokens for acme are dropped. Acme created again mints under a new tid. A record-less
  tenant still mints. All six fail with the check and the purge taken out.
- `TlsCertRevocationTest.aDeletedTenantsServiceCannotRenewItsCert`: an open ManageCert stream is refused its next
  renewal once its tenant is deleted.
- Gates on tacplus 2.4.
