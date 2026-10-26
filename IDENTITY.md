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
