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
