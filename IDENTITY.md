# Identity and Token Architecture

## Authority Boundaries

The identity system has a small number of distinct authorities. Keeping them
separate is what makes the trust model auditable.

1. **The operator deploys.** It provisions clusters and workloads and is the
   only component that wires environment-specific verifiers (e.g. the live
   Kubernetes token verifier — see below). The operator does not mint identity.
2. **kmaker makes kernels only.** kmaker signs kernel certificates
   (`MintKernelCert`) bound to verified pod facts. It is the certificate
   authority for *kernels*; it does not mint Cavalier tokens or ordinary service
   identities.
3. **Kernel mints Cavalier tokens and ordinary service certs.** Kernel is the
   signing authority for all S2S/C2S tokens and for ordinary service TLS
   certificates (the SPIFFE-keyed leaf+intermediate chain issued from
   `TokenMint` when the caller's `sub` is a SPIFFE URI).
4. **Kubernetes tokens, `cloud_proof`, and `cred_pair` `input_token`s are
   layered delegate proofs.** They are *inputs* a service presents to the
   kernel to prove which delegate it is. They are never themselves Cavalier
   identity; the kernel resolves them to a registered delegate and then mints
   its own tokens. A presented credential's facts (e.g. a verified pod's SA)
   are cross-checked, never trusted verbatim.

> Field names/numbers settled in Phase 2 are authoritative:
> `MintServiceTokenRequest.credential_proof` is a `oneof` of
> `input_token = 1`, `cloud_proof = 2`, `kubernetes_token = 8`, and
> `Delegate.kubernetes_service_accounts = 5` (repeated
> `KubernetesServiceAccountMatcher`). The kernel-side cert RPC keeps its
> existing name `MintKernelCert` (it is not being renamed to `SignKernelCert`).

## S2S (Service-to-Service) Tokens

### Bootstrap

Cavalier generates a **cred pair** (Ed25519 keypair) per service at init time.

- The **private key** stays in the service's bootstrap config (never leaves the service).
- The **public key** is registered as a **delegate** in the kernel config.
- Each delegate entry specifies which services the delegate may mint tokens for. Currently each service can only mint for itself.

### Service Startup

1. The service signs a **throwaway JWT** with its cred pair private key (`iss: "<service>"`, `sub: "<service>"`, `aud: "kernel"`, short expiry).
2. The service sends this JWT as `input_token` to kernel's `TokenMint` RPC.
3. Kernel matches the JWT's `kid` to a registered delegate's cred pair, **verifies the signature**, and mints a **refresh token** and **access token**:
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

All S2S tokens are signed by kernel and kernel only. There is no fallthrough to external IdP resolution for S2S flows. If the `kid` does not match a registered delegate cred pair, the request is not treated as S2S.

### Credential Layering (Phase 2)

The cred-pair JWT described above is one of three mutually exclusive ways a
service can prove which delegate it is when minting an S2S token. A
`MintServiceTokenRequest` carries **exactly one** credential in its
`oneof credential_proof`:

- **`input_token` (= 1)** — the existing cred-pair bootstrap JWT (above). Fully
  implemented.
- **`cloud_proof` (= 2)** — a cloud-native identity proof (AWS STS / GCP /
  Azure). **Stub:** the mint path routes this to an explicit
  `UNIMPLEMENTED` rather than silently accepting it.
- **`kubernetes_token` (= 8)** — a projected Kubernetes service-account JWT.
  The kernel structurally checks the token, hands it to a swappable
  `KubernetesTokenVerifier` seam, then maps the verified `(namespace,
  service_account)` to a delegate via that delegate's
  `kubernetes_service_accounts` matchers (`Delegate.kubernetes_service_accounts
  = 5`).

Because `credential_proof` is a `oneof`, new clients can only set one
credential. The mint path additionally counts the flat fields and rejects any
request that somehow sets more than one, so a pre-`oneof` / raw client cannot
smuggle multiple proofs.

Whichever credential is used, if the request also carries a `continuity_token`
the kernel cross-checks it against the **resolved delegate's canonical SPIFFE
id** — i.e. the identity the prior refresh token actually carries — not against
anything derived from the presented credential. This binds continuity to the
delegate the kernel resolved, not to attacker-controlled token contents.

**Kubernetes path is not yet live.** The real `kubernetes_token` verifier is
**not wired** in the kernel as merged on `main`. The default
`KubernetesTokenVerifier` is `UnwiredKubernetesTokenVerifier`, which **fails
closed**: every `kubernetes_token` is rejected with `UNIMPLEMENTED`. Phase 2
ships the kernel-side vertical (proto, routing, SA→delegate mapping, continuity
cross-check, and an in-memory fake for tests) but no production verifier. The
real verifier — a TokenReview client against the API server, or a local
SA-issuer JWKS verifier — depends on operator Phase 3 (projected tokens with
the kernel audience plus a `tokenreviews/create` RBAC grant for the kernel
service account). Swapping it in is a wiring change in `ClusterServer`; the
routing in `IdentityServiceImpl` does not change.

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

### Token Exchange for C2S (Current vs Target)

**Current (legacy):** The client cannot talk directly to kernel, so token exchange was implemented as custom code on the gateway proxy. This is confusing and requires hand-written glue.

**Target:** Kernel exposes a `service_c2s` RPC for token exchange. This RPC:
- Is marked `permit_any_user` so the gateway authenticates the request and proxies it directly to kernel.
- Kernel extracts the user's identity from the bearer token, validates it, mints a new token with the requested `aud`, and returns it.
- No custom proxy code required — standard gateway routing handles it.

### Destination Service Validation (C2S)

The destination service must check:

1. The token is a C2S token (`sub_type: "user"`).
2. The `aud` matches the destination service's own name.
3. The user's **profiles** authorize the requested operation (entitlement check).

## Token Hierarchy Summary

```
S2S Bootstrap:
  cred_pair JWT → kernel.TokenMint → refresh(aud:kernel) + access(aud:kernel)
  refresh(aud:kernel) → kernel.TokenMint(aud:X) → service(aud:X)

C2S Bootstrap:
  IdP OAuth token → oauth.validate → oauth.delegationMint(S2S bearer) → kernel.TokenMint
    → refresh(aud:kernel, sub_type:user, azp:oauth) + access(aud:kernel)

C2S Token Exchange:
  access(aud:kernel) → kernel.TokenExchange(aud:X) → service(aud:X, sub_type:user)
```

## Key Invariants

1. **All Cavalier tokens in the system are signed by kernel.** The exceptions are the *layered delegate proofs* a service presents to bootstrap an S2S token — the throwaway cred pair JWT, a `cloud_proof`, or a `kubernetes_token` — which kernel verifies, resolves to a delegate, and discards. They are never re-emitted as Cavalier identity.
2. **Only OAuth (and fleetwood) validate external IdP tokens.** No other service ever sees or validates non-kernel tokens.
3. **Destination services enforce access policy**, not kernel. Kernel mints tokens; destinations decide who may call them.
4. **`azp` records who brokered the token.** For S2S: the delegate name. For C2S: the on-behalf-of service (oauth, fleetwood, etc.).
5. **`sub_type` is the trust boundary.** Services declared `service_s2s` must reject `sub_type: "user"` tokens. Services declared `service_c2s` accept user tokens and enforce profile-based entitlements.
