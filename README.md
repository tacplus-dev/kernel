# Kernel

Kernel is the distributed coordination store for the control plane. It provides
clustered, in-memory state management over gRPC, built on Hazelcast, with
security, real-time diagnostics, and a built-in token exchange service.

Every kernel instance runs as a Hazelcast cluster node, a gRPC server, and a
security enforcer. Microservices connect to kernel to read and write
distributed state via auto-generated gRPC clients.

Kernel holds **no durable data and no user data**. Durable data belongs in
stratum records. The one exception is kernel's own identity snapshot — see
[Persistence](#persistence).

## Why "Kernel"

The service's formal name in proto definitions is `BackendDB`. Kernel is the
internal code name used everywhere else.

## Architecture

```
                    ┌───────────────────────────────────────────────┐
                    │                kernel cluster                  │
                    │                                               │
  microservices ──► │  gRPC server                                  │
   (via gRPC)       │    ├── SecurityInterceptor (token validation) │
                    │    ├── Rate limiter (polling detection)       │
                    │    └── Auto-generated boundary RPCs           │
                    │                                               │
                    │  Hazelcast IMaps (distributed state)          │
                    │    ├── TokenExchangerInternal                 │
                    │    ├── TrustedCaState                         │
                    │    ├── ClusterState                           │
                    │    ├── ServiceHealthState                     │
                    │    └── ... (external service state roots)     │
                    │                                               │
                    │  Identity snapshot (kernel's own state only)   │
                    │  Background publishers (metrics, health)      │
                    │  TokenExchangerService (built-in RPC)         │
                    └───────────────────────────────────────────────┘
```

## Token Exchanger

TokenExchanger is a service built directly into kernel. It handles
authentication for backend access — every microservice that talks to kernel
must first obtain tokens from TokenExchanger.

### Why it must be built in

TokenExchanger exists inside kernel to solve a chicken-and-egg problem.
Consider Identity (the OAuth2 gateway): Identity needs to publish its
signing keys (JWKs) to kernel so that other services can verify tokens
Identity issues. But to write anything to kernel, Identity first needs a
valid ServiceToken. If the token exchange service were external, it would
itself need a ServiceToken to bootstrap — a circular dependency.

By building TokenExchanger into kernel, the bootstrap flow becomes:

1. Identity (or any service) presents a delegate proof to kernel. In-cluster
   workloads use projected Kubernetes service-account tokens; cloud-native
   workloads use `cloud_proof` once that verifier is implemented.
2. Kernel resolves the proof to a configured delegate and returns a
   **refresh token** plus initial **access token**.
3. The service exchanges the refresh token for a short-lived **access token**
   scoped to the kernel backend.
4. The service can now make authenticated gRPC calls to kernel (e.g.,
   Identity publishes its JWKs to `IdentityState.verifying_keys`).

### What TokenExchanger does

TokenExchanger performs exactly three operations:

1. **Delegate proof → refresh token**: Accepts a Kubernetes service-account
   token or cloud proof, resolves it to a delegate, and returns a refresh token
   bound to that delegate identity.

2. **Refresh token → access token**: Accepts a valid (unexpired) refresh
   token. Returns a short-lived access token for the kernel backend. The
   access token contains the service identity (sub, aud, instance_id).

3. **Refresh token renewal**: Accepts an unexpired refresh token alongside a
   fresh delegate proof. Verifies both resolve to the same subject and
   re-issues a new refresh token with the original `client_id` carrying over.
   This enables seamless token rotation without identity discontinuity.

All tokens issued by TokenExchanger are **exclusively for communicating with
the kernel backend**. They are validated by kernel's SecurityInterceptor
internally. No external service needs to independently verify these tokens.

### State: TokenExchangerInternal

TokenExchanger's backend state root holds:

- **verifying_keys** — The exchanger's public signing keys, rotated
  periodically. Used by the SecurityInterceptor to validate tokens on
  incoming gRPC calls. Participates in the `JwkVerifyingKeysView`.

### Configuration: TokenExchangerConfig

Set via `Config.token_exchanger`:

- `refresh_audience` — Expected `aud` claim in refresh tokens (default: `"refresh"`)
- `key_rotation_interval_seconds` — How often signing keys rotate (default: 7d)
- `default_token_expiry_seconds` — Lifetime of issued access tokens (default: 1h)
- `opa_entry_point` / `opa_bundle` — Optional OPA policy for authorization decisions

### Delegate Proofs

Delegates are configured in `Config.delegates`. Each delegate binds one service
identity to one or more bootstrap matchers:

- `kubernetes_service_accounts` — Kubernetes namespace/service-account pairs
  that may authenticate as the delegate.
- `cloud_identities` — Cloud-native identities that may authenticate as the
  delegate once cloud proof verification is implemented.
- `authorized_services` — Services the delegate may mint tokens for.

## Built-in State Roots

Kernel hosts four built-in state roots plus any number of external service
state roots (e.g., `IdentityStateInternal`, `SnoopyState`, etc.).

### TokenExchangerInternal

The token exchange service's internal state. See [Token Exchanger](#token-exchanger)
above. Access: RO for all authenticated callers (keys only).

### TrustedCaState

Centralized CA certificate store for TLS verification. Loaded from
`Config.trusted_cas` on each config reload. Services read these (RO) to
configure TLS trust for outbound connections.

### ClusterState

The main diagnostics and admin hub. A background publisher on each node
periodically writes metrics from JVM and Hazelcast APIs into these
boundaries:

**Cluster-wide singletons** (any node writes, convergent LWW):
- `cluster_info` — Membership, state, partition count, version
- `cluster_health` — Partition safety, quorum status, migration queue
- `frontend_config` — Current reloaded Config snapshot

**Per-node collections** (keyed by node_id, TTL 120s):
- `node_metrics` — Memory (heap, GC), CPU (load, uptime), disk usage
- `grpc_stats` — Active connections, total RPCs, active streams, rate limiting
- `network_stats` — Listen address, cluster connections, bytes sent/received
- `thread_info` — Thread counts, peak, daemon, deadlocked
- `token_cache_stats` — Cache hit/miss/eviction counts
- `map_stats` — Per-map statistics (size, entry counts, get/put/hit, memory)

**Service tracking** (published by SecurityInterceptor):
- `service_connections` — Which services are connected, per-method RPC counts,
  polling detection, error counts, latency percentiles, mutation counts
- `graph_registry` — Metadata for all boundaries across all state roots

**Queue/Topic/Watch health** (per-queue/topic/watch per-node):
- `queue_stats` — Depth, offer/consume rates, lag, active consumers
- `topic_stats` — Published messages, subscriber count, per-subscriber stats
- `watch_health` — Active Watch streams, messages sent/pending, backpressure
- `mutation_rates` — Per-boundary write throughput with per-service breakdown

**Commands**:
- `set_log_level` — Dynamically change logger levels without restart
- `reload_config` — Reload frontend Config from URL or file

### ServiceHealthState

Health reporting endpoint for all microservices. Uses `instance_keyed`
annotation: the server extracts `instance_id` from the caller's token and
uses `"service_id@instance_id"` as the map key. Entries TTL-expire in 30s —
when a process dies, its health entry is automatically cleaned up.

## Security

### SecurityInterceptor

Every incoming gRPC call passes through the SecurityInterceptor, which:

1. Extracts the bearer token from the request
2. Validates the JWT signature against known signing keys
3. Checks `aud` matches `SecurityConfig.audience` (default: `"kernel"`)
4. Checks token lifetime against `SecurityConfig.token_ttl_seconds`
5. Enforces `BackendSecurity` policies (who can read/write each boundary)
6. Publishes connection activity to `ClusterState.service_connections`

### BackendSecurity (access-policies.yaml)

Per-resource access control, loaded at boot:

- **rw** — Read-write access (Set, Delete, Offer, Publish, Execute)
- **ro** — Read-only access (Get, GetAll, Watch, WatchAll, ContainsKey, etc.)
- **exec** — Execution access (RPC invocation, commands)

Private boundaries (marked `(spec.private) = true`) are enforced by code
generation — no RPCs are generated for them regardless of policy.
Views are always read-only regardless of caller access level.

### Rate Limiting

Kernel detects polling and nudges clients toward Watch/Subscribe streaming:

- `polling_rate` (default 2.0 req/s) — For unary RPCs that have streaming
  alternatives. A low limit encourages using Watch.
- `unary_rate` (default 10.0 req/s) — For unary RPCs without streaming
  alternatives.

Rate limiting is per-service per-method. Violations are tracked in
`ClusterState.grpc_stats` and `service_connections`.

## Configuration

### BootstrapConfig (immutable, read at boot)

- `cluster_name` — Logical cluster identifier (all nodes must match)
- `listener` — gRPC bind address
- `members` — Cluster peers for discovery
- `node_count` — Expected cluster size
- `secret` — Hazelcast membership authentication
- `partition_count` — Data distribution granularity (default: 271)
- `tls` — Node's X.509 cert + key for gRPC TLS
- `config` (oneof) — How to load frontend Config: `url_loader` or `file_loader`

### Config (mutable, reloadable via command)

- `trusted_cas` — CA certificates for TLS verification
- `rate_limit` — Rate limiting thresholds
- `configs` — Per-frontend-service configurations (ConfigHolder)
- `security` — Token validation policy (audience, max TTL)
- `token_exchanger` — TokenExchanger configuration
- `delegates` — Service identities, bootstrap matchers, and S2S mint grants

### Config seeding: the bundle always wins

Kernel installs `Config.configs` into every service's ConfigState root on **every
boot**, overwriting whatever the root already held. The git-committed bundle is
the single source of truth (config-as-code): a changed bundle value always
becomes live on the next kernel restart or roll, for every service, with no
create-only exception.

The bundle is the only writer. Kernel exposes no live config-push RPC: a config
change is a bundle change plus a deploy, the same for every service.

## Persistence

**Kernel does no durability for service state, and holds no user data.** Every
state boundary — kernel's own and every other service's — is in-memory
coordination state. It lives in Hazelcast, survives a single pod restart
through partition backups, is rebuilt from config seeding and from peers when a
pod rejoins, and is gone once every pod has gone down together. That is by
design: durable data belongs in **stratum records**, not in kernel state.

The one thing kernel writes to disk is its **own identity snapshot** — one
atomic `KernelDiskState` object (`_root/kernel_disk_state.snapshot`), written by
`IdentitySnapshot`: signing keys, the public verifying set, the CA tree, the
tenant/project tree, workload revocations, standing grants, tenant-user links
and personal principals. It is written on change, synchronously, and a write
that does not land throws so the RPC fails rather than acking a revocation that
exists only in memory. It is replayed at boot; every restore leg is additive or
subordinate to the config bundle, so a pod rejoining live peers cannot
un-revoke or roll back what the cluster did while it was down. A snapshot that
exists but cannot be parsed fails the boot rather than coming up with identity
silently emptied.

The kernel `data` volume therefore holds only that snapshot and the Ratis
fenced-lock tree.

`(spec.persistence)` is not honored for kernel state boundaries — tacplus
refuses the annotation on one, because durable data belongs in stratum records.

## Consistency Model

All boundaries are **CONSISTENCY_CONVERGENT**:
- Lockless, last-writer-wins, async replication
- Suitable for metrics, diagnostics, observability, and state that tolerates
  brief staleness
- TTL-based eviction for automatic cleanup

## JWK Verifying Keys View

The `JwkVerifyingKeysView` is a cross-service aggregated view that collects
public signing keys from multiple state roots. Currently:

- `TokenExchangerInternal.verifying_keys` — Kernel's own signing keys
- `IdentityState.verifying_keys` — Identity's signing keys

The view auto-generates a `JwkVerifyingKeysViewService` with Watch and Get
RPCs. Frontend services (via the frontendserver library and service_config)
subscribe to this view at boot to discover all signing keys for token
validation on incoming requests.

## Sentinel (Admin Dashboard)

Sentinel is a separate frontend service that provides a web-based admin
dashboard for kernel. It has an empty backend state (`SentinelState`) and
reads `ClusterState` via a security policy RO grant. Its `GetDashboard` RPC
returns cluster info, health, node metrics, gRPC stats, network stats, and
map stats in a single call.

## External Service State Roots

Services define their own state roots in their proto files (e.g.,
`SnoopyState`, `WoodstockState`, `IdentityStateInternal`, `IdentityState`).
Kernel hosts all of these as Hazelcast IMaps. Access is controlled by the
`BackendSecurity` policy — each service gets RW to its own state and RO
(or no access) to others as configured.

## Proto Definition

The complete proto definition is in
[`services/kernel.proto`](kernel.proto). Shared admin metric types are in
[`services/cluster.proto`](cluster.proto).
