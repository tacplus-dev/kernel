# Kernel

Kernel is the distributed backend database for the control plane. It provides
clustered state management over gRPC, built on Hazelcast, with persistence,
security, real-time diagnostics, and a built-in token exchange service.

Every kernel instance runs as a Hazelcast cluster node, a gRPC server, a
persistence manager, and a security enforcer. Microservices connect to kernel
to read and write distributed state via auto-generated gRPC clients.

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
                    │  Persistence (per-boundary disk snapshots)    │
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
- `persistence_status` — On-disk snapshot size, last snapshot timestamp
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

## Persistence

Kernel is the durable store for the whole cluster. Every state boundary marked
`(spec.persistence) = true` — in ANY service's proto, not just kernel's own —
is written to the kernel `data` volume and restored on a cold start. Services
do NOT persist their own state. A boundary WITHOUT the flag is ephemeral: it
lives in Hazelcast memory, survives a single pod restart through partition
backups, and is gone once every pod has restarted.

- **Kernel's own state** — one atomic `KernelDiskState` snapshot
  (`_root/kernel_disk_state.snapshot`), written by `KernelPersistence`: signing
  keys, the public verifying set, the CA tree, the tenant/project tree,
  workload revocations, standing grants and personal principals.
- **Every other flagged boundary** — one **redo log** per boundary under
  `_root/boundaries/<map name>.log`, written by `BoundaryPersistence` through
  the chassis `RedoLog`. Per boundary rather than one blob because the flagged
  set includes collections whose declared maxima run to the millions; one blob
  would rewrite the whole fleet's state on every write. A mutation **appends
  one record for the one key it touched** — O(1) whatever the boundary holds —
  carrying a `PersistenceEntry` whose value is wrapped in an `Any`, so the log
  names the proto type it holds. Periodically the log is **checkpointed**: it
  is rebuilt as the boundary's current state and swapped in by one atomic
  rename, which coalesces the history and truncates it. The trigger is
  size-based — past 4MiB and past twice the size the last checkpoint left — so
  the amortized cost per write stays O(1) and the log stays within twice the
  live state.

Both are written **on change, synchronously, on the node serving the write**.
A write whose record does not land throws, so the RPC fails rather than acking
data that exists only in memory. The other nodes keep their own logs current
from the boundary's Hazelcast entry listener, so every node holds a complete
set.

**Replay is cold-start only.** A node that boots and finds no reachable
Hazelcast peer is forming the cluster and replays its logs; a node that joins
live peers takes its state from them and never reads its own files. A rolling
restart must not let a node resurrect what it held when it went down. A log
that exists but cannot be parsed fails the boot rather than coming up with a
service's state silently emptied — the one tolerated damage is an unterminated
final line, which is a crash between an append and its fsync and therefore a
record no caller was ever acked for.

**A node that joined peers still writes its own full copy.** Taking state from
peers puts nothing on that node's disk, so a row that never mutates again
would be durable on no node at all after a rolling restart. Once its
partitions are safe, a joining node checkpoints every boundary in the
background — off the readiness path — and logs one line per boundary with the
row count written, which is what a rolling deploy is verified against.

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
returns cluster info, health, node metrics, gRPC stats, persistence status,
network stats, and map stats in a single call.

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
