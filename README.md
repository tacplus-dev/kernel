# Elvis

Elvis is the distributed backend database for the control plane. It provides
clustered state management over gRPC, built on Hazelcast, with persistence,
security, real-time diagnostics, and a built-in token exchange service.

Every elvis instance runs as a Hazelcast cluster node, a gRPC server, a
persistence manager, and a security enforcer. Microservices connect to elvis
to read and write distributed state via auto-generated gRPC clients.

## Why "Elvis"

The service's formal name in proto definitions is `BackendDB`. Elvis is the
internal code name used everywhere else.

## Architecture

```
                    ┌───────────────────────────────────────────────┐
                    │                elvis cluster                  │
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
                    │  Persistence (redo logs + full dumps)         │
                    │  Background publishers (metrics, health)      │
                    │  TokenExchangerService (built-in RPC)         │
                    └───────────────────────────────────────────────┘
```

## Token Exchanger

TokenExchanger is a service built directly into elvis. It handles
authentication for backend access — every microservice that talks to elvis
must first obtain tokens from TokenExchanger.

### Why it must be built in

TokenExchanger exists inside elvis to solve a chicken-and-egg problem.
Consider IronMaiden (the OAuth2 gateway): IronMaiden needs to publish its
signing keys (JWKs) to elvis so that other services can verify tokens
IronMaiden issues. But to write anything to elvis, IronMaiden first needs a
valid ServiceToken. If the token exchange service were external, it would
itself need a ServiceToken to bootstrap — a circular dependency.

By building TokenExchanger into elvis, the bootstrap flow becomes:

1. IronMaiden (or any service) has a **CredPair** — a public key registered
   in elvis's Config, bound to a service identity (subject + principal).
2. The service signs a bootstrap JWT with its CredPair private key.
3. The service calls `TokenExchangerService.ExchangeToken(bootstrap_jwt)`.
4. TokenExchanger recognizes the kid from the Config's `cred_pairs` list,
   verifies the signature, and returns a **refresh token**.
5. The service exchanges the refresh token for a short-lived **access token**
   scoped to the elvis backend.
6. The service can now make authenticated gRPC calls to elvis (e.g.,
   IronMaiden publishes its JWKs to `IronMaidenShared.verifying_keys`).

### What TokenExchanger does

TokenExchanger performs exactly three operations:

1. **CredPair token → refresh token**: Accepts a JWT signed by a CredPair
   private key. Validates the signature against the matching CredPair public
   key in Config. Returns a refresh token bound to that CredPair's identity.

2. **Refresh token → access token**: Accepts a valid (unexpired) refresh
   token. Returns a short-lived access token for the elvis backend. The
   access token contains the service identity (sub, aud, instance_id).

3. **Refresh token renewal**: Accepts an unexpired refresh token alongside a
   fresh CredPair-signed token. Verifies both share the same subject and
   re-issues a new refresh token with the original `client_id` carrying over.
   This enables seamless token rotation without identity discontinuity.

All tokens issued by TokenExchanger are **exclusively for communicating with
the elvis backend**. They are validated by elvis's SecurityInterceptor
internally. No external service needs to independently verify these tokens.

### State: TokenExchangerInternal

TokenExchanger's backend state root holds:

- **verifying_keys** — The exchanger's public signing keys, rotated
  periodically. Used by the SecurityInterceptor to validate tokens on
  incoming gRPC calls. Participates in the `JwkVerifyingKeysView`.

### Configuration: TokenExchangerConfig

Set via `Config.token_exchanger`:

- `refresh_audience` — Expected `aud` claim in refresh tokens (default: `"refresh"`)
- `key_rotation_interval_seconds` — How often signing keys rotate (default: 24h)
- `default_token_expiry_seconds` — Lifetime of issued access tokens (default: 1h)
- `opa_entry_point` / `opa_bundle` — Optional OPA policy for authorization decisions

### CredPairs

CredPairs are configured in `Config.cred_pairs`. Each binds a public key to
a service identity:

- `kid` — Key ID, used to match incoming JWTs to this CredPair
- `key` — JWK public key material
- `subject_type` — Identity type (e.g., `"service"`)
- `principal` — Identity name (e.g., `"ironmaiden"`, `"fleetwood"`)

## Built-in State Roots

Elvis hosts four built-in state roots plus any number of external service
state roots (e.g., `IronMaidenInternal`, `SnoopyState`, etc.).

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
- `persistence_status` — Redo log entry count, dump timestamps
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
3. Checks `aud` matches `SecurityConfig.audience` (default: `"elvis"`)
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

Elvis detects polling and nudges clients toward Watch/Subscribe streaming:

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
- `cred_pairs` — Public keys bound to service identities

## Persistence

Elvis persists all boundary data marked with `(spec.persistence) = true`:

- **Redo log** — Records every mutation (put/delete) with map name, key,
  proto bytes, operation type, timestamp, and consistency model. Enables
  recovery and convergent LWW merge on restore.
- **Full dumps** — Periodic snapshots with header (timestamp, entry count,
  node_id). Format configurable (default: binary protobuf).

## Consistency Models

**CONSISTENCY_CONVERGENT** (default for most boundaries):
- Lockless, last-writer-wins, async replication
- Suitable for metrics, diagnostics, observability, and state that tolerates
  brief staleness
- TTL-based eviction for automatic cleanup

**CONSISTENCY_ATOMIC** (for critical state):
- Requires FencedLock (CP subsystem must be enabled)
- Counter-based optimistic locking
- Synchronous backups
- Higher latency, lower throughput

## JWK Verifying Keys View

The `JwkVerifyingKeysView` is a cross-service aggregated view that collects
public signing keys from multiple state roots. Currently:

- `TokenExchangerInternal.verifying_keys` — Elvis's own signing keys
- `IronMaidenShared.verifying_keys` — IronMaiden's signing keys

The view auto-generates a `JwkVerifyingKeysViewService` with Watch and Get
RPCs. Frontend services (via the frontendserver library and service_config)
subscribe to this view at boot to discover all signing keys for token
validation on incoming requests.

## Fleetwood (Admin Dashboard)

Fleetwood is a separate frontend service that provides a web-based admin
dashboard for elvis. It has an empty backend state (`FleetwoodState`) and
reads `ClusterState` via a security policy RO grant. Its `GetDashboard` RPC
returns cluster info, health, node metrics, gRPC stats, persistence status,
network stats, and map stats in a single call.

## External Service State Roots

Services define their own state roots in their proto files (e.g.,
`SnoopyState`, `WoodstockState`, `IronMaidenInternal`, `IronMaidenShared`).
Elvis hosts all of these as Hazelcast IMaps. Access is controlled by the
`BackendSecurity` policy — each service gets RW to its own state and RO
(or no access) to others as configured.

## Proto Definition

The complete proto definition is in
[`services/elvis.proto`](elvis.proto). Shared admin metric types are in
[`services/cluster.proto`](cluster.proto).
