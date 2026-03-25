# tacplus Registry

This file is embedded in `registry.json` and describes how to navigate it.

## Overview

This registry describes a tacplus-generated service mesh with:
- **852** message types across **52** packages
- **510** RPCs across **45** gRPC services
- **52** state boundaries

## Structure

The registry is a recursive `PackageNode` tree. Each node has:
- `name` — short package name
- `full_path` — slash-separated path from root
- `children` — sub-packages
- `types` — message type descriptors (`TypeInfo`)
- `rpcs` — RPC descriptors (`RpcInfo`)
- `boundaries` — state boundary descriptors (`BoundaryInfo`)

Navigate by traversing `children` to reach any package. The tree mirrors the proto package hierarchy.

## Self-Description

The `$schema` field points to `registry.schema.json` (JSON Schema format).
The type definitions under `libs/tacplus` describe this document's own structure:
`PackageNode`, `TypeInfo`, `FieldInfo`, `RpcInfo`, `BoundaryInfo`, `EnumValueInfo`, `StatePermEntry`.

## RPC Categories

Every RPC is classified by verb convention:
- **ACCESSOR** — read/observe operations (Get, Watch, Query, KeySet, Size, ContainsKey, List, Peek, Subscribe)
- **MUTATOR** — write/modify operations (Set, Put, Delete, Remove, Clear, Publish, Offer, Reload)
- **EXECUTOR** — action/command operations (Assist, Authenticate, Authorize, Evaluate, Exchange, etc.)

Per-service aggregate enum values (`ALL_ACCESSORS`, `ALL_MUTATORS`, `ALL_EXECUTORS`) are available for security policy rules.

## Security Metadata

Each `BoundaryInfo` carries:
- `state_perms` — which other state roots this service accesses (target + mode: RO/RW/WORM/CALL)
- `internal` — namespace isolation flag
- `boundary_callers` — which services can call this boundary cross-namespace
- `boundary_perms` — per-boundary access overrides

Each `RpcInfo` carries:
- `disable_auth` — whether authentication is bypassed
- `allowed_callers` — service-level caller restrictions
- `allow_user` — whether end-user tokens are accepted
- `category` — accessor/mutator/executor classification

## Services

- **AegisConfigStateService**
- **AegisStateService**
- **AgenticCodeEventBusStateService**
- **AnthropicConfigStateService**
- **AnthropicService**
- **BigDataService**
- **BigDataStateService**
- **BigdataConfigStateService**
- **CaStateService**
- **ClickHouseStateService**
- **ClickhouseConfigStateService**
- **ClusterService**
- **ClusterStateService**
- **DgraphConfigStateService**
- **DgraphStateService**
- **EntitlementProfileViewService**
- **EventBusService**
- **EventbusConfigStateService**
- **EventbusStateService**
- **FleetwoodConfigStateService**
- **FleetwoodSessionService**
- **FleetwoodTokenService**
- **GatewayConfigStateService**
- **GatewayTlsStateService**
- **GitHubService**
- **GitLabService**
- **GithubConfigStateService**
- **GitlabConfigStateService**
- **IdentityStateService**
- **JwkVerifyingKeysViewService**
- **KernelMintService**
- **LetsEncryptStateService**
- **LetsencryptConfigStateService**
- **LockService**
- **McpAssistService**
- **McpConfigStateService**
- **MintService**
- **OAuthService**
- **OauthConfigStateService**
- **SentinelConfigStateService**
- **SentinelService**
- **ServiceConfigStateService**
- **ServiceHealthStateService**
- **TlsCertService**
- **TrustedCaStateService**

## Packages

- `clients/cavalierctl`
- `common/hazelcast`
- `common/openai`
- `common/sensor`
- `common/tokenrequest`
- `generated/accounting_method`
- `generated/entitlements`
- `generated/services`
- `generated/services_config`
- `libs/accounting`
- `libs/alpn`
- `libs/cloudidentity`
- `libs/cloudvendor`
- `libs/entitlementview`
- `libs/errors`
- `libs/filesystem`
- `libs/grpcconfig`
- `libs/healthreport`
- `libs/host`
- `libs/http`
- `libs/httpclient`
- `libs/ip`
- `libs/jwk`
- `libs/jwkview`
- `libs/key`
- `libs/lock`
- `libs/logger`
- `libs/opa`
- `libs/outputformat`
- `libs/query`
- `libs/spec`
- `libs/tacplus`
- `libs/tlscert`
- `libs/token`
- `libs/tokencache`
- `libs/x509`
- `services/aegis`
- `services/anthropic`
- `services/bigdata`
- `services/clickhouse`
- `services/dgraph`
- `services/eventbus`
- `services/fleetwood`
- `services/gateway`
- `services/github`
- `services/gitlab`
- `services/kernel`
- `services/letsencrypt`
- `services/mcp`
- `services/oauth`
- `services/sentinel`
- `utils/cavalier`

## Documentation

Additional documentation is available in the `docs` map at the root of this registry.
