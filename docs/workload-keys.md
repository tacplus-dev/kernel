# Workload keys: tokens for a workload that can't federate

A workload that can present a Kubernetes service-account token, or a cloud identity, gets its tokens that way. A
workload that can't (a CI runner, a machine outside every cluster and cloud you trust) can be given a **workload
key** instead (kernel#28). The tenant generates a key pair, registers the **public** half with kernel, and the
workload signs a short assertion with the private half each time it needs a token: the RFC 7523 /
`private_key_jwt` pattern. Kernel never holds anything that could impersonate the workload.

Workload keys are for workloads only, never people.

## What a key is

A key is registered in the tenant's own config (`KernelTenantConfig.workload_keys`) and is deleted with the tenant.
Each key is scoped to:

- **one subject**, the workload identity it mints for: a SPIFFE service or workload ID rooted at the tenant's tid,
  `spiffe://<trust-domain>/tenants/<tid>/services/<name>` (or `.../workloads/<name>` below one). Kernel refuses a
  subject of another tenant, of `/system`, or spelled with the tenant's name in place of its tid.
- **its audiences**, the services its tokens may be exchanged for.

Keys are Ed25519 or ES256 (EC P-256). A workload may hold several active keys at once, so it can rotate: register
the new key, move the workload to it, revoke the old one.

**Expiry.** By default a key is never forced to expire. It is **disabled after 90 days unused**, and an admin can
revoke it at any time. A tenant can change both in its config's `kernel.workload_key_policy`
(`UpdateTenantConfig`): `inactive_after_seconds` (0 is the 90-day default) and `max_lifetime_seconds` (0, the
default, is no maximum). A key past its maximum lifetime is refused however recently it was used, and no token it
mints outlives the key. A disabled key stays disabled; register a new one.

Every mint is logged (`audit: workload key mint: tenant=… key=… sub=… assertion_jti=… jti=… exp=…`), as is every
exchange, registration, revocation and refusal. `last_used_at` is recorded on the key, to the hour.

## The RPCs

All are on `kernel.TenantAdmin`, called as an admin of the tenant (or of an ancestor), like `UpdateTenantConfig`:

| RPC | What it does |
| --- | --- |
| `CreateWorkloadKey` | Registers a public key for `subject` with its `audiences`. Kernel assigns the key's `id`, which is the `kid` the workload's assertions carry. |
| `ListWorkloadKeys` | Lists the tenant's keys, revoked and disabled ones included, each with its state (`ACTIVE`, `REVOKED`, `DISABLED`, `EXPIRED`). |
| `RevokeWorkloadKey` | Revokes a key at once. It mints nothing more, and tokens it already minted buy no service tokens. |

`UpdateTenantConfig` never writes `workload_keys`: the stored list is kept whatever the request carries.

The workload itself uses two RPCs on `kernel.Mint`:

1. `MintClientToken` with the signed assertion as `input_token`. It returns a short-lived service access token
   (`sub` = the key's subject, `aud` = `kernel`, at most 15 minutes).
2. `MintToken` with that token as `input_token` and `aud` set to one of the key's audiences (or several in
   `service_auds`). It returns the service token to present to that service. An audience the key does not list is
   refused.

## The assertion

A JWT signed with the private key:

- header: `alg` `EdDSA` (Ed25519) or `ES256`, `kid` the key's `id`;
- `iss` and `sub`: the key's subject (kernel requires `iss`; it scopes the token by the key, not by these);
- `aud`: `kernel`, the token endpoint;
- `iat`: now, and `exp` at most 300 seconds after it;
- `jti`: fresh for every assertion. Kernel remembers it until `exp` and refuses it a second time.

## A short script

Generate the key pair, once, where the workload runs. The private key never leaves it.

```sh
openssl genpkey -algorithm ed25519 -out workload.key
chmod 600 workload.key
```

`workload-key.py` prints the public key as kernel's JWK (`jwk`) and signs assertions (`assert <key-id> <subject>`).
It needs Python 3 and the `cryptography` package.

```python
#!/usr/bin/env python3
"""Workload-key helper: print the public JWK, or sign an assertion for MintClientToken."""
import base64, json, sys, time, uuid
from cryptography.hazmat.primitives import serialization

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

with open("workload.key", "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)

if sys.argv[1] == "jwk":
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(json.dumps({"kty": "KEY_TYPE_OKP", "crv": "Ed25519", "x": b64(raw)}))
elif sys.argv[1] == "assert":
    key_id, subject = sys.argv[2], sys.argv[3]
    now = int(time.time())
    header = {"alg": "EdDSA", "kid": key_id, "typ": "JWT"}
    claims = {"iss": subject, "sub": subject, "aud": "kernel",
              "iat": now, "exp": now + 60, "jti": str(uuid.uuid4())}
    compact = lambda obj: b64(json.dumps(obj, separators=(",", ":")).encode())
    signing_input = compact(header) + "." + compact(claims)
    print(signing_input + "." + b64(key.sign(signing_input.encode())))
```

Register the public key, as a tenant admin (`$ADMIN_TOKEN`). The examples use `grpcurl`, with kernel's protos (or
server reflection) and `$KERNEL` the address kernel's gRPC is reached at; any gRPC client works the same way.

```sh
SUBJECT="spiffe://<trust-domain>/tenants/<tid>/services/ingest"
grpcurl -H "authorization: Bearer $ADMIN_TOKEN" -d @ "$KERNEL" kernel.TenantAdmin/CreateWorkloadKey <<EOF
{"tenantNamespace": "/tenants/acme", "subject": "$SUBJECT", "audiences": ["docstore"],
 "description": "nightly ingest runner", "publicKey": $(./workload-key.py jwk)}
EOF
```

The response is the stored key; its `id` (`wk-…`) is the `kid`. Then, in the workload, each time it needs a token:

```sh
KEY_ID=wk-...
AT=$(grpcurl -d "{\"inputToken\": \"$(./workload-key.py assert "$KEY_ID" "$SUBJECT")\"}" \
  "$KERNEL" kernel.Mint/MintClientToken | jq -r .accessToken.base64)
ST=$(grpcurl -d "{\"inputToken\": \"$AT\", \"aud\": \"docstore\"}" \
  "$KERNEL" kernel.Mint/MintToken | jq -r .accessToken.base64)
```

`$ST` is the service token for `docstore`. To revoke the key:

```sh
grpcurl -H "authorization: Bearer $ADMIN_TOKEN" -d '{"tenantNamespace": "/tenants/acme", "id": "'"$KEY_ID"'"}' \
  "$KERNEL" kernel.TenantAdmin/RevokeWorkloadKey
```

For ES256, generate the key with `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`, publish
`{"kty": "KEY_TYPE_EC", "crv": "P-256", "x": …, "y": …}`, and sign with `alg` `ES256`: ECDSA over SHA-256, the
signature as the 64-byte `r || s`, not DER.
