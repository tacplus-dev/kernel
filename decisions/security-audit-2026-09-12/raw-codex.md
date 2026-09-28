Read-only audit completed; no files were modified. I found 15 high-confidence issues.

## Critical

1. [SecurityAuthenticator.java.template:368](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/codegen/src/main/resources/templates/SecurityAuthenticator.java.template:368) — The generated state-plane authenticator verifies signatures and audience but never validates `exp`, `iat`, or a maximum lifetime.  
   **Failure scenario:** An expired token, or a validly signed token with no expiration, continues authenticating to generated state services indefinitely; the cache behavior does not protect against this because uncached tokens are simply reverified and accepted.

2. [IdentityServiceImpl.java:1593](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:1593) — `exchangeKernelToken` verifies only the signature and never checks the input token’s expiration, issuer, audience, or issued-at time.  
   **Failure scenario:** Any expired refresh, offline, bootstrap, or access token whose signing key is still retained can be exchanged for a fresh token, effectively making expiry renewable rather than terminal.

3. [IdentityServiceImpl.java:2588](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:2588) — `mintX509Cert` appends the authenticated SPIFFE URI but preserves every caller-supplied URI and DNS SAN.  
   **Failure scenario:** A service with any accepted service token submits a certificate request containing another service’s SPIFFE URI or privileged DNS names; kernel signs a certificate valid for both the caller and the injected identities.

4. [IdentityServiceImpl.java:2593](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:2593) — Certificate validity comes directly from the caller’s `certRequest.exp` and is not capped by the authenticating token or a configured certificate lifetime.  
   **Failure scenario:** A caller using a short-lived token requests a certificate expiring years later, retaining a trusted workload identity long after the token, delegate, or authorization expires.

## High

5. [IdentityServiceImpl.java:3123](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:3123) — The shared `verifiedCallerToken` helper validates only the signature and does not enforce expiry, audience, issuer, token use, or service subject type.  
   **Failure scenario:** An expired token still authorizes `MintUserToken`, `CreatePersonalPrincipal`, or `RevokeGrant`; additionally, a kernel-signed user token whose subject equals a delegate name is treated as that delegate by `requireBrokerDelegate`.

6. [IdentityServiceImpl.java:874](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:874) — Delegated-token minting independently repeats the signature-only validation defect and derives the delegate solely from `sub`.  
   **Failure scenario:** An expired service token can keep minting grant-derived access tokens, or a signed non-service token with a delegate-shaped subject can exercise that delegate’s standing grants.

7. [IdentityServiceImpl.java:2752](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:2752) — Workload minting accepts any signed token with a SPIFFE-shaped subject without checking expiry or requiring service/workload token class.  
   **Failure scenario:** An expired parent token can continue creating children; a broker-minted user token whose requested subject is a SPIFFE URI can also enter the workload hierarchy and mint child workload identities.

8. [TlsCertServiceImpl.java:113](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/TlsCertServiceImpl.java:113) — `ManageCert` performs signature-only authentication once when the stream opens and never revalidates the token during renewals.  
   **Failure scenario:** An expired token opens or maintains a stream and repeatedly receives fresh certificates; revocation, token expiry, or later key removal does not terminate an already authenticated stream.

9. [IdentityServiceImpl.java:3505](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:3505) — Cred-pair proof JWTs have no audience, expiration, issued-at, nonce, or replay validation.  
   **Failure scenario:** Anyone who captures one cred-pair proof can replay the exact JWT repeatedly to mint new client tokens until the stored cred-pair itself expires.

10. [IdentityServiceImpl.java:3561](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:3561) — `MintClientToken` accepts any future requested expiration without applying `maxTokenLifetimeSeconds` or the cred-pair expiration as a ceiling.  
    **Failure scenario:** Immediately before a cred-pair expires, its holder requests a token with an arbitrarily distant expiry and retains tenant access long after the credential was intended to stop working.

11. [IdentityServiceImpl.java:687](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:687) — Personal-device proof JWTs likewise have no freshness, audience, challenge, or replay enforcement.  
    **Failure scenario:** A captured device proof can be replayed indefinitely to mint new refresh/offline tokens for that principal until the credential is explicitly revoked.

12. [KernelPersistence.java:124](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/KernelPersistence.java:124) — Security-critical persistence failures are swallowed after in-memory mutations have already been acknowledged.  
    **Failure scenario:** A workload/grant revocation, credential/config change, or new personal principal succeeds in memory while disk writing fails; after a full-cluster restart the old snapshot restores the revoked access or discarded configuration.

## Medium

13. [ClusterServer.java:1160](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/ClusterServer.java:1160) — Tenant snapshot restoration reconstructs map keys by indexing tenant records solely by leaf name.  
    **Failure scenario:** `/tenants/acme/prod` and `/tenants/beta/prod` overwrite each other in `byLeaf`; after restart one namespace receives the other tenant’s status and entitlement constraints.

14. [ClusterServer.java:1111](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/ClusterServer.java:1111) — Snapshot rehydration is non-atomic and catches failures only around the entire incremental replay.  
    **Failure scenario:** One malformed or failing entry aborts restoration after earlier entries were installed; kernel nevertheless starts with an arbitrary prefix of keys, tenants, configs, or revocations restored.

15. [IdentityServiceImpl.java:3662](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/kernel/server/src/main/java/com/gitlab/seabeam/controlplane/schematic/services/kernel/cluster/IdentityServiceImpl.java:3662) — Personal-principal capacity and credential-uniqueness checks are separate from the final distributed-map write.  
    **Failure scenario:** Concurrent registrations for the same credential both observe it as absent and create distinct principals; subsequent device authentication resolves whichever duplicate appears first, while concurrent registrations can also exceed the configured registry cap.
