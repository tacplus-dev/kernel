// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.oauth.Oauth;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Shared tenant-CRUD helpers used by ClusterAdminServiceImpl and
 * TenantAdminServiceImpl.
 *
 * <p>Tenants live in {@code ConfigMap} keyed by the full namespace path
 * (e.g. {@code "local/dev/acme"}). {@code Tenant.name} is the leaf segment.
 * The flat-map-keyed-by-full-path representation is the tree: a parent's
 * children are exactly the keys with {@code parentNs + "/"} as prefix and
 * no further {@code '/'}.
 *
 * <p>{@code TenantConfigEntry} is stored in a parallel map keyed by the
 * same full namespace path.
 *
 * <p>CredPair authentication is not yet implemented; today the C2S auth
 * interceptor's level-or-below check on the {@code target_namespace_field}
 * is the sole gate.
 */
public final class Tenants {

    private Tenants() {}

    /** Result of generating a fresh CredPair (public stored, private returned). */
    public record GeneratedCredPair(Credentials.CredPair credPair, String privateKeyPem) {}

    /** Composes the full namespace for a child of {@code parentNs} with the given leaf name. */
    public static String joinNamespace(String parentNs, String leafName) {
        if (parentNs == null || parentNs.isEmpty()) {
            throw new IllegalArgumentException("parent namespace must not be empty");
        }
        if (leafName == null || leafName.isEmpty()) {
            throw new IllegalArgumentException("leaf name must not be empty");
        }
        return parentNs + "/" + leafName;
    }

    /**
     * Generates a fresh Ed25519 keypair and wraps the public half as a v3
     * {@code credentials.CredPair} whose public_key is a JWK (kty=OKP, kid=id,
     * crv=Ed25519, x=base64url(raw 32-byte key)), verifiable directly via
     * ImmutableJwk. The private key (PKCS#8 PEM) is returned once for the holder
     * to sign cred_pair proofs with.
     *
     * <p>{@code namespaces} are the authorized namespaces RELATIVE to the owning
     * tenant (e.g. {@code ["*"]} for all of the tenant's projects).
     */
    public static GeneratedCredPair generateCredPair(
            String tenantName,
            String id,
            Entitlements.TokenEntitlements entitlements,
            List<String> namespaces,
            String description) {
        KeyPair kp;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Ed25519 keypair generation failed", e);
        }
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        String privatePem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8)
                + "\n-----END PRIVATE KEY-----\n";
        // X.509 SubjectPublicKeyInfo for Ed25519 is a fixed 44-byte structure whose
        // last 32 bytes are the raw public key — the JWK "x" value.
        byte[] x509Pub = kp.getPublic().getEncoded();
        byte[] raw = java.util.Arrays.copyOfRange(x509Pub, x509Pub.length - 32, x509Pub.length);
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        JwkOuterClass.Jwk publicJwk = JwkOuterClass.Jwk.newBuilder()
                .setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
                .setKid(id)
                .setCrv("Ed25519")
                .setX(x)
                .build();

        Credentials.CredPair.Builder builder = Credentials.CredPair.newBuilder()
                .setId(id)
                .setTenantName(tenantName)
                .setPublicKey(publicJwk)
                .setCreatedAt(nowTs());
        if (entitlements != null) {
            builder.setEntitlements(entitlements);
        }
        if (namespaces != null) {
            builder.addAllNamespaces(namespaces);
        }
        if (description != null && !description.isEmpty()) {
            builder.setDescription(description);
        }
        return new GeneratedCredPair(builder.build(), privatePem);
    }

    /**
     * Enforces the cluster-wide invariant that an IdP {@code (issuer_url, client_id)}
     * pair is bound to at most one tenant namespace. The minted token's namespace is
     * derived from the verified provider, so this pair must be globally unique for
     * tenant resolution to be unambiguous (and ns-spoofing impossible).
     *
     * <p>Scans existing tenant configs for any provider colliding with one in
     * {@code newConfig}, excluding {@code selfTenantNs} so a tenant can re-put
     * its own config idempotently. Throws {@code ALREADY_EXISTS} on conflict.
     */
    public static void assertIdpUniqueness(
            ConfigMap configMap,
            String selfTenantNs,
            TenantConfigOuterClass.TenantConfig newConfig) throws ProtoException {
        if (newConfig == null || !newConfig.hasOauth()) {
            return;
        }
        java.util.Set<String> incoming = new java.util.HashSet<>();
        for (Oauth.OAuthProvider p : newConfig.getOauth().getProvidersList()) {
            incoming.add(idpKey(p.getIssuerUrl(), p.getClientId()));
        }
        if (incoming.isEmpty()) {
            return;
        }
        // IdP lives at the tenant level now; scan tenant configs for collisions.
        for (Kernel.TenantConfigEntry e : configMap.proto().getTenantConfigsList()) {
            if (e.getTenantName().equals(selfTenantNs)) {
                continue;
            }
            for (Oauth.OAuthProvider p : e.getConfig().getOauth().getProvidersList()) {
                if (incoming.contains(idpKey(p.getIssuerUrl(), p.getClientId()))) {
                    throw new ProtoException(ProtoException.ALREADY_EXISTS,
                            "IdP (issuer=" + p.getIssuerUrl() + ", client_id=" + p.getClientId()
                                    + ") is already bound to tenant " + e.getTenantName()
                                    + "; an IdP may belong to only one tenant namespace");
                }
            }
        }
    }

    /** Stores an empty ProjectConfig at the given full project namespace. */
    public static void putEmptyProject(ConfigMap configMap, String projectNs) {
        Kernel.ProjectConfigEntry entry = Kernel.ProjectConfigEntry.newBuilder()
                .setProjectNamespace(projectNs)
                .setConfig(Kernel.ProjectConfig.getDefaultInstance())
                .build();
        configMap.putProjectConfigs(projectNs, entry);
    }

    private static String idpKey(String issuerUrl, String clientId) {
        return issuerUrl + "\u0000" + clientId;
    }

    /**
     * Persists a new tenant record (full path key) and its TenantConfig entry,
     * appending the kernel-auto-created bootstrap cred_pair to
     * KernelTenantConfig.cred_pairs so the tenant can mint a token
     * (MintClientToken) and call its first SetConfig.
     */
    public static Kernel.Tenant createTenant(
            ConfigMap configMap,
            String fullNamespace,
            String leafName,
            Entitlements.TokenEntitlements entitlements,
            TenantConfigOuterClass.TenantConfig config,
            Credentials.CredPair bootstrapCredPair) throws ProtoException {

        if (!configMap.getTenants(fullNamespace).getName().isEmpty()) {
            throw new ProtoException(ProtoException.ALREADY_EXISTS,
                    "tenant already exists at " + fullNamespace);
        }

        Timestamp now = nowTs();
        Kernel.Tenant.Builder tb = Kernel.Tenant.newBuilder()
                .setName(leafName)
                .setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
                .setCreatedAt(now)
                .setUpdatedAt(now);
        if (entitlements != null) {
            tb.setEntitlements(entitlements);
        }
        Kernel.Tenant tenant = tb.build();
        configMap.putTenants(fullNamespace, tenant);

        // Build initial TenantConfig, append the bootstrap cred_pair.
        TenantConfigOuterClass.TenantConfig.Builder cfgBuilder =
                (config != null ? config.toBuilder() : TenantConfigOuterClass.TenantConfig.newBuilder());
        Credentials.KernelTenantConfig.Builder kernelCfg =
                cfgBuilder.getKernel().toBuilder();
        if (bootstrapCredPair != null) {
            kernelCfg.addCredPairs(bootstrapCredPair);
        }
        cfgBuilder.setKernel(kernelCfg.build());
        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(fullNamespace)
                .setConfig(cfgBuilder.build())
                .build();
        configMap.putTenantConfigs(fullNamespace, entry);

        // Auto-create the tenant's default project (L3). The tenant may use,
        // replace (SetProjectConfig), or delete (DeleteProject) it.
        putEmptyProject(configMap, fullNamespace + "/default");

        return tenant;
    }

    /** Deletes a tenant and its config entry. No descendant cascade — caller's responsibility. */
    public static void deleteTenant(ConfigMap configMap, String fullNamespace) {
        configMap.deleteTenants(fullNamespace);
        configMap.deleteTenantConfigs(fullNamespace);
    }

    /** Returns true if {@code key} is an immediate child of {@code parentNs}. */
    public static boolean isImmediateChild(String key, String parentNs) {
        if (!key.startsWith(parentNs + "/")) return false;
        String rest = key.substring(parentNs.length() + 1);
        return !rest.isEmpty() && rest.indexOf('/') < 0;
    }

    private static Timestamp nowTs() {
        Instant n = Instant.now();
        return Timestamp.newBuilder()
                .setSeconds(n.getEpochSecond())
                .setNanos(n.getNano())
                .build();
    }

    /** Mints a fresh random cred_pair id. */
    public static String newCredPairId() {
        return "cp-" + UUID.randomUUID().toString().substring(0, 12);
    }

    /**
     * Seeds the cluster-admin cred_pairs (from {@code kernel.Config.cluster_cred_pairs})
     * as a root {@code TenantConfigEntry} keyed by the cluster root namespace, so the
     * standard MintP2SToken resolution path can authenticate them.
     *
     * <p>v3 "fold": a {@code ClusterCredPair} (id + PEM public key, no scope) becomes a
     * unified {@code CredPair} owned by the root namespace, holding {@code config:ANY}
     * (every kernel ClusterAdmin/TenantAdmin RPC) and {@code namespaces=["*"]}. The
     * minted token therefore carries {@code namespace=}root, which satisfies
     * SCOPE_CLUSTER (ClusterAdmin) and is at-or-above any tenant/project for the
     * SCOPE_TENANT level-or-below check (TenantAdmin). Idempotent: re-running overwrites
     * the root entry. No-op when there are no cluster cred_pairs.
     */
    public static void seedClusterCredPairs(
            ConfigMap configMap,
            java.util.List<Credentials.ClusterCredPair> clusterCredPairs,
            String rootNamespace) {
        if (clusterCredPairs == null || clusterCredPairs.isEmpty()) {
            return;
        }
        Entitlements.TokenEntitlements allConfig = Entitlements.TokenEntitlements.newBuilder()
                .addConfig(com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel
                        .tacplus.types.generated.services.Services.ConfigRPCs.CONFIG_RPCS_ANY)
                .build();
        Credentials.KernelTenantConfig.Builder kernelCfg = Credentials.KernelTenantConfig.newBuilder();
        for (Credentials.ClusterCredPair ccp : clusterCredPairs) {
            JwkOuterClass.Jwk jwk = pemToEd25519Jwk(ccp.getPublicKey(), ccp.getId());
            Credentials.CredPair.Builder cp = Credentials.CredPair.newBuilder()
                    .setId(ccp.getId())
                    .setTenantName(rootNamespace)
                    .setPublicKey(jwk)
                    .setEntitlements(allConfig)
                    .addNamespaces("*")
                    .setCreatedAt(nowTs());
            if (!ccp.getDescription().isEmpty()) {
                cp.setDescription(ccp.getDescription());
            }
            kernelCfg.addCredPairs(cp.build());
        }
        TenantConfigOuterClass.TenantConfig cfg = TenantConfigOuterClass.TenantConfig.newBuilder()
                .setKernel(kernelCfg.build())
                .build();
        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(rootNamespace)
                .setConfig(cfg)
                .build();
        configMap.putTenantConfigs(rootNamespace, entry);
    }

    /**
     * Converts an X.509 SubjectPublicKeyInfo PEM (Ed25519) into a v3 {@code Jwk}
     * (kty=OKP, crv=Ed25519, x=base64url(raw 32-byte key)). The Ed25519 SPKI is a
     * fixed 44-byte structure whose last 32 bytes are the raw public key.
     */
    private static JwkOuterClass.Jwk pemToEd25519Jwk(String pem, String kid) {
        String b64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);
        byte[] raw = java.util.Arrays.copyOfRange(der, der.length - 32, der.length);
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        return JwkOuterClass.Jwk.newBuilder()
                .setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
                .setKid(kid)
                .setCrv("Ed25519")
                .setX(x)
                .build();
    }
}
