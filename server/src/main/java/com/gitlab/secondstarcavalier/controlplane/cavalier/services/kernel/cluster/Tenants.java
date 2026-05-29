// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
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

    /** Generates a fresh Ed25519 keypair and wraps the public half as a CredPair. */
    public static GeneratedCredPair generateCredPair(
            String tenantName,
            String id,
            Credentials.Entitlements entitlements,
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
        byte[] x509Pub = kp.getPublic().getEncoded();
        String publicPem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(x509Pub)
                + "\n-----END PUBLIC KEY-----\n";

        Credentials.CredPair.Builder builder = Credentials.CredPair.newBuilder()
                .setId(id)
                .setTenantName(tenantName)
                .setPublicKey(publicPem)
                .setCreatedAt(nowTs());
        if (entitlements != null) {
            builder.setEntitlements(entitlements);
        }
        if (description != null && !description.isEmpty()) {
            builder.setDescription(description);
        }
        return new GeneratedCredPair(builder.build(), privatePem);
    }

    /** Persists a new tenant record (full path key) and its TenantConfig entry. */
    public static Kernel.Tenant createTenant(
            ConfigMap configMap,
            String fullNamespace,
            String leafName,
            Credentials.Entitlements entitlements,
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

        // Build initial TenantConfig, append bootstrap cred_pair.
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
}
