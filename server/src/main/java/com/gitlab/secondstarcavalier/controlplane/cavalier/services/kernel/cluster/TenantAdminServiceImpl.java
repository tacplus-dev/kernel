// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TenantAdminServiceImpl handles tenant-scope control-plane RPCs.
 *
 * <p>The C2S auth interceptor enforces the level-or-below check on the
 * {@code target_namespace_field} for every RPC, so the handler trusts the
 * inbound namespace strings.
 *
 * <p>Tenants are stored as a flat list keyed by full namespace path in the
 * kernel {@link ConfigMap}; sub-tenant tree structure is recovered by prefix
 * matching on the keys.
 */
public class TenantAdminServiceImpl implements TenantAdmin.TenantAdminHandler {
    private static final Logger logger = LoggerFactory.getLogger(TenantAdminServiceImpl.class);

    private final ConfigMap configMap;

    public TenantAdminServiceImpl(ConfigMap configMap) {
        this.configMap = configMap;
        logger.info("TenantAdminServiceImpl initialised");
    }

    @Override
    public TenantConfigOuterClass.TenantConfig getTenantConfig(
            Caller caller, Kernel.GetTenantConfigRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
        if (entry.getTenantName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        return entry.getConfig();
    }

    @Override
    public TenantConfigOuterClass.TenantConfig putTenantConfig(
            Caller caller, Kernel.PutTenantConfigRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        if (!request.hasConfig()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "config is required");
        }
        if (configMap.getTenants(ns).getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        Tenants.assertIdpUniqueness(configMap, ns, request.getConfig());
        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(ns)
                .setConfig(request.getConfig())
                .build();
        configMap.putTenantConfigs(ns, entry);
        logger.info("PutTenantConfig ns={}", ns);
        return request.getConfig();
    }

    @Override
    public Kernel.CreateSubTenantResponse createSubTenant(
            Caller caller, Kernel.CreateSubTenantRequest request) throws ProtoException {
        String parentNs = require(request.getParentNamespace(), "parent_namespace");
        String leaf = require(request.getName(), "name");
        if (leaf.contains("/")) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "name must be a leaf segment (no '/')");
        }
        // Parent must exist unless it's the cluster root (handled by ClusterAdmin instead).
        if (configMap.getTenants(parentNs).getName().isEmpty()) {
            // Allow creation under a non-tenant namespace (e.g. root spiffe_prefix)
            // — cavalierctl uses that path before any ClusterAdmin work runs.
            logger.info("CreateSubTenant: parent ns {} has no Tenant record; treating as root-level", parentNs);
        }
        String fullNs = Tenants.joinNamespace(parentNs, leaf);

        Credentials.Entitlements ent = request.hasEntitlements() ? request.getEntitlements() : null;
        String credId = Tenants.newCredPairId();
        Tenants.GeneratedCredPair gen = Tenants.generateCredPair(
                leaf, credId, ent, "bootstrap cred_pair for sub-tenant " + leaf);

        Kernel.Tenant tenant = Tenants.createTenant(
                configMap, fullNs, leaf, ent,
                request.hasConfig() ? request.getConfig() : null,
                gen.credPair());

        logger.info("CreateSubTenant parent_ns={} ns={} cred_pair_id={}", parentNs, fullNs, credId);
        return Kernel.CreateSubTenantResponse.newBuilder()
                .setTenant(tenant)
                .setCredPair(gen.credPair())
                .setCredPairPrivateKeyPem(gen.privateKeyPem())
                .build();
    }

    @Override
    public Kernel.DeleteSubTenantResponse deleteSubTenant(
            Caller caller, Kernel.DeleteSubTenantRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        // Cascade: delete all descendants too.
        Kernel.ConfigState state = configMap.proto();
        List<String> toDelete = new ArrayList<>();
        for (Kernel.TenantConfigEntry e : state.getTenantConfigsList()) {
            String k = e.getTenantName();
            if (k.equals(ns) || k.startsWith(ns + "/")) {
                toDelete.add(k);
            }
        }
        if (toDelete.isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        for (String k : toDelete) {
            Tenants.deleteTenant(configMap, k);
        }
        logger.info("DeleteSubTenant ns={} cascaded={}", ns, toDelete.size());
        return Kernel.DeleteSubTenantResponse.getDefaultInstance();
    }

    @Override
    public Kernel.ListSubTenantsResponse listSubTenants(
            Caller caller, Kernel.ListSubTenantsRequest request) throws ProtoException {
        String parentNs = require(request.getParentNamespace(), "parent_namespace");
        Kernel.ListSubTenantsResponse.Builder rb = Kernel.ListSubTenantsResponse.newBuilder();
        Kernel.ConfigState state = configMap.proto();
        // Iterate config entries because they share keys with tenants.
        for (Kernel.TenantConfigEntry entry : state.getTenantConfigsList()) {
            String key = entry.getTenantName();
            if (Tenants.isImmediateChild(key, parentNs)) {
                Kernel.Tenant t = configMap.getTenants(key);
                if (!t.getName().isEmpty()) {
                    rb.addTenants(t);
                }
            }
        }
        return rb.build();
    }

    @Override
    public Kernel.AddCredPairResponse addCredPair(
            Caller caller, Kernel.AddCredPairRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        Kernel.Tenant tenant = configMap.getTenants(ns);
        if (tenant.getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        Credentials.Entitlements ent = request.hasEntitlements() ? request.getEntitlements() : null;
        String credId = Tenants.newCredPairId();
        Tenants.GeneratedCredPair gen = Tenants.generateCredPair(
                tenant.getName(), credId, ent, "cred_pair");

        Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
        TenantConfigOuterClass.TenantConfig.Builder cfg = entry.getConfig().toBuilder();
        Credentials.KernelTenantConfig.Builder k = cfg.getKernel().toBuilder();
        k.addCredPairs(gen.credPair());
        cfg.setKernel(k.build());
        configMap.putTenantConfigs(ns, entry.toBuilder().setConfig(cfg.build()).build());

        logger.info("AddCredPair ns={} cred_pair_id={}", ns, credId);
        return Kernel.AddCredPairResponse.newBuilder()
                .setCredPair(gen.credPair())
                .setCredPairPrivateKeyPem(gen.privateKeyPem())
                .build();
    }

    @Override
    public Kernel.RemoveCredPairResponse removeCredPair(
            Caller caller, Kernel.RemoveCredPairRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        String id = require(request.getCredPairId(), "cred_pair_id");

        Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
        if (entry.getTenantName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        TenantConfigOuterClass.TenantConfig.Builder cfg = entry.getConfig().toBuilder();
        Credentials.KernelTenantConfig.Builder k = cfg.getKernel().toBuilder();
        List<Credentials.CredPair> kept = new ArrayList<>();
        boolean removed = false;
        for (Credentials.CredPair cp : k.getCredPairsList()) {
            if (cp.getId().equals(id)) {
                removed = true;
            } else {
                kept.add(cp);
            }
        }
        if (!removed) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no cred_pair " + id + " at " + ns);
        }
        k.clearCredPairs();
        k.addAllCredPairs(kept);
        cfg.setKernel(k.build());
        configMap.putTenantConfigs(ns, entry.toBuilder().setConfig(cfg.build()).build());

        logger.info("RemoveCredPair ns={} cred_pair_id={}", ns, id);
        return Kernel.RemoveCredPairResponse.getDefaultInstance();
    }

    private static String require(String v, String name) throws ProtoException {
        if (v == null || v.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, name + " is required");
        }
        return v;
    }
}
