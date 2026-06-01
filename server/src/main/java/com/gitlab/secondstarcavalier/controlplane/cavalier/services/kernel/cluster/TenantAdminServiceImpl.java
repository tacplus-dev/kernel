// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.project_config.ProjectConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.credpair.Credpair;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.spec.Spec;
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
        // The immutable system slice (L1) is stored inline (root-written via
        // SetRootConfig); return the config as-is.
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
        // Preserve the immutable-to-tenant system slice (L1): keep whatever is
        // currently stored (root-written), ignoring any tenant-supplied value.
        Credentials.TenantSystemConfig existingSystem =
                configMap.getTenantConfigs(ns).getConfig().getKernel().getSystem();
        TenantConfigOuterClass.TenantConfig.Builder cfg = request.getConfig().toBuilder();
        cfg.setKernel(cfg.getKernel().toBuilder().setSystem(existingSystem));
        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(ns)
                .setConfig(cfg.build())
                .build();
        configMap.putTenantConfigs(ns, entry);
        logger.info("PutTenantConfig ns={}", ns);
        return entry.getConfig();
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
        Tenants.GeneratedP2SCredPair gen = Tenants.generateP2SCredPair(
                credId, Spec.Capability.CAPABILITY_RW, "bootstrap RW cred_pair for sub-tenant " + leaf);

        Kernel.Tenant tenant = Tenants.createTenant(
                configMap, fullNs, leaf, ent,
                request.hasConfig() ? request.getConfig() : null,
                gen.credPair());

        // Public P2S cred_pair is in the tenant config (GetTenantConfig); the
        // private key is delivered once here.
        logger.info("CreateSubTenant parent_ns={} ns={} cred_pair_id={}", parentNs, fullNs, credId);
        return Kernel.CreateSubTenantResponse.newBuilder()
                .setTenant(tenant)
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
        // Cascade project configs (L3) under this namespace too.
        List<String> projDelete = new ArrayList<>();
        for (Kernel.ProjectConfigEntry e : configMap.proto().getProjectConfigsList()) {
            String k = e.getProjectNamespace();
            if (k.equals(ns) || k.startsWith(ns + "/")) {
                projDelete.add(k);
            }
        }
        for (String k : projDelete) {
            configMap.deleteProjectConfigs(k);
        }
        logger.info("DeleteSubTenant ns={} cascaded={} projects={}", ns, toDelete.size(), projDelete.size());
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
        String credId = Tenants.newCredPairId();
        // P2S cred_pair. Capability defaults to RW; a per-request capability param
        // is a follow-up (AddCredPairRequest currently carries C2S entitlements).
        Tenants.GeneratedP2SCredPair gen = Tenants.generateP2SCredPair(
                credId, Spec.Capability.CAPABILITY_RW, "cred_pair");

        Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
        TenantConfigOuterClass.TenantConfig.Builder cfg = entry.getConfig().toBuilder();
        Credentials.KernelTenantConfig.Builder k = cfg.getKernel().toBuilder();
        k.addPipelineCredPairs(gen.credPair());
        cfg.setKernel(k.build());
        configMap.putTenantConfigs(ns, entry.toBuilder().setConfig(cfg.build()).build());

        logger.info("AddCredPair ns={} cred_pair_id={}", ns, credId);
        return Kernel.AddCredPairResponse.newBuilder()
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
        // C2S cred_pairs moved to ProjectConfig; tenant-level cred_pairs are P2S
        // pipeline cred_pairs.
        List<Credpair.P2SCredPair> kept = new ArrayList<>();
        boolean removed = false;
        for (Credpair.P2SCredPair cp : k.getPipelineCredPairsList()) {
            if (cp.getId().equals(id)) {
                removed = true;
            } else {
                kept.add(cp);
            }
        }
        if (!removed) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no cred_pair " + id + " at " + ns);
        }
        k.clearPipelineCredPairs();
        k.addAllPipelineCredPairs(kept);
        cfg.setKernel(k.build());
        configMap.putTenantConfigs(ns, entry.toBuilder().setConfig(cfg.build()).build());

        logger.info("RemoveCredPair ns={} cred_pair_id={}", ns, id);
        return Kernel.RemoveCredPairResponse.getDefaultInstance();
    }

    // --- Project config (L3) — ProjectConfig is the atomic unit ---

    @Override
    public ProjectConfigOuterClass.ProjectConfig getProjectConfig(
            Caller caller, Kernel.GetProjectConfigRequest request) throws ProtoException {
        String ns = require(request.getProjectNamespace(), "project_namespace");
        Kernel.ProjectConfigEntry entry = configMap.getProjectConfigs(ns);
        if (entry.getProjectNamespace().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no project at " + ns);
        }
        return entry.getConfig();
    }

    @Override
    public ProjectConfigOuterClass.ProjectConfig setProjectConfig(
            Caller caller, Kernel.SetProjectConfigRequest request) throws ProtoException {
        String ns = require(request.getProjectNamespace(), "project_namespace");
        if (!request.hasConfig()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "config is required");
        }
        // IdP (issuer, client_id) must be globally unique across projects.
        Tenants.assertIdpUniqueness(configMap, ns, request.getConfig());
        Kernel.ProjectConfigEntry entry = Kernel.ProjectConfigEntry.newBuilder()
                .setProjectNamespace(ns)
                .setConfig(request.getConfig())
                .build();
        configMap.putProjectConfigs(ns, entry);
        logger.info("SetProjectConfig ns={}", ns);
        return request.getConfig();
    }

    @Override
    public Kernel.ListProjectsResponse listProjects(
            Caller caller, Kernel.ListProjectsRequest request) throws ProtoException {
        String tenantNs = require(request.getTenantNamespace(), "tenant_namespace");
        Kernel.ListProjectsResponse.Builder rb = Kernel.ListProjectsResponse.newBuilder();
        for (Kernel.ProjectConfigEntry e : configMap.proto().getProjectConfigsList()) {
            if (Tenants.isImmediateChild(e.getProjectNamespace(), tenantNs)) {
                rb.addProjectNamespaces(e.getProjectNamespace());
            }
        }
        return rb.build();
    }

    @Override
    public Kernel.DeleteProjectResponse deleteProject(
            Caller caller, Kernel.DeleteProjectRequest request) throws ProtoException {
        String ns = require(request.getProjectNamespace(), "project_namespace");
        if (configMap.getProjectConfigs(ns).getProjectNamespace().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no project at " + ns);
        }
        configMap.deleteProjectConfigs(ns);
        logger.info("DeleteProject ns={}", ns);
        return Kernel.DeleteProjectResponse.getDefaultInstance();
    }

    private static String require(String v, String name) throws ProtoException {
        if (v == null || v.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, name + " is required");
        }
        return v;
    }
}
