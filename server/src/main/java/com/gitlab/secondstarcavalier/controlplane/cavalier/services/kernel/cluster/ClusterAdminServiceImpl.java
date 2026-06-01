// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.ClusterAdmin;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.spec.Spec;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ClusterAdminServiceImpl handles cluster-scope tenant lifecycle.
 *
 * <p>Tenants live under the cluster's SPIFFE prefix as a flat list keyed
 * by their full namespace path (e.g. {@code "local/dev/acme"}).
 * {@code Tenant.name} stores only the leaf segment.
 *
 * <p>Authentication today is the standard JWT bearer flow handled by the
 * generated wrapper. Cluster-cred-pair signed-request auth is a follow-up
 * (see task #55).
 */
public class ClusterAdminServiceImpl implements ClusterAdmin.ClusterAdminHandler {
    private static final Logger logger = LoggerFactory.getLogger(ClusterAdminServiceImpl.class);

    private final ConfigMap configMap;
    private final Supplier<String> spiffePrefixReader;

    public ClusterAdminServiceImpl(ConfigMap configMap, Supplier<String> spiffePrefixReader) {
        this.configMap = configMap;
        this.spiffePrefixReader = spiffePrefixReader;
        logger.info("ClusterAdminServiceImpl initialised");
    }

    @Override
    public Kernel.CreateTenantResponse createTenant(Caller caller, Kernel.CreateTenantRequest request)
            throws ProtoException {
        String name = request.getName();
        if (name.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "tenant name must not be empty");
        }
        if (name.contains("/")) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "tenant name must be a leaf segment (no '/')");
        }
        String fullNs = Tenants.joinNamespace(spiffePrefixReader.get(), name);

        Credentials.Entitlements ent = request.hasEntitlements() ? request.getEntitlements() : null;
        String credId = Tenants.newCredPairId();
        // Auto-create the bootstrap RW P2S cred_pair so the tenant can mint a P2S
        // token and call its first SetConfig.
        Tenants.GeneratedP2SCredPair gen = Tenants.generateP2SCredPair(
                credId, Spec.Capability.CAPABILITY_RW, "bootstrap RW cred_pair for tenant " + name);

        Kernel.Tenant tenant = Tenants.createTenant(
                configMap, fullNs, name, ent,
                request.hasConfig() ? request.getConfig() : null,
                gen.credPair());

        // Return the initial config (which now contains the bootstrap P2S cred_pair)
        // plus the private key, delivered once.
        logger.info("CreateTenant ns={} name={} cred_pair_id={}", fullNs, name, credId);
        return Kernel.CreateTenantResponse.newBuilder()
                .setTenant(tenant)
                .setConfig(configMap.getTenantConfigs(fullNs).getConfig())
                .setCredPairPrivateKeyPem(gen.privateKeyPem())
                .build();
    }

    @Override
    public Kernel.DeleteTenantResponse deleteTenant(Caller caller, Kernel.DeleteTenantRequest request)
            throws ProtoException {
        String name = request.getName();
        if (name.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "tenant name must not be empty");
        }
        String fullNs = Tenants.joinNamespace(spiffePrefixReader.get(), name);
        Tenants.deleteTenant(configMap, fullNs);
        logger.info("DeleteTenant ns={}", fullNs);
        return Kernel.DeleteTenantResponse.getDefaultInstance();
    }

    @Override
    public Kernel.ListTenantsResponse listTenants(Caller caller, Kernel.ListTenantsRequest request)
            throws ProtoException {
        Kernel.ListTenantsResponse.Builder rb = Kernel.ListTenantsResponse.newBuilder();
        Kernel.ConfigState state = configMap.proto();
        rb.addAllTenants(state.getTenantsList());
        return rb.build();
    }

    @Override
    public Kernel.RootConfig getRootConfig(Caller caller, Kernel.GetRootConfigRequest request)
            throws ProtoException {
        // Assemble RootConfig from each tenant's stored system slice — there is no
        // singleton state field; the system slice lives in tenant_configs.
        Kernel.RootConfig.Builder rb = Kernel.RootConfig.newBuilder();
        for (Kernel.TenantConfigEntry e : configMap.proto().getTenantConfigsList()) {
            if (e.getConfig().getKernel().hasSystem()) {
                rb.putTenants(e.getTenantName(), e.getConfig().getKernel().getSystem());
            }
        }
        return rb.build();
    }

    @Override
    public Kernel.RootConfig setRootConfig(Caller caller, Kernel.SetRootConfigRequest request)
            throws ProtoException {
        if (!request.hasConfig()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "config is required");
        }
        // Write each tenant's immutable system slice into its tenant_configs entry
        // (proven keyed-map storage; no singleton state field).
        for (var e : request.getConfig().getTenantsMap().entrySet()) {
            String ns = e.getKey();
            Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
            if (entry.getTenantName().isEmpty()) {
                throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
            }
            TenantConfigOuterClass.TenantConfig.Builder cfg = entry.getConfig().toBuilder();
            cfg.setKernel(cfg.getKernel().toBuilder().setSystem(e.getValue()));
            configMap.putTenantConfigs(ns, entry.toBuilder().setConfig(cfg.build()).build());
        }
        logger.info("SetRootConfig tenants={}", request.getConfig().getTenantsCount());
        return request.getConfig();
    }
}
