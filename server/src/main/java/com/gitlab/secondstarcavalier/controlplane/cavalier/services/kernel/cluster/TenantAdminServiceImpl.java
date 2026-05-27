// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.generated.tenant_config.TenantConfigOuterClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TenantAdminServiceImpl is the kernel-hosted per-tenant control-plane handler.
 *
 * <p>All RPCs require a signed request authenticated by a CredPair belonging
 * to the caller's tenant. The caller's effective SPIFFE is
 * {@code spiffe://<spiffe_prefix>/<tenant_name>/users/cred-pair:<cred_pair_id>}.
 *
 * <p>Today this is a skeleton — every RPC returns UNIMPLEMENTED. Real
 * implementation lands in follow-ups:
 * <ul>
 *   <li>Signature verification against the calling tenant's stored CredPair list
 *   <li>Hazelcast nonce store (shared with ClusterAdmin)
 *   <li>AddCredPair: generate keypair, persist public half in KernelTenantConfig
 *   <li>DeleteCredPair: enforce self-deletion rules
 *       (a) cannot delete the cred_pair authenticating this very call,
 *       (b) cannot leave the tenant without ≥1 full-ceiling cred_pair
 *   <li>ListCredPairs: read from KernelTenantConfig (public halves only)
 *   <li>GetTenantConfig / PutTenantConfig: serve / replace the tenant's full
 *       TenantConfig atomically; enforce entitlements ceiling on every
 *       CredPair in the new config
 * </ul>
 */
public class TenantAdminServiceImpl implements TenantAdmin.TenantAdminHandler {
    private static final Logger logger = LoggerFactory.getLogger(TenantAdminServiceImpl.class);

    public TenantAdminServiceImpl() {
        logger.info("TenantAdminServiceImpl initialised (skeleton — RPCs return UNIMPLEMENTED)");
    }

    @Override
    public Kernel.AddCredPairResponse addCredPair(Caller caller, Kernel.AddCredPairRequest request)
            throws ProtoException {
        logger.warn("TenantAdmin.AddCredPair called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"TenantAdmin.AddCredPair is not yet implemented");
    }

    @Override
    public Kernel.DeleteCredPairResponse deleteCredPair(Caller caller, Kernel.DeleteCredPairRequest request)
            throws ProtoException {
        logger.warn("TenantAdmin.DeleteCredPair called but not implemented yet (caller={}, id={})",
                caller, request.getCredPairId());
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"TenantAdmin.DeleteCredPair is not yet implemented");
    }

    @Override
    public Kernel.ListCredPairsResponse listCredPairs(Caller caller, Kernel.ListCredPairsRequest request)
            throws ProtoException {
        logger.warn("TenantAdmin.ListCredPairs called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"TenantAdmin.ListCredPairs is not yet implemented");
    }

    @Override
    public TenantConfigOuterClass.TenantConfig getTenantConfig(Caller caller, Kernel.GetTenantConfigRequest request)
            throws ProtoException {
        logger.warn("TenantAdmin.GetTenantConfig called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"TenantAdmin.GetTenantConfig is not yet implemented");
    }

    @Override
    public TenantConfigOuterClass.TenantConfig putTenantConfig(Caller caller, Kernel.PutTenantConfigRequest request)
            throws ProtoException {
        logger.warn("TenantAdmin.PutTenantConfig called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"TenantAdmin.PutTenantConfig is not yet implemented");
    }
}
