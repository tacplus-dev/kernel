// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.ClusterAdmin;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ClusterAdminServiceImpl is the kernel-hosted tenant lifecycle handler.
 *
 * <p>All RPCs require a signed request authenticated by one of the cluster
 * cred_pairs in {@link Kernel.Config#getClusterCredPairsList()}. The caller's
 * effective SPIFFE is {@code spiffe://<spiffe_prefix>/cluster-admin}.
 *
 * <p>Today this is a skeleton — every RPC returns UNIMPLEMENTED. Real
 * implementation lands in follow-ups:
 * <ul>
 *   <li>Signature verification (Ed25519 over canonical request + nonce + timestamp)
 *   <li>Hazelcast-backed nonce store (5-min TTL) for replay protection
 *   <li>CreateTenant: generate tenant CredPair, persist to ConfigState
 *   <li>DeleteTenant: remove from ConfigState
 *   <li>ListTenants: read from ConfigState
 * </ul>
 */
public class ClusterAdminServiceImpl implements ClusterAdmin.ClusterAdminHandler {
    private static final Logger logger = LoggerFactory.getLogger(ClusterAdminServiceImpl.class);

    public ClusterAdminServiceImpl() {
        // No state held by the skeleton.
        logger.info("ClusterAdminServiceImpl initialised (skeleton — RPCs return UNIMPLEMENTED)");
    }

    @Override
    public Kernel.CreateTenantResponse createTenant(Caller caller, Kernel.CreateTenantRequest request)
            throws ProtoException {
        logger.warn("ClusterAdmin.CreateTenant called but not implemented yet (caller={}, name={})",
                caller, request.getName());
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"ClusterAdmin.CreateTenant is not yet implemented");
    }

    @Override
    public Kernel.DeleteTenantResponse deleteTenant(Caller caller, Kernel.DeleteTenantRequest request)
            throws ProtoException {
        logger.warn("ClusterAdmin.DeleteTenant called but not implemented yet (caller={}, name={})",
                caller, request.getName());
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"ClusterAdmin.DeleteTenant is not yet implemented");
    }

    @Override
    public Kernel.ListTenantsResponse listTenants(Caller caller, Kernel.ListTenantsRequest request)
            throws ProtoException {
        logger.warn("ClusterAdmin.ListTenants called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,"ClusterAdmin.ListTenants is not yet implemented");
    }
}
