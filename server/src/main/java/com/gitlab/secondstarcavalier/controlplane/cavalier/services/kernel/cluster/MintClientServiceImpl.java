// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.MintClient;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MintClientServiceImpl is the kernel-hosted client cred_pair → bearer token
 * exchange (mirror of Mint.MintServiceToken for external clients).
 *
 * <p>Today this is a skeleton — every RPC returns UNIMPLEMENTED. Real
 * implementation lands in follow-ups and mirrors the existing
 * MintServiceToken handler:
 * <ul>
 *   <li>Parse and validate the input JWT (signature, exp, nonce)
 *   <li>Resolve cred_pair_id:
 *       <ul>
 *         <li>kernel.Config.cluster_cred_pairs → subject SPIFFE
 *             {@code spiffe://<prefix>/cluster-admin}</li>
 *         <li>tenant's KernelTenantConfig.cred_pairs → subject SPIFFE
 *             {@code spiffe://<prefix>/<tenant_name>/users/cred-pair:<id>}</li>
 *       </ul>
 *   <li>Verify the JWT signature against the stored public key
 *   <li>Mint a kernel-signed access (and optional refresh) token with the
 *       resolved SPIFFE as subject
 * </ul>
 */
public class MintClientServiceImpl implements MintClient.MintClientHandler {
    private static final Logger logger = LoggerFactory.getLogger(MintClientServiceImpl.class);

    public MintClientServiceImpl() {
        logger.info("MintClientServiceImpl initialised (skeleton — RPCs return UNIMPLEMENTED)");
    }

    @Override
    public Tokenrequest.TokenMintResponse mintClientToken(Caller caller, Tokenrequest.MintClientTokenRequest request)
            throws ProtoException {
        logger.warn("MintClient.MintClientToken called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,
                "MintClient.MintClientToken is not yet implemented");
    }
}
