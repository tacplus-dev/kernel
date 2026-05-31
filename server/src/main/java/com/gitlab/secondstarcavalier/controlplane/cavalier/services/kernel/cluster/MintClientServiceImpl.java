// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.MintClient;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.credpair.Credpair;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.spec.Spec;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MintClientServiceImpl hosts the kernel's cred_pair → token exchanges.
 *
 * <p>{@link #mintP2SToken} is the P2S (pipeline/CI) mint: a P2S cred_pair JWT
 * (signed by the holder's private key, carrying the cred_pair_id as the JWT kid)
 * is exchanged for a kernel-signed P2S bearer token. Kernel resolves the
 * cred_pair_id against the tenants' {@code pipeline_cred_pairs}, verifies the JWT
 * signature against the stored JWK public key, and mints a token whose
 * {@code sub_type=pipeline}, {@code capability} and {@code namespace} come from the
 * cred_pair. That token gates the P2S management RPCs (ClusterAdmin/TenantAdmin),
 * enforced by capability + level-or-below.
 *
 * <p>{@code mintClientToken} (C2S client cred_pair) is still a skeleton; deeper
 * C2S-cred_pair support lands later with CloudAuth.
 */
public class MintClientServiceImpl implements MintClient.MintClientHandler {
    private static final Logger logger = LoggerFactory.getLogger(MintClientServiceImpl.class);

    private static final long DEFAULT_P2S_TTL_SECONDS = 3600; // 1 hour

    private final ConfigMap configMap;
    private final KeyRotator keyRotator;
    private final String tokenIssuer;

    public MintClientServiceImpl(ConfigMap configMap, KeyRotator keyRotator, String tokenIssuer) {
        this.configMap = configMap;
        this.keyRotator = keyRotator;
        this.tokenIssuer = tokenIssuer;
        logger.info("MintClientServiceImpl initialised (P2S mint enabled; client-cred_pair mint skeleton)");
    }

    @Override
    public Tokenrequest.TokenMintResponse mintClientToken(Caller caller, Tokenrequest.MintClientTokenRequest request)
            throws ProtoException {
        logger.warn("MintClient.MintClientToken called but not implemented yet (caller={})", caller);
        throw new ProtoException(ProtoException.UNIMPLEMENTED,
                "MintClient.MintClientToken is not yet implemented");
    }

    @Override
    public Tokenrequest.TokenMintResponse mintP2SToken(Caller caller, Tokenrequest.MintP2STokenRequest request)
            throws ProtoException {
        // Parse the presented cred_pair proof JWT.
        TokenWrapper proof;
        try {
            proof = TokenWrapper.parse(request.getInputToken());
        } catch (Exception e) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "invalid input_token: " + e.getMessage());
        }
        String credPairId = proof.getKid();
        if (credPairId == null || credPairId.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "input_token missing kid (cred_pair_id)");
        }

        // Resolve the P2SCredPair by id across tenants' pipeline_cred_pairs.
        // The owning tenant's namespace becomes the minted token's namespace.
        Credpair.P2SCredPair matched = null;
        String namespace = null;
        for (Kernel.TenantConfigEntry e : configMap.proto().getTenantConfigsList()) {
            for (Credpair.P2SCredPair cp : e.getConfig().getKernel().getPipelineCredPairsList()) {
                if (credPairId.equals(cp.getId())) {
                    matched = cp;
                    namespace = e.getTenantName();
                    break;
                }
            }
            if (matched != null) {
                break;
            }
        }
        if (matched == null) {
            throw new ProtoException(ProtoException.UNAUTHENTICATED,
                    "unknown P2S cred_pair: " + credPairId);
        }

        // Expiry check on the cred_pair itself.
        long now = Instant.now().getEpochSecond();
        if (matched.hasExpiresAt() && matched.getExpiresAt().getSeconds() > 0
                && matched.getExpiresAt().getSeconds() <= now) {
            throw new ProtoException(ProtoException.UNAUTHENTICATED,
                    "P2S cred_pair " + credPairId + " has expired");
        }

        // Verify the proof signature against the cred_pair's JWK public key.
        try {
            proof.verify(ImmutableJwk.from(matched.getPublicKey()));
        } catch (Exception e) {
            throw new ProtoException(ProtoException.UNAUTHENTICATED,
                    "P2S proof verification failed: " + e.getMessage());
        }

        Spec.Capability cap = matched.getCapability();
        if (cap == Spec.Capability.CAPABILITY_UNSPECIFIED) {
            throw new ProtoException(ProtoException.FAILED_PRECONDITION,
                    "P2S cred_pair " + credPairId + " has no capability");
        }
        String capStr = cap == Spec.Capability.CAPABILITY_RW ? "RW" : "RO";

        ImmutableKey signingKey = keyRotator.getActiveSigningKey();
        if (signingKey == null) {
            throw new ProtoException(ProtoException.UNAVAILABLE, "no active signing key");
        }

        long exp;
        if (request.getExp() > 0) {
            exp = request.getExp();
            if (exp <= now) {
                throw new ProtoException(ProtoException.INVALID_ARGUMENT, "exp must be in the future");
            }
        } else {
            exp = now + DEFAULT_P2S_TTL_SECONDS;
        }

        // Mint the P2S bearer token: identity-only, capability-carrying.
        TokenWrapper token = TokenWrapper.create()
                .setIssuer(tokenIssuer)
                .setSubject("cred-pair:" + credPairId)
                .setAudience("kernel")
                .setIssuedAt(now)
                .setExpiration(exp)
                .setJTI(UUID.randomUUID().toString());
        token.setNamespace(namespace);
        token.setSubType("pipeline");
        token.setCustomField("capability", capStr);
        token.sign(signingKey);

        logger.info("Minted P2S token: cred_pair={} namespace={} capability={} exp={}",
                credPairId, namespace, capStr, exp);
        TokenOuterClass.Token proto = token.getProto();
        return Tokenrequest.TokenMintResponse.newBuilder()
                .setAccessToken(proto)
                .build();
    }
}
