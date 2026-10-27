// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import io.grpc.Status;

/**
 * Default {@link KubernetesTokenVerifier} used until a real verifier is wired.
 *
 * <p>Phase 2 builds the kernel-side vertical (proto, routing, SA->delegate
 * mapping, continuity cross-check, tests) without a live cluster. The real
 * verifier — a TokenReview client against the API server, or a local
 * SA-issuer JWKS verifier — depends on operator Phase 3 (projected tokens with
 * the kernel audience + a {@code tokenreviews/create} RBAC grant for the kernel
 * service account). Until that lands, the kernel is configured with this
 * implementation, which fails closed: any {@code kubernetes_token} credential
 * is rejected with {@link Status#UNIMPLEMENTED} rather than silently accepted.
 *
 * <p>Swapping in {@code TokenReviewVerifier} / {@code LocalJwksVerifier} is a
 * wiring change in {@code ClusterServer}; the routing in
 * {@code IdentityServiceImpl} does not change.
 */
public final class UnwiredKubernetesTokenVerifier implements KubernetesTokenVerifier {

    @Override
    public VerifiedK8sIdentity verify(String token, String requiredAudience)
            throws K8sTokenVerificationException {
        throw new K8sTokenVerificationException(
                Status.UNIMPLEMENTED,
                "kubernetes_token credential is not yet wired in this kernel build "
                        + "(real TokenReview / local-JWKS verifier lands with operator Phase 3)");
    }
}
