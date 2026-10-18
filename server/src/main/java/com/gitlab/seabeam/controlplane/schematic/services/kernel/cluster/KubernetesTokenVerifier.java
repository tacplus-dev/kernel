// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import io.grpc.Status;

/**
 * Swappable seam for validating a Kubernetes projected service-account token.
 *
 * <p>This is deliberately an interface so the kernel does NOT hard-wire the
 * TokenReview-vs-local-JWKS decision (review finding M1 / plan Open Question 6).
 * Phase 2 ships with an in-memory fake for tests; the real wiring
 * ({@code TokenReviewVerifier} against the API server, or a local SA-issuer
 * {@code /openid/v1/jwks} verifier) lands when operator Phase 3 (projected
 * tokens + kernel TokenReview RBAC) exists. Because routing depends only on
 * this interface, swapping implementations is a wiring/config change, not a
 * rewrite of the mint path.
 *
 * <p>Failure mapping is the implementation's responsibility and must be
 * deliberate (review finding L1):
 * <ul>
 *   <li>structurally bad / unauthenticated token -> {@link Status#UNAUTHENTICATED}</li>
 *   <li>token valid but not for the required audience -> {@link Status#UNAUTHENTICATED}</li>
 *   <li>verifier backend (API server / JWKS) unreachable -> {@link Status#UNAVAILABLE}</li>
 * </ul>
 * Implementations must never collapse "bad token" and "backend down" into a
 * single opaque {@code INTERNAL}.
 */
public interface KubernetesTokenVerifier {

    /**
     * Validates {@code token} and returns the verified identity, or throws.
     *
     * @param token            the raw projected service-account JWT.
     * @param requiredAudience the audience the kernel requires the token to be
     *                         valid for (the configured kernel/Schematic workload
     *                         audience — never the {@code kmaker} audience).
     *                         Implementations must both request this audience
     *                         and re-check that the returned audiences contain
     *                         it (belt-and-suspenders, review finding M4).
     * @return the validated identity (namespace, SA, uid, audiences, extras).
     * @throws K8sTokenVerificationException with a deliberate gRPC status.
     */
    VerifiedK8sIdentity verify(String token, String requiredAudience)
            throws K8sTokenVerificationException;

    /**
     * Carries the gRPC {@link Status} the routing layer should surface, so the
     * verifier (not the catch-all) decides UNAUTHENTICATED vs UNAVAILABLE.
     */
    final class K8sTokenVerificationException extends Exception {
        private final transient Status status;

        public K8sTokenVerificationException(Status status, String message) {
            super(message);
            this.status = status;
        }

        public Status status() {
            return status;
        }
    }
}
