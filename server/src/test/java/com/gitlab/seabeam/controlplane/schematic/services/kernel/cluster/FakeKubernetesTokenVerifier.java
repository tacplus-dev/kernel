// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import io.grpc.Status;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * In-memory {@link KubernetesTokenVerifier} for tests — lets the whole Phase 2
 * vertical run without an API server or projected tokens. A test supplies a
 * function mapping (token, requiredAudience) to either a
 * {@link VerifiedK8sIdentity} or a thrown
 * {@link K8sTokenVerificationException}. The verifier also records whether it
 * was invoked, so the "reject before any verifier work" tests can assert the
 * seam was never touched.
 */
final class FakeKubernetesTokenVerifier implements KubernetesTokenVerifier {

    @FunctionalInterface
    interface VerifyFn {
        VerifiedK8sIdentity apply(String token, String requiredAudience)
                throws K8sTokenVerificationException;
    }

    private final VerifyFn fn;
    private volatile boolean invoked = false;

    FakeKubernetesTokenVerifier(VerifyFn fn) {
        this.fn = fn;
    }

    /** Always returns the given identity for any token. */
    static FakeKubernetesTokenVerifier returning(VerifiedK8sIdentity identity) {
        return new FakeKubernetesTokenVerifier((t, a) -> identity);
    }

    /** Always throws with the given status (e.g. UNAVAILABLE for "API server down"). */
    static FakeKubernetesTokenVerifier failing(Status status, String message) {
        return new FakeKubernetesTokenVerifier((t, a) -> {
            throw new K8sTokenVerificationException(status, message);
        });
    }

    /** Fails the test if the verifier is ever called (spy for before-work assertions). */
    static FakeKubernetesTokenVerifier neverCalled() {
        return new FakeKubernetesTokenVerifier((t, a) -> {
            throw new AssertionError("verifier must not be invoked for this request");
        });
    }

    boolean wasInvoked() {
        return invoked;
    }

    @Override
    public VerifiedK8sIdentity verify(String token, String requiredAudience)
            throws K8sTokenVerificationException {
        invoked = true;
        return fn.apply(token, requiredAudience);
    }

    // Small builders used by tests.

    static VerifiedK8sIdentity identity(String namespace, String sa, List<String> audiences) {
        return new VerifiedK8sIdentity(namespace, sa, "uid-" + sa, audiences, Map.of());
    }
}
