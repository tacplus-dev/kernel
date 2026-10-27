// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import java.util.List;
import java.util.Map;

/**
 * The validated identity carried by a Kubernetes projected service-account
 * token, as returned by a {@link KubernetesTokenVerifier}.
 *
 * <p>The {@code kubernetesNamespace} / {@code kubernetesServiceAccount} pair is
 * what the kernel maps to a {@code Delegate} via
 * {@code Delegate.kubernetes_service_accounts}. The remaining fields are
 * advisory for the service-token path (the kernel maps SA -> delegate; it does
 * not pod-bind the way kmaker's cert path does) but are captured so a future
 * replay / pod-binding policy can use them without a proto change.
 *
 * @param kubernetesNamespace      K8s namespace of the service account (e.g. {@code "schematic"}).
 * @param kubernetesServiceAccount K8s ServiceAccount name (e.g. {@code "oauth"}).
 * @param serviceAccountUid        UID of the service account, when reported.
 * @param audiences                audiences the verifier confirmed the token is valid for.
 * @param podExtras                advisory pod-name / pod-uid extras
 *                                 ({@code authentication.kubernetes.io/pod-*}).
 */
public record VerifiedK8sIdentity(
        String kubernetesNamespace,
        String kubernetesServiceAccount,
        String serviceAccountUid,
        List<String> audiences,
        Map<String, String> podExtras) {

    public VerifiedK8sIdentity {
        audiences = audiences == null ? List.of() : List.copyOf(audiences);
        podExtras = podExtras == null ? Map.of() : Map.copyOf(podExtras);
    }
}
