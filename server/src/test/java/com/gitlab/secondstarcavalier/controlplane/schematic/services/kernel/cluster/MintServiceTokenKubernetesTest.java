// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import io.grpc.Status;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 2 test matrix for the kernel's Kubernetes service-account token credential
 * path on {@code MintServiceToken}. Runs entirely against a
 * {@link FakeKubernetesTokenVerifier} — no API server, no projected tokens.
 */
class MintServiceTokenKubernetesTest {

    private static final String TRUST_DOMAIN = "test.schematic.io";
    private static final String KERNEL_AUDIENCE = "schematic-kernel";
    private static final String K8S_NAMESPACE = "schematic";
    private static final String K8S_SA = "oauth-sa";
    private static final String DELEGATE_NAME = "oauth";
    private static final Caller CALLER = new Caller("", "test-req");

    // ---- Harness -----------------------------------------------------------

    /** In-memory verifying-key store; doubles as KeyRotator publisher + reader. */
    private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
    private final List<Kernel.Delegate> delegates = new ArrayList<>();
    private KeyRotator keyRotator;

    private IdentityServiceImpl newService(KubernetesTokenVerifier verifier) {
        keyRotator = new KeyRotator(
                3600, 86_400,
                verifyingKeys::add,
                kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
                () -> verifyingKeys,
                null);
        keyRotator.start();
        return new IdentityServiceImpl(
                3600, 86_400, 86_400,
                keyRotator,
                () -> verifyingKeys,
                () -> delegates,
                null,            // serviceEntitlements
                null,            // signingCa (unused on the k8s/credpair mint path)
                name -> null,    // serviceCaReader
                (name, chain) -> { }, // serviceCaWriter
                () -> TRUST_DOMAIN,
                "https://kernel.test/oidc",
                null,            // opaEvalClient
                null,            // proxyPolicyOpaClient
                null,            // configMap
                new WorkloadMap(new InMemoryManager()),
                null,            // persistState
                verifier,
                KERNEL_AUDIENCE);
    }

    private void addDelegateWithSa(String namespace, String sa) {
        delegates.add(Kernel.Delegate.newBuilder()
                .setName(DELEGATE_NAME)
                .addKubernetesServiceAccounts(Kernel.KubernetesServiceAccountMatcher.newBuilder()
                        .setKubernetesNamespace(namespace)
                        .setKubernetesServiceAccount(sa)
                        .build())
                .build());
    }

    private String delegateSpiffe(String delegateName) {
        return Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", delegateName);
    }

    /** Mints a refresh (continuity) token bound to {@code subject} with the given instance_id. */
    private String mintContinuityToken(String subject, String instanceId) {
        ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
        long now = Instant.now().getEpochSecond();
        TokenWrapper t = TokenWrapper.create()
                .setIssuer("https://kernel.test/oidc")
                .setSubject(subject)
                .setAudience("kernel")
                .setIssuedAt(now)
                .setExpiration(now + 3600)
                .setJTI(UUID.randomUUID().toString());
        t.setTokenUse(com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.Helpers
                .tokenUseToString(TokenOuterClass.TokenUse.TOKEN_USE_REFRESH));
        t.setCustomField("instance_id", instanceId);
        t.sign(signingKey);
        return t.getBase64();
    }

    private static int codeOf(Executable e) {
        ProtoException ex = assertThrows(ProtoException.class, e::run);
        return ex.getCode();
    }

    @FunctionalInterface
    private interface Executable {
        void run() throws Exception;
    }

    // ---- Tests -------------------------------------------------------------

    @Test
    void validK8sToken_mapsToDelegate_mintsServiceToken() throws Exception {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, K8S_SA, List.of(KERNEL_AUDIENCE))));

        Tokenrequest.TokenMintResponse resp = svc.mintServiceToken(CALLER,
                Tokenrequest.MintServiceTokenRequest.newBuilder()
                        .setKubernetesToken(fakeJwt())
                        .build());

        assertNotNull(resp.getAccessToken());
        TokenWrapper at = TokenWrapper.parse(resp.getAccessToken().getBase64());
        assertEquals(delegateSpiffe(DELEGATE_NAME), at.getSubject());
        assertEquals("service", at.getSubType());
        assertFalse(at.getInstanceId().isEmpty());
        // Service mints carry no refresh token.
        assertFalse(resp.hasRefreshToken());
    }

    @Test
    void wrongAudience_rejected() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        // Verifier returns an identity whose audiences omit the kernel audience —
        // the kernel must re-check returned audiences (M4), not just trust the call.
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, K8S_SA, List.of("some-other-audience"))));

        assertEquals(ProtoException.UNAUTHENTICATED,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq(fakeJwt()))));
    }

    @Test
    void kmakerAudienceToken_rejected() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, K8S_SA, List.of("kmaker"))));

        assertEquals(ProtoException.UNAUTHENTICATED,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq(fakeJwt()))));
    }

    @Test
    void wrongServiceAccount_rejected() {
        // Namespace exists on a delegate, but the SA name is different.
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, "different-sa", List.of(KERNEL_AUDIENCE))));

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq(fakeJwt()))));
    }

    @Test
    void unknownServiceAccount_rejected() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity("other-ns", "other-sa", List.of(KERNEL_AUDIENCE))));

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq(fakeJwt()))));
    }

    @Test
    void tokenReviewApiFailure_failsClosed() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(
                FakeKubernetesTokenVerifier.failing(Status.UNAVAILABLE, "api server unreachable"));

        // Fails closed as UNAVAILABLE — not INTERNAL, not a mint.
        assertEquals(ProtoException.UNAVAILABLE,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq(fakeJwt()))));
    }

    @Test
    void unwiredVerifier_failsClosedUnimplemented() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        // null verifier -> IdentityServiceImpl installs UnwiredKubernetesTokenVerifier.
        IdentityServiceImpl svc = newService(null);

        assertEquals(ProtoException.UNIMPLEMENTED,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq(fakeJwt()))));
    }

    @Test
    void continuityToken_subjectMismatch_rejected() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, K8S_SA, List.of(KERNEL_AUDIENCE))));

        // Continuity token minted for a completely unrelated subject.
        String continuity = mintContinuityToken("spiffe://" + TRUST_DOMAIN + "/system/services/someone-else",
                "instance-xyz");

        assertEquals(ProtoException.INVALID_ARGUMENT,
                codeOf(() -> svc.mintServiceToken(CALLER,
                        Tokenrequest.MintServiceTokenRequest.newBuilder()
                                .setKubernetesToken(fakeJwt())
                                .setContinuityToken(continuity)
                                .build())));
    }

    @Test
    void continuityToken_delegateMismatch_rejected() {
        // H5: K8s token resolves delegate B (oauth), but the continuity token was
        // minted for delegate A. Even though the continuity token is validly signed
        // by the kernel key, it must be rejected because its sub != resolved delegate.
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, K8S_SA, List.of(KERNEL_AUDIENCE))));

        // Validly-signed continuity token for delegate A ("billing"), not the
        // resolved delegate B ("oauth").
        String continuity = mintContinuityToken(delegateSpiffe("billing"), "instance-A");

        assertEquals(ProtoException.INVALID_ARGUMENT,
                codeOf(() -> svc.mintServiceToken(CALLER,
                        Tokenrequest.MintServiceTokenRequest.newBuilder()
                                .setKubernetesToken(fakeJwt())
                                .setContinuityToken(continuity)
                                .build())));
    }

    @Test
    void continuityToken_matchingDelegate_preservesInstanceId() throws Exception {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.returning(
                FakeKubernetesTokenVerifier.identity(K8S_NAMESPACE, K8S_SA, List.of(KERNEL_AUDIENCE))));

        // Continuity token minted for the RESOLVED delegate's SPIFFE subject.
        String continuity = mintContinuityToken(delegateSpiffe(DELEGATE_NAME), "instance-keep-me");

        Tokenrequest.TokenMintResponse resp = svc.mintServiceToken(CALLER,
                Tokenrequest.MintServiceTokenRequest.newBuilder()
                        .setKubernetesToken(fakeJwt())
                        .setContinuityToken(continuity)
                        .build());

        TokenWrapper at = TokenWrapper.parse(resp.getAccessToken().getBase64());
        assertEquals("instance-keep-me", at.getInstanceId());
    }

    @Test
    void multipleCredentialProofs_rejectedByRuntimeGuard() throws Exception {
        // The credential fields are FLAT proto fields (not a oneof), because the
        // Rust/Go identity-manager templates construct the request with flat field
        // names. So setting two of them leaves BOTH populated — the wire format does
        // not enforce exclusivity. Exclusivity (the H5 "reject >1" requirement) is
        // enforced entirely by the runtime credentialCount guard in mintServiceToken,
        // which fires before any verifier work.
        Tokenrequest.MintServiceTokenRequest req = Tokenrequest.MintServiceTokenRequest.newBuilder()
                .setInputToken("input-and-k8s-both-set")
                .setKubernetesToken(fakeJwt())
                .build();

        // Flat fields: both are retained (no oneof auto-clear), and survive a wire
        // round-trip.
        assertFalse(req.getInputToken().isEmpty());
        assertFalse(req.getKubernetesToken().isEmpty());
        Tokenrequest.MintServiceTokenRequest reparsed =
                Tokenrequest.MintServiceTokenRequest.parseFrom(req.toByteArray());
        assertFalse(reparsed.getInputToken().isEmpty());
        assertFalse(reparsed.getKubernetesToken().isEmpty());

        // The runtime guard rejects the >1 state with INVALID_ARGUMENT and never
        // reaches the verifier seam.
        FakeKubernetesTokenVerifier spy = FakeKubernetesTokenVerifier.neverCalled();
        IdentityServiceImpl svc = newService(spy);
        assertEquals(ProtoException.INVALID_ARGUMENT,
                codeOf(() -> svc.mintServiceToken(CALLER, req)));
        assertFalse(spy.wasInvoked(), "multi-credential request must be rejected before the verifier");
    }

    @Test
    void malformedK8sToken_rejectedBeforeVerifier() {
        addDelegateWithSa(K8S_NAMESPACE, K8S_SA);
        FakeKubernetesTokenVerifier spy = FakeKubernetesTokenVerifier.neverCalled();
        IdentityServiceImpl svc = newService(spy);

        assertEquals(ProtoException.INVALID_ARGUMENT,
                codeOf(() -> svc.mintServiceToken(CALLER, k8sReq("not-a-jwt"))));
        assertFalse(spy.wasInvoked(), "verifier must not be touched for a structurally-invalid token");
    }

    @Test
    void noCredentialProof_rejected() {
        IdentityServiceImpl svc = newService(FakeKubernetesTokenVerifier.neverCalled());
        assertEquals(ProtoException.INVALID_ARGUMENT,
                codeOf(() -> svc.mintServiceToken(CALLER,
                        Tokenrequest.MintServiceTokenRequest.newBuilder().build())));
    }

    @Test
    void inputTokenPath_unknownToken_rejectedUnauthenticated() {
        // A well-formed but unknown input_token routes through the input_token
        // (exchange) path, matches no kernel verifying key, and is rejected
        // UNAUTHENTICATED. The fake k8s verifier must never be touched on the
        // input_token path.
        FakeKubernetesTokenVerifier spy = FakeKubernetesTokenVerifier.neverCalled();
        IdentityServiceImpl svc = newService(spy);

        // Unknown-but-well-formed JWT -> UNAUTHENTICATED from the input_token path.
        assertEquals(ProtoException.UNAUTHENTICATED,
                codeOf(() -> svc.mintServiceToken(CALLER, inputTokenReq(fakeJwt()))));
        assertFalse(spy.wasInvoked(), "input_token path must not touch the k8s verifier");
    }

    @Test
    void credPairBootstrapInputToken_nowRejectedUnauthenticated() {
        // Cred_pair-bootstrap removal: service delegates no longer carry static
        // cred_pair public keys, so input_token cannot bootstrap a service identity.
        // A non-kernel-signed token falls through to UNAUTHENTICATED. Service
        // bootstrap is via kubernetes_token only.

        FakeKubernetesTokenVerifier spy = FakeKubernetesTokenVerifier.neverCalled();
        IdentityServiceImpl svc = newService(spy);

        assertEquals(ProtoException.UNAUTHENTICATED,
                codeOf(() -> svc.mintServiceToken(CALLER, inputTokenReq(fakeJwt()))));
        assertFalse(spy.wasInvoked(), "input_token must not touch the k8s verifier");
    }

    // ---- helpers -----------------------------------------------------------

    private static Tokenrequest.MintServiceTokenRequest k8sReq(String token) {
        return Tokenrequest.MintServiceTokenRequest.newBuilder().setKubernetesToken(token).build();
    }

    private static Tokenrequest.MintServiceTokenRequest inputTokenReq(String token) {
        return Tokenrequest.MintServiceTokenRequest.newBuilder().setInputToken(token).build();
    }

    /** A structurally well-formed (3-segment) but otherwise meaningless JWT. */
    private static String fakeJwt() {
        return "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0"
                + ".eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YmVkcm9jazpvYXV0aC1zYSJ9"
                + ".c2lnbmF0dXJl";
    }
}
