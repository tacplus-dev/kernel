// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.Channel;
import io.grpc.CallOptions;
import io.grpc.MethodDescriptor;
import io.grpc.ClientCall;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test matrix for the kernel's standing-delegation ({@link Kernel.Grant}) mint
 * path, {@code MintDelegatedToken}: OPA fresh-replay, {@code authorized_scope}
 * intersection, the paired negative control (design doc item6-piece-b), and the
 * per-use grant revocation check every exchange of a delegation-derived token
 * runs (BIG GOAL 5 item A / the OT revocation-timing ruling).
 * Runs entirely against a {@link FakeOpaEvalGrpcClient} — no real UncleOPA.
 */
class MintDelegatedTokenTest {

    private static final String TRUST_DOMAIN = "test.schematic.io";
    private static final String KERNEL_AUDIENCE = "schematic-kernel";
    private static final String DELEGATE_NAME = "oauth";
    private static final String GRANT_SUBJECT = "spiffe://" + TRUST_DOMAIN + "/system/users/alice";
    private static final String GRANT_ID = "grant-1";
    // The revocation tests exchange the minted token, and the U2S exchange path
    // resolves sub through findDelegateByName — which rejects a SPIFFE *user*
    // URI outright (pre-existing; see the result note). An IDP-style subject is
    // the shape a Grant actually records at consent time anyway.
    private static final String IDP_GRANT_SUBJECT = "alice@example.com";
    private static final Caller CALLER = new Caller("", "test-req");

    // ---- Harness -----------------------------------------------------------

    private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
    private final List<Kernel.Delegate> delegates = new ArrayList<>();
    private final List<Kernel.Grant> grants = new CopyOnWriteArrayList<>();
    private KeyRotator keyRotator;

    private IdentityServiceImpl newService(OpaEvalGrpcClient opaEvalClient) {
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
                () -> grants,
                null,            // serviceEntitlements
                null,            // signingCa
                name -> null,    // serviceCaReader
                (name, chain) -> { }, // serviceCaWriter
                () -> TRUST_DOMAIN,
                "https://kernel.test/oidc",
                opaEvalClient,
                null,            // proxyPolicyOpaClient
                null,            // configMap
                new WorkloadMap(new InMemoryManager()),
                null,            // persistState
                null,            // kubernetesTokenVerifier
                KERNEL_AUDIENCE);
    }

    /** Mints and signs a caller S2S token for {@code delegateName}, the kernel's own key. */
    private String mintCallerToken(String delegateName) {
        ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
        long now = Instant.now().getEpochSecond();
        TokenWrapper t = TokenWrapper.create()
                .setIssuer("https://kernel.test/oidc")
                .setSubject(Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", delegateName))
                .setAudience("kernel")
                .setIssuedAt(now)
                .setExpiration(now + 3600)
                .setJTI(UUID.randomUUID().toString());
        t.sign(signingKey);
        return t.getBase64();
    }

    private Tokenrequest.MintDelegatedTokenResponse mintAs(IdentityServiceImpl svc, String callerDelegateName,
            String grantId) throws Exception {
        io.grpc.Context ctx = io.grpc.Context.current()
                .withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, mintCallerToken(callerDelegateName));
        io.grpc.Context previous = ctx.attach();
        try {
            return svc.mintDelegatedToken(CALLER,
                    Tokenrequest.MintDelegatedTokenRequest.newBuilder().setGrantId(grantId).build());
        } finally {
            ctx.detach(previous);
        }
    }

    private static int codeOf(Executable e) {
        ProtoException ex = assertThrows(ProtoException.class, e::run);
        return ex.getCode();
    }

    /** Asserts the exchange was denied specifically by the grant re-check, not incidentally. */
    private static void assertDeniedByRevokedGrant(Executable e) {
        ProtoException ex = assertThrows(ProtoException.class, e::run);
        assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
        assertTrue(ex.getMessage().contains("standing delegation " + GRANT_ID + " is no longer active"),
                "expected the per-use grant check to be the denier, got: " + ex.getMessage());
    }

    @FunctionalInterface
    private interface Executable {
        void run() throws Exception;
    }

    private static Kernel.Grant.Builder grantBuilder() {
        return Kernel.Grant.newBuilder()
                .setId(GRANT_ID)
                .setDelegateName(DELEGATE_NAME)
                .setSubject(GRANT_SUBJECT)
                .setClaims(Struct.newBuilder()
                        .putFields("sub", Value.newBuilder().setStringValue(GRANT_SUBJECT).build())
                        .build())
                .setCreatedAtMs(Instant.now().toEpochMilli());
    }

    private static Entitlements.TokenEntitlements scope(List<String> grantTokens, String principalScope) {
        Entitlements.TokenEntitlements.Builder b = Entitlements.TokenEntitlements.newBuilder()
                .addAllGrants(grantTokens);
        if (principalScope != null) {
            b.setPrincipalScope(principalScope);
        }
        return b.build();
    }

    /** A minimal fake OpaEvalGrpcClient — subclasses the concrete generated client
     * (no interface exists) with a channel that throws if ever actually used, and
     * overrides evalEntitlement to return a canned result. */
    private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
        private final Entitlements.TokenEntitlements toReturn;
        private volatile boolean invoked = false;

        FakeOpaEvalGrpcClient(Entitlements.TokenEntitlements toReturn) {
            super(UNUSABLE_CHANNEL, () -> "unused-token");
            this.toReturn = toReturn;
        }

        static FakeOpaEvalGrpcClient returning(Entitlements.TokenEntitlements toReturn) {
            return new FakeOpaEvalGrpcClient(toReturn);
        }

        static FakeOpaEvalGrpcClient neverCalled() {
            return new FakeOpaEvalGrpcClient(null) {
                @Override
                public Userentitlements.EntitlementEvalResult evalEntitlement(Userentitlements.EntitlementEvalInput request) {
                    throw new AssertionError("OPA client must not be invoked");
                }
            };
        }

        boolean wasInvoked() {
            return invoked;
        }

        @Override
        public Userentitlements.EntitlementEvalResult evalEntitlement(Userentitlements.EntitlementEvalInput request) {
            invoked = true;
            return Userentitlements.EntitlementEvalResult.newBuilder()
                    .setTokenEntitlements(toReturn)
                    .build();
        }

        private static final Channel UNUSABLE_CHANNEL = new Channel() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> newCall(
                    MethodDescriptor<ReqT, RespT> methodDescriptor, CallOptions callOptions) {
                throw new UnsupportedOperationException("fake channel must never be used");
            }

            @Override
            public String authority() {
                throw new UnsupportedOperationException("fake channel must never be used");
            }
        };
    }

    // ---- Tests -------------------------------------------------------------

    @Test
    void positivePath_mintsIntersectedToken() throws Exception {
        grants.add(grantBuilder()
                .setAuthorizedScope(scope(
                        List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG", "KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"),
                        "PRINCIPAL_SCOPE_SELF_ONLY"))
                .build());
        FakeOpaEvalGrpcClient opa = FakeOpaEvalGrpcClient.returning(scope(
                List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG", "KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"),
                "PRINCIPAL_SCOPE_SELF_ONLY"));
        IdentityServiceImpl svc = newService(opa);

        Tokenrequest.MintDelegatedTokenResponse resp = mintAs(svc, DELEGATE_NAME, GRANT_ID);

        assertNotNull(resp.getToken());
        TokenWrapper token = TokenWrapper.parse(resp.getToken().getBase64());
        assertEquals(GRANT_SUBJECT, token.getSubject());
        assertEquals(DELEGATE_NAME, token.getAct());
        assertEquals("kernel", token.getAzp());
        assertTrue(opa.wasInvoked());
    }

    @Test
    void wrongDelegate_rejected_opaNeverInvoked() {
        grants.add(grantBuilder().setAuthorizedScope(scope(List.of(), null)).build());
        FakeOpaEvalGrpcClient opa = FakeOpaEvalGrpcClient.neverCalled();
        IdentityServiceImpl svc = newService(opa);

        // A different delegate ("billing") presents the grant id that names "oauth".
        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> mintAs(svc, "billing", GRANT_ID)));
    }

    @Test
    void expiredGrant_rejected() {
        grants.add(grantBuilder()
                .setAuthorizedScope(scope(List.of(), null))
                .setExpiresAtMs(Instant.now().toEpochMilli() - 60_000)
                .build());
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.neverCalled());

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> mintAs(svc, DELEGATE_NAME, GRANT_ID)));
    }

    @Test
    void unknownGrantId_rejected() {
        // No grants seeded at all.
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.neverCalled());

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> mintAs(svc, DELEGATE_NAME, "no-such-grant")));
    }

    // ---- Per-use standing-delegation revocation --------------------------

    /** Exchanges a delegation-derived token for a service token — one "use". */
    private Tokenrequest.TokenMintResponse useFor(IdentityServiceImpl svc, TokenOuterClass.Token token,
            String aud) throws Exception {
        return svc.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
                .setInputToken(token.getBase64())
                .setAud(aud)
                .build());
    }

    @Test
    void revokingTheGrantKillsAnAlreadyMintedTokenOnItsNextUse() throws Exception {
        grants.add(grantBuilder().setSubject(IDP_GRANT_SUBJECT)
                .setAuthorizedScope(scope(List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"), null))
                // Well beyond the token's own 1h exp, so nothing below can pass or
                // fail because the grant or the token merely aged out.
                .setExpiresAtMs(Instant.now().toEpochMilli() + 86_400_000L)
                .build());
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.returning(
                scope(List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"), null)));

        TokenOuterClass.Token minted = mintAs(svc, DELEGATE_NAME, GRANT_ID).getToken();
        assertEquals(GRANT_ID, TokenWrapper.parse(minted.getBase64()).getCustomField("gid"),
                "the minted token must record the grant it derives from");

        // Positive control: used while the delegation stands, within its own exp.
        Tokenrequest.TokenMintResponse before = useFor(svc, minted, "kernel");
        assertNotNull(before.getAccessToken());
        assertEquals(GRANT_ID, TokenWrapper.parse(before.getAccessToken().getBase64()).getCustomField("gid"),
                "the derived service token must keep the lineage so it is re-checked too");

        // The user revokes the standing delegation.
        grants.removeIf(g -> GRANT_ID.equals(g.getId()));

        // The SAME token, unchanged and still well inside its own expiry, is dead.
        assertDeniedByRevokedGrant(() -> useFor(svc, minted, "kernel"));
        // ...and so is the service token already derived from it.
        assertDeniedByRevokedGrant(() -> useFor(svc, before.getAccessToken(), "kernel"));
    }

    @Test
    void grantExpiringMidTokenLifetimeKillsTheDerivedTokenOnNextUse() throws Exception {
        grants.add(grantBuilder().setSubject(IDP_GRANT_SUBJECT)
                .setAuthorizedScope(scope(List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"), null))
                .setExpiresAtMs(Instant.now().toEpochMilli() + 86_400_000L)
                .build());
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.returning(
                scope(List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"), null)));

        TokenOuterClass.Token minted = mintAs(svc, DELEGATE_NAME, GRANT_ID).getToken();
        assertNotNull(useFor(svc, minted, "kernel").getAccessToken());

        // The grant reaches its own expiry while the minted token is still valid.
        Kernel.Grant live = grants.get(0);
        grants.set(0, live.toBuilder().setExpiresAtMs(Instant.now().toEpochMilli() - 1).build());

        assertDeniedByRevokedGrant(() -> useFor(svc, minted, "kernel"));
    }

    @Test
    void tokenWithNoGrantLineageIsUnaffected() throws Exception {
        // A grant exists but this token does not derive from one: the check is a
        // no-op for every non-delegated token on the same exchange path.
        grants.add(grantBuilder().setAuthorizedScope(scope(List.of(), null)).build());
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.neverCalled());

        TokenWrapper plain = TokenWrapper.parse(mintCallerToken(DELEGATE_NAME));
        assertNull(plain.getCustomField("gid"));
        assertNotNull(useFor(svc, plain.getProto(), "kernel").getAccessToken());
    }

    @Test
    void intersectionNarrowsWidenedFreshOpaResult() throws Exception {
        // The grant only recorded consent for GET_TENANT_CONFIG at consent time...
        grants.add(grantBuilder()
                .setAuthorizedScope(scope(List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"),
                        "PRINCIPAL_SCOPE_SELF_ONLY"))
                .build());
        // ...but the user's LIVE authority has since widened (fresh OPA now also
        // grants GET_PROJECT_CONFIG and a wider principal_scope). The final token
        // must still be bounded by the grant's narrower recorded scope, not by
        // fresh OPA alone.
        FakeOpaEvalGrpcClient opa = FakeOpaEvalGrpcClient.returning(scope(
                List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG", "KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"),
                "PRINCIPAL_SCOPE_ANY"));
        IdentityServiceImpl svc = newService(opa);

        Tokenrequest.MintDelegatedTokenResponse resp = mintAs(svc, DELEGATE_NAME, GRANT_ID);

        TokenWrapper token = TokenWrapper.parse(resp.getToken().getBase64());
        String entitlementsJson = token.getCustomField("service_entitlements");
        assertNotNull(entitlementsJson);
        assertTrue(entitlementsJson.contains("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"));
        assertFalse(entitlementsJson.contains("KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"),
                "widened fresh-OPA grant must be excluded — the recorded authorized_scope bounds the mint");
    }
}
