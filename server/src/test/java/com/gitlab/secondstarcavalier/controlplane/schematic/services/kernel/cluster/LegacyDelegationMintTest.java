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
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * BIG GOAL 7 item 7 — the legacy {@code MintToken} delegation arm.
 *
 * <p>{@code kernel.Mint/MintToken} is declared {@code auth_disabled}/self-authenticating,
 * and {@code doTokenMint} used to route a request with an EMPTY {@code input_token} and a
 * caller-supplied {@code subject} into {@code delegationMint}: any registered delegate —
 * not just the {@code oauth}/{@code saml} brokers {@code MintUserToken} is restricted to —
 * could mint a user token with an arbitrary {@code sub} and arbitrary claims, with no OPA
 * entitlement resolution at all. That arm is removed; {@code MintToken} is now the exchange
 * RPC its proto contract says it is, and on-behalf-of minting goes through
 * {@code MintUserToken} only.
 *
 * <p>Paired control: {@link #legacyDelegationArmNoLongerMintsArbitrarySubjects()} is the
 * bypass (it MINTS a token on the pre-fix code, and is refused on the fixed code);
 * {@link #mintUserTokenStillMintsForTheSameDelegate()} and
 * {@link #mintTokenStillExchangesAKernelSignedToken()} are the positive controls that the
 * legitimate broker path and the real MintToken exchange path both still work.
 */
class LegacyDelegationMintTest {

    private static final String TRUST_DOMAIN = "test.schematic.io";
    private static final String KERNEL_AUDIENCE = "schematic-kernel";
    private static final String DELEGATE_NAME = "oauth";
    private static final String VICTIM_SUBJECT = "victim@example.com";
    private static final String ACME_NS = "/tenants/acme";
    private static final Caller CALLER = new Caller("", "test-req");

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
                updated -> { },  // grantWriter — this test never revokes
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
                new PrincipalMap(new InMemoryManager()),
                null,            // persistState
                null,            // kubernetesTokenVerifier
                KERNEL_AUDIENCE,
                null);           // opaConfigWriter
    }

    private void registerDelegate() {
        delegates.add(Kernel.Delegate.newBuilder()
                .setName(DELEGATE_NAME)
                .addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
                .build());
    }

    /** Mints and signs a caller S2S token for {@code delegateName} with the kernel's own key. */
    private String mintCallerToken(String delegateName) {
        ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
        long now = Instant.now().getEpochSecond();
        String subject = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", delegateName);
        TokenWrapper t = TokenWrapper.create()
                .setIssuer("https://kernel.test/oidc")
                .setSubject(subject)
                .setAudience("kernel")
                .setIssuedAt(now)
                .setExpiration(now + 3600)
                .setJTI(UUID.randomUUID().toString());
        t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
        t.sign(signingKey);
        return t.getBase64();
    }

    /** Runs {@code body} with the delegate's bearer token on the gRPC context, as the wire does. */
    private <T> T asDelegate(ThrowingSupplier<T> body) throws Exception {
        io.grpc.Context ctx = io.grpc.Context.current()
                .withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, mintCallerToken(DELEGATE_NAME));
        io.grpc.Context previous = ctx.attach();
        try {
            return body.get();
        } finally {
            ctx.detach(previous);
        }
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private static Struct attackerClaims() {
        return Struct.newBuilder()
                .putFields("iss", Value.newBuilder().setStringValue("https://attacker.example/").build())
                .putFields("email", Value.newBuilder().setStringValue(VICTIM_SUBJECT).build())
                .putFields("groups", Value.newBuilder().setStringValue("admin").build())
                .build();
    }

    // ---- The bypass --------------------------------------------------------

    /**
     * The reproduction. A registered delegate calls the legacy {@code MintToken} with no
     * {@code input_token}, a caller-supplied {@code subject} and caller-supplied claims.
     *
     * <p>Pre-fix this returned a signed user token for {@code victim@example.com} without
     * ever consulting OPA. Post-fix {@code MintToken} refuses: it is an exchange RPC and
     * requires an {@code input_token}.
     */
    @Test
    void legacyDelegationArmNoLongerMintsArbitrarySubjects() throws Exception {
        registerDelegate();
        // If the delegation arm is still live it mints without touching OPA at all, so an
        // OPA client that explodes on use also proves the arm skipped entitlement resolution.
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.neverCalled());

        Tokenrequest.TokenMintRequest request = Tokenrequest.TokenMintRequest.newBuilder()
                .setSubject(VICTIM_SUBJECT)
                .setClaims(attackerClaims())
                .build();

        Tokenrequest.TokenMintResponse minted = null;
        ProtoException refused = null;
        try {
            minted = asDelegate(() -> svc.mintToken(CALLER, request));
        } catch (ProtoException e) {
            refused = e;
        }

        if (minted != null) {
            TokenWrapper token = TokenWrapper.parse(minted.getAccessToken().getBase64());
            fail("BYPASS REPRODUCED: legacy MintToken minted a user token for a caller-supplied"
                    + " subject with no OPA entitlement resolution — sub=" + token.getSubject()
                    + ", azp=" + token.getAzp()
                    + ", groups=" + token.getCustomField("groups"));
        }

        assertNotNull(refused, "expected MintToken to refuse the delegation-shaped request");
        assertEquals(ProtoException.INVALID_ARGUMENT, refused.getCode(),
                "expected INVALID_ARGUMENT, got: " + refused.getMessage());
        assertTrue(refused.getMessage().contains("input_token is required"),
                "expected the missing-input_token refusal, got: " + refused.getMessage());
    }

    // ---- Positive controls -------------------------------------------------

    /** The supported on-behalf-of path still mints, and still runs OPA. */
    @Test
    void mintUserTokenStillMintsForTheSameDelegate() throws Exception {
        registerDelegate();
        FakeOpaEvalGrpcClient opa = FakeOpaEvalGrpcClient.returning(
                Entitlements.TokenEntitlements.newBuilder()
                        .addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
                        .build());
        IdentityServiceImpl svc = newService(opa);

        Tokenrequest.TokenMintResponse resp = asDelegate(() -> svc.mintUserToken(CALLER,
                Tokenrequest.MintUserTokenRequest.newBuilder()
                        .setSubject(VICTIM_SUBJECT)
                        .setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
                        .setClaims(attackerClaims())
                        .build()));

        TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
        assertEquals(VICTIM_SUBJECT, refresh.getSubject());
        assertEquals(DELEGATE_NAME, refresh.getAzp());
        assertTrue(opa.wasInvoked(), "MintUserToken must resolve entitlements via OPA");
    }

    /** MintToken itself is untouched: a kernel-signed token still exchanges. */
    @Test
    void mintTokenStillExchangesAKernelSignedToken() throws Exception {
        registerDelegate();
        FakeOpaEvalGrpcClient opa = FakeOpaEvalGrpcClient.returning(
                Entitlements.TokenEntitlements.newBuilder()
                        .addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
                        .build());
        IdentityServiceImpl svc = newService(opa);

        Tokenrequest.TokenMintResponse minted = asDelegate(() -> svc.mintUserToken(CALLER,
                Tokenrequest.MintUserTokenRequest.newBuilder()
                        .setSubject(VICTIM_SUBJECT)
                        .setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
                        .setClaims(attackerClaims())
                        .build()));
        String refreshToken = minted.getRefreshToken().getBase64();

        Tokenrequest.TokenMintResponse exchanged = svc.mintToken(CALLER,
                Tokenrequest.TokenMintRequest.newBuilder()
                        .setInputToken(refreshToken)
                        .build());

        TokenWrapper access = TokenWrapper.parse(exchanged.getAccessToken().getBase64());
        assertEquals(VICTIM_SUBJECT, access.getSubject());
    }

    // ---- Fakes -------------------------------------------------------------

    /** Copy of {@code MintDelegatedTokenTest}'s fake: the generated client is concrete. */
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
                public Userentitlements.EntitlementEvalResult evalEntitlement(
                        Userentitlements.EntitlementEvalInput request) {
                    throw new AssertionError("OPA client must not be invoked");
                }
            };
        }

        boolean wasInvoked() {
            return invoked;
        }

        @Override
        public Userentitlements.EntitlementEvalResult evalEntitlement(
                Userentitlements.EntitlementEvalInput request) {
            invoked = true;
            // A namespace is not optional: the mint refuses when the policy names
            // no tenant. Which tenant it is does not matter to anything asserted
            // here — same fixture shape as MintDelegatedTokenTest's fake.
            return Userentitlements.EntitlementEvalResult.newBuilder()
                    .setNamespace(ACME_NS)
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
}
