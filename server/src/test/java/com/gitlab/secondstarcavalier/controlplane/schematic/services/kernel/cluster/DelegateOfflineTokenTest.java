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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test matrix for runtime delegation (token-management item 2): the user mints a
 * delegate-bound Offline Token with {@code MintDelegateOfflineToken} and gets
 * back ONLY a one-time code, and the delegate exchanges that code for the
 * withheld token with {@code BrokerDelegateOfflineToken}.
 *
 * <p>Covers the happy path, the identity boundary (the code alone buys nothing),
 * the code's TTL, single-use burn, and the narrow-only request scope.
 * Runs entirely against a {@link FakeOpaEvalGrpcClient} — no real UncleOPA.
 */
class DelegateOfflineTokenTest {

    private static final String TRUST_DOMAIN = "test.schematic.io";
    private static final String KERNEL_AUDIENCE = "schematic-kernel";
    private static final String DELEGATE_NAME = "scotty";
    private static final String OTHER_DELEGATE_NAME = "oauth";
    // A tenant-owned service: N delegates share this name, one per tenant.
    private static final String TENANT_DELEGATE_NAME = "docmanager";
    private static final String ACME_NS = "/tenants/acme";
    private static final String USER_SUBJECT = "alice@example.com";
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
                updated -> { },  // grantsWriter — unused here
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

    /** Registers a delegate rooted at {@code tenantNamespace} ("" = /system). */
    private void addDelegate(String tenantNamespace, String name) {
        delegates.add(Kernel.Delegate.newBuilder()
                .setName(name)
                .setTenantNamespace(tenantNamespace)
                .build());
    }

    /** The USER's own bearer token — the credential the mint half authenticates. */
    private String mintUserToken() {
        ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
        long now = Instant.now().getEpochSecond();
        TokenWrapper t = TokenWrapper.create()
                .setIssuer("https://kernel.test/oidc")
                .setSubject(USER_SUBJECT)
                .setAudience("kernel")
                .setIssuedAt(now)
                .setExpiration(now + 3600)
                .setJTI(UUID.randomUUID().toString());
        // A user token carries the tenant subtree its IdP maps to; the same one
        // this suite's fake OPA names, since kernel re-resolves it on the mint.
        t.setNamespace(ACME_NS);
        t.sign(signingKey);
        return t.getBase64();
    }

    /** The DELEGATE's own S2S token — the credential the redeem half authenticates. */
    private String mintDelegateToken(String tenantNamespace, String delegateName) {
        ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
        long now = Instant.now().getEpochSecond();
        String subject = tenantNamespace.isEmpty()
                ? Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", delegateName)
                : Spiffe.namespaceSpiffeId(TRUST_DOMAIN, tenantNamespace)
                        + "/" + Spiffe.SERVICES_SEGMENT + "/" + delegateName;
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

    private Tokenrequest.MintDelegateOfflineTokenResponse mintCodeFor(IdentityServiceImpl svc,
            String delegateNamespace, String delegateName, Entitlements.TokenEntitlements requestScope)
            throws Exception {
        Tokenrequest.MintDelegateOfflineTokenRequest.Builder req =
                Tokenrequest.MintDelegateOfflineTokenRequest.newBuilder()
                        .setDelegateName(delegateName)
                        .setDelegateNamespace(delegateNamespace);
        if (requestScope != null) {
            req.setScope(requestScope);
        }
        io.grpc.Context ctx = io.grpc.Context.current()
                .withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, mintUserToken());
        io.grpc.Context previous = ctx.attach();
        try {
            return svc.mintDelegateOfflineToken(CALLER, req.build());
        } finally {
            ctx.detach(previous);
        }
    }

    private Tokenrequest.RedeemDelegateOfflineTokenResponse redeemAs(IdentityServiceImpl svc,
            String tenantNamespace, String delegateName, String code) throws Exception {
        io.grpc.Context ctx = io.grpc.Context.current()
                .withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, mintDelegateToken(tenantNamespace, delegateName));
        io.grpc.Context previous = ctx.attach();
        try {
            return svc.brokerDelegateOfflineToken(CALLER,
                    Tokenrequest.RedeemDelegateOfflineTokenRequest.newBuilder().setCode(code).build());
        } finally {
            ctx.detach(previous);
        }
    }

    private static int codeOf(Executable e) {
        ProtoException ex = assertThrows(ProtoException.class, e::run);
        return ex.getCode();
    }

    @FunctionalInterface
    private interface Executable {
        void run() throws Exception;
    }

    private static Entitlements.TokenEntitlements scope(List<String> grantTokens) {
        return Entitlements.TokenEntitlements.newBuilder().addAllGrants(grantTokens).build();
    }

    /** Ages the entry filed under {@code code} so its TTL has already run out. */
    private static void expireCode(IdentityServiceImpl svc, String code) {
        IdentityServiceImpl.WithheldOfflineToken held = svc.withheldOfflineTokens.get(code);
        assertNotNull(held, "precondition: the code must be held before it can be aged");
        svc.withheldOfflineTokens.put(code, new IdentityServiceImpl.WithheldOfflineToken(
                held.token, held.act, Instant.now().toEpochMilli() - 1));
    }

    /** A minimal fake OpaEvalGrpcClient — see MintDelegatedTokenTest for the shape. */
    private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
        private final Entitlements.TokenEntitlements toReturn;

        FakeOpaEvalGrpcClient(Entitlements.TokenEntitlements toReturn) {
            super(UNUSABLE_CHANNEL, () -> "unused-token");
            this.toReturn = toReturn;
        }

        static FakeOpaEvalGrpcClient returning(Entitlements.TokenEntitlements toReturn) {
            return new FakeOpaEvalGrpcClient(toReturn);
        }

        @Override
        public Userentitlements.EntitlementEvalResult evalEntitlement(Userentitlements.EntitlementEvalInput request) {
            // A namespace is not optional: the mint refuses when the policy names
            // no tenant (requireNamespaceFromOpa). Which tenant it is does not
            // matter to anything asserted here.
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

    private static FakeOpaEvalGrpcClient permissiveOpa() {
        return FakeOpaEvalGrpcClient.returning(scope(List.of("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")));
    }

    // ---- Tests -------------------------------------------------------------

    @Test
    void positivePath_codeRedeemsToTheWithheldOfflineToken() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        addDelegate("", DELEGATE_NAME);

        Tokenrequest.MintDelegateOfflineTokenResponse minted = mintCodeFor(svc, "", DELEGATE_NAME, null);

        // The user gets a code and nothing else — the OT never transits their client.
        assertTrue(minted.getCode().length() >= 64, "code must clear the proto's min size");
        assertTrue(minted.getExpiresAtMs() > Instant.now().toEpochMilli());

        Tokenrequest.RedeemDelegateOfflineTokenResponse redeemed =
                redeemAs(svc, "", DELEGATE_NAME, minted.getCode());

        TokenWrapper ot = TokenWrapper.parse(redeemed.getToken().getBase64());
        assertEquals(USER_SUBJECT, ot.getSubject());
        assertEquals(DELEGATE_NAME, ot.getAct(), "act is the bare delegate name");
        assertEquals("kernel", ot.getAzp());
        assertEquals("offline", ot.getTokenUse(), "the withheld credential is an Offline Token");
    }

    @Test
    void unknownDelegateIsRefused() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        // No delegate registered at all.

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> mintCodeFor(svc, "", DELEGATE_NAME, null)));
    }

    @Test
    void aDelegateOfTheSameNameInAnotherTenantIsADifferentDelegate() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        addDelegate(ACME_NS, TENANT_DELEGATE_NAME);

        // The /system delegate of that name does not exist...
        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> mintCodeFor(svc, "", TENANT_DELEGATE_NAME, null)));
        // ...the tenant's one does.
        assertNotNull(mintCodeFor(svc, ACME_NS, TENANT_DELEGATE_NAME, null).getCode());
    }

    @Test
    void theWrongDelegateCannotRedeem() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        addDelegate("", DELEGATE_NAME);
        addDelegate("", OTHER_DELEGATE_NAME);

        String code = mintCodeFor(svc, "", DELEGATE_NAME, null).getCode();

        // Holding the code is not enough: the redeeming identity must BE the
        // delegate the OT was minted for.
        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> redeemAs(svc, "", OTHER_DELEGATE_NAME, code)));

        // Positive control: a refused attempt does not burn the code.
        assertNotNull(redeemAs(svc, "", DELEGATE_NAME, code).getToken());
    }

    @Test
    void anExpiredCodeIsRefused() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        addDelegate("", DELEGATE_NAME);

        String code = mintCodeFor(svc, "", DELEGATE_NAME, null).getCode();
        expireCode(svc, code);

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> redeemAs(svc, "", DELEGATE_NAME, code)));
        assertFalse(svc.withheldOfflineTokens.containsKey(code),
                "a dead entry is dropped on the way past, not left to the next sweep");
    }

    @Test
    void aCodeIsSingleUse() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        addDelegate("", DELEGATE_NAME);

        String code = mintCodeFor(svc, "", DELEGATE_NAME, null).getCode();

        assertNotNull(redeemAs(svc, "", DELEGATE_NAME, code).getToken());
        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> redeemAs(svc, "", DELEGATE_NAME, code)),
                "the second redemption of a burned code must be refused");
    }

    @Test
    void anUnknownCodeIsRefused() throws Exception {
        IdentityServiceImpl svc = newService(permissiveOpa());
        addDelegate("", DELEGATE_NAME);

        assertEquals(ProtoException.PERMISSION_DENIED,
                codeOf(() -> redeemAs(svc, "", DELEGATE_NAME, "no-such-code")));
    }

    @Test
    void requestScopeNarrowsAndCannotWiden() throws Exception {
        // The user's live authority is two grants...
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.returning(scope(List.of(
                "KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG", "KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"))));
        addDelegate("", DELEGATE_NAME);

        // ...and they delegate one of them, plus one they do not hold. The mint
        // intersects: the held-and-asked-for grant survives, the other two do not.
        String code = mintCodeFor(svc, "", DELEGATE_NAME, scope(List.of(
                "KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG", "KERNEL_MINT_MINT_WORKLOAD"))).getCode();

        TokenWrapper ot = TokenWrapper.parse(
                redeemAs(svc, "", DELEGATE_NAME, code).getToken().getBase64());
        String entitlementsJson = ot.getCustomField("service_entitlements");
        assertNotNull(entitlementsJson);
        assertTrue(entitlementsJson.contains("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"));
        assertFalse(entitlementsJson.contains("KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"),
                "a grant the user holds but did not delegate must be excluded");
        assertFalse(entitlementsJson.contains("KERNEL_MINT_MINT_WORKLOAD"),
                "the request scope can only narrow — it must never add authority");
    }

    @Test
    void noRequestScopeMeansTheUsersFullCurrentAuthority() throws Exception {
        IdentityServiceImpl svc = newService(FakeOpaEvalGrpcClient.returning(scope(List.of(
                "KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG", "KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"))));
        addDelegate("", DELEGATE_NAME);

        String code = mintCodeFor(svc, "", DELEGATE_NAME, null).getCode();

        TokenWrapper ot = TokenWrapper.parse(
                redeemAs(svc, "", DELEGATE_NAME, code).getToken().getBase64());
        String entitlementsJson = ot.getCustomField("service_entitlements");
        assertTrue(entitlementsJson.contains("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG"));
        assertTrue(entitlementsJson.contains("KERNEL_TENANT_ADMIN_GET_PROJECT_CONFIG"));
    }
}
