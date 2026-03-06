// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.entitlement.Entitlement;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.TokenExchangerServiceGrpc;

import com.google.protobuf.ListValue;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;

import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * gRPC service implementing the token exchange protocol.
 *
 * <p>Two exchange phases:
 * <ol>
 *   <li><b>Phase 1 (External → Refresh):</b> Validates an external IdP token
 *       against all known JWKs and mints a refresh token.</li>
 *   <li><b>Phase 2 (Refresh → Service):</b> Validates a refresh token using
 *       exchanger signing keys only, clones claims, sets requested audience,
 *       and signs with active key.</li>
 * </ol>
 */
public class TokenExchangerService extends TokenExchangerServiceGrpc.TokenExchangerServiceImplBase {

    private static final Logger logger = LoggerFactory.getLogger(TokenExchangerService.class);

    /** Standard JWT claims that conflict with ours — these are NOT carried forward as custom claims. */
    private static final Set<String> STANDARD_JWT_CLAIMS = Set.of(
            "sub", "iss", "aud", "exp", "iat", "azp", "nbf", "jti");

    private final Kernel.TokenExchangerConfig config;
    private final String refreshAudience;
    private final long defaultTokenExpirySeconds;
    private final ExternalJwkResolver externalJwkResolver;
    private final KeyRotator keyRotator;
    private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
    private final Supplier<List<JwkOuterClass.CredPair>> credPairsReader;
    private final Supplier<List<Entitlement.ServiceEntitlementMapping>> entitlementMappingsReader;
    private final Supplier<List<Entitlement.ServiceEntitlements>> serviceEntitlementsReader;

    public TokenExchangerService(
            Kernel.TokenExchangerConfig config,
            ExternalJwkResolver externalJwkResolver,
            KeyRotator keyRotator,
            Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
            Supplier<List<JwkOuterClass.CredPair>> credPairsReader,
            Supplier<List<Entitlement.ServiceEntitlementMapping>> entitlementMappingsReader,
            Supplier<List<Entitlement.ServiceEntitlements>> serviceEntitlementsReader) {
        this.config = config;
        this.refreshAudience = config.getRefreshAudience().isEmpty()
                ? "refresh" : config.getRefreshAudience();
        this.defaultTokenExpirySeconds = config.getDefaultTokenExpirySeconds() > 0
                ? config.getDefaultTokenExpirySeconds() : 3600;
        this.externalJwkResolver = externalJwkResolver;
        this.keyRotator = keyRotator;
        this.verifyingKeysReader = verifyingKeysReader;
        this.credPairsReader = credPairsReader;
        this.entitlementMappingsReader = entitlementMappingsReader;
        this.serviceEntitlementsReader = serviceEntitlementsReader;
    }

    @Override
    public void exchangeToken(Kernel.TokenRequest request,
                              StreamObserver<TokenOuterClass.Token> responseObserver) {
        try {
            TokenOuterClass.Token result = doExchange(request);
            responseObserver.onNext(result);
            responseObserver.onCompleted();
        } catch (StatusException e) {
            responseObserver.onError(e.toGrpcStatus().asRuntimeException());
        } catch (Exception e) {
            logger.error("Token exchange failed", e);
            responseObserver.onError(Status.INTERNAL
                    .withDescription("token exchange failed: " + e.getMessage())
                    .asRuntimeException());
        }
    }

    private TokenOuterClass.Token doExchange(Kernel.TokenRequest request) throws StatusException {
        // 1. Input token must not be empty
        if (request.getInputToken().isEmpty()) {
            throw new StatusException(Status.INVALID_ARGUMENT, "input_token is required");
        }

        // 2. Parse input token
        TokenWrapper inputToken;
        try {
            inputToken = TokenWrapper.parse(request.getInputToken());
        } catch (Exception e) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "invalid input_token: " + e.getMessage());
        }

        String inputAud = inputToken.getAudience();

        // Routing: if the input token's audience is already the refresh audience,
        // this is a refresh token being exchanged for a service token (Phase 2).
        // Otherwise it's an external/bootstrap token (Phase 1).
        if (refreshAudience.equals(inputAud)) {
            // Phase 2: Refresh → Service Token
            return exchangeRefreshToService(request, inputToken);
        }

        // Phase 1: External/Bootstrap → Refresh
        return exchangeExternalToRefresh(request, inputToken);
    }

    /**
     * Phase 1: Validates external token against all known JWKs
     * and mints a refresh token.
     *
     * <p>For bootstrap JWTs from CredPair holders: looks up the CredPair by kid,
     * verifies the signature, and derives the subject from the identity mapping.
     * For external IdP tokens: resolves the key via issuer discovery.
     */
    private TokenOuterClass.Token exchangeExternalToRefresh(
            Kernel.TokenRequest request, TokenWrapper inputToken) throws StatusException {

        String kid = inputToken.getKid();
        if (kid.isEmpty()) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "input_token missing kid header");
        }

        // Try CredPair lookup by kid
        JwkOuterClass.CredPair matchedCredPair = null;
        for (JwkOuterClass.CredPair cp : credPairsReader.get()) {
            if (cp.hasPublicKey() && kid.equals(cp.getPublicKey().getKid())) {
                matchedCredPair = cp;
                break;
            }
        }

        if (matchedCredPair != null) {
            // CredPair flow: verify signature with CredPair's public key
            ImmutableJwk verificationKey = ImmutableJwk.from(matchedCredPair.getPublicKey());
            try {
                inputToken.verify(verificationKey);
            } catch (Exception e) {
                throw new StatusException(Status.UNAUTHENTICATED,
                        "bootstrap JWT verification failed: " + e.getMessage());
            }

            // Look up identity mapping by kid → service name
            Entitlement.ServiceEntitlementMapping mapping = findMappingByKid(kid);
            if (mapping == null) {
                throw new StatusException(Status.PERMISSION_DENIED,
                        "no entitlement mapping for kid: " + kid);
            }

            String serviceName = mapping.getService();

            // Derive entitlements from proto descriptors via service entitlements
            Entitlement.ServiceEntitlements entitlements = findEntitlements(serviceName + "-entitlements");
            if (entitlements == null) {
                throw new StatusException(Status.PERMISSION_DENIED,
                        "no service entitlements for: " + serviceName);
            }

            // Instance ID: check for continuity token to preserve instance_id across restarts
            String instanceId;
            if (!request.getContinuityToken().isEmpty()) {
                instanceId = resolveInstanceIdFromContinuityToken(request, serviceName);
            } else {
                instanceId = UUID.randomUUID().toString();
                logger.info("Generated new instance_id={} for sub={}", instanceId, serviceName);
            }

            return mintRefreshToken(serviceName, request, Map.of(
                    "instance_id", instanceId
            ), buildEntitlementsClaim(entitlements));
        }

        // External IdP flow: resolve key via issuer
        String issuer = inputToken.getIssuer();
        ImmutableJwk verificationKey;
        try {
            verificationKey = externalJwkResolver.resolveKey(kid, issuer);
        } catch (ExternalJwkResolver.ResolveException e) {
            throw new StatusException(Status.UNAUTHENTICATED,
                    "failed to resolve key: " + e.getMessage());
        }

        try {
            inputToken.verify(verificationKey);
        } catch (Exception e) {
            throw new StatusException(Status.UNAUTHENTICATED,
                    "input_token verification failed: " + e.getMessage());
        }

        // Use subject from the input token for external IdP flow
        String subject = inputToken.getSubject();

        return mintRefreshToken(subject, request, Map.of(), null);
    }

    /**
     * Mints a new refresh token with the given subject and entitlements.
     * @param entitlementsClaim protobuf Value containing the entitlements map, or null
     */
    private TokenOuterClass.Token mintRefreshToken(
            String subject, Kernel.TokenRequest request,
            Map<String, Object> extraClaims, Value entitlementsClaim) throws StatusException {

        ImmutableKey signingKey = keyRotator.getActiveSigningKey();
        if (signingKey == null) {
            throw new StatusException(Status.UNAVAILABLE, "no active signing key");
        }

        long now = Instant.now().getEpochSecond();
        long exp;
        if (request.getExp() > 0) {
            exp = request.getExp();
        } else {
            exp = now + defaultTokenExpirySeconds;
        }

        TokenWrapper newToken = TokenWrapper.create()
                .setIssuer("token-exchanger")
                .setSubject(subject)
                .setAudience(refreshAudience)
                .setIssuedAt(now)
                .setExpiration(exp)
                .setJTI(UUID.randomUUID().toString());

        // Set azp = "kernel" (kernel is the minter)
        newToken.setCustomField("azp", "kernel");

        // Include extra claims
        for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
            newToken.setCustomField(entry.getKey(), entry.getValue());
        }

        // Inject entitlements (structured map: {service: [rpcs]})
        if (entitlementsClaim != null) {
            newToken.setCustomField("entitlements", entitlementsClaim);
        }

        newToken.sign(signingKey);

        logger.info("Minted refresh token: sub={}, exp={}", subject, exp);
        return newToken.getProto();
    }

    /**
     * Phase 2: Validates refresh token using exchanger signing keys,
     * then takes one of two paths:
     * <ul>
     *   <li><b>S2S</b> (sub = known service name): carries forward instance_id
     *       and scopes entitlements to target service.</li>
     *   <li><b>U2S</b> (sub = "api"): carries forward flat IDP claims.</li>
     * </ul>
     */
    private TokenOuterClass.Token exchangeRefreshToService(
            Kernel.TokenRequest request, TokenWrapper inputToken) throws StatusException {

        // Validate input token using exchanger signing keys ONLY
        String kid = inputToken.getKid();
        if (kid.isEmpty()) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "input_token missing kid header");
        }

        JwkOuterClass.Jwk matchingKey = null;
        for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
            if (kid.equals(jwk.getKid())) {
                matchingKey = jwk;
                break;
            }
        }

        if (matchingKey == null) {
            throw new StatusException(Status.UNAUTHENTICATED,
                    "refresh token signed with unknown key: " + kid);
        }

        ImmutableJwk immJwk = ImmutableJwk.from(matchingKey);
        try {
            inputToken.verify(immJwk);
        } catch (Exception e) {
            throw new StatusException(Status.UNAUTHENTICATED,
                    "refresh token verification failed: " + e.getMessage());
        }

        ImmutableKey signingKey = keyRotator.getActiveSigningKey();
        if (signingKey == null) {
            throw new StatusException(Status.UNAVAILABLE, "no active signing key");
        }

        // Compute expiration
        long inputExp = inputToken.getExpiration();
        long exp;
        if (request.getExp() == 0) {
            exp = inputExp;
        } else if (request.getExp() > inputExp) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "requested exp " + request.getExp()
                            + " exceeds refresh token exp " + inputExp);
        } else {
            exp = request.getExp();
        }

        long now = Instant.now().getEpochSecond();
        String subject = inputToken.getSubject();

        // Build base service token
        TokenWrapper newToken = TokenWrapper.create()
                .setIssuer("token-exchanger")
                .setSubject(subject)
                .setAudience(request.getAud())
                .setIssuedAt(now)
                .setExpiration(exp)
                .setJTI(UUID.randomUUID().toString());

        // Set azp = "kernel" (kernel is the minter)
        newToken.setCustomField("azp", "kernel");

        // Detect S2S vs U2S by checking if sub is "api"
        boolean isU2S = "api".equals(subject);

        if (!isU2S) {
            // S2S path: carry forward instance_id
            if (inputToken.getProto().hasPayload()) {
                Map<String, Value> fields = inputToken.getProto().getPayload().getFieldsMap();
                Value instanceIdVal = fields.get("instance_id");
                if (instanceIdVal != null && instanceIdVal.getKindCase() == Value.KindCase.STRING_VALUE) {
                    newToken.setCustomField("instance_id", instanceIdVal.getStringValue());
                }

                // Scope entitlements from refresh token to the target service
                Value entitlementsVal = fields.get("entitlements");
                if (entitlementsVal != null && entitlementsVal.getKindCase() == Value.KindCase.STRUCT_VALUE) {
                    String targetAud = request.getAud();
                    Struct entMap = entitlementsVal.getStructValue();
                    Value svcEntitlements = entMap.getFieldsOrDefault(targetAud, null);
                    if (svcEntitlements != null) {
                        newToken.setCustomField("entitlements", svcEntitlements);
                    }
                }
            }

            logger.info("Minted service token (S2S): sub={}, aud={}, exp={}",
                    subject, request.getAud(), exp);
        } else {
            // U2S path: carry forward flat IDP claims (origin_ prefixed and others)
            if (inputToken.getProto().hasPayload()) {
                Map<String, Value> fields = inputToken.getProto().getPayload().getFieldsMap();
                for (Map.Entry<String, Value> entry : fields.entrySet()) {
                    String key = entry.getKey();
                    // Skip standard JWT claims — the minter manages those
                    if (STANDARD_JWT_CLAIMS.contains(key)) {
                        continue;
                    }
                    newToken.setCustomField(key, entry.getValue());
                }
            }

            logger.info("Minted service token (U2S): sub={}, aud={}, exp={}",
                    subject, request.getAud(), exp);
        }

        newToken.sign(signingKey);
        return newToken.getProto();
    }

    /**
     * Resolves instance_id from a continuity token during bootstrap exchange.
     * Validates: the continuity token is a valid, non-expired refresh token
     * and shares the same subject as the bootstrap JWT.
     */
    private String resolveInstanceIdFromContinuityToken(
            Kernel.TokenRequest request, String bootstrapSubject) throws StatusException {

        TokenWrapper continuityToken;
        try {
            continuityToken = TokenWrapper.parse(request.getContinuityToken());
        } catch (Exception e) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "invalid continuity_token: " + e.getMessage());
        }

        // Validate: must be a refresh token (audience = refreshAudience)
        if (!refreshAudience.equals(continuityToken.getAudience())) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "continuity_token must be a refresh token (expected aud=" + refreshAudience + ")");
        }

        // Validate: must be signed by exchanger
        String kid = continuityToken.getKid();
        if (kid == null || kid.isEmpty()) {
            throw new StatusException(Status.INVALID_ARGUMENT, "continuity_token missing kid");
        }
        JwkOuterClass.Jwk matchingKey = null;
        for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
            if (kid.equals(jwk.getKid())) {
                matchingKey = jwk;
                break;
            }
        }
        if (matchingKey == null) {
            throw new StatusException(Status.UNAUTHENTICATED,
                    "continuity_token signed with unknown key: " + kid);
        }
        try {
            continuityToken.verify(ImmutableJwk.from(matchingKey));
        } catch (Exception e) {
            throw new StatusException(Status.UNAUTHENTICATED,
                    "continuity_token verification failed: " + e.getMessage());
        }

        // Validate: same subject as bootstrap JWT
        if (!bootstrapSubject.equals(continuityToken.getSubject())) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "continuity_token subject '" + continuityToken.getSubject()
                            + "' does not match bootstrap subject '" + bootstrapSubject + "'");
        }

        // Extract instance_id from continuity token
        Object instanceIdObj = continuityToken.getCustomField("instance_id");
        if (instanceIdObj == null || instanceIdObj.toString().isEmpty()) {
            throw new StatusException(Status.INVALID_ARGUMENT,
                    "continuity_token missing instance_id claim");
        }

        String instanceId = instanceIdObj.toString();
        logger.info("Preserved instance_id={} via continuity token for sub={}",
                instanceId, bootstrapSubject);
        return instanceId;
    }

    /**
     * Finds the entitlement mapping by credential_id (kid).
     */
    private Entitlement.ServiceEntitlementMapping findMappingByKid(String kid) {
        for (Entitlement.ServiceEntitlementMapping m : entitlementMappingsReader.get()) {
            if (kid.equals(m.getCredentialId())) {
                return m;
            }
        }
        return null;
    }

    /**
     * Finds the ServiceEntitlements by its id.
     */
    private Entitlement.ServiceEntitlements findEntitlements(String entitlementsId) {
        for (Entitlement.ServiceEntitlements se : serviceEntitlementsReader.get()) {
            if (entitlementsId.equals(se.getId())) {
                return se;
            }
        }
        return null;
    }

    /**
     * Builds a protobuf Value containing the entitlements map: {service: [rpcs]}.
     */
    private Value buildEntitlementsClaim(Entitlement.ServiceEntitlements entitlements) {
        Struct.Builder entMap = Struct.newBuilder();
        for (Entitlement.ServiceEntitlement ent : entitlements.getEntitlementsList()) {
            ListValue.Builder rpcs = ListValue.newBuilder();
            for (String rpc : ent.getAllowedRpcsList()) {
                rpcs.addValues(Value.newBuilder().setStringValue(rpc).build());
            }
            entMap.putFields(ent.getServiceName(),
                    Value.newBuilder().setListValue(rpcs.build()).build());
        }
        return Value.newBuilder().setStructValue(entMap.build()).build();
    }

    /**
     * Internal exception carrying a gRPC status.
     */
    private static final class StatusException extends Exception {
        private final Status status;

        StatusException(Status status, String message) {
            super(message);
            this.status = status;
        }

        Status toGrpcStatus() {
            return status.withDescription(getMessage());
        }
    }
}
