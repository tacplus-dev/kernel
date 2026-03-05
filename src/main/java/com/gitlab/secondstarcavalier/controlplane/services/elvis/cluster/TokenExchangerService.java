// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.elvis.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.libs.entitlement.Entitlement;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.services.elvis.Elvis;
import com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.services.elvis.TokenExchangerServiceGrpc;

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
import java.util.UUID;
import java.util.function.Supplier;

import static com.gitlab.secondstarcavalier.controlplane.services.elvis.tacplus.types.libs.entitlement.Helpers.subjectTypeToString;

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

    private final Elvis.TokenExchangerConfig config;
    private final String refreshAudience;
    private final long defaultTokenExpirySeconds;
    private final ExternalJwkResolver externalJwkResolver;
    private final KeyRotator keyRotator;
    private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
    private final Supplier<List<JwkOuterClass.CredPair>> credPairsReader;
    private final Supplier<List<Entitlement.ServiceEntitlementMapping>> entitlementMappingsReader;
    private final Supplier<List<Entitlement.ServiceEntitlements>> serviceEntitlementsReader;

    public TokenExchangerService(
            Elvis.TokenExchangerConfig config,
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
    public void exchangeToken(Elvis.TokenRequest request,
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

    private TokenOuterClass.Token doExchange(Elvis.TokenRequest request) throws StatusException {
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

        String requestedAud = request.getAud();
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
     * verifies the signature, and derives the subject from the CredPair identity.
     * For external IdP tokens: resolves the key via issuer discovery.
     */
    private TokenOuterClass.Token exchangeExternalToRefresh(
            Elvis.TokenRequest request, TokenWrapper inputToken) throws StatusException {

        // 3a. Validate input token — try CredPair lookup first, then external resolver
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

            // Look up entitlement mapping for this CredPair principal
            Entitlement.ServiceEntitlementMapping mapping = findMapping(matchedCredPair.getPrincipal());
            if (mapping == null) {
                throw new StatusException(Status.PERMISSION_DENIED,
                        "no entitlement mapping for principal: " + matchedCredPair.getPrincipal());
            }

            // Resolve the ServiceEntitlements by ID
            Entitlement.ServiceEntitlements entitlements = findEntitlements(mapping.getEntitlementsId());
            if (entitlements == null) {
                throw new StatusException(Status.PERMISSION_DENIED,
                        "no service entitlements for id: " + mapping.getEntitlementsId());
            }

            // Derive subject from mapping's subject_type + principal
            String subjectPrefix = subjectTypeToString(mapping.getSubjectType());
            String subject = subjectPrefix + ":" + mapping.getPrincipal();

            // Instance ID: check for continuity token to preserve instance_id across restarts
            String instanceId;
            if (!request.getContinuityToken().isEmpty()) {
                instanceId = resolveInstanceIdFromContinuityToken(request, subject);
            } else {
                instanceId = UUID.randomUUID().toString();
                logger.info("Generated new instance_id={} for sub={}", instanceId, subject);
            }

            return mintRefreshToken(subject, request, Map.of(
                    "subject_type", subjectPrefix,
                    "principal", mapping.getPrincipal(),
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
        // External IdP tokens don't use CredPair entitlements — IronMaiden resolves
        // entitlements via OPA for these tokens independently.
        String subject = inputToken.getSubject();

        return mintRefreshToken(subject, request, Map.of(), null);
    }

    /**
     * Mints a new refresh token with the given subject and entitlements.
     * @param entitlementsClaim protobuf Value containing the entitlements map, or null
     */
    private TokenOuterClass.Token mintRefreshToken(
            String subject, Elvis.TokenRequest request,
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
     *   <li><b>CredPair-origin</b> (detected by {@code subject_type} claim):
     *       copies {@code subject_type} and {@code principal} into service token.</li>
     *   <li><b>External-origin</b> (no {@code subject_type} claim):
     *       carries forward the {@code origin} claim map.</li>
     * </ul>
     */
    private TokenOuterClass.Token exchangeRefreshToService(
            Elvis.TokenRequest request, TokenWrapper inputToken) throws StatusException {

        // 6a. Validate input token using exchanger signing keys ONLY
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

        // 6b-c. Compute expiration
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

        // 6d. Build base service token
        TokenWrapper newToken = TokenWrapper.create()
                .setIssuer("token-exchanger")
                .setSubject(inputToken.getSubject())
                .setAudience(request.getAud())
                .setIssuedAt(now)
                .setExpiration(exp)
                .setJTI(UUID.randomUUID().toString());

        // 6e. Detect CredPair vs External origin and populate claims
        boolean isCredPairOrigin = false;
        if (inputToken.getProto().hasPayload()) {
            isCredPairOrigin = inputToken.getProto().getPayload()
                    .containsFields("subject_type");
        }

        if (isCredPairOrigin) {
            // CredPair path: copy subject_type, principal, and instance_id — no OPA
            Map<String, Value> fields = inputToken.getProto().getPayload().getFieldsMap();
            Value subjectTypeVal = fields.get("subject_type");
            if (subjectTypeVal != null && subjectTypeVal.getKindCase() == Value.KindCase.STRING_VALUE) {
                newToken.setCustomField("subject_type", subjectTypeVal.getStringValue());
            }
            Value principalVal = fields.get("principal");
            if (principalVal != null && principalVal.getKindCase() == Value.KindCase.STRING_VALUE) {
                newToken.setCustomField("principal", principalVal.getStringValue());
            }
            // Propagate instance_id from refresh token to service token
            Value instanceIdVal = fields.get("instance_id");
            if (instanceIdVal != null && instanceIdVal.getKindCase() == Value.KindCase.STRING_VALUE) {
                newToken.setCustomField("instance_id", instanceIdVal.getStringValue());
            }

            // Scope entitlements from refresh token to the target service.
            // If no entitlements exist for the target audience, the service token
            // is issued without entitlements — authorization is enforced by
            // SecurityInterceptor graph policies, not by entitlements.
            Value entitlementsVal = fields.get("entitlements");
            if (entitlementsVal != null && entitlementsVal.getKindCase() == Value.KindCase.STRUCT_VALUE) {
                String targetAud = request.getAud();
                Struct entMap = entitlementsVal.getStructValue();
                Value svcEntitlements = entMap.getFieldsOrDefault(targetAud, null);
                if (svcEntitlements != null) {
                    // Set as flat list for the access token
                    newToken.setCustomField("entitlements", svcEntitlements);
                }
            }

            logger.info("Minted service token (CredPair): sub={}, aud={}, exp={}, instance_id={}",
                    inputToken.getSubject(), request.getAud(), exp,
                    instanceIdVal != null ? instanceIdVal.getStringValue() : "none");
        } else {
            // External path: carry forward the "origin" claim map as-is
            if (inputToken.getProto().hasPayload()) {
                Value originVal = inputToken.getProto().getPayload().getFieldsOrDefault("origin", null);
                if (originVal != null) {
                    newToken.setCustomField("origin", originVal);
                }
            }

            logger.info("Minted service token (External): sub={}, aud={}, exp={}",
                    inputToken.getSubject(), request.getAud(), exp);
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
            Elvis.TokenRequest request, String bootstrapSubject) throws StatusException {

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
     * Finds the entitlement mapping for the given principal.
     * CredPair principals are matched as "local:<principal>".
     */
    private Entitlement.ServiceEntitlementMapping findMapping(String principal) {
        String localId = "local:" + principal;
        for (Entitlement.ServiceEntitlementMapping m : entitlementMappingsReader.get()) {
            if (localId.equals(m.getStringId())) {
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
