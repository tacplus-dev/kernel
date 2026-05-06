// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass.TokenUse;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.ExternalTokenMint;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.vservices.proxypolicy.Proxypolicy;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.protobuf.ListValue;
import com.google.protobuf.NullValue;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues externally-usable tokens for proxy services to forward to third-party APIs.
 *
 * <p>Validates the user token, evaluates the proxy policy via OPA (which determines
 * whether the request is allowed, may rewrite the destination URL, and may mutate
 * token claims), then mints a fresh token stamped with TOKEN_USE_EXTERNAL.
 *
 * <p>External tokens are categorically rejected by all Cavalier service authorizers,
 * preventing replay attacks where a compromised proxy reuses an external token
 * against internal services.
 */
public class ExternalTokenMintServiceImpl implements ExternalTokenMint.ExternalTokenMintHandler {

    private static final Logger logger = LoggerFactory.getLogger(ExternalTokenMintServiceImpl.class);

    /** Maximum lifetime of an externally-minted token. */
    private static final long EXTERNAL_TOKEN_MAX_TTL_SECONDS = 300;

    /**
     * Cavalier-internal claim key names (all JwtPayloadType names) that must not be
     * copied verbatim from the user token into the external token. Standard JWT
     * fields (iss, sub, aud, exp, iat, jti) are also excluded since they are set
     * explicitly on the new token.
     */
    private static final Set<String> EXCLUDED_CLAIM_KEYS;
    static {
        var keys = new java.util.HashSet<>(Helpers.jwtPayloadTypeValidValues());
        // Also exclude well-known JWT fields set explicitly in the minted token.
        keys.addAll(Set.of("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "typ"));
        EXCLUDED_CLAIM_KEYS = Set.copyOf(keys);
    }

    private static final String TOKEN_USE_EXTERNAL =
            Helpers.tokenUseToString(TokenUse.TOKEN_USE_EXTERNAL);

    private final KeyRotator keyRotator;
    private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
    @Nullable
    private final OpaEvalGrpcClient proxyPolicyOpaClient;

    public ExternalTokenMintServiceImpl(
            KeyRotator keyRotator,
            Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
            @Nullable OpaEvalGrpcClient proxyPolicyOpaClient) {
        this.keyRotator = keyRotator;
        this.verifyingKeysReader = verifyingKeysReader;
        this.proxyPolicyOpaClient = proxyPolicyOpaClient;
    }

    @Override
    public Tokenrequest.ExternalTokenMintResponse mintExternalToken(
            Caller caller, Tokenrequest.ExternalTokenMintRequest request) throws ProtoException {

        String rawToken = request.getUserToken();
        String metadata = request.getMetadata();

        // Parse and verify the user token against kernel's current verifying keys.
        TokenWrapper userToken;
        try {
            userToken = TokenWrapper.parse(rawToken);
        } catch (Exception e) {
            throw ProtoException.newErrMissingInvalidData(null, "invalid user_token: %s", e.getMessage());
        }

        String kid = userToken.getKid();
        if (kid == null || kid.isEmpty()) {
            throw ProtoException.newErrMissingInvalidData(null, "user_token missing kid header");
        }

        ImmutableJwk matchingKey = null;
        for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
            if (kid.equals(jwk.getKid())) {
                matchingKey = ImmutableJwk.from(jwk);
                break;
            }
        }
        if (matchingKey == null) {
            throw ProtoException.newErrPermissionDenied(null,
                    "user_token signed with unknown key: " + kid);
        }

        try {
            userToken.verify(matchingKey);
        } catch (Exception e) {
            throw ProtoException.newErrPermissionDenied(null,
                    "user_token verification failed: " + e.getMessage());
        }

        // Build a Struct from the user token payload to pass to OPA.
        Struct claims = buildClaimsStruct(userToken);

        // Evaluate proxy policy via OPA.
        if (proxyPolicyOpaClient == null) {
            throw ProtoException.newErrGeneral(null,
                    "proxy policy OPA client not configured");
        }

        Proxypolicy.ProxyPolicyEvalResult opaResult;
        try {
            var input = Proxypolicy.ProxyPolicyEvalInput.newBuilder()
                    .setClaims(claims)
                    .setMetadata(metadata)
                    .build();
            opaResult = proxyPolicyOpaClient.evalProxyPolicy(input);
        } catch (Exception e) {
            throw ProtoException.newErrGeneral(null,
                    "proxy policy evaluation failed: " + e.getMessage());
        }

        if (!opaResult.getAllow()) {
            String reason = opaResult.getReason();
            if (reason == null || reason.isEmpty()) {
                reason = "proxy policy denied the request";
            }
            throw ProtoException.newErrPermissionDenied(null, reason);
        }

        // Determine effective audience and destination URL from OPA result.
        String effectiveAud = opaResult.getAud();
        if (effectiveAud == null || effectiveAud.isEmpty()) {
            effectiveAud = userToken.getAudience();
        }
        // resolvedUrl is whatever OPA returned. Empty string is valid — the proxy
        // will fall back to its own DEFAULT_API_ENDPOINT when it receives an empty dst_url.
        String resolvedUrl = opaResult.getUrl();

        // Compute expiry: now + max TTL, capped by user token's own expiry.
        long now = Instant.now().getEpochSecond();
        long userExp = userToken.getExpiration();
        long exp = Math.min(now + EXTERNAL_TOKEN_MAX_TTL_SECONDS, userExp > 0 ? userExp : Long.MAX_VALUE);
        if (exp <= now) {
            throw ProtoException.newErrPermissionDenied(null, "user_token has already expired");
        }

        // Mint a fresh external token.
        TokenWrapper externalToken = TokenWrapper.create()
                .setIssuer(userToken.getIssuer())
                .setSubject(userToken.getSubject())
                .setAudience(effectiveAud)
                .setIssuedAt(now)
                .setExpiration(exp)
                .setJTI(UUID.randomUUID().toString());

        // Stamp token_use = external — categorically rejected by all Cavalier authorizers.
        externalToken.setTokenUse(TOKEN_USE_EXTERNAL);

        // Forward user's non-internal custom claims (e.g. email, name) to the external token.
        for (Map.Entry<String, String> entry : userToken.getProto().getPayloadMap().entrySet()) {
            if (!EXCLUDED_CLAIM_KEYS.contains(entry.getKey())) {
                externalToken.setCustomField(entry.getKey(), entry.getValue());
            }
        }

        // Merge extra_claims from OPA result (add-only, may override forwarded claims).
        Struct extraClaims = opaResult.getExtraClaims();
        if (extraClaims != null) {
            for (Map.Entry<String, Value> entry : extraClaims.getFieldsMap().entrySet()) {
                externalToken.setCustomField(entry.getKey(), valueToString(entry.getValue()));
            }
        }

        // Sign with the current active key.
        ImmutableKey signingKey = keyRotator.getActiveSigningKey();
        if (signingKey == null) {
            throw ProtoException.newErrGeneral(null, "no active signing key");
        }
        externalToken.sign(signingKey);

        var authType = opaResult.getAuthType();
        logger.info("external token minted: caller_req={}, sub={}, aud={}, metadata={}, dst_url={}, auth_type={}",
                caller.getRequestId(), userToken.getSubject(), effectiveAud, metadata, resolvedUrl, authType);

        return Tokenrequest.ExternalTokenMintResponse.newBuilder()
                .setToken(externalToken.getProto())
                .setDstUrl(resolvedUrl)
                .setAuthType(authType)
                .build();
    }

    /**
     * Builds a {@code google.protobuf.Struct} from the user token's payload map,
     * parsing JSON arrays/objects back into structured {@code Value} nodes.
     */
    private static Struct buildClaimsStruct(TokenWrapper token) {
        Struct.Builder builder = Struct.newBuilder();
        for (Map.Entry<String, String> entry : token.getProto().getPayloadMap().entrySet()) {
            String val = entry.getValue();
            Value pv;
            if (val.startsWith("[") || val.startsWith("{")) {
                try {
                    pv = parseJsonValue(val);
                } catch (Exception e) {
                    pv = Value.newBuilder().setStringValue(val).build();
                }
            } else {
                pv = Value.newBuilder().setStringValue(val).build();
            }
            builder.putFields(entry.getKey(), pv);
        }
        return builder.build();
    }

    private static Value parseJsonValue(String json) {
        JsonElement el = JsonParser.parseString(json);
        return jsonElementToProtoValue(el);
    }

    private static Value jsonElementToProtoValue(JsonElement el) {
        if (el.isJsonNull()) {
            return Value.newBuilder().setNullValue(NullValue.NULL_VALUE).build();
        } else if (el.isJsonPrimitive()) {
            var prim = el.getAsJsonPrimitive();
            if (prim.isBoolean()) {
                return Value.newBuilder().setBoolValue(prim.getAsBoolean()).build();
            } else if (prim.isNumber()) {
                return Value.newBuilder().setNumberValue(prim.getAsDouble()).build();
            } else {
                return Value.newBuilder().setStringValue(prim.getAsString()).build();
            }
        } else if (el.isJsonArray()) {
            ListValue.Builder list = ListValue.newBuilder();
            for (JsonElement item : el.getAsJsonArray()) {
                list.addValues(jsonElementToProtoValue(item));
            }
            return Value.newBuilder().setListValue(list).build();
        } else if (el.isJsonObject()) {
            Struct.Builder struct = Struct.newBuilder();
            for (Map.Entry<String, JsonElement> entry : el.getAsJsonObject().entrySet()) {
                struct.putFields(entry.getKey(), jsonElementToProtoValue(entry.getValue()));
            }
            return Value.newBuilder().setStructValue(struct).build();
        }
        return Value.newBuilder().setStringValue(el.toString()).build();
    }

    /**
     * Converts a {@code google.protobuf.Value} to a string suitable for storage
     * in a token payload field. Arrays and objects are JSON-encoded.
     */
    private static String valueToString(Value v) {
        return switch (v.getKindCase()) {
            case STRING_VALUE -> v.getStringValue();
            case BOOL_VALUE   -> Boolean.toString(v.getBoolValue());
            case NUMBER_VALUE -> {
                double d = v.getNumberValue();
                yield d == Math.floor(d) && !Double.isInfinite(d)
                        ? Long.toString((long) d) : Double.toString(d);
            }
            case LIST_VALUE   -> valueToJsonElement(v).toString();
            case STRUCT_VALUE -> valueToJsonElement(v).toString();
            default -> "";
        };
    }

    private static com.google.gson.JsonElement valueToJsonElement(Value v) {
        return switch (v.getKindCase()) {
            case STRING_VALUE -> new com.google.gson.JsonPrimitive(v.getStringValue());
            case BOOL_VALUE   -> new com.google.gson.JsonPrimitive(v.getBoolValue());
            case NUMBER_VALUE -> new com.google.gson.JsonPrimitive(v.getNumberValue());
            case NULL_VALUE   -> com.google.gson.JsonNull.INSTANCE;
            case LIST_VALUE   -> {
                var arr = new com.google.gson.JsonArray();
                for (Value item : v.getListValue().getValuesList()) {
                    arr.add(valueToJsonElement(item));
                }
                yield arr;
            }
            case STRUCT_VALUE -> {
                var obj = new com.google.gson.JsonObject();
                for (Map.Entry<String, Value> e : v.getStructValue().getFieldsMap().entrySet()) {
                    obj.add(e.getKey(), valueToJsonElement(e.getValue()));
                }
                yield obj;
            }
            default -> com.google.gson.JsonNull.INSTANCE;
        };
    }
}
