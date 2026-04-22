// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass.JwtPayloadType;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass.TokenUse;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass.SubType;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.MintGrpc;
import com.google.protobuf.Value;
import com.google.gson.Gson;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kernel's identity authority — mints JWT tokens and signs X.509 certificates.
 *
 * <p>Implements two RPCs:
 * <ul>
 * <li><b>TokenMint:</b> mints signed JWTs. Handles both direct credential
 * exchange (delegate presents cred_pair JWT) and delegation (broker
 * authenticates via header, mints on behalf).</li>
 * <li><b>X509Mint:</b> signs X.509 certificates under per-service intermediate CAs.
 * Authenticates caller via bearer token, creates an intermediate CA per
 * service (signed by root CA, pathlen:0), signs the caller-provided public
 * key, and returns an X509CertChain (leaf + intermediate). Provides
 * per-service trust isolation.</li>
 * </ul>
 */
public class IdentityServiceImpl extends MintGrpc.MintImplBase {

	private static final Logger logger = LoggerFactory.getLogger(IdentityServiceImpl.class);

	// Standard Cavalier claims — all proto-defined JwtPayloadType values plus "typ".
	// External IdP claims with these names get origin_ prefixed to avoid collision.
	private static final Set<String> STANDARD_JWT_CLAIMS;
	static {
		var claims = new java.util.HashSet<>(Helpers.jwtPayloadTypeValidValues());
		claims.add("typ");
		STANDARD_JWT_CLAIMS = Set.copyOf(claims);
	}

	// Claims from external IdPs that get origin_ prefix to avoid collision with Cavalier claims.
	private static final Set<String> WELL_KNOWN_JWT_CLAIMS = Set.of(
			"iss", "sub", "aud", "exp", "nbf", "iat", "jti");

	// Legacy typ claim value — kept for backwards compatibility during rollout.
	private static final String TOKEN_TYPE_REFRESH = Helpers.tokenUseToString(TokenUse.TOKEN_USE_REFRESH);

	// Claim values — derived from proto-defined enums.
	private static final String TOKEN_USE_REFRESH = Helpers.tokenUseToString(TokenUse.TOKEN_USE_REFRESH);
	private static final String TOKEN_USE_ACCESS = Helpers.tokenUseToString(TokenUse.TOKEN_USE_ACCESS);
	private static final String TOKEN_USE_SERVICE = Helpers.tokenUseToString(TokenUse.TOKEN_USE_SERVICE);
	private static final String TOKEN_USE_BOOTSTRAP = Helpers.tokenUseToString(TokenUse.TOKEN_USE_BOOTSTRAP);
	private static final String SUB_TYPE_SERVICE = Helpers.subTypeToString(SubType.SUB_TYPE_SERVICE);
	private static final String SUB_TYPE_USER = Helpers.subTypeToString(SubType.SUB_TYPE_USER);

	// Claim names — derived from proto-defined JwtPayloadType enum.
	private static final String TERMINAL = Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_TERMINAL);
	// TODO: Replace with Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_PARENT_SUB)
	// after tacplus is rebuilt with the renamed token.proto enum value.
	private static final String PARENT_SUB = "parent_sub";
	private static final String LOCALITY = Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_LOCALITY);
	private static final String SERVICE_ENTITLEMENTS = Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_SERVICE_ENTITLEMENTS);

	private static final Pattern WORKLOAD_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_-]+");

	private static final Gson GSON = new Gson();

	/** Intermediate CA lifetime: 10 years. */
	private static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	private static final long DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 2592000; // 30 days

	private final long defaultTokenExpirySeconds;
	private final long maxTokenLifetimeSeconds;
	private final ExternalJwkResolver externalJwkResolver;
	private final KeyRotator keyRotator;
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	private final Supplier<List<Kernel.Delegate>> delegatesReader;
	private final Map<String, List<String>> serviceEntitlements;
	private final ImmutableCertChain signingCa;
	private final Function<String, X509.X509CertChain> serviceCaReader;
	private final BiConsumer<String, X509.X509CertChain> serviceCaWriter;
	private final Supplier<String> spiffePrefixReader;
	private final String tokenIssuer;
	@Nullable
	private final OpaEvalGrpcClient opaEvalClient;

	public IdentityServiceImpl(
			long defaultTokenExpirySeconds,
			long maxTokenLifetimeSeconds,
			ExternalJwkResolver externalJwkResolver,
			KeyRotator keyRotator,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			Supplier<List<Kernel.Delegate>> delegatesReader,
			Map<String, List<String>> serviceEntitlements,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter,
			Supplier<String> spiffePrefixReader,
			String tokenIssuer,
			@Nullable OpaEvalGrpcClient opaEvalClient) {
		this.defaultTokenExpirySeconds = defaultTokenExpirySeconds > 0 ? defaultTokenExpirySeconds : 3600;
		this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds > 0 ? maxTokenLifetimeSeconds : DEFAULT_MAX_TOKEN_LIFETIME_SECONDS;
		this.externalJwkResolver = externalJwkResolver;
		this.keyRotator = keyRotator;
		this.verifyingKeysReader = verifyingKeysReader;
		this.delegatesReader = delegatesReader;
		this.serviceEntitlements = serviceEntitlements != null ? serviceEntitlements : Map.of();
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
		this.spiffePrefixReader = spiffePrefixReader;
		this.tokenIssuer = (tokenIssuer != null && !tokenIssuer.isEmpty()) ? tokenIssuer : Kernel.getDescriptor().getPackage();
		this.opaEvalClient = opaEvalClient;
	}

	// ========================================================================
	// TokenMint RPC (legacy — delegates to doTokenMint)
	// ========================================================================

	@Override
	public void tokenMint(Tokenrequest.TokenMintRequest request,
			StreamObserver<Tokenrequest.TokenMintResponse> responseObserver) {
		try {
			Tokenrequest.TokenMintResponse result = doTokenMint(request);
			responseObserver.onNext(result);
			responseObserver.onCompleted();
		} catch (StatusException e) {
			responseObserver.onError(e.toGrpcStatus().asRuntimeException());
		} catch (Exception e) {
			logger.error("TokenMint failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("token mint failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	// ========================================================================
	// MintServiceToken RPC (S2S bootstrap — replaces TokenMint for S2S)
	// ========================================================================

	@Override
	public void mintServiceToken(Tokenrequest.MintServiceTokenRequest request,
			StreamObserver<Tokenrequest.TokenMintResponse> responseObserver) {
		try {
			// S2S fields map 1:1 — convert to legacy request and delegate.
			Tokenrequest.TokenMintRequest legacyRequest = Tokenrequest.TokenMintRequest.newBuilder()
					.setInputToken(request.getInputToken())
					.setCloudProof(request.getCloudProof())
					.setContinuityToken(request.getContinuityToken())
					.setAud(request.getAud())
					.setExp(request.getExp())
					.setTokenPurpose(request.getTokenPurpose())
					.setLocalityToken(request.getLocalityToken())
					.build();
			Tokenrequest.TokenMintResponse result = doTokenMint(legacyRequest);
			responseObserver.onNext(result);
			responseObserver.onCompleted();
		} catch (StatusException e) {
			responseObserver.onError(e.toGrpcStatus().asRuntimeException());
		} catch (Exception e) {
			logger.error("MintServiceToken failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("service token mint failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	// ========================================================================
	// MintUserToken RPC (C2S delegation — replaces TokenMint delegation path)
	// ========================================================================

	@Override
	public void mintUserToken(Tokenrequest.MintUserTokenRequest request,
			StreamObserver<Tokenrequest.TokenMintResponse> responseObserver) {
		try {
			Tokenrequest.TokenMintResponse result = doMintUserToken(request);
			responseObserver.onNext(result);
			responseObserver.onCompleted();
		} catch (StatusException e) {
			responseObserver.onError(e.toGrpcStatus().asRuntimeException());
		} catch (Exception e) {
			logger.error("MintUserToken failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("user token mint failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	/**
	 * C2S delegation: a trusted broker (e.g. OAuth) authenticates via its service token
	 * in the header and requests a token on behalf of a user. Kernel calls UncleOPA to
	 * resolve user claims into entitlement profiles — the broker does not determine
	 * authorization.
	 */
	private Tokenrequest.TokenMintResponse doMintUserToken(Tokenrequest.MintUserTokenRequest request)
			throws StatusException {

		// Authenticate the calling broker via its bearer token.
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"MintUserToken requires authorization header");
		}

		TokenWrapper callerToken;
		try {
			callerToken = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"invalid caller token: " + e.getMessage());
		}

		String kid = callerToken.getKid();
		if (kid == null || kid.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token missing kid");
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
					"caller token signed with unknown key: " + kid);
		}

		try {
			callerToken.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"caller token verification failed: " + e.getMessage());
		}

		// Caller must be a known delegate.
		String callerSub = callerToken.getSubject();
		Kernel.Delegate delegate = findDelegateByName(callerSub);
		if (delegate == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"caller " + callerSub + " is not a registered delegate");
		}

		// Resolve entitlements via UncleOPA.
		Userentitlements.EntitlementEvalResult opaResult = resolveEntitlementsViaOpa(request.getClaims(), request.getTraceId());
		Entitlements.TokenEntitlements expanded = expandEntitlements(opaResult);

		// Mint the token.
		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long maxExp = now + maxTokenLifetimeSeconds;
		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		} else {
			exp = now + defaultTokenExpirySeconds;
		}

		// Always mint refresh + access for C2S (user tokens are always refresh-based).
		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(request.getSubject())
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		// azp = delegate name (not SPIFFE URI) — must match TokenEntitlements.azp entries.
		newToken.setAzp(delegate.getName());
		newToken.setTokenUse(TOKEN_USE_REFRESH);
		newToken.setCustomField("typ", TOKEN_TYPE_REFRESH); // backwards compat
		newToken.setSubType(SUB_TYPE_USER);

		// Set expanded service_entitlements claim (typed TokenEntitlements).
		newToken.setServiceEntitlements(expanded);

		// Forward custom claims from the request (e.g., IDP claims like email, name).
		if (request.hasClaims()) {
			for (Map.Entry<String, Value> entry : request.getClaims().getFieldsMap().entrySet()) {
				String key = entry.getKey();
				if (STANDARD_JWT_CLAIMS.contains(key)) {
					continue;
				}
				String outputKey = WELL_KNOWN_JWT_CLAIMS.contains(key) ? "origin_" + key : key;
				Value val = entry.getValue();
				if (val.hasStringValue()) {
					newToken.setCustomField(outputKey, val.getStringValue());
				} else if (val.hasNumberValue()) {
					newToken.setCustomField(outputKey, Long.toString((long) val.getNumberValue()));
				} else if (val.hasBoolValue()) {
					newToken.setCustomField(outputKey, Boolean.toString(val.getBoolValue()));
				} else {
					newToken.setCustomField(outputKey, val.toString());
				}
			}
		}

		// Inject delegate's static custom claims.
		for (Map.Entry<String, String> entry : delegate.getCustomClaimsMap().entrySet()) {
			if (!STANDARD_JWT_CLAIMS.contains(entry.getKey())) {
				newToken.setCustomField(entry.getKey(), entry.getValue());
			}
		}

		newToken.sign(signingKey);

		logger.info("MintUserToken: sub={}, azp={}, exp={}, service_entitlements={}",
				request.getSubject(), delegate.getName(), exp,
				newToken.getServiceEntitlements());

		// Also mint an access token.
		TokenOuterClass.Token accessProto = mintAccessFromRefresh(newToken, signingKey, now, exp);
		return Tokenrequest.TokenMintResponse.newBuilder()
				.setRefreshToken(newToken.getProto())
				.setAccessToken(accessProto)
				.build();
	}

	/**
	 * Resolves user claims into entitlements via UncleOPA.
	 * Returns the raw EntitlementEvalResult (grant_all flags + explicit entitlements).
	 * Throws UNAVAILABLE if OPA evaluation fails.
	 */
	private Userentitlements.EntitlementEvalResult resolveEntitlementsViaOpa(
			com.google.protobuf.Struct claims, String traceId) throws StatusException {
		if (opaEvalClient == null) {
			throw new StatusException(Status.UNAVAILABLE,
					"UncleOPA client not configured — cannot resolve entitlements");
		}

		Map<String, String> claimsMap = new LinkedHashMap<>();
		if (claims != null) {
			for (Map.Entry<String, Value> entry : claims.getFieldsMap().entrySet()) {
				Value val = entry.getValue();
				if (val.hasStringValue()) {
					claimsMap.put(entry.getKey(), val.getStringValue());
				} else if (val.hasNumberValue()) {
					claimsMap.put(entry.getKey(), Long.toString((long) val.getNumberValue()));
				} else if (val.hasBoolValue()) {
					claimsMap.put(entry.getKey(), Boolean.toString(val.getBoolValue()));
				}
			}
		}

		try {
			var inputBuilder = Userentitlements.EntitlementEvalInput.newBuilder()
					.putAllClaims(claimsMap);
			// Propagate trace_id so uncleopa appears in trace tail.
			if (traceId != null && !traceId.isEmpty()) {
				inputBuilder.setTraceId(traceId);
			}
			return opaEvalClient.evalEntitlement(inputBuilder.build());
		} catch (Exception e) {
			logger.error("UncleOPA EvalEntitlement failed", e);
			throw new StatusException(Status.UNAVAILABLE,
					"entitlement evaluation failed: " + e.getMessage());
		}
	}

	/**
	 * Extracts the TokenEntitlements returned directly by OPA.
	 * OPA is responsible for all entitlement expansion — kernel embeds the
	 * result as-is in the JWT service_entitlements claim.
	 */
	private static Entitlements.TokenEntitlements expandEntitlements(
			Userentitlements.EntitlementEvalResult result) {
		return result.getTokenEntitlements();
	}

	private Tokenrequest.TokenMintResponse doTokenMint(Tokenrequest.TokenMintRequest request) throws StatusException {
		if (request.getInputToken().isEmpty()) {
			// Delegation path: caller authenticates via header, mints on behalf.
			if (request.getSubject().isEmpty()) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"input_token or subject is required");
			}
			return delegationMint(request);
		}

		TokenWrapper inputToken;
		try {
			inputToken = TokenWrapper.parse(request.getInputToken());
		} catch (Exception e) {
			throw new StatusException(Status.INVALID_ARGUMENT, "invalid input_token: " + e.getMessage());
		}

		// Route by token origin:
		// 1. CredPair tokens (throwaway JWTs signed by a delegate's key) go to
		//    the bootstrap path which generates instance_id and refresh tokens.
		// 2. Kernel-signed tokens go to the exchange path.
		// 3. Everything else (external IDP tokens) goes to the bootstrap path.
		//
		// CredPair keys must be checked BEFORE verifying keys because CredPair
		// public keys are also in the verifying keys view (for JWT verification
		// by other services). Without this ordering, CredPair throwaway JWTs
		// would match a verifying key and incorrectly route to exchangeKernelToken.
		String kid = inputToken.getKid();
		if (!kid.isEmpty()) {
			for (Kernel.Delegate delegate : delegatesReader.get()) {
				for (JwkOuterClass.Jwk jwk : delegate.getCredPairsList()) {
					if (kid.equals(jwk.getKid())) {
						return exchangeExternalToRefresh(request, inputToken);
					}
				}
			}

			for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
				if (kid.equals(jwk.getKid())) {
					return exchangeKernelToken(request, inputToken);
				}
			}
		}

		return exchangeExternalToRefresh(request, inputToken);
	}

	private Tokenrequest.TokenMintResponse exchangeExternalToRefresh(Tokenrequest.TokenMintRequest request,
			TokenWrapper inputToken) throws StatusException {

		String kid = inputToken.getKid();
		if (kid.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "input_token missing kid header");
		}

		Kernel.Delegate matchedDelegate = null;
		JwkOuterClass.Jwk matchedJwk = null;
		for (Kernel.Delegate delegate : delegatesReader.get()) {
			for (JwkOuterClass.Jwk jwk : delegate.getCredPairsList()) {
				if (kid.equals(jwk.getKid())) {
					matchedDelegate = delegate;
					matchedJwk = jwk;
					break;
				}
			}
			if (matchedDelegate != null) {
				break;
			}
		}

		if (matchedDelegate != null) {
			ImmutableJwk verificationKey = ImmutableJwk.from(matchedJwk);
			try {
				inputToken.verify(verificationKey);
			} catch (Exception e) {
				throw new StatusException(
						Status.UNAUTHENTICATED, "bootstrap JWT verification failed: " + e.getMessage());
			}

			String delegateName = matchedDelegate.getName();

			String instanceId;
			if (!request.getContinuityToken().isEmpty()) {
				instanceId = resolveInstanceIdFromContinuityToken(request, delegateName);
			} else {
				instanceId = UUID.randomUUID().toString();
				logger.info("Generated new instance_id={} for sub={}", instanceId, delegateName);
			}

			String spiffeId = "spiffe://" + spiffePrefixReader.get() + "/" + delegateName;
			Map<String, Object> extraClaims = new java.util.LinkedHashMap<>();
			extraClaims.put("instance_id", instanceId);
			extraClaims.put("sub_type", SUB_TYPE_SERVICE);

			return mintRefreshToken(
					spiffeId, Kernel.getDescriptor().getPackage(), request,
					extraClaims);
		}

		String issuer = inputToken.getIssuer();
		ImmutableJwk verificationKey;
		try {
			verificationKey = externalJwkResolver.resolveKey(kid, issuer);
		} catch (ExternalJwkResolver.ResolveException e) {
			throw new StatusException(Status.UNAUTHENTICATED, "failed to resolve key: " + e.getMessage());
		}

		try {
			inputToken.verify(verificationKey);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "input_token verification failed: " + e.getMessage());
		}

		String subject = inputToken.getSubject();

		return mintRefreshToken(subject, Kernel.getDescriptor().getPackage(), request,
				Map.of("sub_type", SUB_TYPE_USER));
	}

	/**
	 * Delegation path: a trusted broker (e.g. oauth) authenticates via its
	 * service token in the header and requests a token for a user it has already
	 * verified. Kernel trusts the broker's attestation.
	 */
	private Tokenrequest.TokenMintResponse delegationMint(Tokenrequest.TokenMintRequest request)
			throws StatusException {

		// Extract raw bearer token from the caller's auth header.
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"delegation requires authorization header");
		}

		// Parse and verify the caller's service token against cluster keys.
		TokenWrapper callerToken;
		try {
			callerToken = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"invalid caller token: " + e.getMessage());
		}

		String kid = callerToken.getKid();
		if (kid == null || kid.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token missing kid");
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
					"caller token signed with unknown key: " + kid);
		}

		try {
			callerToken.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"caller token verification failed: " + e.getMessage());
		}

		// The caller's sub must be a known delegate name.
		String callerSub = callerToken.getSubject();
		Kernel.Delegate delegate = findDelegateByName(callerSub);
		if (delegate == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"caller " + callerSub + " is not a registered delegate");
		}

		// Validate delegate is authorized for the target audience (if specified).
		if (!request.getAud().isEmpty()) {
			boolean authorized = false;
			for (var svcName : delegate.getAuthorizedServicesList()) {
				String enumName = svcName.name();
				if (enumName.equals("SERVICE_NAME_ANY")) {
					authorized = true;
					break;
				}
				String svc = enumName.replace("SERVICE_NAME_", "").toLowerCase();
				if (svc.equals(request.getAud())) {
					authorized = true;
					break;
				}
			}
			if (!authorized) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"delegate " + callerSub + " not authorized for service " + request.getAud());
			}
		}

		// Mint the token with the delegated subject and azp = caller's delegate name.
		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long maxExp = now + maxTokenLifetimeSeconds;
		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		} else {
			exp = now + defaultTokenExpirySeconds;
		}

		boolean isRefresh = request.getTokenPurpose() ==
				com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass.TokenPurpose.TOKEN_PURPOSE_REFRESH;

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(request.getSubject())
				.setAudience(request.getAud().isEmpty() ? Kernel.getDescriptor().getPackage() : request.getAud())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		// azp = the delegate name (not SPIFFE URI) — must match TokenEntitlements.azp entries.
		newToken.setAzp(delegate.getName());

		// Token type claims: token_use identifies the token's role in the hierarchy,
		// sub_type identifies what the subject represents (user vs service).
		// Delegation is always a broker minting on behalf of a user.
		newToken.setTokenUse(isRefresh ? TOKEN_USE_REFRESH : TOKEN_USE_ACCESS);
		newToken.setSubType(SUB_TYPE_USER);
		if (isRefresh) {
			newToken.setCustomField("typ", TOKEN_TYPE_REFRESH); // backwards compat
		}

		// Forward custom claims from the request (e.g., IDP claims like email, name).
		// Well-known JWT claims from external IdPs get origin_ prefix to avoid collision.
		if (request.hasClaims()) {
			for (Map.Entry<String, Value> entry : request.getClaims().getFieldsMap().entrySet()) {
				String key = entry.getKey();
				if (STANDARD_JWT_CLAIMS.contains(key)) {
					continue;
				}
				String outputKey = WELL_KNOWN_JWT_CLAIMS.contains(key) ? "origin_" + key : key;
				Value val = entry.getValue();
				if (val.hasStringValue()) {
					newToken.setCustomField(outputKey, val.getStringValue());
				} else if (val.hasNumberValue()) {
					newToken.setCustomField(outputKey, Long.toString((long) val.getNumberValue()));
				} else if (val.hasBoolValue()) {
					newToken.setCustomField(outputKey, Boolean.toString(val.getBoolValue()));
				} else {
					newToken.setCustomField(outputKey, val.toString());
				}
			}
		}

		// Inject delegate's static custom claims.
		for (Map.Entry<String, String> entry : delegate.getCustomClaimsMap().entrySet()) {
			if (!STANDARD_JWT_CLAIMS.contains(entry.getKey())) {
				newToken.setCustomField(entry.getKey(), entry.getValue());
			}
		}

		newToken.sign(signingKey);

		logger.info("Minted delegated token: sub={}, aud={}, azp={}, exp={}, isRefresh={}",
				request.getSubject(), newToken.getAudience(), callerSub, exp, isRefresh);

		if (isRefresh) {
			// Also mint an access token (clone of refresh without typ).
			TokenOuterClass.Token accessProto = mintAccessFromRefresh(newToken, signingKey, now, exp);
			return Tokenrequest.TokenMintResponse.newBuilder()
					.setRefreshToken(newToken.getProto())
					.setAccessToken(accessProto)
					.build();
		}
		return Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(newToken.getProto())
				.build();
	}

	private Tokenrequest.TokenMintResponse mintRefreshToken(
			String subject, String azp, Tokenrequest.TokenMintRequest request,
			Map<String, Object> extraClaims)
			throws StatusException {

		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long maxExp = now + maxTokenLifetimeSeconds;
		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		} else {
			exp = now + defaultTokenExpirySeconds;
		}

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(subject)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		newToken.setTokenUse(TOKEN_USE_REFRESH);
		newToken.setCustomField("typ", TOKEN_TYPE_REFRESH); // backwards compat
		newToken.setAzp(azp);

		for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
			newToken.setCustomField(entry.getKey(), entry.getValue());
		}

		newToken.sign(signingKey);

		logger.info("Minted refresh token: sub={}, exp={}", subject, exp);

		// Also mint an access token (clone of refresh without typ).
		TokenOuterClass.Token accessProto = mintAccessFromRefresh(newToken, signingKey, now, exp);

		return Tokenrequest.TokenMintResponse.newBuilder()
				.setRefreshToken(newToken.getProto())
				.setAccessToken(accessProto)
				.build();
	}

	/**
	 * Exchanges a kernel-signed token (refresh or access) for a new token.
	 * Refresh tokens produce access tokens; access tokens produce service-specific tokens.
	 * Refresh tokens CANNOT directly produce service-specific tokens (aud must be empty).
	 */
	private Tokenrequest.TokenMintResponse exchangeKernelToken(Tokenrequest.TokenMintRequest request,
			TokenWrapper inputToken) throws StatusException {

		// Check token_use first, fall back to legacy typ for backwards compat.
		String tokenUse = inputToken.getTokenUse();
		boolean isRefresh;
		if (!tokenUse.isEmpty()) {
			isRefresh = TOKEN_USE_REFRESH.equals(tokenUse);
		} else {
			isRefresh = TOKEN_TYPE_REFRESH.equals(inputToken.getCustomField("typ"));
		}

		String kid = inputToken.getKid();
		if (kid.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "input_token missing kid header");
		}

		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}

		if (matchingKey == null) {
			throw new StatusException(Status.UNAUTHENTICATED, "refresh token signed with unknown key: " + kid);
		}

		ImmutableJwk immJwk = ImmutableJwk.from(matchingKey);
		try {
			inputToken.verify(immJwk);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "refresh token verification failed: " + e.getMessage());
		}

		// Bootstrap tokens are exchanged for real refresh+access pairs (workload bootstrap).
		if (TOKEN_USE_BOOTSTRAP.equals(tokenUse)) {
			ImmutableKey bsSigningKey = keyRotator.getActiveSigningKey();
			if (bsSigningKey == null) {
				throw new StatusException(Status.UNAVAILABLE, "no active signing key");
			}
			long bsNow = Instant.now().getEpochSecond();
			long bsExp = bsNow + defaultTokenExpirySeconds;
			return exchangeBootstrapToRefresh(inputToken, bsSigningKey, bsNow, bsExp);
		}

		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long maxExp = now + maxTokenLifetimeSeconds;
		long exp;
		if (request.getExp() == 0) {
			exp = now + defaultTokenExpirySeconds;
		} else {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		}
		String subject = inputToken.getSubject();

		Kernel.Delegate delegate = findDelegateByName(subject);
		boolean isS2S = delegate != null;

		// Locality validation for workload tokens (child workloads present a locality_token on refresh).
		// TODO: Wire WorkloadState map after codegen — look up parent's locality and compare.
		if (isRefresh) {
			String parentSub = inputToken.getCustomField(PARENT_SUB);
			if (parentSub != null && !parentSub.isEmpty()) {
				String localityToken = request.getLocalityToken();
				if (localityToken == null || localityToken.isEmpty()) {
					logger.warn("Workload token refresh without locality_token: sub={}", subject);
					// TODO: reject once WorkloadState locality lookups are wired
				}
			}
		}

		// Refresh tokens cannot directly mint service-specific tokens.
		// Exchange refresh → access first, then access → service token.
		if (isRefresh && !request.getAud().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"refresh tokens cannot mint service-specific tokens; exchange for an access token first");
		}

		if (isS2S && !request.getAud().isEmpty()) {
			String targetAud = request.getAud();
			boolean authorized = targetAud.equals(subject);
			if (!authorized && delegate != null) {
				for (var svcName : delegate.getAuthorizedServicesList()) {
					// ServiceName enum values are SERVICE_NAME_SENTINEL etc.
					// Strip prefix and lowercase to get service name for comparison.
					String enumName = svcName.name();
					if (enumName.equals("SERVICE_NAME_ANY")) {
						authorized = true;
						break;
					}
					String svc = enumName.replace("SERVICE_NAME_", "").toLowerCase();
					if (svc.equals(targetAud)) {
						authorized = true;
						break;
					}
				}
			}
			if (!authorized) {
				throw new StatusException(
						Status.PERMISSION_DENIED,
						"delegate " + subject + " not authorized for service " + targetAud);
			}
		}

		TokenWrapper newToken;

		if (isS2S) {
			// S2S: build identity-only token (no profiles — authorization is receiver-side).
			newToken = TokenWrapper.create()
					.setIssuer(tokenIssuer)
					.setSubject(subject)
					.setAudience(request.getAud())
					.setIssuedAt(now)
					.setExpiration(exp)
					.setJTI(UUID.randomUUID().toString());

			String inputAzp = inputToken.getAzp();
			newToken.setAzp(!inputAzp.isEmpty() ? inputAzp : Kernel.getDescriptor().getPackage());
			newToken.setPrincipal(subject);
			newToken.setSubType(SUB_TYPE_SERVICE);
			newToken.setTokenUse(
					request.getAud().isEmpty() ? TOKEN_USE_ACCESS : TOKEN_USE_SERVICE);

			{
				String instanceId = inputToken.getInstanceId();
				if (instanceId != null && !instanceId.isEmpty()) {
					newToken.setInstanceId(instanceId);
				}
			}

			// Forward workload claims from input token to service token.
			{
				String terminal = inputToken.getCustomField(TERMINAL);
				if (terminal != null) newToken.setCustomField(TERMINAL, terminal);
				String parentSub = inputToken.getCustomField(PARENT_SUB);
				if (parentSub != null) newToken.setCustomField(PARENT_SUB, parentSub);
			}

			for (Map.Entry<String, String> entry : delegate.getCustomClaimsMap().entrySet()) {
				if (!STANDARD_JWT_CLAIMS.contains(entry.getKey())) {
					newToken.setCustomField(entry.getKey(), entry.getValue());
				}
			}

			logger.info("Minted service token (S2S): sub={}, aud={}, exp={}",
					subject, request.getAud(), exp);
		} else {
			// U2S: clone the entire input token as a mutable copy.
			// Preserves all claims (profiles, azp, custom IDP claims) exactly.
			// Only update the fields that differ for a service token.
			newToken = TokenWrapper.from(inputToken.getProto().toBuilder()
					.setSignature("")
					.setBase64("")
					.removePayload("typ")
					.build());

			if (!request.getAud().isEmpty()) {
				newToken.setAudience(request.getAud());
			}
			newToken.setIssuedAt(now)
					.setExpiration(exp)
					.setJTI(UUID.randomUUID().toString());
			newToken.setPrincipal(subject);
			newToken.setTokenUse(
					request.getAud().isEmpty() ? TOKEN_USE_ACCESS : TOKEN_USE_SERVICE);

			logger.info("Minted service token (U2S): sub={}, aud={}, exp={}, profiles={}",
					subject, newToken.getAudience(), exp, newToken.getProfiles());
		}

		newToken.sign(signingKey);
		return Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(newToken.getProto())
				.build();
	}

	/**
	 * Creates an access token by cloning a signed refresh token, stripping typ=refresh,
	 * setting token_use=access, and re-signing with a new jti.
	 */
	private TokenOuterClass.Token mintAccessFromRefresh(TokenWrapper refreshToken,
			ImmutableKey signingKey, long now, long exp) {
		TokenWrapper accessToken = TokenWrapper.from(refreshToken.getProto().toBuilder()
				.setSignature("")
				.setBase64("")
				.removePayload("typ")
				.build());
		accessToken.setTokenUse(TOKEN_USE_ACCESS);
		accessToken.setIssuedAt(now)
				.setJTI(UUID.randomUUID().toString());
		accessToken.sign(signingKey);
		return accessToken.getProto();
	}

	private String resolveInstanceIdFromContinuityToken(Tokenrequest.TokenMintRequest request,
			String bootstrapSubject) throws StatusException {

		TokenWrapper continuityToken;
		try {
			continuityToken = TokenWrapper.parse(request.getContinuityToken());
		} catch (Exception e) {
			throw new StatusException(Status.INVALID_ARGUMENT, "invalid continuity_token: " + e.getMessage());
		}

		// Check token_use first, fall back to legacy typ for backwards compat.
		String continuityTokenUse = continuityToken.getTokenUse();
		boolean isRefreshToken;
		if (!continuityTokenUse.isEmpty()) {
			isRefreshToken = TOKEN_USE_REFRESH.equals(continuityTokenUse);
		} else {
			isRefreshToken = TOKEN_TYPE_REFRESH.equals(continuityToken.getCustomField("typ"));
		}
		if (!isRefreshToken) {
			throw new StatusException(
					Status.INVALID_ARGUMENT,
					"continuity_token must be a refresh token (expected token_use=refresh)");
		}

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
			throw new StatusException(Status.UNAUTHENTICATED, "continuity_token signed with unknown key: " + kid);
		}
		try {
			continuityToken.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(
					Status.UNAUTHENTICATED, "continuity_token verification failed: " + e.getMessage());
		}

		if (!bootstrapSubject.equals(continuityToken.getSubject())) {
			throw new StatusException(
					Status.INVALID_ARGUMENT,
					"continuity_token subject '" + continuityToken.getSubject() + "' does not match bootstrap subject '"
							+ bootstrapSubject + "'");
		}

		String instanceId = continuityToken.getCustomField("instance_id");
		if (instanceId == null || instanceId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "continuity_token missing instance_id claim");
		}
		logger.info("Preserved instance_id={} via continuity token for sub={}", instanceId, bootstrapSubject);
		return instanceId;
	}

	private Kernel.Delegate findDelegateByName(String name) {
		// When sub is a SPIFFE URI (spiffe://<prefix>/<delegate_name>),
		// extract the delegate name portion for lookup.
		String lookupName = name;
		String prefix = "spiffe://" + spiffePrefixReader.get() + "/";
		if (name.startsWith(prefix)) {
			lookupName = name.substring(prefix.length());
		}
		for (Kernel.Delegate d : delegatesReader.get()) {
			if (lookupName.equals(d.getName())) {
				return d;
			}
		}
		return null;
	}

	// ========================================================================
	// X509Mint RPC
	// ========================================================================

	@Override
	public void x509Mint(Tokenrequest.X509MintRequest request,
			StreamObserver<X509.X509CertChain> responseObserver) {
		try {
			// Authenticate caller from raw Bearer token (MintService is auth-exempt,
			// so SecurityInterceptor doesn't validate — we do it manually here).
			// Fall back to input_token from request body (gateway-mediated calls).
			String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
			if ((rawToken == null || rawToken.isEmpty()) && !request.getInputToken().isEmpty()) {
				rawToken = request.getInputToken();
			}
			if (rawToken == null || rawToken.isEmpty()) {
				responseObserver.onError(Status.UNAUTHENTICATED
						.withDescription("missing authorization header")
						.asRuntimeException());
				return;
			}

			TokenWrapper token;
			try {
				token = TokenWrapper.parse(rawToken);
			} catch (Exception e) {
				responseObserver.onError(Status.UNAUTHENTICATED
						.withDescription("invalid token: " + e.getMessage())
						.asRuntimeException());
				return;
			}

			// Verify token signature against cluster keys.
			String kid = token.getKid();
			JwkOuterClass.Jwk matchingKey = null;
			for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
				if (kid.equals(jwk.getKid())) {
					matchingKey = jwk;
					break;
				}
			}
			if (matchingKey == null) {
				responseObserver.onError(Status.UNAUTHENTICATED
						.withDescription("token signed with unknown key: " + kid)
						.asRuntimeException());
				return;
			}
			try {
				token.verify(ImmutableJwk.from(matchingKey));
			} catch (Exception e) {
				responseObserver.onError(Status.UNAUTHENTICATED
						.withDescription("token verification failed: " + e.getMessage())
						.asRuntimeException());
				return;
			}

			// Extract service name from token subject.
			String serviceName = token.getSubject();
			if (serviceName == null || serviceName.isEmpty()) {
				responseObserver.onError(Status.INVALID_ARGUMENT
						.withDescription("token has no sub claim")
						.asRuntimeException());
				return;
			}

			// Get or create intermediate CA for this service (signed by cavalier-issued signing chain).
			ImmutableCertChain intermediateCa = getOrCreateIntermediateCa(serviceName, signingCa);

			// Construct SPIFFE URI SAN from auth context.
			String azp = token.getAzp();
			if (azp.isEmpty()) azp = Kernel.getDescriptor().getPackage();
			String spiffePrefix = spiffePrefixReader.get();
			String spiffeId = "spiffe://" + spiffePrefix + "/" + azp + "/" + serviceName;

			// Enrich cert request with SPIFFE URI SAN.
			X509.X509CertRequest enrichedRequest = request.getCertRequest().toBuilder()
					.addUriSans(spiffeId)
					.build();

			// Sign the enriched cert request with the intermediate CA.
			X509.X509Cert leafCert = intermediateCa.sign(enrichedRequest);

			// Build response: leaf cert + intermediate CA cert in chain.
			X509.X509CertChain certChain = X509.X509CertChain.newBuilder()
					.addChain(leafCert)
					.addChain(intermediateCa.leaf().getProto())
					.build();

			logger.info("X509Mint: service={}, spiffeId={}, keyId={}",
					serviceName, spiffeId, request.getCertRequest().getKey().getId());

			responseObserver.onNext(certChain);
			responseObserver.onCompleted();
		} catch (Exception e) {
			logger.error("X509Mint failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("certificate signing failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	/**
	 * Gets or creates a per-service intermediate CA.
	 * The intermediate CA is signed by the root CA with BasicConstraints CA:TRUE, pathlen:0.
	 * It's stored in the Ca state's service_cas collection, keyed by service name.
	 */
	private synchronized ImmutableCertChain getOrCreateIntermediateCa(
			String serviceName, ImmutableCertChain rootCa) throws Exception {

		// Check if intermediate CA already exists for this service.
		X509.X509CertChain existing = serviceCaReader.apply(serviceName);
		if (existing != null && existing.getChainCount() > 0) {
			return ImmutableCertChain.from(existing);
		}

		// Generate Ed25519 keypair for the intermediate CA.
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
		KeyPair intermediateKeyPair = kpg.generateKeyPair();

		String intermediateId = serviceName + "-intermediate-ca";
		long now = Instant.now().getEpochSecond();
		long intermediateExp = now + INTERMEDIATE_CA_LIFETIME_SECONDS;

		// Build public key proto for signing request.
		byte[] pubKeyBytes = intermediateKeyPair.getPublic().getEncoded();
		String pubKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubKeyBytes);
		KeyOuterClass.PublicKey intermediatePubKey = KeyOuterClass.PublicKey.newBuilder()
				.setId(intermediateId)
				.setBase64(pubKeyBase64)
				.build();

		// Sign the intermediate CA cert with the root CA (CA:TRUE, pathlen:0).
		X509.X509CertRequest intermediateRequest = X509.X509CertRequest.newBuilder()
				.setKey(intermediatePubKey)
				.setExp(intermediateExp)
				.setIssuer(serviceName + " Intermediate CA")
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN)
				.setIsCa(true)
				.setPathLenConstraint(0)
				.build();

		X509.X509Cert intermediateCert = rootCa.sign(intermediateRequest);

		// Build the private key proto.
		byte[] privKeyBytes = intermediateKeyPair.getPrivate().getEncoded();
		String privKeyPem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privKeyBytes)
				+ "\n-----END PRIVATE KEY-----\n";
		String privKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(privKeyPem.getBytes());

		KeyOuterClass.Key intermediateKey = KeyOuterClass.Key.newBuilder()
				.setId(intermediateId)
				.setBase64(privKeyBase64)
				.setCreated(now)
				.build();

		// Store the intermediate CA keypair in the Ca state.
		X509.X509CertChain intermediateProto = X509.X509CertChain.newBuilder()
				.setKey(intermediateKey)
				.addChain(intermediateCert)
				.build();

		serviceCaWriter.accept(serviceName, intermediateProto);
		logger.info("Created intermediate CA for service: {}", serviceName);

		return ImmutableCertChain.from(intermediateProto);
	}

	// ========================================================================
	// Workload Identity (SPIFFE)
	// ========================================================================

	@Override
	public void workloadMint(Tokenrequest.WorkloadMintRequest request,
			StreamObserver<Tokenrequest.WorkloadMintResponse> responseObserver) {
		try {
			Tokenrequest.WorkloadMintResponse result = doWorkloadMint(request);
			responseObserver.onNext(result);
			responseObserver.onCompleted();
		} catch (StatusException e) {
			responseObserver.onError(e.toGrpcStatus().asRuntimeException());
		} catch (Exception e) {
			logger.error("WorkloadMint failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("workload mint failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	private Tokenrequest.WorkloadMintResponse doWorkloadMint(Tokenrequest.WorkloadMintRequest request)
			throws StatusException {
		// Auth: extract caller's bearer token.
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "workload mint requires authorization header");
		}
		TokenWrapper callerToken;
		try {
			callerToken = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "invalid caller token: " + e.getMessage());
		}

		// Verify against cluster keys.
		String kid = callerToken.getKid();
		if (kid == null || kid.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token missing kid");
		}
		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token signed with unknown key: " + kid);
		}
		try {
			callerToken.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token verification failed: " + e.getMessage());
		}

		// Validate caller has a SPIFFE sub and is not terminal.
		String callerSub = callerToken.getSubject();
		if (callerSub == null || !callerSub.startsWith("spiffe://")) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"caller sub is not a SPIFFE URI — only SPIFFE-identified services can mint workloads");
		}
		String callerTerminal = callerToken.getCustomField(TERMINAL);
		if ("true".equals(callerTerminal)) {
			throw new StatusException(Status.PERMISSION_DENIED, "terminal workloads cannot mint children");
		}

		// Validate workload_name.
		String workloadName = request.getWorkloadName();
		if (workloadName == null || workloadName.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "workload_name is required");
		}
		if (!WORKLOAD_NAME_PATTERN.matcher(workloadName).matches()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "workload_name must match [a-zA-Z0-9_-]+");
		}

		// Construct child SPIFFE URI.
		String childSub = callerSub + "/" + workloadName;

		// Mint bootstrap token (short-lived).
		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long bootstrapExp;
		if (request.getExp() > 0) {
			bootstrapExp = request.getExp();
			if (bootstrapExp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT, "exp must be in the future");
			}
			// Cap bootstrap token lifetime to 5 minutes.
			if (bootstrapExp > now + 300) {
				bootstrapExp = now + 300;
			}
		} else {
			bootstrapExp = now + 60; // default 60s
		}

		TokenWrapper bootstrapToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(childSub)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(bootstrapExp)
				.setJTI(UUID.randomUUID().toString());

		bootstrapToken.setCustomField(PARENT_SUB, callerSub);
		bootstrapToken.setCustomField(TERMINAL, request.getTerminal() ? "true" : "false");
		bootstrapToken.setTokenUse(TOKEN_USE_BOOTSTRAP);
		bootstrapToken.setSubType(SUB_TYPE_SERVICE);

		bootstrapToken.sign(signingKey);

		logger.info("WorkloadMint: parent={}, child={}, terminal={}",
				callerSub, childSub, request.getTerminal());

		return Tokenrequest.WorkloadMintResponse.newBuilder()
				.setBootstrapToken(bootstrapToken.getProto())
				.build();
	}

	/** Exchanges a bootstrap token for a real refresh + access token pair. */
	private Tokenrequest.TokenMintResponse exchangeBootstrapToRefresh(
			TokenWrapper bootstrapToken, ImmutableKey signingKey, long now, long exp) throws StatusException {

		String sub = bootstrapToken.getSubject();
		String parentSub = bootstrapToken.getCustomField(PARENT_SUB);
		String terminal = bootstrapToken.getCustomField(TERMINAL);

		if (sub == null || !sub.startsWith("spiffe://")) {
			throw new StatusException(Status.INVALID_ARGUMENT, "bootstrap token sub is not a SPIFFE URI");
		}

		String instanceId = UUID.randomUUID().toString();

		// Mint refresh token.
		TokenWrapper refreshToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(sub)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		refreshToken.setTokenUse(TOKEN_USE_REFRESH);
		refreshToken.setCustomField("typ", TOKEN_TYPE_REFRESH); // backwards compat
		refreshToken.setSubType(SUB_TYPE_SERVICE);
		refreshToken.setAzp(Kernel.getDescriptor().getPackage());
		refreshToken.setInstanceId(instanceId);
		if (parentSub != null) refreshToken.setCustomField(PARENT_SUB, parentSub);
		if (terminal != null) refreshToken.setCustomField(TERMINAL, terminal);

		refreshToken.sign(signingKey);

		// Mint access token.
		TokenOuterClass.Token accessProto = mintAccessFromRefresh(refreshToken, signingKey, now, exp);

		logger.info("Bootstrap exchange: sub={}, instance_id={}", sub, instanceId);

		return Tokenrequest.TokenMintResponse.newBuilder()
				.setRefreshToken(refreshToken.getProto())
				.setAccessToken(accessProto)
				.build();
	}

	@Override
	public void workloadRevoke(Kernel.WorkloadRevokeRequest request,
			StreamObserver<com.google.protobuf.Empty> responseObserver) {
		try {
			doWorkloadRevoke(request);
			responseObserver.onNext(com.google.protobuf.Empty.getDefaultInstance());
			responseObserver.onCompleted();
		} catch (StatusException e) {
			responseObserver.onError(e.toGrpcStatus().asRuntimeException());
		} catch (Exception e) {
			logger.error("WorkloadRevoke failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("workload revoke failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	private void doWorkloadRevoke(Kernel.WorkloadRevokeRequest request) throws StatusException {
		// Auth: extract caller's bearer token.
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "workload revoke requires authorization header");
		}
		TokenWrapper callerToken;
		try {
			callerToken = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "invalid caller token: " + e.getMessage());
		}

		// Verify against cluster keys.
		String kid = callerToken.getKid();
		if (kid == null || kid.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token missing kid");
		}
		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token signed with unknown key: " + kid);
		}
		try {
			callerToken.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token verification failed: " + e.getMessage());
		}

		// Validate caller has a SPIFFE sub.
		String callerSub = callerToken.getSubject();
		if (callerSub == null || !callerSub.startsWith("spiffe://")) {
			throw new StatusException(Status.PERMISSION_DENIED, "caller sub is not a SPIFFE URI");
		}

		// Validate target is a descendant of the caller.
		String targetSpiffeId = request.getSpiffeId();
		if (targetSpiffeId == null || targetSpiffeId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "spiffe_id is required");
		}
		if (!targetSpiffeId.startsWith(callerSub + "/")) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"cannot revoke " + targetSpiffeId + " — not a descendant of " + callerSub);
		}

		// TODO: Write revocation to WorkloadState after codegen runs.
		logger.info("WorkloadRevoke (deferred): caller={}, target={}", callerSub, targetSpiffeId);
	}

	// ========================================================================
	// Internal
	// ========================================================================

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
