// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.MintGrpc;
import com.google.protobuf.Value;
import com.google.gson.Gson;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
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

	private static final Set<String> STANDARD_JWT_CLAIMS = Set.of("sub", "iss", "aud", "exp", "iat", "azp", "nbf",
			"jti", "typ", "profiles", "token_use", "sub_type");

	// Claims from external IdPs that get origin_ prefix to avoid collision with Cavalier claims.
	private static final Set<String> WELL_KNOWN_JWT_CLAIMS = Set.of(
			"iss", "sub", "aud", "exp", "nbf", "iat", "jti");

	// Legacy typ claim value — kept for backwards compatibility during rollout.
	private static final String TOKEN_TYPE_REFRESH = "refresh";

	// token_use claim values — unambiguous token type identification.
	private static final String TOKEN_USE_REFRESH = "refresh";
	private static final String TOKEN_USE_ACCESS = "access";
	private static final String TOKEN_USE_SERVICE = "service";

	// sub_type claim values — identifies what the sub claim represents.
	private static final String SUB_TYPE_SERVICE = "service";
	private static final String SUB_TYPE_USER = "user";

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
	private final Supplier<String> trustDomainReader;
	private final String tokenIssuer;

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
			Supplier<String> trustDomainReader,
			String tokenIssuer) {
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
		this.trustDomainReader = trustDomainReader;
		this.tokenIssuer = (tokenIssuer != null && !tokenIssuer.isEmpty()) ? tokenIssuer : "kernel";
	}

	// ========================================================================
	// TokenMint RPC
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

			return mintRefreshToken(
					delegateName, delegateName, request,
					Map.of("instance_id", instanceId, "sub_type", SUB_TYPE_SERVICE));
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

		return mintRefreshToken(subject, "kernel", request,
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
				.setAudience(request.getAud().isEmpty() ? "kernel" : request.getAud())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		// azp = the delegate name (e.g. "oauth")
		newToken.setAzp(callerSub);

		// Token type claims: token_use identifies the token's role in the hierarchy,
		// sub_type identifies what the subject represents (user vs service).
		// Delegation is always a broker minting on behalf of a user.
		newToken.setTokenUse(isRefresh ? TOKEN_USE_REFRESH : TOKEN_USE_ACCESS);
		newToken.setSubType(SUB_TYPE_USER);
		if (isRefresh) {
			newToken.setCustomField("typ", TOKEN_TYPE_REFRESH); // backwards compat
		}

		// Set profiles from the request as a comma-delimited string.
		if (!request.getProfilesList().isEmpty()) {
			newToken.setProfiles(request.getProfilesList());
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

		logger.info("Minted delegated token: sub={}, aud={}, azp={}, exp={}, isRefresh={}, profiles={}",
				request.getSubject(), newToken.getAudience(), callerSub, exp, isRefresh,
				newToken.getProfiles());

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
				.setAudience("kernel")
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
			// S2S: build token from scratch with delegate-specific profiles.
			newToken = TokenWrapper.create()
					.setIssuer(tokenIssuer)
					.setSubject(subject)
					.setAudience(request.getAud())
					.setIssuedAt(now)
					.setExpiration(exp)
					.setJTI(UUID.randomUUID().toString());

			String inputAzp = inputToken.getAzp();
			newToken.setAzp(!inputAzp.isEmpty() ? inputAzp : "kernel");
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

			List<String> delegateProfiles = delegate.getAuthorizedProfilesList();
			if (delegateProfiles != null && !delegateProfiles.isEmpty()) {
				newToken.setProfiles(delegateProfiles);
			} else {
				newToken.setProfiles(List.of(delegate.getName()));
			}

			for (Map.Entry<String, String> entry : delegate.getCustomClaimsMap().entrySet()) {
				if (!STANDARD_JWT_CLAIMS.contains(entry.getKey())) {
					newToken.setCustomField(entry.getKey(), entry.getValue());
				}
			}

			logger.info("Minted service token (S2S): sub={}, aud={}, exp={}, profiles={}",
					subject, request.getAud(), exp, newToken.getProfiles());
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
		for (Kernel.Delegate d : delegatesReader.get()) {
			if (name.equals(d.getName())) {
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
			if (azp.isEmpty()) azp = "kernel";
			String trustDomain = trustDomainReader.get();
			String spiffeId = "spiffe://" + trustDomain + "/" + azp + "/" + serviceName;

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
