// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.TokenExchangeGrpc;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * C2S token exchange — authenticated users exchange their access token
 * (aud:kernel) for a service-scoped token (aud:target_service).
 *
 * <p>Gateway proxies requests to this service with auth_any_user policy.
 * The bearer token is validated and cloned. azp, profiles, and custom
 * claims are preserved. Only aud, exp, jti, and token_use are changed.
 */
public class TokenExchangeServiceImpl extends TokenExchangeGrpc.TokenExchangeImplBase {

	private static final Logger logger = LoggerFactory.getLogger(TokenExchangeServiceImpl.class);

	private static final String TOKEN_USE_REFRESH = "refresh";
	private static final String TOKEN_USE_SERVICE = "service";
	private static final String TOKEN_TYPE_REFRESH = "refresh";

	private final long defaultTokenExpirySeconds;
	private final long maxTokenLifetimeSeconds;
	private final KeyRotator keyRotator;
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	private final String tokenIssuer;

	public TokenExchangeServiceImpl(
			long defaultTokenExpirySeconds,
			long maxTokenLifetimeSeconds,
			KeyRotator keyRotator,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			String tokenIssuer) {
		this.defaultTokenExpirySeconds = defaultTokenExpirySeconds > 0 ? defaultTokenExpirySeconds : 3600;
		this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds > 0 ? maxTokenLifetimeSeconds : 2592000;
		this.keyRotator = keyRotator;
		this.verifyingKeysReader = verifyingKeysReader;
		this.tokenIssuer = (tokenIssuer != null && !tokenIssuer.isEmpty()) ? tokenIssuer : "kernel";
	}

	@Override
	public void exchange(Kernel.TokenExchangeRequest request,
			StreamObserver<Tokenrequest.TokenMintResponse> responseObserver) {
		try {
			Tokenrequest.TokenMintResponse result = doExchange(request);
			responseObserver.onNext(result);
			responseObserver.onCompleted();
		} catch (Exception e) {
			if (e instanceof io.grpc.StatusRuntimeException sre) {
				responseObserver.onError(sre);
			} else {
				logger.error("TokenExchange failed", e);
				responseObserver.onError(Status.INTERNAL
						.withDescription("token exchange failed: " + e.getMessage())
						.asRuntimeException());
			}
		}
	}

	private Tokenrequest.TokenMintResponse doExchange(Kernel.TokenExchangeRequest request)
			throws io.grpc.StatusRuntimeException {

		// Extract raw bearer token from context (set by ClusterServer.rpcInterceptor).
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw Status.UNAUTHENTICATED
					.withDescription("missing bearer token")
					.asRuntimeException();
		}

		// Parse and validate the bearer token.
		TokenWrapper inputToken;
		try {
			inputToken = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw Status.UNAUTHENTICATED
					.withDescription("invalid bearer token: " + e.getMessage())
					.asRuntimeException();
		}

		// Reject refresh tokens — only access tokens can be exchanged for service tokens.
		String tokenUse = inputToken.getTokenUse();
		if (TOKEN_USE_REFRESH.equals(tokenUse)) {
			throw Status.INVALID_ARGUMENT
					.withDescription("refresh tokens cannot be exchanged; use an access token")
					.asRuntimeException();
		}
		if (tokenUse.isEmpty() && TOKEN_TYPE_REFRESH.equals(inputToken.getCustomField("typ"))) {
			throw Status.INVALID_ARGUMENT
					.withDescription("refresh tokens cannot be exchanged; use an access token")
					.asRuntimeException();
		}

		// Validate signature against kernel's verifying keys.
		String kid = inputToken.getKid();
		if (kid == null || kid.isEmpty()) {
			throw Status.UNAUTHENTICATED
					.withDescription("bearer token missing kid header")
					.asRuntimeException();
		}

		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw Status.UNAUTHENTICATED
					.withDescription("bearer token signed with unknown key: " + kid)
					.asRuntimeException();
		}

		ImmutableJwk immJwk = ImmutableJwk.from(matchingKey);
		try {
			inputToken.verify(immJwk);
		} catch (Exception e) {
			throw Status.UNAUTHENTICATED
					.withDescription("bearer token verification failed: " + e.getMessage())
					.asRuntimeException();
		}

		// Get signing key.
		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw Status.UNAVAILABLE
					.withDescription("no active signing key")
					.asRuntimeException();
		}

		// Compute expiry.
		long now = Instant.now().getEpochSecond();
		long exp = now + defaultTokenExpirySeconds;

		String targetAud = request.getAud();
		String subject = inputToken.getSubject();

		// Clone the input token, preserving all claims (azp, profiles, custom IDP claims).
		// Only update the fields that differ for a service token.
		TokenWrapper newToken = TokenWrapper.from(inputToken.getProto().toBuilder()
				.setSignature("")
				.setBase64("")
				.removePayload("typ")
				.build());

		newToken.setAudience(targetAud);
		newToken.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		newToken.setPrincipal(subject);
		newToken.setTokenUse(TOKEN_USE_SERVICE);

		newToken.sign(signingKey);

		logger.info("C2S token exchange: sub={}, aud={}, azp={}, exp={}",
				subject, targetAud, newToken.getAzp(), exp);

		return Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(newToken.getProto())
				.build();
	}
}
