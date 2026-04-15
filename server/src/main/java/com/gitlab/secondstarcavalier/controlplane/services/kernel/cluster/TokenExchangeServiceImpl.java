// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.generated.services.Services;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.TokenExchangeGrpc;
import com.google.protobuf.Descriptors;
import com.google.protobuf.ProtocolMessageEnum;
import com.google.protobuf.util.JsonFormat;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.time.Instant;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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

	private static final String TOKEN_USE_REFRESH = Helpers.tokenUseToString(
			TokenOuterClass.TokenUse.TOKEN_USE_REFRESH);
	private static final String TOKEN_USE_SERVICE = Helpers.tokenUseToString(
			TokenOuterClass.TokenUse.TOKEN_USE_SERVICE);
	private static final String TOKEN_TYPE_REFRESH = TOKEN_USE_REFRESH;
	private static final String TERMINAL = Helpers.jwtPayloadTypeToString(
			TokenOuterClass.JwtPayloadType.JWT_PAYLOAD_TYPE_TERMINAL);

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

		// Reject terminal tokens — they cannot be exchanged further.
		String terminalClaim = inputToken.getCustomField(TERMINAL);
		if ("true".equals(terminalClaim)) {
			throw Status.PERMISSION_DENIED
					.withDescription("terminal token cannot be exchanged")
					.asRuntimeException();
		}

		// Validate mutually exclusive downscope options.
		boolean hasInclude = request.hasIncludeEntitlements();
		boolean hasExclude = request.hasExcludeEntitlements();
		if (hasInclude && hasExclude) {
			throw Status.INVALID_ARGUMENT
					.withDescription("include_entitlements and exclude_entitlements are mutually exclusive")
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

		// Clone the input token, preserving all claims (azp, custom IDP claims).
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

		// Apply downscoping to service_entitlements if the source token carries them.
		String srcEntClaim = inputToken.getServiceEntitlementsClaim();
		if (srcEntClaim != null && !srcEntClaim.isEmpty()) {
			try {
				Entitlements.TokenEntitlements.Builder srcBuilder =
						Entitlements.TokenEntitlements.newBuilder();
				JsonFormat.parser().ignoringUnknownFields().merge(srcEntClaim, srcBuilder);
				Entitlements.TokenEntitlements srcEnt = srcBuilder.build();

				Entitlements.TokenEntitlements result;
				if (hasInclude) {
					result = intersectEntitlements(srcEnt, request.getIncludeEntitlements());
				} else if (hasExclude) {
					result = subtractEntitlements(srcEnt, request.getExcludeEntitlements());
				} else {
					result = srcEnt;
				}

				// Scope to target service: strip entitlements for other services.
				result = scopeToService(result, targetAud);

				String entJson = com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.generated
						.entitlements.Helpers.tokenEntitlementsToJson(result);
				newToken.setServiceEntitlementsClaim(entJson);
			} catch (io.grpc.StatusRuntimeException e) {
				throw e;
			} catch (Exception e) {
				throw Status.INTERNAL
						.withDescription("failed to process service_entitlements: " + e.getMessage())
						.asRuntimeException();
			}
		}

		// Set terminal flag if requested.
		if (request.getTerminal()) {
			newToken.setCustomField(TERMINAL, "true");
		}

		newToken.sign(signingKey);

		logger.info("C2S token exchange: sub={}, aud={}, azp={}, exp={}, terminal={}",
				subject, targetAud, newToken.getAzp(), exp, request.getTerminal());

		return Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(newToken.getProto())
				.build();
	}

	/**
	 * Intersects source entitlements with the include set.
	 * For each service, only RPCs present in BOTH source and include are kept.
	 * If source has _ANY wildcard, the include set is used as-is for that service.
	 */
	private static Entitlements.TokenEntitlements intersectEntitlements(
			Entitlements.TokenEntitlements source,
			Entitlements.TokenEntitlements include) {
		Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();

		builder.addAllSentinel(intersectRPCs(
				source.getSentinelList(), include.getSentinelList(),
				Services.SentinelRPCs.SENTINEL_RPCS_ANY));
		builder.addAllGateway(intersectRPCs(
				source.getGatewayList(), include.getGatewayList(),
				Services.GatewayRPCs.GATEWAY_RPCS_ANY));
		builder.addAllMcp(intersectRPCs(
				source.getMcpList(), include.getMcpList(),
				Services.McpRPCs.MCP_RPCS_ANY));
		builder.addAllEventbus(intersectRPCs(
				source.getEventbusList(), include.getEventbusList(),
				Services.EventbusRPCs.EVENTBUS_RPCS_ANY));
		builder.addAllFleetwood(intersectRPCs(
				source.getFleetwoodList(), include.getFleetwoodList(),
				Services.FleetwoodRPCs.FLEETWOOD_RPCS_ANY));
		builder.addAllAnthropic(intersectRPCs(
				source.getAnthropicList(), include.getAnthropicList(),
				Services.AnthropicRPCs.ANTHROPIC_RPCS_ANY));
		builder.addAllGithub(intersectRPCs(
				source.getGithubList(), include.getGithubList(),
				Services.GithubRPCs.GITHUB_RPCS_ANY));
		builder.addAllGitlab(intersectRPCs(
				source.getGitlabList(), include.getGitlabList(),
				Services.GitlabRPCs.GITLAB_RPCS_ANY));
		builder.addAllOpenai(intersectRPCs(
				source.getOpenaiList(), include.getOpenaiList(),
				Services.OpenaiRPCs.OPENAI_RPCS_ANY));

		return builder.build();
	}

	/**
	 * Intersects two RPC lists. If source contains the _ANY wildcard, returns include as-is.
	 * Otherwise, returns only RPCs present in both lists.
	 */
	@SuppressWarnings("unchecked")
	private static <E extends ProtocolMessageEnum> List<E> intersectRPCs(
			List<E> source, List<E> include, E anyValue) {
		if (source.isEmpty() || include.isEmpty()) {
			return List.of();
		}
		// Source has wildcard → include set is the effective result.
		if (source.contains(anyValue)) {
			return include;
		}
		// Include has wildcard → source set is the effective result.
		if (include.contains(anyValue)) {
			return source;
		}
		Set<E> sourceSet = new HashSet<>(source);
		return include.stream().filter(sourceSet::contains).toList();
	}

	/**
	 * Subtracts exclude entitlements from source.
	 * For each service, RPCs in the exclude set are removed from the source.
	 * _ANY in exclude removes all RPCs for that service.
	 */
	private static Entitlements.TokenEntitlements subtractEntitlements(
			Entitlements.TokenEntitlements source,
			Entitlements.TokenEntitlements exclude) {
		Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();

		builder.addAllSentinel(subtractRPCs(
				source.getSentinelList(), exclude.getSentinelList(),
				Services.SentinelRPCs.SENTINEL_RPCS_ANY));
		builder.addAllGateway(subtractRPCs(
				source.getGatewayList(), exclude.getGatewayList(),
				Services.GatewayRPCs.GATEWAY_RPCS_ANY));
		builder.addAllMcp(subtractRPCs(
				source.getMcpList(), exclude.getMcpList(),
				Services.McpRPCs.MCP_RPCS_ANY));
		builder.addAllEventbus(subtractRPCs(
				source.getEventbusList(), exclude.getEventbusList(),
				Services.EventbusRPCs.EVENTBUS_RPCS_ANY));
		builder.addAllFleetwood(subtractRPCs(
				source.getFleetwoodList(), exclude.getFleetwoodList(),
				Services.FleetwoodRPCs.FLEETWOOD_RPCS_ANY));
		builder.addAllAnthropic(subtractRPCs(
				source.getAnthropicList(), exclude.getAnthropicList(),
				Services.AnthropicRPCs.ANTHROPIC_RPCS_ANY));
		builder.addAllGithub(subtractRPCs(
				source.getGithubList(), exclude.getGithubList(),
				Services.GithubRPCs.GITHUB_RPCS_ANY));
		builder.addAllGitlab(subtractRPCs(
				source.getGitlabList(), exclude.getGitlabList(),
				Services.GitlabRPCs.GITLAB_RPCS_ANY));
		builder.addAllOpenai(subtractRPCs(
				source.getOpenaiList(), exclude.getOpenaiList(),
				Services.OpenaiRPCs.OPENAI_RPCS_ANY));

		return builder.build();
	}

	/**
	 * Subtracts exclude RPCs from source RPCs.
	 * If exclude contains _ANY, the entire service is removed (empty list).
	 */
	@SuppressWarnings("unchecked")
	private static <E extends ProtocolMessageEnum> List<E> subtractRPCs(
			List<E> source, List<E> exclude, E anyValue) {
		if (source.isEmpty() || exclude.isEmpty()) {
			return source;
		}
		// Exclude has wildcard → remove entire service.
		if (exclude.contains(anyValue)) {
			return List.of();
		}
		Set<E> excludeSet = new HashSet<>(exclude);
		return source.stream().filter(e -> !excludeSet.contains(e)).toList();
	}

	/**
	 * Scopes entitlements to the target service.
	 * If the target is "kernel", all entitlements are preserved.
	 * Otherwise, only the target service's entitlements are kept.
	 */
	private static Entitlements.TokenEntitlements scopeToService(
			Entitlements.TokenEntitlements entitlements, String targetAud) {
		// If the target is kernel, preserve all entitlements.
		if (Kernel.getDescriptor().getPackage().equals(targetAud)) {
			return entitlements;
		}

		Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();
		switch (targetAud) {
			case "sentinel" -> builder.addAllSentinel(entitlements.getSentinelList());
			case "gateway" -> builder.addAllGateway(entitlements.getGatewayList());
			case "mcp" -> builder.addAllMcp(entitlements.getMcpList());
			case "eventbus" -> builder.addAllEventbus(entitlements.getEventbusList());
			case "fleetwood" -> builder.addAllFleetwood(entitlements.getFleetwoodList());
			case "anthropic" -> builder.addAllAnthropic(entitlements.getAnthropicList());
			case "github" -> builder.addAllGithub(entitlements.getGithubList());
			case "gitlab" -> builder.addAllGitlab(entitlements.getGitlabList());
			case "openai" -> builder.addAllOpenai(entitlements.getOpenaiList());
			default -> {
				// Unknown service — no entitlements scoped.
			}
		}
		return builder.build();
	}
}
