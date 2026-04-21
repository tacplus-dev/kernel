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
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.TokenExchangeGrpc;
import com.google.protobuf.util.JsonFormat;
import io.grpc.Context;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.time.Instant;
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
		Entitlements.TokenEntitlements srcEnt = inputToken.getServiceEntitlements();
		if (srcEnt != null) {
			try {
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
				newToken.setServiceEntitlements(result);
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

	// Generic per-service entitlement result used by intersect/subtract helpers.
	private record SvcEnt<E>(boolean any, List<E> rpcs) {}

	/**
	 * Intersects two per-service entitlement grants. Returns the narrower of the two.
	 * any+any→any, any+specific→specific, specific+specific→intersection.
	 */
	private static <E> SvcEnt<E> intersectSvc(boolean anyA, List<E> rpcsA, boolean anyB, List<E> rpcsB) {
		if (!anyA && rpcsA.isEmpty()) return new SvcEnt<>(false, List.of());
		if (!anyB && rpcsB.isEmpty()) return new SvcEnt<>(false, List.of());
		if (anyA && anyB) return new SvcEnt<>(true, List.of());
		if (anyA) return new SvcEnt<>(false, rpcsB);
		if (anyB) return new SvcEnt<>(false, rpcsA);
		Set<E> setA = new HashSet<>(rpcsA);
		return new SvcEnt<>(false, rpcsB.stream().filter(setA::contains).toList());
	}

	/**
	 * Subtracts exclude from source per-service entitlements.
	 * any-exclude_any→empty, specific-exclude_any→empty, specific-specific→difference.
	 * any-specific stays any (can't enumerate "all except N" in this model).
	 */
	private static <E> SvcEnt<E> subtractSvc(boolean anyA, List<E> rpcsA, boolean anyB, List<E> rpcsB) {
		if (!anyA && rpcsA.isEmpty()) return new SvcEnt<>(false, List.of());
		if (!anyB && rpcsB.isEmpty()) return new SvcEnt<>(anyA, rpcsA);
		if (anyB) return new SvcEnt<>(false, List.of());
		if (anyA) return new SvcEnt<>(true, List.of());
		Set<E> excludeSet = new HashSet<>(rpcsB);
		return new SvcEnt<>(false, rpcsA.stream().filter(e -> !excludeSet.contains(e)).toList());
	}

	/**
	 * Intersects source entitlements with the include set.
	 * For each service, only RPCs present in BOTH source and include are kept.
	 * If source has any=true, the include set is used as-is for that service.
	 */
	private static Entitlements.TokenEntitlements intersectEntitlements(
			Entitlements.TokenEntitlements source,
			Entitlements.TokenEntitlements include) {
		Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();

		var sentinel = intersectSvc(source.getSentinel().getAny(), source.getSentinel().getSentinelList(),
				include.getSentinel().getAny(), include.getSentinel().getSentinelList());
		if (sentinel.any() || !sentinel.rpcs().isEmpty())
			builder.setSentinel(Entitlements.SentinelEntitlements.newBuilder()
					.setAny(sentinel.any()).addAllSentinel(sentinel.rpcs()).build());

		var gateway = intersectSvc(source.getGateway().getAny(), source.getGateway().getGatewayList(),
				include.getGateway().getAny(), include.getGateway().getGatewayList());
		if (gateway.any() || !gateway.rpcs().isEmpty())
			builder.setGateway(Entitlements.GatewayEntitlements.newBuilder()
					.setAny(gateway.any()).addAllGateway(gateway.rpcs()).build());

		var mcp = intersectSvc(source.getMcp().getAny(), source.getMcp().getMcpList(),
				include.getMcp().getAny(), include.getMcp().getMcpList());
		if (mcp.any() || !mcp.rpcs().isEmpty())
			builder.setMcp(Entitlements.McpEntitlements.newBuilder()
					.setAny(mcp.any()).addAllMcp(mcp.rpcs()).build());

		var eventbus = intersectSvc(source.getEventbus().getAny(), source.getEventbus().getEventbusList(),
				include.getEventbus().getAny(), include.getEventbus().getEventbusList());
		if (eventbus.any() || !eventbus.rpcs().isEmpty())
			builder.setEventbus(Entitlements.EventbusEntitlements.newBuilder()
					.setAny(eventbus.any()).addAllEventbus(eventbus.rpcs()).build());

		var fleetwood = intersectSvc(source.getFleetwood().getAny(), source.getFleetwood().getFleetwoodList(),
				include.getFleetwood().getAny(), include.getFleetwood().getFleetwoodList());
		if (fleetwood.any() || !fleetwood.rpcs().isEmpty())
			builder.setFleetwood(Entitlements.FleetwoodEntitlements.newBuilder()
					.setAny(fleetwood.any()).addAllFleetwood(fleetwood.rpcs()).build());

		var anthropic = intersectSvc(source.getAnthropic().getAny(), source.getAnthropic().getAnthropicList(),
				include.getAnthropic().getAny(), include.getAnthropic().getAnthropicList());
		if (anthropic.any() || !anthropic.rpcs().isEmpty())
			builder.setAnthropic(Entitlements.AnthropicEntitlements.newBuilder()
					.setAny(anthropic.any()).addAllAnthropic(anthropic.rpcs()).build());

		var github = intersectSvc(source.getGithub().getAny(), source.getGithub().getGithubList(),
				include.getGithub().getAny(), include.getGithub().getGithubList());
		if (github.any() || !github.rpcs().isEmpty())
			builder.setGithub(Entitlements.GithubEntitlements.newBuilder()
					.setAny(github.any()).addAllGithub(github.rpcs()).build());

		var gitlab = intersectSvc(source.getGitlab().getAny(), source.getGitlab().getGitlabList(),
				include.getGitlab().getAny(), include.getGitlab().getGitlabList());
		if (gitlab.any() || !gitlab.rpcs().isEmpty())
			builder.setGitlab(Entitlements.GitlabEntitlements.newBuilder()
					.setAny(gitlab.any()).addAllGitlab(gitlab.rpcs()).build());

		var openai = intersectSvc(source.getOpenai().getAny(), source.getOpenai().getOpenaiList(),
				include.getOpenai().getAny(), include.getOpenai().getOpenaiList());
		if (openai.any() || !openai.rpcs().isEmpty())
			builder.setOpenai(Entitlements.OpenaiEntitlements.newBuilder()
					.setAny(openai.any()).addAllOpenai(openai.rpcs()).build());

		return builder.build();
	}

	/**
	 * Subtracts exclude entitlements from source.
	 * For each service, RPCs in the exclude set are removed from the source.
	 * any=true in exclude removes all RPCs for that service.
	 */
	private static Entitlements.TokenEntitlements subtractEntitlements(
			Entitlements.TokenEntitlements source,
			Entitlements.TokenEntitlements exclude) {
		Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();

		var sentinel = subtractSvc(source.getSentinel().getAny(), source.getSentinel().getSentinelList(),
				exclude.getSentinel().getAny(), exclude.getSentinel().getSentinelList());
		if (sentinel.any() || !sentinel.rpcs().isEmpty())
			builder.setSentinel(Entitlements.SentinelEntitlements.newBuilder()
					.setAny(sentinel.any()).addAllSentinel(sentinel.rpcs()).build());

		var gateway = subtractSvc(source.getGateway().getAny(), source.getGateway().getGatewayList(),
				exclude.getGateway().getAny(), exclude.getGateway().getGatewayList());
		if (gateway.any() || !gateway.rpcs().isEmpty())
			builder.setGateway(Entitlements.GatewayEntitlements.newBuilder()
					.setAny(gateway.any()).addAllGateway(gateway.rpcs()).build());

		var mcp = subtractSvc(source.getMcp().getAny(), source.getMcp().getMcpList(),
				exclude.getMcp().getAny(), exclude.getMcp().getMcpList());
		if (mcp.any() || !mcp.rpcs().isEmpty())
			builder.setMcp(Entitlements.McpEntitlements.newBuilder()
					.setAny(mcp.any()).addAllMcp(mcp.rpcs()).build());

		var eventbus = subtractSvc(source.getEventbus().getAny(), source.getEventbus().getEventbusList(),
				exclude.getEventbus().getAny(), exclude.getEventbus().getEventbusList());
		if (eventbus.any() || !eventbus.rpcs().isEmpty())
			builder.setEventbus(Entitlements.EventbusEntitlements.newBuilder()
					.setAny(eventbus.any()).addAllEventbus(eventbus.rpcs()).build());

		var fleetwood = subtractSvc(source.getFleetwood().getAny(), source.getFleetwood().getFleetwoodList(),
				exclude.getFleetwood().getAny(), exclude.getFleetwood().getFleetwoodList());
		if (fleetwood.any() || !fleetwood.rpcs().isEmpty())
			builder.setFleetwood(Entitlements.FleetwoodEntitlements.newBuilder()
					.setAny(fleetwood.any()).addAllFleetwood(fleetwood.rpcs()).build());

		var anthropic = subtractSvc(source.getAnthropic().getAny(), source.getAnthropic().getAnthropicList(),
				exclude.getAnthropic().getAny(), exclude.getAnthropic().getAnthropicList());
		if (anthropic.any() || !anthropic.rpcs().isEmpty())
			builder.setAnthropic(Entitlements.AnthropicEntitlements.newBuilder()
					.setAny(anthropic.any()).addAllAnthropic(anthropic.rpcs()).build());

		var github = subtractSvc(source.getGithub().getAny(), source.getGithub().getGithubList(),
				exclude.getGithub().getAny(), exclude.getGithub().getGithubList());
		if (github.any() || !github.rpcs().isEmpty())
			builder.setGithub(Entitlements.GithubEntitlements.newBuilder()
					.setAny(github.any()).addAllGithub(github.rpcs()).build());

		var gitlab = subtractSvc(source.getGitlab().getAny(), source.getGitlab().getGitlabList(),
				exclude.getGitlab().getAny(), exclude.getGitlab().getGitlabList());
		if (gitlab.any() || !gitlab.rpcs().isEmpty())
			builder.setGitlab(Entitlements.GitlabEntitlements.newBuilder()
					.setAny(gitlab.any()).addAllGitlab(gitlab.rpcs()).build());

		var openai = subtractSvc(source.getOpenai().getAny(), source.getOpenai().getOpenaiList(),
				exclude.getOpenai().getAny(), exclude.getOpenai().getOpenaiList());
		if (openai.any() || !openai.rpcs().isEmpty())
			builder.setOpenai(Entitlements.OpenaiEntitlements.newBuilder()
					.setAny(openai.any()).addAllOpenai(openai.rpcs()).build());

		return builder.build();
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
			case "sentinel"  -> { if (entitlements.hasSentinel())  builder.setSentinel(entitlements.getSentinel()); }
			case "gateway"   -> { if (entitlements.hasGateway())   builder.setGateway(entitlements.getGateway()); }
			case "mcp"       -> { if (entitlements.hasMcp())       builder.setMcp(entitlements.getMcp()); }
			case "eventbus"  -> { if (entitlements.hasEventbus())  builder.setEventbus(entitlements.getEventbus()); }
			case "fleetwood" -> { if (entitlements.hasFleetwood()) builder.setFleetwood(entitlements.getFleetwood()); }
			case "anthropic" -> { if (entitlements.hasAnthropic()) builder.setAnthropic(entitlements.getAnthropic()); }
			case "github"    -> { if (entitlements.hasGithub())    builder.setGithub(entitlements.getGithub()); }
			case "gitlab"    -> { if (entitlements.hasGitlab())    builder.setGitlab(entitlements.getGitlab()); }
			case "openai"    -> { if (entitlements.hasOpenai())    builder.setOpenai(entitlements.getOpenai()); }
			default -> {
				// Unknown service — no entitlements scoped.
			}
		}
		return builder.build();
	}
}
