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
	/** Returns true if the list contains the ANY enum value (number 99). */
	private static <E extends com.google.protobuf.ProtocolMessageEnum> boolean containsAny(List<E> rpcs) {
		return rpcs.stream().anyMatch(r -> r.getNumber() == 99);
	}

	/**
	 * Intersects two per-service RPC lists. Returns the narrower of the two.
	 * ANY+ANY→ANY, ANY+specific→specific, specific+specific→intersection.
	 */
	private static <E extends com.google.protobuf.ProtocolMessageEnum> List<E> intersectRPCs(List<E> a, List<E> b) {
		if (a.isEmpty() || b.isEmpty()) return List.of();
		boolean anyA = containsAny(a), anyB = containsAny(b);
		if (anyA && anyB) return a.stream().filter(e -> e.getNumber() == 99).limit(1).toList();
		if (anyA) return b;
		if (anyB) return a;
		Set<E> setA = new HashSet<>(a);
		return b.stream().filter(setA::contains).toList();
	}

	/**
	 * Subtracts exclude from source RPC list.
	 * ANY-excludeANY→empty, specific-excludeANY→empty, ANY-specific stays ANY.
	 */
	private static <E extends com.google.protobuf.ProtocolMessageEnum> List<E> subtractRPCs(List<E> a, List<E> b) {
		if (a.isEmpty() || b.isEmpty()) return a;
		if (containsAny(b)) return List.of();
		if (containsAny(a)) return a; // can't enumerate "all except N"
		Set<E> excludeSet = new HashSet<>(b);
		return a.stream().filter(e -> !excludeSet.contains(e)).toList();
	}

	/**
	 * Intersects source entitlements with the include set.
	 * For each service, only RPCs present in BOTH source and include are kept.
	 * If source has any=true, the include set is used as-is for that service.
	 */
	private static Entitlements.TokenEntitlements intersectEntitlements(
			Entitlements.TokenEntitlements source,
			Entitlements.TokenEntitlements include) {
		var b = Entitlements.TokenEntitlements.newBuilder();
		var sentinel = intersectRPCs(source.getSentinelList(), include.getSentinelList());
		if (!sentinel.isEmpty()) b.addAllSentinel(sentinel);
		var gateway = intersectRPCs(source.getGatewayList(), include.getGatewayList());
		if (!gateway.isEmpty()) b.addAllGateway(gateway);
		var mcp = intersectRPCs(source.getMcpList(), include.getMcpList());
		if (!mcp.isEmpty()) b.addAllMcp(mcp);
		var eventbus = intersectRPCs(source.getEventbusList(), include.getEventbusList());
		if (!eventbus.isEmpty()) b.addAllEventbus(eventbus);
		var fleetwood = intersectRPCs(source.getFleetwoodList(), include.getFleetwoodList());
		if (!fleetwood.isEmpty()) b.addAllFleetwood(fleetwood);
		var anthropic = intersectRPCs(source.getAnthropicList(), include.getAnthropicList());
		if (!anthropic.isEmpty()) b.addAllAnthropic(anthropic);
		var github = intersectRPCs(source.getGithubList(), include.getGithubList());
		if (!github.isEmpty()) b.addAllGithub(github);
		var gitlab = intersectRPCs(source.getGitlabList(), include.getGitlabList());
		if (!gitlab.isEmpty()) b.addAllGitlab(gitlab);
		var openai = intersectRPCs(source.getOpenaiList(), include.getOpenaiList());
		if (!openai.isEmpty()) b.addAllOpenai(openai);
		return b.build();
	}

	private static Entitlements.TokenEntitlements subtractEntitlements(
			Entitlements.TokenEntitlements source,
			Entitlements.TokenEntitlements exclude) {
		var b = Entitlements.TokenEntitlements.newBuilder();
		var sentinel = subtractRPCs(source.getSentinelList(), exclude.getSentinelList());
		if (!sentinel.isEmpty()) b.addAllSentinel(sentinel);
		var gateway = subtractRPCs(source.getGatewayList(), exclude.getGatewayList());
		if (!gateway.isEmpty()) b.addAllGateway(gateway);
		var mcp = subtractRPCs(source.getMcpList(), exclude.getMcpList());
		if (!mcp.isEmpty()) b.addAllMcp(mcp);
		var eventbus = subtractRPCs(source.getEventbusList(), exclude.getEventbusList());
		if (!eventbus.isEmpty()) b.addAllEventbus(eventbus);
		var fleetwood = subtractRPCs(source.getFleetwoodList(), exclude.getFleetwoodList());
		if (!fleetwood.isEmpty()) b.addAllFleetwood(fleetwood);
		var anthropic = subtractRPCs(source.getAnthropicList(), exclude.getAnthropicList());
		if (!anthropic.isEmpty()) b.addAllAnthropic(anthropic);
		var github = subtractRPCs(source.getGithubList(), exclude.getGithubList());
		if (!github.isEmpty()) b.addAllGithub(github);
		var gitlab = subtractRPCs(source.getGitlabList(), exclude.getGitlabList());
		if (!gitlab.isEmpty()) b.addAllGitlab(gitlab);
		var openai = subtractRPCs(source.getOpenaiList(), exclude.getOpenaiList());
		if (!openai.isEmpty()) b.addAllOpenai(openai);
		return b.build();
	}

	/**
	 * Scopes entitlements to the target service (strips all other services).
	 * If the target is "kernel", all entitlements are preserved.
	 */
	/**
	 * Scopes a full TokenEntitlements down to only the grants relevant to targetAud
	 * and its vservices. azp constraints are preserved whenever any grants survive.
	 * Returns the full entitlements unchanged when targetAud is kernel (aud:kernel
	 * access tokens carry all entitlements). Returns an empty result for unknown
	 * service names.
	 */
	static Entitlements.TokenEntitlements scopeToService(
			Entitlements.TokenEntitlements entitlements, String targetAud) {
		if (Kernel.getDescriptor().getPackage().equals(targetAud)) return entitlements;
		var b = Entitlements.TokenEntitlements.newBuilder();
		switch (targetAud) {
			case "sentinel"  -> b.addAllSentinel(entitlements.getSentinelList());
			case "gateway"   -> b.addAllGateway(entitlements.getGatewayList());
			case "mcp"       -> b.addAllMcp(entitlements.getMcpList());
			case "eventbus"  -> b.addAllEventbus(entitlements.getEventbusList())
			                     .addAllClaudesensor(entitlements.getClaudesensorList());
			case "fleetwood" -> b.addAllFleetwood(entitlements.getFleetwoodList());
			case "anthropic" -> b.addAllAnthropic(entitlements.getAnthropicList());
			case "github"    -> b.addAllGithub(entitlements.getGithubList());
			case "gitlab"    -> b.addAllGitlab(entitlements.getGitlabList());
			case "openai"    -> b.addAllOpenai(entitlements.getOpenaiList());
			case "mock"      -> b.addAllMock(entitlements.getMockList());
			case "argus"     -> b.addAllArgus(entitlements.getArgusList());
			// unknown service: return empty entitlements
			default -> { return b.build(); }
		}
		b.addAllAzp(entitlements.getAzpList());
		return b.build();
	}
}
