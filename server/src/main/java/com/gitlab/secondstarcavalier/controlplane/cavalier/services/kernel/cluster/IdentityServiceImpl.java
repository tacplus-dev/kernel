// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.grants.Grants;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.token.Helpers;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.token.TokenOuterClass.JwtPayloadType;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.token.TokenOuterClass.TokenUse;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.token.TokenOuterClass.SubType;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import io.grpc.Status;

import com.google.protobuf.Descriptors;
import com.google.protobuf.Message;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
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
 * Authenticates caller via bearer token (which must carry a canonical
 * SPIFFE URI in its {@code sub} claim — see {@link SpiffeIds}), creates a
 * per-SPIFFE-URI intermediate CA (signed by root CA, pathlen:0), signs the
 * caller-provided public key with the SPIFFE URI as URI SAN, and returns
 * an X509CertChain (leaf + intermediate). The same SPIFFE URI keys the
 * intermediate CA in {@link TlsCertServiceImpl}, so both cert-issuing paths
 * produce certs under one consistent per-service intermediate.</li>
 * </ul>
 *
 * <p><b>NOTE:</b> X509Mint is the legacy one-shot cert path retained for
 * non-Rust services (e.g. EventBus) until their tacplus templates gain
 * ManageCert-based auto-TLS (task #31). New services should use
 * {@link TlsCertServiceImpl}'s {@code ManageCert} bidi stream instead.
 */
public class IdentityServiceImpl implements Mint.MintHandler {

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
	// TODO: Replace with Helpers.tokenUseToString(TokenUse.TOKEN_USE_OFFLINE) once
	// tacplus is rebuilt with token.proto TOKEN_USE_OFFLINE=7 (commit 9acf59f).
	// The literal matches that enum's (spec.json_return_value).
	private static final String TOKEN_USE_OFFLINE = "offline";
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

	// Plausible-kid gate, mirroring SecurityInterceptor/SecurityAuthenticator (Phase 0.1
	// DoS-hardening). Production kids are base64url(24 bytes) = 32 chars of [A-Za-z0-9_-]
	// (see generateRandomID); we accept the permissive-but-safe superset up to KID_MAX_LENGTH
	// so a bogus/oversized kid is cheaply rejected before any key-set scan.
	private static final int KID_MAX_LENGTH =
			Integer.getInteger("tacplus.auth.kidMaxLength", 128);
	private static final Pattern KID_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{1,512}$");

	/**
	 * Phase 0.1 fast-rejection gate: is {@code kid} a plausible key id worth scanning
	 * the verifying-key set for? Cheap format + length check (configurable cap via
	 * {@code tacplus.auth.kidMaxLength}, permissive {@code [A-Za-z0-9_-]} charset) so an
	 * attacker-supplied bogus/oversized kid is rejected before any O(keys) lookup. This
	 * is the single implementation; every externally-influenced kid scan calls it and
	 * then throws its own call-site-appropriate status on {@code false}. Validation only:
	 * deliberately NO sleep/retry/semaphore — the blocking just-published-key retry lives
	 * exclusively on the cross-kernel propagation (data-plane interceptor) path.
	 */
	private static boolean isPlausibleKid(String kid) {
		return kid != null
				&& kid.length() <= KID_MAX_LENGTH
				&& KID_FORMAT.matcher(kid).matches();
	}

	// v3 project-scoping session claims, stamped on a user's refresh/offline token
	// from the OPA result at login. They let a refresh→access exchange scope the
	// AT to one authorized project (and switch projects) without re-running login.
	// authorized_projects is a JSON array of leaf names; default_project is a leaf.
	private static final String CLAIM_AUTHORIZED_PROJECTS = "authorized_projects";
	private static final String CLAIM_DEFAULT_PROJECT = "default_project";


	/** Intermediate CA lifetime: 10 years. */
	private static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	private static final long DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 2592000; // 30 days
	private static final long DEFAULT_OFFLINE_TOKEN_LIFETIME_SECONDS = 7776000; // 90 days

	/** Default cred_pair → C2S token lifetime (MintClientToken). */
	private static final long DEFAULT_TOKEN_TTL_SECONDS = 3600; // 1 hour

	/** Maximum lifetime of an externally-minted token (MintExternalToken). */
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

	static record ExternalSigningSelection(
			KeyRotator.SigAlg signingAlg,
			ImmutableKey signingKey) {}

	static KeyRotator.SigAlg externalSigningAlgForKeyType(KeyOuterClass.KeyType requestedKeyType)
			throws ProtoException {
		if (requestedKeyType == null
				|| requestedKeyType == KeyOuterClass.KeyType.KEY_TYPE_UNDEFINED) {
			return KeyRotator.SigAlg.ED25519;
		}

		return switch (requestedKeyType) {
			case KEY_TYPE_OKP -> KeyRotator.SigAlg.ED25519;
			case KEY_TYPE_EC -> KeyRotator.SigAlg.ES256;
			case KEY_TYPE_RSA -> throw ProtoException.newErrMissingInvalidData(null,
					"requested_signing_key_type KEY_TYPE_RSA is not supported by kernel signing keys");
			case UNRECOGNIZED -> throw ProtoException.newErrMissingInvalidData(null,
					"requested_signing_key_type has unknown enum value");
			default -> throw ProtoException.newErrMissingInvalidData(null,
					"unsupported requested_signing_key_type: %s", requestedKeyType);
		};
	}

	static ExternalSigningSelection externalSigningKeyForRequest(
			KeyRotator keyRotator,
			KeyOuterClass.KeyType requestedKeyType) throws ProtoException {
		KeyRotator.SigAlg signingAlg = externalSigningAlgForKeyType(requestedKeyType);
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(signingAlg);
		if (signingKey == null) {
			throw ProtoException.newErrGeneral(null,
					"no active signing key for requested_signing_key_type "
							+ requestedKeyType + " (" + signingAlg + ")");
		}

		return new ExternalSigningSelection(signingAlg, signingKey);
	}

	private final long defaultTokenExpirySeconds;
	private final long maxTokenLifetimeSeconds;
	private final long offlineTokenLifetimeSeconds;
	private final KeyRotator keyRotator;
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	private final Supplier<List<Kernel.Delegate>> delegatesReader;
	private final Map<String, List<String>> serviceEntitlements;
	private final ImmutableCertChain signingCa;
	private final Function<String, X509.X509CertChain> serviceCaReader;
	private final BiConsumer<String, X509.X509CertChain> serviceCaWriter;
	private final Supplier<String> trustDomainReader;
	private final String tokenIssuer;
	// Phase 2: Kubernetes service-account token credential support. The verifier
	// is a swappable seam (TokenReview vs local JWKS — review M1 / plan Q6); it
	// defaults to UnwiredKubernetesTokenVerifier (fails UNIMPLEMENTED) until the
	// real impl lands with operator Phase 3. The audience is the configured
	// kernel/Cavalier workload audience the projected token must carry — never the
	// kmaker audience (plan invariant lines 341-349).
	private final KubernetesTokenVerifier kubernetesTokenVerifier;
	private final String kubernetesTokenAudience;
	@Nullable
	private final OpaEvalGrpcClient opaEvalClient;
	@Nullable
	private final com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient;
	private final ConfigMap configMap;

	public IdentityServiceImpl(
			long defaultTokenExpirySeconds,
			long maxTokenLifetimeSeconds,
			long offlineTokenLifetimeSeconds,
			KeyRotator keyRotator,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			Supplier<List<Kernel.Delegate>> delegatesReader,
			Map<String, List<String>> serviceEntitlements,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter,
			Supplier<String> trustDomainReader,
			String tokenIssuer,
			@Nullable OpaEvalGrpcClient opaEvalClient,
			@Nullable com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient,
			ConfigMap configMap,
			@Nullable KubernetesTokenVerifier kubernetesTokenVerifier,
			@Nullable String kubernetesTokenAudience) {
		this.defaultTokenExpirySeconds = defaultTokenExpirySeconds > 0 ? defaultTokenExpirySeconds : 3600;
		this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds > 0 ? maxTokenLifetimeSeconds : DEFAULT_MAX_TOKEN_LIFETIME_SECONDS;
		this.offlineTokenLifetimeSeconds = offlineTokenLifetimeSeconds > 0 ? offlineTokenLifetimeSeconds : DEFAULT_OFFLINE_TOKEN_LIFETIME_SECONDS;
		this.keyRotator = keyRotator;
		this.verifyingKeysReader = verifyingKeysReader;
		this.delegatesReader = delegatesReader;
		this.serviceEntitlements = serviceEntitlements != null ? serviceEntitlements : Map.of();
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
		this.trustDomainReader = trustDomainReader;
		this.tokenIssuer = (tokenIssuer != null && !tokenIssuer.isEmpty()) ? tokenIssuer : Kernel.getDescriptor().getPackage();
		this.opaEvalClient = opaEvalClient;
		this.proxyPolicyOpaClient = proxyPolicyOpaClient;
		this.configMap = configMap;
		// Default to the fail-closed UNIMPLEMENTED verifier so an un-wired kernel
		// never silently accepts a kubernetes_token.
		this.kubernetesTokenVerifier =
				kubernetesTokenVerifier != null ? kubernetesTokenVerifier : new UnwiredKubernetesTokenVerifier();
		this.kubernetesTokenAudience = kubernetesTokenAudience != null ? kubernetesTokenAudience : "";
	}

	// ========================================================================
	// MintToken RPC (legacy — delegates to doTokenMint)
	// ========================================================================

	@Override
	public Tokenrequest.TokenMintResponse mintToken(Caller caller, Tokenrequest.TokenMintRequest request)
			throws ProtoException {
		try {
			return doTokenMint(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("TokenMint failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "token mint failed: " + e.getMessage(), e);
		}
	}

	// ========================================================================
	// MintServiceToken RPC (S2S bootstrap — replaces TokenMint for S2S)
	// ========================================================================

	@Override
	public Tokenrequest.TokenMintResponse mintServiceToken(Caller caller,
			Tokenrequest.MintServiceTokenRequest request) throws ProtoException {
		try {
			// ---- Step 1 (H5): reject >1 / 0 credential proofs BEFORE any
			// verifier-specific logic (no JWT parse, no TokenReview, no network).
			// The oneof already collapses new clients to one credential, but a raw
			// or pre-oneof client could still set multiple flat fields; this guard
			// defends that case and is the ordering the malformed/multi-credential
			// tests assert fires before the verifier seam is ever touched.
			int credentialCount = 0;
			if (!request.getInputToken().isEmpty()) {
				credentialCount++;
			}
			if (request.hasCloudProof()) {
				credentialCount++;
			}
			if (!request.getKubernetesToken().isEmpty()) {
				credentialCount++;
			}
			if (credentialCount > 1) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exactly one credential proof must be set (got " + credentialCount + ")");
			}

			// ---- Step 5: route by credential type instead of blindly copying into
			// the legacy mint request. Each path resolves a Delegate first, then
			// passes the RESOLVED delegate identity into the continuity cross-check
			// (the H5 confused-deputy fix) — never a token-derived subject.
			// Route by credential field presence. The credentials are flat proto
			// fields (not a oneof) because the Rust/Go identity-manager templates
			// construct the request with flat field names; exclusivity is enforced
			// by the credentialCount guard above, so exactly one is set here.
			if (!request.getKubernetesToken().isEmpty()) {
				return mintFromKubernetesToken(request);
			} else if (request.hasCloudProof()) {
				// cloud_proof is a no-op in the legacy router today (it is copied but
				// never read). Route it to an explicit UNIMPLEMENTED stub rather than
				// silently dropping it, until the cloud path is audited (plan Q7).
				throw new StatusException(Status.UNIMPLEMENTED,
						"cloud_proof credential is not yet implemented in the mint path");
			} else if (!request.getInputToken().isEmpty()) {
				return doTokenMint(adaptToLegacy(request));
			} else {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exactly one credential proof must be set (input_token, cloud_proof, or kubernetes_token)");
			}
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MintServiceToken failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "service token mint failed: " + e.getMessage(), e);
		}
	}

	/** Maps the split S2S request onto the legacy TokenMintRequest for the input_token path. */
	private Tokenrequest.TokenMintRequest adaptToLegacy(Tokenrequest.MintServiceTokenRequest request) {
		return Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(request.getInputToken())
				.setContinuityToken(request.getContinuityToken())
				.setAud(request.getAud())
				.setExp(request.getExp())
				.setTokenPurpose(request.getTokenPurpose())
				.setLocalityToken(request.getLocalityToken())
				.build();
	}

	/**
	 * Kubernetes service-account token path (Phase 2).
	 *
	 * <p>Validates the projected SA token via the swappable
	 * {@link KubernetesTokenVerifier}, maps the verified (namespace, SA) to a
	 * Delegate, then mints exactly as the cred_pair path does after a delegate
	 * match — so the K8s path's token output is identical to the cred_pair path's.
	 */
	private Tokenrequest.TokenMintResponse mintFromKubernetesToken(
			Tokenrequest.MintServiceTokenRequest request) throws StatusException {

		String token = request.getKubernetesToken();
		// Structural pre-checks run BEFORE the verifier seam so a malformed token
		// never spends a verifier round-trip / retry budget (H5 ordering).
		if (token.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "kubernetes_token is empty");
		}
		if (!isPlausibleJwt(token)) {
			throw new StatusException(Status.INVALID_ARGUMENT, "kubernetes_token is not a well-formed JWT");
		}

		VerifiedK8sIdentity identity;
		try {
			identity = kubernetesTokenVerifier.verify(token, kubernetesTokenAudience);
		} catch (KubernetesTokenVerifier.K8sTokenVerificationException e) {
			// The verifier owns the status (UNAUTHENTICATED for bad token/audience,
			// UNAVAILABLE for backend down, UNIMPLEMENTED when un-wired). Never
			// collapse to INTERNAL (review L1).
			throw new StatusException(e.status(), e.getMessage());
		}

		// Belt-and-suspenders audience re-check (review M4): even though the
		// verifier was asked for kubernetesTokenAudience, re-assert the returned
		// audiences actually contain it, so a kmaker-only token cannot slip through.
		if (!kubernetesTokenAudience.isEmpty() && !identity.audiences().contains(kubernetesTokenAudience)) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"kubernetes_token audiences " + identity.audiences()
							+ " do not include required kernel audience");
		}

		Kernel.Delegate matchedDelegate = findDelegateByKubernetesServiceAccount(
				identity.kubernetesNamespace(), identity.kubernetesServiceAccount());
		if (matchedDelegate == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no delegate authorizes Kubernetes service account "
							+ identity.kubernetesNamespace() + "/" + identity.kubernetesServiceAccount());
		}

		String delegateName = matchedDelegate.getName();
		String spiffeId = SpiffeIds.build(trustDomainReader.get(), delegateName);

		// Capture pod extras for audit (advisory for the service-token path).
		if (!identity.podExtras().isEmpty()) {
			logger.info("Kubernetes SA {}/{} -> delegate {} (pod extras: {})",
					identity.kubernetesNamespace(), identity.kubernetesServiceAccount(),
					delegateName, identity.podExtras());
		}

		String instanceId;
		if (!request.getContinuityToken().isEmpty()) {
			// H5 cross-check: bind the continuity token to the RESOLVED delegate's
			// canonical SPIFFE subject (what the prior refresh token actually
			// carries), NOT to anything derived from the presented K8s token.
			instanceId = resolveInstanceIdFromContinuityToken(
					request.getContinuityToken(), spiffeId);
		} else {
			instanceId = UUID.randomUUID().toString();
			logger.info("Generated new instance_id={} for sub={}", instanceId, delegateName);
		}

		Map<String, Object> extraClaims = new java.util.LinkedHashMap<>();
		extraClaims.put("instance_id", instanceId);
		extraClaims.put("sub_type", SUB_TYPE_SERVICE);

		// Mint via the shared mintRefreshToken helper. The legacy request carries
		// only the "what to mint" fields here (no input_token). This is now the sole
		// service-bootstrap caller of mintRefreshToken (the static cred_pair
		// bootstrap arm that previously also called it has been removed).
		Tokenrequest.TokenMintRequest mintShape = Tokenrequest.TokenMintRequest.newBuilder()
				.setAud(request.getAud())
				.setExp(request.getExp())
				.setTokenPurpose(request.getTokenPurpose())
				.setLocalityToken(request.getLocalityToken())
				.build();
		return mintRefreshToken(spiffeId, Kernel.getDescriptor().getPackage(), mintShape, extraClaims);
	}

	/** Resolves a Delegate by a verified (K8s namespace, service account) pair. */
	private Kernel.Delegate findDelegateByKubernetesServiceAccount(String namespace, String serviceAccount) {
		for (Kernel.Delegate delegate : delegatesReader.get()) {
			for (Kernel.KubernetesServiceAccountMatcher matcher : delegate.getKubernetesServiceAccountsList()) {
				if (matcher.getKubernetesNamespace().equals(namespace)
						&& matcher.getKubernetesServiceAccount().equals(serviceAccount)) {
					return delegate;
				}
			}
		}
		return null;
	}

	/**
	 * Cheap structural check that a string is shaped like a compact JWS
	 * (three base64url segments). Lets the k8s path reject garbage before
	 * touching the verifier seam.
	 */
	private static boolean isPlausibleJwt(String token) {
		if (token == null) {
			return false;
		}
		String[] parts = token.split("\\.", -1);
		if (parts.length != 3) {
			return false;
		}
		for (String part : parts) {
			if (part.isEmpty() || !JWT_SEGMENT_PATTERN.matcher(part).matches()) {
				return false;
			}
		}
		return true;
	}

	private static final Pattern JWT_SEGMENT_PATTERN = Pattern.compile("[A-Za-z0-9_-]+");

	// ========================================================================
	// MintUserToken RPC (C2S delegation — replaces TokenMint delegation path)
	// ========================================================================

	@Override
	public Tokenrequest.TokenMintResponse mintUserToken(Caller caller,
			Tokenrequest.MintUserTokenRequest request) throws ProtoException {
		try {
			return doMintUserToken(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MintUserToken failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "user token mint failed: " + e.getMessage(), e);
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
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set. Same UNAUTHENTICATED-unknown-key contract as the miss below;
		// validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"caller token signed with unknown key: " + kid);
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

		// Resolve and mint via shared internal method.
		return mintUserTokenInternal(request.getSubject(), request.getClaims(),
				request.getExp(), request.getTraceId(), delegate.getName(),
				request.getOfflineAccess());
	}

	/**
	 * Internal token minting: resolves entitlements via OPA, creates refresh + access tokens.
	 * Used by both MintUserToken (broker-authenticated) and CliTokenBroker (kernel-internal).
	 */
	Tokenrequest.TokenMintResponse mintUserTokenInternal(
			String subject, com.google.protobuf.Struct claims,
			long requestedExp, String traceId, String delegateName,
			boolean offlineAccess)
			throws StatusException {

		Kernel.Delegate delegate = findDelegateByName(delegateName);
		if (delegate == null) {
			throw new StatusException(Status.INTERNAL,
					"delegate not found: " + delegateName);
		}

		// Resolve entitlements via UncleOPA.
		Userentitlements.EntitlementEvalResult opaResult = resolveEntitlementsViaOpa(claims, traceId);
		Entitlements.TokenEntitlements expanded = expandEntitlements(opaResult);

		// Mint the token.
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		// Long-lived token: an Offline Token (OT) when offline_access is requested
		// (months), otherwise a refresh token (RT). The OT is exempt from the
		// short-lived max_token_lifetime ceiling and uses the offline ceiling.
		long longLivedDefault = offlineAccess ? offlineTokenLifetimeSeconds : defaultTokenExpirySeconds;
		long maxExp = now + (offlineAccess ? offlineTokenLifetimeSeconds : maxTokenLifetimeSeconds);
		long exp;
		if (requestedExp > 0) {
			exp = requestedExp;
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		} else {
			exp = now + longLivedDefault;
		}

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(subject)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		newToken.setAzp(delegate.getName());
		if (offlineAccess) {
			newToken.setTokenUse(TOKEN_USE_OFFLINE);
		} else {
			newToken.setTokenUse(TOKEN_USE_REFRESH);
			newToken.setCustomField("typ", TOKEN_TYPE_REFRESH);
		}
		newToken.setSubType(SUB_TYPE_USER);
		// Namespace: OPA maps the caller's IdP (issuer/claims) to the tenant subtree
		// they belong to. Fall back to the cluster root when the policy returns none.
		newToken.setNamespace(namespaceFromOpaOrRoot(opaResult));

		if (claims != null) {
			newToken.setClaimsFromStruct(claims, STANDARD_JWT_CLAIMS, WELL_KNOWN_JWT_CLAIMS);
		}

		for (Map.Entry<String, String> entry : delegate.getCustomClaimsMap().entrySet()) {
			if (!STANDARD_JWT_CLAIMS.contains(entry.getKey())) {
				newToken.setCustomField(entry.getKey(), entry.getValue());
			}
		}

		// v3: record the session's authorized projects so later refresh→access
		// exchanges can scope/switch the AT's project without re-login.
		stampProjectClaims(newToken, opaResult);

		newToken.sign(signingKey);

		logger.info("MintUserToken: sub={}, azp={}, exp={}, offline={}",
				subject, delegate.getName(), exp, offlineAccess);

		// The access token is always short-lived and never outlives its parent.
		// A long-lived OT must not be mirrored into a long-lived AT.
		long accessExp = Math.min(exp, now + defaultTokenExpirySeconds);
		TokenOuterClass.Token accessProto = mintAccessFromRefresh(
				newToken, signingKey, now, accessExp, null, expanded);
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

		try {
			var inputBuilder = Userentitlements.EntitlementEvalInput.newBuilder()
					.setClaims(claims);
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
	 * Extracts and normalizes the TokenEntitlements returned by OPA. OPA may
	 * return operator/UI convenience grants such as ANTHROPIC_ANY; runtime tokens
	 * carry exact RPC grants only.
	 */
	private static Entitlements.TokenEntitlements expandEntitlements(
			Userentitlements.EntitlementEvalResult result) {
		return normalizeServiceEntitlements(result.getTokenEntitlements());
	}

	/**
	 * JWTs carry service_entitlements as flat grant strings:
	 * {"grants":["OPENAI_PROXY_CREATE_CHAT_COMPLETION"],"azp":["delegate"]}.
	 * The generated proto may be either the older repeated EntitlementGrant
	 * message or the newer repeated string shape, so conversion is descriptor-
	 * driven during the transition.
	 */
	private static void setFlatServiceEntitlements(TokenWrapper token, Entitlements.TokenEntitlements entitlements) {
		if (token == null || entitlements == null) {
			return;
		}
		token.setCustomField(SERVICE_ENTITLEMENTS,
				flatServiceEntitlementsJson(normalizeServiceEntitlements(entitlements)));
	}

	static Entitlements.TokenEntitlements normalizeServiceEntitlements(
			Entitlements.TokenEntitlements entitlements) {
		if (entitlements == null) {
			return Entitlements.TokenEntitlements.getDefaultInstance();
		}
		return buildTokenEntitlements(
				Grants.normalize(entitlementGrantTokens(entitlements)),
				entitlements.getAzpList());
	}

	private Entitlements.TokenEntitlements resolveCurrentAccessEntitlements(
			TokenWrapper sessionToken) throws StatusException {
		Userentitlements.EntitlementEvalResult opaResult =
				resolveEntitlementsViaOpa(buildClaimsStruct(sessionToken), "");
		return expandEntitlements(opaResult);
	}

	private static Entitlements.TokenEntitlements readServiceEntitlements(TokenWrapper token) {
		if (token == null) {
			return null;
		}
		Entitlements.TokenEntitlements typed = token.getServiceEntitlements();
		if (typed != null && !entitlementGrantTokens(typed).isEmpty()) {
			return typed;
		}
		String raw = token.getCustomField(SERVICE_ENTITLEMENTS);
		Entitlements.TokenEntitlements parsed = parseServiceEntitlementsClaim(raw);
		return parsed != null ? parsed : typed;
	}

	private static String flatServiceEntitlementsJson(Entitlements.TokenEntitlements entitlements) {
		com.google.gson.JsonObject obj = new com.google.gson.JsonObject();
		com.google.gson.JsonArray grants = new com.google.gson.JsonArray();
		for (String token : entitlementGrantTokens(entitlements)) {
			grants.add(token);
		}
		obj.add("grants", grants);
		if (entitlements.getAzpCount() > 0) {
			com.google.gson.JsonArray azp = new com.google.gson.JsonArray();
			for (String value : entitlements.getAzpList()) {
				azp.add(value);
			}
			obj.add("azp", azp);
		}
		return new com.google.gson.Gson().toJson(obj);
	}

	private static Entitlements.TokenEntitlements parseServiceEntitlementsClaim(String raw) {
		if (raw == null || raw.isEmpty()) {
			return null;
		}
		try {
			com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(raw);
			if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
				String nested = el.getAsString();
				if (nested.startsWith("{") || nested.startsWith("[")) {
					el = com.google.gson.JsonParser.parseString(nested);
				}
			}
			java.util.ArrayList<String> grants = new java.util.ArrayList<>();
			java.util.ArrayList<String> azp = new java.util.ArrayList<>();
			collectEntitlementClaim(el, grants, azp);
			return buildTokenEntitlements(grants, azp);
		} catch (Exception e) {
			return null;
		}
	}

	private static void collectEntitlementClaim(
			com.google.gson.JsonElement el, List<String> grants, List<String> azp) {
		if (el == null || el.isJsonNull()) {
			return;
		}
		if (el.isJsonPrimitive()) {
			com.google.gson.JsonPrimitive prim = el.getAsJsonPrimitive();
			if (prim.isString()) {
				grants.add(prim.getAsString());
			}
			return;
		}
		if (el.isJsonArray()) {
			for (com.google.gson.JsonElement item : el.getAsJsonArray()) {
				collectEntitlementClaim(item, grants, azp);
			}
			return;
		}
		if (!el.isJsonObject()) {
			return;
		}
		com.google.gson.JsonObject obj = el.getAsJsonObject();
		com.google.gson.JsonElement token = obj.get("token");
		if (token != null && token.isJsonPrimitive()) {
			grants.add(token.getAsString());
		}
		com.google.gson.JsonElement grantList = obj.get("grants");
		if (grantList != null) {
			collectEntitlementClaim(grantList, grants, azp);
		}
		com.google.gson.JsonElement azpList = obj.get("azp");
		if (azpList != null && azpList.isJsonArray()) {
			for (com.google.gson.JsonElement item : azpList.getAsJsonArray()) {
				if (item.isJsonPrimitive()) {
					azp.add(item.getAsString());
				}
			}
		}
		for (Map.Entry<String, com.google.gson.JsonElement> entry : obj.entrySet()) {
			String key = entry.getKey();
			if (!key.equals("token") && !key.equals("grants") && !key.equals("azp")) {
				collectEntitlementClaim(entry.getValue(), grants, azp);
			}
		}
	}

	private static List<String> entitlementGrantTokens(Entitlements.TokenEntitlements entitlements) {
		java.util.ArrayList<String> tokens = new java.util.ArrayList<>();
		if (entitlements == null) {
			return tokens;
		}
		Descriptors.FieldDescriptor grantsField =
				entitlements.getDescriptorForType().findFieldByName("grants");
		if (grantsField == null || !grantsField.isRepeated()) {
			return tokens;
		}
		int count = entitlements.getRepeatedFieldCount(grantsField);
		for (int i = 0; i < count; i++) {
			Object value = entitlements.getRepeatedField(grantsField, i);
			if (value instanceof String) {
				tokens.add((String) value);
			} else if (value instanceof Message) {
				Message msg = (Message) value;
				Descriptors.FieldDescriptor tokenField =
						msg.getDescriptorForType().findFieldByName("token");
				if (tokenField != null) {
					Object token = msg.getField(tokenField);
					if (token instanceof String && !((String) token).isEmpty()) {
						tokens.add((String) token);
					}
				}
			}
		}
		return tokens;
	}

	private static Entitlements.TokenEntitlements buildTokenEntitlements(List<String> grants, List<String> azp) {
		Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();
		Descriptors.FieldDescriptor grantsField =
				builder.getDescriptorForType().findFieldByName("grants");
		if (grantsField != null && grantsField.isRepeated()) {
			for (String token : grants) {
				if (token == null || token.isEmpty()) {
					continue;
				}
				if (grantsField.getType() == Descriptors.FieldDescriptor.Type.STRING) {
					builder.addRepeatedField(grantsField, token);
				} else if (grantsField.getType() == Descriptors.FieldDescriptor.Type.MESSAGE) {
					Message.Builder grantBuilder = builder.newBuilderForField(grantsField);
					Descriptors.FieldDescriptor tokenField =
							grantBuilder.getDescriptorForType().findFieldByName("token");
					if (tokenField != null) {
						grantBuilder.setField(tokenField, token);
						builder.addRepeatedField(grantsField, grantBuilder.build());
					}
				}
			}
		}
		builder.addAllAzp(azp);
		return builder.build();
	}

	/**
	 * Resolves the namespace claim for a user token from the OPA result. OPA maps the
	 * caller's IdP (issuer/claims) to the tenant subtree they belong to, as a
	 * leading-slash absolute path (e.g. "/local/dev/drpepper"). Falls back to the
	 * cluster-root namespace when the policy returns none.
	 */
	private String namespaceFromOpaOrRoot(Userentitlements.EntitlementEvalResult result) {
		String ns = result.getNamespace();
		if (ns != null && !ns.isEmpty()) {
			return ns;
		}
		return SpiffeIds.namespaceRoot();
	}

	/**
	 * Parses a JSON string into a protobuf Value, preserving arrays and objects.
	 */
	private static com.google.protobuf.Value parseJsonValue(String json) {
		com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(json);
		return jsonElementToProtoValue(el);
	}

	private static com.google.protobuf.Value jsonElementToProtoValue(com.google.gson.JsonElement el) {
		if (el.isJsonNull()) {
			return com.google.protobuf.Value.newBuilder()
					.setNullValue(com.google.protobuf.NullValue.NULL_VALUE).build();
		} else if (el.isJsonPrimitive()) {
			com.google.gson.JsonPrimitive prim = el.getAsJsonPrimitive();
			if (prim.isBoolean()) {
				return com.google.protobuf.Value.newBuilder()
						.setBoolValue(prim.getAsBoolean()).build();
			} else if (prim.isNumber()) {
				return com.google.protobuf.Value.newBuilder()
						.setNumberValue(prim.getAsDouble()).build();
			} else {
				return com.google.protobuf.Value.newBuilder()
						.setStringValue(prim.getAsString()).build();
			}
		} else if (el.isJsonArray()) {
			com.google.protobuf.ListValue.Builder list = com.google.protobuf.ListValue.newBuilder();
			for (com.google.gson.JsonElement item : el.getAsJsonArray()) {
				list.addValues(jsonElementToProtoValue(item));
			}
			return com.google.protobuf.Value.newBuilder().setListValue(list).build();
		} else if (el.isJsonObject()) {
			com.google.protobuf.Struct.Builder struct = com.google.protobuf.Struct.newBuilder();
			for (Map.Entry<String, com.google.gson.JsonElement> entry : el.getAsJsonObject().entrySet()) {
				struct.putFields(entry.getKey(), jsonElementToProtoValue(entry.getValue()));
			}
			return com.google.protobuf.Value.newBuilder().setStructValue(struct).build();
		}
		return com.google.protobuf.Value.newBuilder().setStringValue(el.toString()).build();
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

		// Route by token origin. The static-keypair cred_pair bootstrap arm has
		// been removed (services now bootstrap via projected Kubernetes tokens on
		// the kubernetes_token credential field); input_token here is only ever a
		// kernel-signed token presented for EXCHANGE (refresh->access,
		// access->service-scoped). It is verified solely against the kernel's own
		// verifying keys.
		String kid = inputToken.getKid();
		// Phase 0.1: only an implausible (malformed/oversized) kid skips the kernel
		// key-set scan here — kernel-owned verifying kids are always plausible
		// (base64url, within the cap), so a bogus kid cannot match and we avoid the
		// O(keys) scan. Routing contract is preserved: a non-matching/implausible kid
		// still falls through to the UNAUTHENTICATED below. Validation only, no retry.
		if (!kid.isEmpty() && isPlausibleKid(kid)) {
			for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
				if (kid.equals(jwk.getKid())) {
					return exchangeKernelToken(request, inputToken);
				}
			}
		}

		// Not a kernel-signed token. The static cred_pair bootstrap path that used
		// to mint a first refresh token from a delegate-keypair-signed throwaway JWT
		// is gone — services bootstrap via projected Kubernetes tokens
		// (kubernetes_token). The kernel makes NO external IdP calls: it is the
		// cluster trust root and only exchanges its own credentials. External IdP
		// tokens must be exchanged via MintUserToken by an authorized broker.
		throw new StatusException(Status.UNAUTHENTICATED, "input_token is not a recognized kernel-signed token; service bootstrap is via the kubernetes_token credential and external IdP tokens must be exchanged via MintUserToken by an authorized broker");
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
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set, mirroring the UNAUTHENTICATED-unknown-key miss below.
		// Validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"caller token signed with unknown key: " + kid);
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
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
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
				com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.token.TokenOuterClass.TokenPurpose.TOKEN_PURPOSE_REFRESH;

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
		// User tokens live at the cluster root and can level-or-below to any tenant.
		newToken.setNamespace(SpiffeIds.namespaceRoot());
		if (isRefresh) {
			newToken.setCustomField("typ", TOKEN_TYPE_REFRESH); // backwards compat
		}

		// Forward custom claims from the request (e.g., IDP claims like email, name).
		// Well-known JWT claims from external IdPs get origin_ prefix to avoid collision.
		if (request.hasClaims()) {
			newToken.setClaimsFromStruct(request.getClaims(), STANDARD_JWT_CLAIMS, WELL_KNOWN_JWT_CLAIMS);
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

		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
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

		// Namespace: services derive from their SPIFFE-URI subject; users live at root.
		boolean isServiceMint = SUB_TYPE_SERVICE.equals(extraClaims.get("sub_type"));
		newToken.setNamespace(isServiceMint
				? SpiffeIds.namespaceFromSpiffe(subject)
				: SpiffeIds.namespaceRoot());

		for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
			newToken.setCustomField(entry.getKey(), entry.getValue());
		}

		newToken.sign(signingKey);

		logger.info("Minted refresh token: sub={}, exp={}", subject, exp);

		// Also mint an access token (clone of refresh without typ).
		TokenOuterClass.Token accessProto = mintAccessFromRefresh(newToken, signingKey, now, exp);

		// Services don't need refresh tokens — they re-bootstrap from their
		// cred pair (private key) when the access token expires, not via
		// refresh-token flow like users. Omit the refresh token for service
		// callers (sub_type=service); clients now parse instance_id from the
		// access_token's claims.
		Object subType = extraClaims.get("sub_type");
		boolean isService = SUB_TYPE_SERVICE.equals(subType);
		Tokenrequest.TokenMintResponse.Builder resp = Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(accessProto);
		if (!isService) {
			resp.setRefreshToken(newToken.getProto());
		}
		// Batch mint: also return one service token per requested audience, so a
		// bootstrap/login call can hand back RT + AT + N ST in a single round
		// trip. Each service token is minted from the freshly issued access token
		// via the normal access→service exchange path.
		if (!request.getServiceAudsList().isEmpty()) {
			TokenWrapper accessWrapper = TokenWrapper.from(accessProto);
			for (String svcAud : request.getServiceAudsList()) {
				if (svcAud.isEmpty()) {
					throw new StatusException(Status.INVALID_ARGUMENT,
							"service_auds entries must be non-empty");
				}
				Tokenrequest.TokenMintRequest svcReq = Tokenrequest.TokenMintRequest.newBuilder()
						.setAud(svcAud)
						.setExp(request.getExp())
						.build();
				resp.addServiceTokens(exchangeKernelToken(svcReq, accessWrapper).getAccessToken());
			}
		}
		return resp.build();
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
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set, mirroring the UNAUTHENTICATED-unknown-key miss below.
		// Validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED, "refresh token signed with unknown key: " + kid);
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
			ImmutableKey bsSigningKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
			if (bsSigningKey == null) {
				throw new StatusException(Status.UNAVAILABLE, "no active signing key");
			}
			long bsNow = Instant.now().getEpochSecond();
			long bsExp = bsNow + defaultTokenExpirySeconds;
			return exchangeBootstrapToRefresh(inputToken, bsSigningKey, bsNow, bsExp);
		}

		// Offline Token (OT) input. An OT mints a short-lived access token for the
		// data plane, or — when offline_access is set — a fresh OT (renewal). It can
		// never directly mint a service-scoped token via aud; batch service_auds are
		// derived from the freshly minted AT so the chain remains OT → AT → ST.
		if (TOKEN_USE_OFFLINE.equals(tokenUse)) {
			if (!request.getAud().isEmpty()) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"offline tokens cannot mint service-specific tokens; exchange for an access token first");
			}
			ImmutableKey otSigningKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
			if (otSigningKey == null) {
				throw new StatusException(Status.UNAVAILABLE, "no active signing key");
			}
			long otNow = Instant.now().getEpochSecond();
			if (request.getOfflineAccess()) {
				return renewOfflineToken(inputToken, otSigningKey, otNow, request);
			}
			// Data plane: OT → AT (mintAccessFromRefresh stamps AT.parent_jti = OT.jti).
			// The AT is scoped to the requested (or default) project — this is the
			// project-switch path for offline-token holders.
			long otAccessExp = otNow + defaultTokenExpirySeconds;
			Entitlements.TokenEntitlements accessEntitlements =
					resolveCurrentAccessEntitlements(inputToken);
			TokenOuterClass.Token at = mintAccessFromRefresh(
					inputToken, otSigningKey, otNow, otAccessExp, request.getProject(),
					accessEntitlements);
			Tokenrequest.TokenMintResponse.Builder resp = Tokenrequest.TokenMintResponse.newBuilder()
					.setAccessToken(at);
			if (!request.getServiceAudsList().isEmpty()) {
				TokenWrapper accessWrapper = TokenWrapper.from(at);
				for (String svcAud : request.getServiceAudsList()) {
					if (svcAud.isEmpty()) {
						throw new StatusException(Status.INVALID_ARGUMENT,
								"service_auds entries must be non-empty");
					}
					Tokenrequest.TokenMintRequest svcReq = Tokenrequest.TokenMintRequest.newBuilder()
							.setAud(svcAud)
							.setExp(request.getExp())
							.build();
					resp.addServiceTokens(exchangeKernelToken(svcReq, accessWrapper).getAccessToken());
				}
			}
			return resp.build();
		}

		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
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

		// Batch mint (AT + N ST in one call): when the caller lists service_auds,
		// return the access token plus one service token per audience. Each
		// service token is minted via the normal access→service exchange path
		// (recursing with the freshly minted access token as input), so S2S/U2S
		// entitlement scoping and delegate authorization are applied exactly as
		// for a standalone service-token request.
		if (!request.getServiceAudsList().isEmpty()) {
			TokenOuterClass.Token accessProto = isRefresh
					? mintAccessFromRefresh(inputToken, signingKey, now, exp, request.getProject(),
							resolveCurrentAccessEntitlements(inputToken))
					: inputToken.getProto();
			TokenWrapper accessWrapper = TokenWrapper.from(accessProto);

			Tokenrequest.TokenMintResponse.Builder batch =
					Tokenrequest.TokenMintResponse.newBuilder().setAccessToken(accessProto);
			for (String svcAud : request.getServiceAudsList()) {
				if (svcAud.isEmpty()) {
					throw new StatusException(Status.INVALID_ARGUMENT,
							"service_auds entries must be non-empty");
				}
				Tokenrequest.TokenMintRequest svcReq = Tokenrequest.TokenMintRequest.newBuilder()
						.setAud(svcAud)
						.setExp(request.getExp())
						.build();
				Tokenrequest.TokenMintResponse svcResp = exchangeKernelToken(svcReq, accessWrapper);
				batch.addServiceTokens(svcResp.getAccessToken());
			}
			return batch.build();
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

		Entitlements.TokenEntitlements refreshAccessEntitlements = null;
		if (isRefresh && !isS2S) {
			refreshAccessEntitlements = resolveCurrentAccessEntitlements(inputToken);
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
			// Service namespace = path component of the SPIFFE-URI subject.
			newToken.setNamespace(SpiffeIds.namespaceFromSpiffe(subject));
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

			// v3: a refresh→access exchange scopes the AT to one authorized
			// project (the project-switch path). An access→service exchange
			// (aud set) keeps the already-project-scoped namespace as-is.
			if (isRefresh && request.getAud().isEmpty()) {
				String projectNs = projectScopedNamespace(inputToken, request.getProject());
				if (projectNs != null) {
					newToken.setNamespace(projectNs);
				}
				setFlatServiceEntitlements(newToken, refreshAccessEntitlements);
			}

			// Scope service_entitlements to the target service and its vservices.
			if (!request.getAud().isEmpty()) {
				Entitlements.TokenEntitlements te = readServiceEntitlements(newToken);
				if (te != null) {
					setFlatServiceEntitlements(newToken,
							TokenExchangeServiceImpl.scopeToService(te, request.getAud()));
				}
			}

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
			ImmutableKey signingKey, long now, long exp) throws StatusException {
		return mintAccessFromRefresh(refreshToken, signingKey, now, exp, null, null);
	}

	/**
	 * As {@link #mintAccessFromRefresh(TokenWrapper, ImmutableKey, long, long)},
	 * but scopes the access token to a single project (v3). {@code requestedProject}
	 * (may be null/empty) selects which authorized project to scope to; empty uses
	 * the session's default project.
	 */
	private TokenOuterClass.Token mintAccessFromRefresh(TokenWrapper refreshToken,
			ImmutableKey signingKey, long now, long exp, String requestedProject)
			throws StatusException {
		return mintAccessFromRefresh(refreshToken, signingKey, now, exp, requestedProject, null);
	}

	/**
	 * As {@link #mintAccessFromRefresh(TokenWrapper, ImmutableKey, long, long, String)},
	 * but also stamps the current OPA-resolved service entitlements onto the AT.
	 */
	private TokenOuterClass.Token mintAccessFromRefresh(TokenWrapper refreshToken,
			ImmutableKey signingKey, long now, long exp, String requestedProject,
			@Nullable Entitlements.TokenEntitlements accessEntitlements)
			throws StatusException {
		TokenWrapper accessToken = TokenWrapper.from(refreshToken.getProto().toBuilder()
				.setSignature("")
				.setBase64("")
				.removePayload("typ")
				.removePayload(SERVICE_ENTITLEMENTS)
				.build());
		accessToken.setTokenUse(TOKEN_USE_ACCESS);
		// v3: an IDP user's access token is scoped to exactly one project. The
		// refresh/offline token carries the session's authorized_projects +
		// default_project; service/workload tokens carry none (→ namespace
		// unchanged, the cloned tenant/SPIFFE namespace stands).
		String projectNs = projectScopedNamespace(refreshToken, requestedProject);
		if (projectNs != null) {
			accessToken.setNamespace(projectNs);
		}
		// Lineage: the access token (AT) records the jti of the refresh/offline token
		// (OT/RT) it was minted from, so the kernel can refuse to mint downstream tokens
		// once the parent is revoked. parent_jti is kernel-only (services ignore it).
		String parentJti = refreshToken.getJTI();
		accessToken.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		if (parentJti != null && !parentJti.isEmpty()) {
			accessToken.setCustomField("parent_jti", parentJti);
		}
		if (accessEntitlements != null) {
			setFlatServiceEntitlements(accessToken, accessEntitlements);
		}
		accessToken.sign(signingKey);
		return accessToken.getProto();
	}

	/**
	 * v3 project scoping. Reads the session refresh/offline token's
	 * {@code authorized_projects} + {@code default_project} claims (stamped at
	 * login from the OPA result) and returns the full project namespace
	 * ({@code tenantNs + "/" + leaf}) the access token should be scoped to.
	 *
	 * <p>{@code requestedProject} (may be null/empty) selects the project to
	 * switch to and must be one of the authorized projects; empty uses
	 * {@code default_project}. Returns {@code null} when the token carries no
	 * project authorization (service/workload tokens) — the caller then keeps
	 * the cloned namespace unchanged.
	 *
	 * @throws StatusException PERMISSION_DENIED if the requested project is not authorized.
	 */
	private String projectScopedNamespace(TokenWrapper rt, String requestedProject)
			throws StatusException {
		String defaultProject = rt.getCustomField(CLAIM_DEFAULT_PROJECT);
		String authJson = rt.getCustomField(CLAIM_AUTHORIZED_PROJECTS);
		if (authJson == null && (defaultProject == null || defaultProject.isEmpty())) {
			return null; // not a project-scoped (IDP user) session
		}
		List<String> authorized = parseStringList(authJson);
		String leaf = (requestedProject != null && !requestedProject.isEmpty())
				? requestedProject
				: defaultProject;
		if (leaf == null || leaf.isEmpty()) {
			return null; // nothing to scope to
		}
		if (!authorized.isEmpty() && !authorized.contains(leaf)) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"not authorized for project '" + leaf + "'");
		}
		String tenantNs = rt.getNamespace();
		if (tenantNs == null || tenantNs.isEmpty()) {
			return null;
		}
		String base = tenantNs.endsWith("/") ? tenantNs.substring(0, tenantNs.length() - 1) : tenantNs;
		return base + "/" + leaf;
	}

	/** Parses a JSON string array (as written by Gson) into a list; null/blank → empty. */
	private static List<String> parseStringList(String json) {
		if (json == null || json.isEmpty()) {
			return List.of();
		}
		try {
			com.google.gson.JsonElement el = com.google.gson.JsonParser.parseString(json);
			if (!el.isJsonArray()) {
				return List.of();
			}
			List<String> out = new java.util.ArrayList<>();
			for (com.google.gson.JsonElement e : el.getAsJsonArray()) {
				if (e.isJsonPrimitive()) {
					out.add(e.getAsString());
				}
			}
			return out;
		} catch (Exception e) {
			return List.of();
		}
	}

	/**
	 * Stamps the v3 project-scoping session claims on a freshly built user
	 * refresh/offline token from the OPA evaluation result, so later
	 * refresh→access exchanges can scope (and switch) the AT's project.
	 */
	private static void stampProjectClaims(TokenWrapper rt, Userentitlements.EntitlementEvalResult opaResult) {
		rt.setCustomField(CLAIM_AUTHORIZED_PROJECTS,
				new com.google.gson.Gson().toJson(opaResult.getAuthorizedProjectsList()));
		if (!opaResult.getDefaultProject().isEmpty()) {
			rt.setCustomField(CLAIM_DEFAULT_PROJECT, opaResult.getDefaultProject());
		}
	}

	/**
	 * Mints a fresh Offline Token (OT) from a presented, already-verified OT
	 * (renewal). The fresh OT keeps the holder's identity and claims, gets a new
	 * jti and a new months-long expiry, and is returned alongside a fresh
	 * short-lived access token so the caller refreshes both in one round trip.
	 * A renewed OT is a fresh root: it carries no parent_jti (per the token-chain
	 * lineage rules, only AT/ST chain to a parent).
	 */
	private Tokenrequest.TokenMintResponse renewOfflineToken(TokenWrapper oldOt,
			ImmutableKey signingKey, long now, Tokenrequest.TokenMintRequest request)
			throws StatusException {
		long maxExp = now + offlineTokenLifetimeSeconds;
		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds offline token lifetime ceiling " + maxExp);
			}
		} else {
			exp = now + offlineTokenLifetimeSeconds;
		}

		TokenWrapper freshOt = TokenWrapper.from(oldOt.getProto().toBuilder()
				.setSignature("")
				.setBase64("")
				.removePayload(SERVICE_ENTITLEMENTS)
				.build());
		freshOt.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		freshOt.setTokenUse(TOKEN_USE_OFFLINE);
		freshOt.sign(signingKey);

		// Also hand back a fresh short-lived AT for immediate data-plane use.
		long accessExp = now + defaultTokenExpirySeconds;
		TokenOuterClass.Token at = mintAccessFromRefresh(freshOt, signingKey, now, accessExp,
				null, resolveCurrentAccessEntitlements(freshOt));

		logger.info("Renewed offline token (OT): sub={}, exp={}", freshOt.getSubject(), exp);
		return Tokenrequest.TokenMintResponse.newBuilder()
				.setRefreshToken(freshOt.getProto())
				.setAccessToken(at)
				.build();
	}

	/**
	 * Verifies the continuity token and returns its {@code instance_id}, after
	 * asserting it was minted for {@code resolvedSubject} — the canonical
	 * identity of the Delegate resolved by the credential path (cred_pair JWT or
	 * Kubernetes SA), NOT a value taken from the presented continuity token. This
	 * binding is the H5 confused-deputy fix: a continuity token minted for
	 * delegate A cannot be replayed by a caller who authenticates as delegate B.
	 *
	 * @param rawContinuityToken the raw continuity (prior refresh) token.
	 * @param resolvedSubject    the resolved delegate's canonical SPIFFE subject
	 *                           (what the prior refresh token's {@code sub} carries).
	 */
	private String resolveInstanceIdFromContinuityToken(String rawContinuityToken,
			String resolvedSubject) throws StatusException {

		TokenWrapper continuityToken;
		try {
			continuityToken = TokenWrapper.parse(rawContinuityToken);
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
		// Phase 0.1: reject implausible kids cheaply, consistent with the data-plane
		// interceptor's gate. Note: unlike the data-plane path we deliberately do NOT add a
		// Thread.sleep retry loop here — this runs inside the mint RPC handler in the kernel
		// that itself owns/publishes the verifying keys, so the just-published-key propagation
		// race the interceptor compensates for does not apply, and a blocking retry on a mint
		// handler would reintroduce the very pool-exhaustion DoS we are closing elsewhere.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.INVALID_ARGUMENT, "continuity_token has malformed kid");
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

		if (!resolvedSubject.equals(continuityToken.getSubject())) {
			throw new StatusException(
					Status.INVALID_ARGUMENT,
					"continuity_token subject '" + continuityToken.getSubject()
							+ "' does not match the resolved delegate identity '" + resolvedSubject + "'");
		}

		String instanceId = continuityToken.getCustomField("instance_id");
		if (instanceId == null || instanceId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "continuity_token missing instance_id claim");
		}
		logger.info("Preserved instance_id={} via continuity token for sub={}", instanceId, resolvedSubject);
		return instanceId;
	}

	private Kernel.Delegate findDelegateByName(String name) {
		// When sub is a SPIFFE URI (spiffe://<prefix>/<delegate_name>), extract
		// the bare delegate name for lookup via SpiffeIds.
		String lookupName = SpiffeIds.isSpiffeUri(name) ? SpiffeIds.serviceName(name) : name;
		for (Kernel.Delegate d : delegatesReader.get()) {
			if (lookupName.equals(d.getName())) {
				return d;
			}
		}
		return null;
	}

	// ========================================================================
	// MintX509Cert RPC
	// ========================================================================

	@Override
	public X509.X509CertChain mintX509Cert(Caller caller, Tokenrequest.X509MintRequest request)
			throws ProtoException {
		try {
			return doX509Mint(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("X509Mint failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "certificate signing failed: " + e.getMessage(), e);
		}
	}

	private X509.X509CertChain doX509Mint(Tokenrequest.X509MintRequest request) throws StatusException, Exception {
		String traceId = UUID.randomUUID().toString();
		long startNanos = System.nanoTime();
		X509.X509CertRequest originalCertRequest = request.getCertRequest();
		logger.info("X509Mint[{}] begin aud={}, inputToken={}, keyId={}, issuer={}, exp={}, dnsSans={}, uriSans={}",
				traceId,
				request.getAud(),
				!request.getInputToken().isEmpty(),
				originalCertRequest.hasKey() ? originalCertRequest.getKey().getId() : "",
				originalCertRequest.getIssuer(),
				originalCertRequest.getExp(),
				originalCertRequest.getDnsNamesCount(),
				originalCertRequest.getUriSansCount());

		// Authenticate caller from raw Bearer token (MintService is auth-exempt,
		// so SecurityInterceptor doesn't validate — we do it manually here).
		// Fall back to input_token from request body (gateway-mediated calls).
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if ((rawToken == null || rawToken.isEmpty()) && !request.getInputToken().isEmpty()) {
			rawToken = request.getInputToken();
		}
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "missing authorization header");
		}

		TokenWrapper token;
		try {
			token = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "invalid token: " + e.getMessage());
		}
		logger.info("X509Mint[{}] parsed token kid={}, sub={}", traceId, token.getKid(), token.getSubject());

		// Verify token signature against cluster keys.
		String kid = token.getKid();
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set, mirroring the UNAUTHENTICATED-unknown-key miss below.
		// Validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED, "token signed with unknown key: " + kid);
		}
		JwkOuterClass.Jwk matchingKey = null;
		List<JwkOuterClass.Jwk> verifyingKeys = verifyingKeysReader.get();
		logger.info("X509Mint[{}] loaded {} verifying keys", traceId, verifyingKeys.size());
		for (JwkOuterClass.Jwk jwk : verifyingKeys) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw new StatusException(Status.UNAUTHENTICATED, "token signed with unknown key: " + kid);
		}
		try {
			token.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "token verification failed: " + e.getMessage());
		}
		logger.info("X509Mint[{}] verified token in {}ms", traceId, elapsedMillis(startNanos));

		// Kernel-minted service tokens encode the canonical SPIFFE URI in the
		// `sub` claim (e.g. "spiffe://local/dev/oauth"). That URI IS the
		// workload identity for this cluster and propagates unchanged through
		// the cert: token sub → URI SAN. No reconstruction.
		//
		// External-IdP-minted tokens (cred_pair, OIDC) carry a non-SPIFFE
		// `sub`; X509Mint is not for those flows — reject explicitly.
		String spiffeId = token.getSubject();
		if (spiffeId == null || spiffeId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "token has no sub claim");
		}
		if (!SpiffeIds.isSpiffeUri(spiffeId)) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"X509Mint requires a kernel-minted service token; sub is not a SPIFFE URI: " + spiffeId);
		}

		// Intermediate CA state is keyed by bare service name, matching the
		// ManageCert path. The full SPIFFE URI remains the leaf cert identity.
		String serviceName = SpiffeIds.serviceName(spiffeId);
		logger.info("X509Mint[{}] resolving intermediate CA service={}, spiffeId={}",
				traceId, serviceName, spiffeId);
		ImmutableCertChain intermediateCa = getOrCreateIntermediateCa(traceId, serviceName, signingCa);
		logger.info("X509Mint[{}] intermediate CA ready service={} in {}ms",
				traceId, serviceName, elapsedMillis(startNanos));

		// Enrich cert request with the SPIFFE URI SAN (canonical identity).
		X509.X509CertRequest enrichedRequest = request.getCertRequest().toBuilder()
				.addUriSans(spiffeId)
				.build();

		// Sign the enriched cert request with the intermediate CA.
		logger.info("X509Mint[{}] signing leaf service={}, keyId={}, issuer={}, exp={}, dnsSans={}, uriSans={}",
				traceId,
				serviceName,
				enrichedRequest.hasKey() ? enrichedRequest.getKey().getId() : "",
				enrichedRequest.getIssuer(),
				enrichedRequest.getExp(),
				enrichedRequest.getDnsNamesCount(),
				enrichedRequest.getUriSansCount());
		X509.X509Cert leafCert = intermediateCa.sign(enrichedRequest);
		logger.info("X509Mint[{}] leaf signed service={} in {}ms",
				traceId, serviceName, elapsedMillis(startNanos));

		// Build response: leaf cert + intermediate CA cert in chain.
		X509.X509CertChain certChain = X509.X509CertChain.newBuilder()
				.addChain(leafCert)
				.addChain(intermediateCa.leaf().getProto())
				.build();

		logger.info("X509Mint: spiffeId={}, keyId={}",
				spiffeId, request.getCertRequest().getKey().getId());

		return certChain;
	}

	private static long elapsedMillis(long startNanos) {
		return (System.nanoTime() - startNanos) / 1_000_000L;
	}

	/**
	 * Gets or creates a per-service intermediate CA.
	 * The intermediate CA is signed by the root CA with BasicConstraints CA:TRUE, pathlen:0.
	 * It's stored in the Ca state's service_cas collection, keyed by service name.
	 */
	private synchronized ImmutableCertChain getOrCreateIntermediateCa(
			String serviceName, ImmutableCertChain rootCa) throws Exception {
		return getOrCreateIntermediateCa(null, serviceName, rootCa);
	}

	private synchronized ImmutableCertChain getOrCreateIntermediateCa(
			String traceId, String serviceName, ImmutableCertChain rootCa) throws Exception {
		long startNanos = System.nanoTime();

		// Check if intermediate CA already exists for this service.
		X509.X509CertChain existing = serviceCaReader.apply(serviceName);
		if (existing != null && existing.getChainCount() > 0) {
			ImmutableCertChain reusable = ServiceIntermediateCa.reusable(serviceName, existing, rootCa, logger);
			if (reusable == null) {
				logger.info("Recreating intermediate CA for service: {}{}", serviceName,
						traceId != null ? " traceId=" + traceId : "");
			} else {
				if (traceId != null) {
					logger.info("X509Mint[{}] found existing intermediate CA service={}, chainLength={} in {}ms",
							traceId, serviceName, existing.getChainCount(), elapsedMillis(startNanos));
				}
				return reusable;
			}
		}

		// Generate EC P-384 keypair for the intermediate CA.
		// Ed25519 is avoided because Netty (used by Keycloak/Quarkus) has known
		// compatibility issues with Ed25519 in TLS certificate chains.
		if (traceId != null) {
			logger.info("X509Mint[{}] generating intermediate CA key service={}", traceId, serviceName);
		}
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair intermediateKeyPair = kpg.generateKeyPair();
		if (traceId != null) {
			logger.info("X509Mint[{}] generated intermediate CA key service={} in {}ms",
					traceId, serviceName, elapsedMillis(startNanos));
		}

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

		if (traceId != null) {
			logger.info("X509Mint[{}] signing intermediate CA service={} issuer={}",
					traceId, serviceName, intermediateRequest.getIssuer());
		}
		X509.X509Cert intermediateCert = rootCa.sign(intermediateRequest);
		if (traceId != null) {
			logger.info("X509Mint[{}] signed intermediate CA service={} in {}ms",
					traceId, serviceName, elapsedMillis(startNanos));
		}

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
				.setId(serviceName)
				.setKey(intermediateKey)
				.addChain(intermediateCert)
				.build();

		if (traceId != null) {
			logger.info("X509Mint[{}] writing intermediate CA service={}", traceId, serviceName);
		}
		serviceCaWriter.accept(serviceName, intermediateProto);
		logger.info("Created intermediate CA for service: {}{}", serviceName,
				traceId != null ? " traceId=" + traceId : "");

		return ImmutableCertChain.from(intermediateProto);
	}

	// ========================================================================
	// Workload Identity (SPIFFE)
	// ========================================================================

	@Override
	public Tokenrequest.WorkloadMintResponse mintWorkload(Caller caller,
			Tokenrequest.WorkloadMintRequest request) throws ProtoException {
		try {
			return doWorkloadMint(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("WorkloadMint failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "workload mint failed: " + e.getMessage(), e);
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
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set, mirroring the UNAUTHENTICATED-unknown-key miss below.
		// Validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token signed with unknown key: " + kid);
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
		if (!SpiffeIds.isSpiffeUri(callerSub)) {
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

		// Construct child SPIFFE URI via the generated self-describing helper.
		String childSub = Spiffe.workloadSpiffeId(callerSub, workloadName);

		// Mint bootstrap token (short-lived).
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
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
		// Service namespace = path component of the SPIFFE-URI childSub.
		bootstrapToken.setNamespace(SpiffeIds.namespaceFromSpiffe(childSub));

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

		if (!SpiffeIds.isSpiffeUri(sub)) {
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
		// Service namespace = path component of the SPIFFE-URI sub (validated above).
		refreshToken.setNamespace(SpiffeIds.namespaceFromSpiffe(sub));
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
	public void revokeWorkload(Caller caller,
			Kernel.WorkloadRevokeRequest request) throws ProtoException {
		try {
			doWorkloadRevoke(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("WorkloadRevoke failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "workload revoke failed: " + e.getMessage(), e);
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
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set, mirroring the UNAUTHENTICATED-unknown-key miss below.
		// Validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token signed with unknown key: " + kid);
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
		if (!SpiffeIds.isSpiffeUri(callerSub)) {
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
	// MintExternalToken RPC (WIF external tokens for proxy → third-party APIs)
	// ========================================================================

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
		// Phase 0.1: reject implausible (malformed/oversized) kids before scanning the
		// verifying-key set, mirroring the PERMISSION_DENIED-unknown-key miss below.
		// Validation only, no retry.
		if (!isPlausibleKid(kid)) {
			throw ProtoException.newErrPermissionDenied(null,
					"user_token signed with unknown key: " + kid);
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

		// Determine the external assertion audience. Federation providers match aud
		// exactly, so an OPA-supplied upstream audience becomes the assertion aud.
		// The original service audience has already been validated by proxy policy.
		String callerAud = userToken.getAudience();
		var appendAuds = opaResult.getAppendAudList();
		String effectiveAud = externalAudienceForPolicy(callerAud, appendAuds);

		// Determine effective token_use. OPA must return TOKEN_USE_EXTERNAL or unset;
		// any other value is rejected to prevent external tokens being replayed internally.
		var opaTokenUse = opaResult.getTokenUse();
		if (opaTokenUse != TokenUse.TOKEN_USE_UNSPECIFIED && opaTokenUse != TokenUse.TOKEN_USE_EXTERNAL) {
			throw ProtoException.newErrPermissionDenied(null,
					"proxy policy returned invalid token_use: " + opaTokenUse);
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

		// TokenWrapper.sign auto-derives the JWT alg from the requested key family.
		ExternalSigningSelection signingSelection =
				externalSigningKeyForRequest(keyRotator, request.getRequestedSigningKeyType());
		externalToken.sign(signingSelection.signingKey());

		var authType = opaResult.getAuthType();
		String callerId = (caller != null) ? caller.getRequestId() : "unknown";
		logger.info("external token minted: caller_req={}, sub={}, aud={}, append_aud={}, metadata={}, dst_url={}, auth_type={}, signing_alg={}",
				callerId, userToken.getSubject(), effectiveAud, appendAuds, metadata, resolvedUrl,
				authType, signingSelection.signingAlg());

		return Tokenrequest.ExternalTokenMintResponse.newBuilder()
				.setToken(externalToken.getProto())
				.setDstUrl(resolvedUrl)
				.setAuthType(authType)
				.build();
	}

	static String externalAudienceForPolicy(String callerAud, List<String> appendAuds) {
		if (appendAuds != null) {
			for (String aud : appendAuds) {
				if (aud != null && !aud.isBlank()) {
					return aud;
				}
			}
		}
		return callerAud == null ? "" : callerAud;
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

	// ========================================================================
	// MintClientToken RPC (cred_pair → C2S token exchange; no P2S in v3)
	// ========================================================================

	@Override
	public Tokenrequest.TokenMintResponse mintClientToken(Caller caller, Tokenrequest.MintClientTokenRequest request)
			throws ProtoException {
		// Parse the presented cred_pair proof JWT.
		TokenWrapper proof;
		try {
			proof = TokenWrapper.parse(request.getInputToken());
		} catch (Exception e) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT, "invalid input_token: " + e.getMessage());
		}
		String credPairId = proof.getKid();
		if (credPairId == null || credPairId.isEmpty()) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"input_token missing kid (cred_pair_id)");
		}

		// Resolve the CredPair by id across tenants' cred_pairs. The owning
		// tenant's namespace becomes the minted token's namespace (entitlements +
		// at-or-below cover the tenant and its projects).
		Credentials.CredPair matched = null;
		String namespace = null;
		for (Kernel.TenantConfigEntry e : configMap.proto().getTenantConfigsList()) {
			for (Credentials.CredPair cp : e.getConfig().getKernel().getCredPairsList()) {
				if (credPairId.equals(cp.getId())) {
					matched = cp;
					namespace = e.getTenantName();
					break;
				}
			}
			if (matched != null) {
				break;
			}
		}
		if (matched == null) {
			throw new ProtoException(ProtoException.UNAUTHENTICATED,
					"unknown cred_pair: " + credPairId);
		}

		// Expiry check on the cred_pair itself.
		long now = Instant.now().getEpochSecond();
		if (matched.hasExpiresAt() && matched.getExpiresAt().getSeconds() > 0
				&& matched.getExpiresAt().getSeconds() <= now) {
			throw new ProtoException(ProtoException.UNAUTHENTICATED,
					"cred_pair " + credPairId + " has expired");
		}

		// Verify the proof signature against the cred_pair's JWK public key.
		try {
			proof.verify(ImmutableJwk.from(matched.getPublicKey()));
		} catch (Exception e) {
			throw new ProtoException(ProtoException.UNAUTHENTICATED,
					"cred_pair proof verification failed: " + e.getMessage());
		}

		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new ProtoException(ProtoException.UNAVAILABLE, "no active signing key");
		}

		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new ProtoException(ProtoException.INVALID_ARGUMENT, "exp must be in the future");
			}
		} else {
			exp = now + DEFAULT_TOKEN_TTL_SECONDS;
		}

		// Mint a C2S token carrying the cred_pair's entitlements + namespace.
		// No P2S/capability: the single C2S authorizer checks service_entitlements
		// against (method, target namespace), identically to IDP-user tokens.
		TokenWrapper token = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject("cred-pair:" + credPairId)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		token.setNamespace(namespace);
		setFlatServiceEntitlements(token, matched.getEntitlements());
		token.sign(signingKey);

		logger.info("Minted cred_pair token: cred_pair={} namespace={} exp={}",
				credPairId, namespace, exp);
		TokenOuterClass.Token proto = token.getProto();
		return Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(proto)
				.build();
	}

	// ========================================================================
	// Internal
	// ========================================================================

	static final class StatusException extends Exception {
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
