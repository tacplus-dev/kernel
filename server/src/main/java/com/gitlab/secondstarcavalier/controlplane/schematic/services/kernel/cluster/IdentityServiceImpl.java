// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.grants.Grants;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.Helpers;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass.JwtPayloadType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass.TokenUse;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass.SubType;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.spec.Spec;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import io.grpc.Status;

import com.google.protobuf.Descriptors;
import com.google.protobuf.Message;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
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

	// Standard Schematic claims — all proto-defined JwtPayloadType values plus "typ".
	// External IdP claims with these names get origin_ prefixed to avoid collision.
	// Package-private so the claim-copy regression test can exercise the real sets.
	static final Set<String> STANDARD_JWT_CLAIMS;
	static {
		var claims = new java.util.HashSet<>(Helpers.jwtPayloadTypeValidValues());
		claims.add("typ");
		STANDARD_JWT_CLAIMS = Set.copyOf(claims);
	}

	// Claims from external IdPs that get origin_ prefix to avoid collision with Schematic claims.
	static final Set<String> WELL_KNOWN_JWT_CLAIMS = Set.of(
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

	/** SPIFFE URI scheme prefix — the authority follows it. */
	private static final String SPIFFE_PREFIX = Spiffe.SCHEME + "://";

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

	// Standing-delegation lineage. A token minted from a Kernel.Grant carries the
	// grant's id here, and every token cloned from it (AT, ST) keeps the claim, so
	// each exchange can re-check that the SAME delegation record is still live —
	// see assertGrantStillActive. Kernel-only (services ignore it); a forged value
	// can only ever deny an exchange, never widen authority.
	private static final String CLAIM_GRANT_ID = "gid";


	/** Intermediate CA lifetime: 10 years. */
	private static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	private static final long DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 2592000; // 30 days
	private static final long DEFAULT_OFFLINE_TOKEN_LIFETIME_SECONDS = 7776000; // 90 days

	/** Default cred_pair → C2S token lifetime (MintClientToken). */
	private static final long DEFAULT_TOKEN_TTL_SECONDS = 3600; // 1 hour

	/** Maximum lifetime of an externally-minted token (MintExternalToken). */
	private static final long EXTERNAL_TOKEN_MAX_TTL_SECONDS = 300;

	/**
	 * Schematic-internal claim key names (all JwtPayloadType names) that must not be
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
	private final Supplier<List<Kernel.Grant>> grantsReader;
	/**
	 * Replaces the live standing-delegation record carrying the same
	 * {@code Grant.id} — the single write path {@code RevokeGrant} uses to mark a
	 * grant revoked. Paired with {@link #grantsReader} the way
	 * {@code serviceCaWriter} is paired with {@code serviceCaReader}; null on a
	 * read-only wiring, in which case RevokeGrant reports UNIMPLEMENTED rather
	 * than silently reporting success for a write that went nowhere.
	 */
	@Nullable
	private final java.util.function.Consumer<Kernel.Grant> grantsWriter;
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
	// kernel/Schematic workload audience the projected token must carry — never the
	// kmaker audience (plan invariant lines 341-349).
	private final KubernetesTokenVerifier kubernetesTokenVerifier;
	private final String kubernetesTokenAudience;
	@Nullable
	private final OpaEvalGrpcClient opaEvalClient;
	@Nullable
	private final com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient;
	private final ConfigMap configMap;
	/**
	 * WorkloadState boundary access. Its {@code revocations} collection is the record
	 * {@code RevokeWorkload} writes and every kernel-signed token exchange reads
	 * (see {@link #assertNotRevoked}); required, never null — a kernel that
	 * cannot record a revocation must fail the RPC, not report success.
	 */
	private final WorkloadMap workloadMap;
	/**
	 * Fired after a revocation lands so the write survives a restart. The disk
	 * snapshot reads WorkloadState.revocations, but nothing else on this path
	 * triggers a snapshot.
	 */
	private final Runnable persistState;

	public IdentityServiceImpl(
			long defaultTokenExpirySeconds,
			long maxTokenLifetimeSeconds,
			long offlineTokenLifetimeSeconds,
			KeyRotator keyRotator,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			Supplier<List<Kernel.Delegate>> delegatesReader,
			Supplier<List<Kernel.Grant>> grantsReader,
			@Nullable java.util.function.Consumer<Kernel.Grant> grantsWriter,
			Map<String, List<String>> serviceEntitlements,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter,
			Supplier<String> trustDomainReader,
			String tokenIssuer,
			@Nullable OpaEvalGrpcClient opaEvalClient,
			@Nullable com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient,
			ConfigMap configMap,
			WorkloadMap workloadMap,
			Runnable persistState,
			@Nullable KubernetesTokenVerifier kubernetesTokenVerifier,
			@Nullable String kubernetesTokenAudience) {
		this.defaultTokenExpirySeconds = defaultTokenExpirySeconds > 0 ? defaultTokenExpirySeconds : 3600;
		this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds > 0 ? maxTokenLifetimeSeconds : DEFAULT_MAX_TOKEN_LIFETIME_SECONDS;
		this.offlineTokenLifetimeSeconds = offlineTokenLifetimeSeconds > 0 ? offlineTokenLifetimeSeconds : DEFAULT_OFFLINE_TOKEN_LIFETIME_SECONDS;
		this.keyRotator = keyRotator;
		this.verifyingKeysReader = verifyingKeysReader;
		this.delegatesReader = delegatesReader;
		this.grantsReader = grantsReader != null ? grantsReader : List::of;
		this.grantsWriter = grantsWriter;
		this.serviceEntitlements = serviceEntitlements != null ? serviceEntitlements : Map.of();
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
		this.trustDomainReader = trustDomainReader;
		this.tokenIssuer = (tokenIssuer != null && !tokenIssuer.isEmpty()) ? tokenIssuer : Kernel.getDescriptor().getPackage();
		this.opaEvalClient = opaEvalClient;
		this.proxyPolicyOpaClient = proxyPolicyOpaClient;
		this.configMap = configMap;
		this.workloadMap = java.util.Objects.requireNonNull(workloadMap,
				"workloadMap is required — workload revocation must be recorded and enforced");
		this.persistState = persistState != null ? persistState : () -> { };
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

	// ========================================================================
	// MintDelegatedToken RPC (standing delegation — Grant record mint)
	// ========================================================================

	@Override
	public Tokenrequest.MintDelegatedTokenResponse mintDelegatedToken(Caller caller,
			Tokenrequest.MintDelegatedTokenRequest request) throws ProtoException {
		try {
			return doMintDelegatedToken(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MintDelegatedToken failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "delegated token mint failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Standing delegation (Grant) mint: a delegate presents its own S2S bearer
	 * token plus a Grant id it holds. Kernel verifies the caller's identity,
	 * confirms it matches the Grant's delegate_name, replays the Grant's
	 * recorded claims into OPA fresh (the same {@link #resolveEntitlementsViaOpa}
	 * path {@link #mintUserTokenInternal} uses), intersects the fresh result
	 * with the Grant's authorized_scope, and mints a single short-lived access
	 * token: sub = grant.subject, act = grant.delegate_name, azp = kernel (this
	 * mint is not broker-attested — kernel mints it directly from a stored
	 * record). No refresh/offline companion is issued; the delegate re-mints
	 * per use from the same grant_id.
	 */
	private Tokenrequest.MintDelegatedTokenResponse doMintDelegatedToken(
			Tokenrequest.MintDelegatedTokenRequest request) throws StatusException {

		// Authenticate the calling delegate via its own bearer token — same
		// 5-step pattern as doMintUserToken/doWorkloadMint (raw token -> parse
		// -> kid -> verify -> resolve SPIFFE-or-bare sub).
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"MintDelegatedToken requires authorization header");
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

		// The caller's own verified identity. A service token's sub may arrive
		// as a full SPIFFE URI, resolved to the bare delegate name exactly as
		// findDelegateByName does.
		String rawCallerSub = callerToken.getSubject();
		String callerDelegateName = SpiffeIds.isSpiffeUri(rawCallerSub)
				? SpiffeIds.serviceName(rawCallerSub) : rawCallerSub;

		// Paired negative control: no live Grant record authorizes the
		// (caller identity, grant_id) pair presented. Three candidate misses —
		// id doesn't exist, id exists but names a different delegate, id
		// exists and matches but has expired — collapse to the SAME
		// status/message shape (non-enumerating, mirroring
		// findDelegateByName's own PERMISSION_DENIED), except expiry gets a
		// distinguishable suffix since that is not a confused-identity case.
		// Run before any OPA call — cheapest-check-first, mirroring
		// doMintUserToken's ordering.
		String grantId = request.getGrantId();
		Kernel.Grant grant = findGrantById(grantId);
		if (grant == null || !callerDelegateName.equals(grant.getDelegateName())) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no usable grant " + grantId + " for delegate " + callerDelegateName);
		}
		long expiresAtMs = grant.getExpiresAtMs();
		if (expiresAtMs != 0 && expiresAtMs <= System.currentTimeMillis()) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no usable grant " + grantId + " for delegate " + callerDelegateName
							+ " — grant expired at " + expiresAtMs);
		}
		// A revoked grant is marked, not deleted (audit trail), so it is still
		// found above — the record's own revoked_at_ms is what makes it unusable.
		// Collapses to the same non-enumerating shape as the identity misses.
		if (grant.getRevokedAtMs() != 0) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no usable grant " + grantId + " for delegate " + callerDelegateName);
		}

		// Replay the grant's recorded claims into OPA fresh — the exact same
		// EvalEntitlement path MintUserToken uses. Fresh OPA gives "cannot
		// exceed the user's CURRENT authority"; the recorded authorized_scope
		// (intersected below) gives "the user downscoped it at consent time".
		Userentitlements.EntitlementEvalResult opaResult =
				resolveEntitlementsViaOpa(grant.getClaims(), request.getTraceId());
		Entitlements.TokenEntitlements fresh = expandEntitlements(opaResult);
		Entitlements.TokenEntitlements scoped = intersectAuthorizedScope(fresh, grant.getAuthorizedScope());

		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long exp = now + defaultTokenExpirySeconds;

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(grant.getSubject())
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		// azp is always kernel on a Grant mint (kernel mints this directly, not
		// on a broker's attestation, per the controller's ruling); the
		// delegate identity goes on the act claim instead (Piece A). Order
		// mirrors mintUserTokenInternal's setAzp-before-replay, though the
		// STANDARD_JWT_CLAIMS skip-list makes the order non-load-bearing
		// either way.
		newToken.setAzp(Kernel.getDescriptor().getPackage());
		newToken.setAct(grant.getDelegateName());
		newToken.setSubType(SUB_TYPE_USER);
		newToken.setTokenUse(TOKEN_USE_ACCESS);
		// Namespace resolution is automatically correct by reusing the same
		// two calls (resolveEntitlementsViaOpa then namespaceFromOpaOrRoot) in
		// the same order mintUserTokenInternal does.
		newToken.setNamespace(namespaceFromOpaOrRoot(opaResult));

		Struct claims = grant.getClaims();
		if (claims != null) {
			newToken.setClaimsFromStruct(claims, STANDARD_JWT_CLAIMS, WELL_KNOWN_JWT_CLAIMS);
		}

		setFlatServiceEntitlements(newToken, scoped);

		// Stamp the grant lineage LAST, after the claims replay, so a recorded IDP
		// claim literally named "gid" cannot displace it. Every later exchange of
		// this token — and of any token cloned from it — re-checks that this same
		// grant is still live (assertGrantStillActive), so revoking the grant kills
		// the derived tokens on their next use instead of at their natural expiry.
		newToken.setCustomField(CLAIM_GRANT_ID, grantId);

		newToken.sign(signingKey);

		logger.info("MintDelegatedToken: grant_id={}, sub={}, act={}, azp=kernel, exp={}",
				grantId, grant.getSubject(), grant.getDelegateName(), exp);

		return Tokenrequest.MintDelegatedTokenResponse.newBuilder()
				.setToken(newToken.getProto())
				.build();
	}

	/**
	 * Intersects a fresh OPA entitlement result with a Grant's recorded
	 * authorized_scope: grants + data_grants narrow by set intersection,
	 * principal_scope narrows to the lower of the two (absent/UNSPECIFIED on
	 * either side is treated as SELF_ONLY, the enum's own documented default),
	 * and azp is deliberately DROPPED — not intersected — since the minted
	 * token's azp ("kernel") could never have been a possible consent-time azp
	 * value; an empty azp list means "applies regardless of azp" by the
	 * field's own contract, the conservative reading already defined for it.
	 */
	private static Entitlements.TokenEntitlements intersectAuthorizedScope(
			Entitlements.TokenEntitlements fresh, Entitlements.TokenEntitlements recorded) {
		Set<String> grants = new TreeSet<>(Grants.normalize(entitlementGrantTokens(fresh)));
		grants.retainAll(Grants.normalize(entitlementGrantTokens(recorded)));

		// data_grants have no wildcard catalog entries — Grants.normalize would
		// silently DROP any token it doesn't recognize — so intersect the flat
		// lists directly rather than normalizing.
		Set<String> dataGrants = new TreeSet<>(fresh.getDataGrantsList());
		dataGrants.retainAll(recorded.getDataGrantsList());

		String principalScope = Spec.PrincipalScope.forNumber(
				Math.min(principalScopeRank(fresh.getPrincipalScope()),
						principalScopeRank(recorded.getPrincipalScope())))
				.name();

		return buildTokenEntitlements(
				new java.util.ArrayList<>(grants), new java.util.ArrayList<>(dataGrants),
				List.of(), principalScope);
	}

	/**
	 * Parses a principal_scope claim string (an enum VALUE NAME, e.g.
	 * "PRINCIPAL_SCOPE_ANY") into its ordinal rank. Absent/empty/unrecognized
	 * values are treated as SELF_ONLY, the enum's own documented default for
	 * "a token that says nothing about principal scope".
	 */
	private static int principalScopeRank(String value) {
		if (value != null && !value.isEmpty()) {
			try {
				Spec.PrincipalScope parsed = Spec.PrincipalScope.valueOf(value);
				if (parsed.getNumber() > 0) {
					return parsed.getNumber();
				}
			} catch (IllegalArgumentException ignored) {
				// Unrecognized value — fall through to the SELF_ONLY default.
			}
		}
		return Spec.PrincipalScope.PRINCIPAL_SCOPE_SELF_ONLY.getNumber();
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
				entitlements.getDataGrantsList(),
				entitlements.getAzpList(),
				entitlements.getPrincipalScope());
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
		// data_grants (BIG GOAL 3 item 7/9): MAY_REDACT field unlocks, e.g.
		// ACCOUNTINGRECORD_ACCOUNTING_RECORD_PRINCIPAL_SUB. Distinct from "grants"
		// (RPC authorization) — these gate egress redaction of specific fields.
		// Omitted when empty for the same reason principal_scope is: an absent
		// key and an empty array read the same way to the egress sanitizer
		// (fail-closed, no grants), so there is no need to spell out the empty
		// case explicitly.
		if (entitlements.getDataGrantsCount() > 0) {
			com.google.gson.JsonArray dataGrants = new com.google.gson.JsonArray();
			for (String value : entitlements.getDataGrantsList()) {
				dataGrants.add(value);
			}
			obj.add("data_grants", dataGrants);
		}
		if (entitlements.getAzpCount() > 0) {
			com.google.gson.JsonArray azp = new com.google.gson.JsonArray();
			for (String value : entitlements.getAzpList()) {
				azp.add(value);
			}
			obj.add("azp", azp);
		}
		// principal_scope: how wide this caller's authority over PRINCIPALS is.
		// Written only when the policy stamped one, because absent and
		// PRINCIPAL_SCOPE_SELF_ONLY mean the same thing to the reader and an
		// empty string would be a third spelling of it. Without this the scope
		// crossed opa -> kernel as a typed field and then died here, since this
		// method — not protojson — is what composes the claim.
		if (!entitlements.getPrincipalScope().isEmpty()) {
			obj.addProperty("principal_scope", entitlements.getPrincipalScope());
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
			java.util.ArrayList<String> dataGrants = new java.util.ArrayList<>();
			java.util.ArrayList<String> azp = new java.util.ArrayList<>();
			String[] principalScope = new String[] {""};
			collectEntitlementClaim(el, grants, dataGrants, azp, principalScope);
			return buildTokenEntitlements(grants, dataGrants, azp, principalScope[0]);
		} catch (Exception e) {
			return null;
		}
	}

	private static void collectEntitlementClaim(
			com.google.gson.JsonElement el, List<String> grants, List<String> dataGrants, List<String> azp,
			String[] principalScope) {
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
				collectEntitlementClaim(item, grants, dataGrants, azp, principalScope);
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
			collectEntitlementClaim(grantList, grants, dataGrants, azp, principalScope);
		}
		// data_grants (BIG GOAL 3 item 7/9): kept out of the generic sweep below,
		// same as azp/principal_scope — otherwise its values fold into "grants" as
		// if they were RPC grant tokens (the bug this fixes; see
		// platform/services/opa/internal/handler.go for the matching bug on the
		// opa side of this same claim).
		com.google.gson.JsonElement dataGrantList = obj.get("data_grants");
		if (dataGrantList != null && dataGrantList.isJsonArray()) {
			for (com.google.gson.JsonElement item : dataGrantList.getAsJsonArray()) {
				if (item.isJsonPrimitive()) {
					dataGrants.add(item.getAsString());
				}
			}
		}
		com.google.gson.JsonElement azpList = obj.get("azp");
		if (azpList != null && azpList.isJsonArray()) {
			for (com.google.gson.JsonElement item : azpList.getAsJsonArray()) {
				if (item.isJsonPrimitive()) {
					azp.add(item.getAsString());
				}
			}
		}
		// principal_scope is a SCALAR sitting on the same object as grants, and the
		// sweep below folds every unrecognised key into the grant list. Read it
		// here or its VALUE arrives as a grant token no catalog ever declared.
		com.google.gson.JsonElement scope = obj.get("principal_scope");
		if (scope != null && scope.isJsonPrimitive() && scope.getAsJsonPrimitive().isString()) {
			principalScope[0] = scope.getAsString();
		}
		for (Map.Entry<String, com.google.gson.JsonElement> entry : obj.entrySet()) {
			String key = entry.getKey();
			if (!key.equals("token") && !key.equals("grants") && !key.equals("data_grants")
					&& !key.equals("azp") && !key.equals("principal_scope")) {
				collectEntitlementClaim(entry.getValue(), grants, dataGrants, azp, principalScope);
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

	private static Entitlements.TokenEntitlements buildTokenEntitlements(
			List<String> grants, List<String> dataGrants, List<String> azp, String principalScope) {
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
		if (dataGrants != null) {
			for (String grant : dataGrants) {
				if (grant != null && !grant.isEmpty()) {
					builder.addDataGrants(grant);
				}
			}
		}
		builder.addAllAzp(azp);
		if (principalScope != null && !principalScope.isEmpty()) {
			builder.setPrincipalScope(principalScope);
		}
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
		// MintToken is the EXCHANGE RPC (RT->AT->ST): it requires a kernel-signed
		// input_token. The former delegation arm — empty input_token plus a
		// caller-supplied subject and claims — is gone: it let any registered
		// delegate mint a user token for an arbitrary subject with none of
		// MintUserToken's restrictions (oauth/saml brokers only, OPA entitlement
		// resolution). On-behalf-of minting is MintUserToken only.
		if (request.getInputToken().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"input_token is required; MintToken is the exchange path — mint a user token via MintUserToken");
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

		// A revoked workload identity gets nothing further from the kernel. This is
		// the single choke point for every kernel-signed exchange — bootstrap
		// -> refresh, refresh -> access, access -> service — so an existing token
		// held by a revoked workload stops buying new ones.
		assertNotRevoked(inputToken.getSubject(), "workload");

		// Same choke point, for standing delegations: a token that derives from a
		// Grant is only exchangeable while that Grant is still live.
		assertGrantStillActive(inputToken);

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

		// A child workload proves on refresh that it can still reach its parent, by
		// presenting the locality token the parent registered in WorkloadState.
		if (isRefresh) {
			assertParentLocality(inputToken, request.getLocalityToken(), subject);
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
	static String projectScopedNamespace(TokenWrapper rt, String requestedProject)
			throws StatusException {
		String defaultProject = rt.getCustomField(CLAIM_DEFAULT_PROJECT);
		String authJson = rt.getCustomField(CLAIM_AUTHORIZED_PROJECTS);
		if (authJson == null && (defaultProject == null || defaultProject.isEmpty())) {
			return null; // not a project-scoped (IDP user) session
		}
		List<String> authorized = parseStringList(authJson);
		String leaf = projectLeaf((requestedProject != null && !requestedProject.isEmpty())
				? requestedProject
				: defaultProject);
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

	/**
	 * Normalizes a requested project to the leaf segment this method appends.
	 * A caller that sends a leading slash (or a whole path) would otherwise be
	 * concatenated verbatim onto the tenant namespace, producing a malformed
	 * claim: root tenant {@code "/"} plus {@code "/drpepper/prod"} minted
	 * {@code namespace: //drpepper/prod}, which {@code Spiffe.normalizeNamespace}
	 * rejects as an empty segment, so every level-or-below check on that token
	 * failed. Stripping here also makes the {@code authorized_projects} check
	 * above compare the same value that is appended.
	 */
	private static String projectLeaf(String requestedProject) {
		if (requestedProject == null) {
			return null;
		}
		String leaf = requestedProject;
		while (leaf.startsWith("/")) {
			leaf = leaf.substring(1);
		}
		return leaf;
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
		String lookupName;
		if (SpiffeIds.isSpiffeUri(name)) {
			try {
				lookupName = SpiffeIds.serviceName(name);
			} catch (IllegalArgumentException e) {
				// A SPIFFE URI that names something other than a service/workload
				// — a user subject, spiffe://<td>/system/users/<n>, is the one a
				// Grant records — is simply not a delegate. That is a lookup miss,
				// which every caller already handles (PERMISSION_DENIED where a
				// delegate is required; the U2S path on token exchange), not an
				// INTERNAL crash.
				return null;
			}
		} else {
			lookupName = name;
		}
		for (Kernel.Delegate d : delegatesReader.get()) {
			if (lookupName.equals(d.getName())) {
				return d;
			}
		}
		return null;
	}

	/**
	 * Per-use standing-delegation revocation check. A token minted from a
	 * {@link Kernel.Grant} carries the grant id on {@code gid}, and every token
	 * cloned from it keeps the claim, so this fires on OT/AT → AT, AT → ST and
	 * every renewal alike. The grant is looked up again on each exchange and the
	 * exchange is denied unless the SAME record is still present, unexpired, and
	 * still names the delegate the token records on {@code act}. Revoking a grant
	 * therefore kills already-minted derived tokens within one request rather than
	 * at their natural expiry. The token's own exp still bounds it on top of this.
	 *
	 * <p>Deliberately uncached, per the OT revocation-timing ruling: a short-TTL
	 * positive cache is a later, measured optimization, never the default.
	 *
	 * <p>The misses — gone, revoked, expired, or no longer naming this delegate —
	 * collapse to one non-enumerating message, mirroring
	 * {@code doMintDelegatedToken}'s own paired negative control.
	 */
	private void assertGrantStillActive(TokenWrapper token) throws StatusException {
		String grantId = token.getCustomField(CLAIM_GRANT_ID);
		if (grantId == null || grantId.isEmpty()) {
			return; // not a delegation-derived token
		}
		Kernel.Grant grant = findGrantById(grantId);
		long expiresAtMs = grant != null ? grant.getExpiresAtMs() : 0;
		if (grant == null
				|| !token.getAct().equals(grant.getDelegateName())
				|| grant.getRevokedAtMs() != 0
				|| (expiresAtMs != 0 && expiresAtMs <= System.currentTimeMillis())) {
			logger.warn("Rejected exchange of a token whose standing delegation is no longer active: "
					+ "grant_id={}, sub={}, act={}", grantId, token.getSubject(), token.getAct());
			throw new StatusException(Status.PERMISSION_DENIED,
					"standing delegation " + grantId + " is no longer active");
		}
	}

	/** Looks up a standing delegation Grant by its opaque id. Null if none exists. */
	private Kernel.Grant findGrantById(String id) {
		for (Kernel.Grant g : grantsReader.get()) {
			if (id.equals(g.getId())) {
				return g;
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

		// A revoked identity cannot be re-minted under the same SPIFFE ID, and the
		// ancestor walk covers the caller too: a revoked parent can mint nothing.
		assertNotRevoked(childSub, "workload");

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

		// Record the revocation. Keyed by SPIFFE ID, so re-revoking is idempotent.
		// Every kernel-signed token exchange reads this back through
		// assertNotRevoked, and the disk snapshot carries it across restarts.
		Kernel.WorkloadRevocation revocation = Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(targetSpiffeId)
				.setRevokedBy(callerSub)
				.setRevokedAtMs(Instant.now().toEpochMilli())
				.build();
		try {
			workloadMap.putRevocations(targetSpiffeId, revocation);
		} catch (Exception e) {
			// Never report success on a revocation that did not land.
			throw new StatusException(Status.INTERNAL,
					"failed to record revocation for " + targetSpiffeId + ": " + e.getMessage());
		}
		persistState.run();

		logger.info("WorkloadRevoke: caller={}, target={}", callerSub, targetSpiffeId);
	}

	// ========================================================================
	// RevokeGrant RPC (standing delegation — runtime revocation)
	// ========================================================================

	@Override
	public void revokeGrant(Caller caller, Kernel.GrantRevokeRequest request) throws ProtoException {
		try {
			doRevokeGrant(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("RevokeGrant failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "grant revoke failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Revokes a standing delegation at runtime. Only a party to the grant may
	 * revoke it: the user it acts for (caller sub == {@code grant.subject}) or the
	 * delegate holding it (caller identity == {@code grant.delegate_name}). Both
	 * are withdrawing authority they already hold, so this needs no authorization
	 * model beyond the caller's own verified identity — the same reasoning that
	 * limits {@code RevokeWorkload} to the identity's own ancestor.
	 *
	 * <p>The record is MARKED ({@code revoked_at_ms}), never deleted, so the
	 * delegation that existed and the moment it was withdrawn stay auditable.
	 * The write goes to the live grants store and is then persisted through the
	 * same {@code persistState} hook {@code RevokeWorkload} uses, so the
	 * revocation survives a kernel restart.
	 *
	 * <p>From that moment {@link #doMintDelegatedToken} refuses to mint from the
	 * grant and {@link #assertGrantStillActive} denies every exchange of a token
	 * already minted from it — the already-minted token dies on its next use, not
	 * at its natural expiry.
	 *
	 * <p>Idempotent: re-revoking an already-revoked grant succeeds and leaves the
	 * original timestamp alone rather than rewriting the audit record.
	 */
	private void doRevokeGrant(Kernel.GrantRevokeRequest request) throws StatusException {
		TokenWrapper callerToken = verifiedCallerToken("RevokeGrant");

		// The caller's own verified identity. A service token's sub may arrive as a
		// full SPIFFE URI, resolved to the bare delegate name exactly as
		// doMintDelegatedToken does; a user token carries the IDP subject a Grant
		// records at consent time verbatim.
		String rawCallerSub = callerToken.getSubject();
		String callerDelegateName = SpiffeIds.isSpiffeUri(rawCallerSub)
				? SpiffeIds.serviceName(rawCallerSub) : rawCallerSub;

		String grantId = request.getGrantId();
		if (grantId == null || grantId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "grant_id is required");
		}

		// Non-enumerating, same shape as the mint path: "no such id" and "not your
		// grant" are one message, so revoke cannot be used to probe which ids exist.
		Kernel.Grant grant = findGrantById(grantId);
		if (grant == null
				|| !(rawCallerSub.equals(grant.getSubject())
						|| callerDelegateName.equals(grant.getDelegateName()))) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no revocable grant " + grantId + " for caller " + rawCallerSub);
		}

		if (grant.getRevokedAtMs() != 0) {
			logger.info("RevokeGrant: grant_id={} already revoked at {} — no-op", grantId, grant.getRevokedAtMs());
			return;
		}

		if (grantsWriter == null) {
			// Never report success for a revocation that cannot land.
			throw new StatusException(Status.UNIMPLEMENTED, "this kernel has no writable grants store");
		}
		long revokedAtMs = Instant.now().toEpochMilli();
		try {
			grantsWriter.accept(grant.toBuilder().setRevokedAtMs(revokedAtMs).build());
		} catch (Exception e) {
			throw new StatusException(Status.INTERNAL,
					"failed to record revocation for grant " + grantId + ": " + e.getMessage());
		}
		persistState.run();

		logger.info("RevokeGrant: grant_id={}, caller={}, subject={}, delegate={}, revoked_at_ms={}",
				grantId, rawCallerSub, grant.getSubject(), grant.getDelegateName(), revokedAtMs);
	}

	/**
	 * Parses and verifies the caller's own bearer token against the cluster's
	 * verifying keys — the authentication half of the pattern
	 * {@code doWorkloadRevoke} and {@code doMintDelegatedToken} each spell out
	 * inline. Only new call sites use it; the existing ones are left as they are.
	 *
	 * @param rpcLabel the RPC name, for the missing-header message
	 */
	private TokenWrapper verifiedCallerToken(String rpcLabel) throws StatusException {
		String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
		if (rawToken == null || rawToken.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, rpcLabel + " requires authorization header");
		}

		TokenWrapper callerToken;
		try {
			callerToken = TokenWrapper.parse(rawToken);
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "invalid caller token: " + e.getMessage());
		}

		String kid = callerToken.getKid();
		if (kid == null || kid.isEmpty()) {
			throw new StatusException(Status.UNAUTHENTICATED, "caller token missing kid");
		}
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
		return callerToken;
	}

	/**
	 * Fails closed if a child workload's refresh does not carry the locality token its
	 * parent registered in {@code WorkloadState.localities}, per the proto contract on
	 * {@code WorkloadLocality}: the parent rotates a token, registers it under its own
	 * SPIFFE ID and shares it with its children, so presenting it proves the child can
	 * still reach the parent. The token is a shared secret, not an identity — compared
	 * in constant time.
	 *
	 * <p>Enforced from the moment a parent registers a locality. Nothing writes
	 * {@code WorkloadState.localities} yet — the parent-side registration is unbuilt — so
	 * demanding a token from every child unconditionally would reject every workload
	 * refresh in the fleet rather than tighten anything. Once a parent has registered,
	 * both a missing and a mismatched token are rejected. This only ever denies a refresh
	 * that previously succeeded; it never admits one that previously failed.
	 *
	 * @param inputToken    the refresh token being exchanged
	 * @param localityToken the locality token the caller presented, possibly empty
	 * @param subject       the child workload's SPIFFE ID, for the error and the log
	 */
	private void assertParentLocality(TokenWrapper inputToken, String localityToken, String subject)
			throws StatusException {
		String parentSub = inputToken.getCustomField(PARENT_SUB);
		if (parentSub == null || parentSub.isEmpty()) return; // not a child workload

		String expected = workloadMap.getLocalities(parentSub).getLocalityToken();
		if (expected.isEmpty()) {
			// The parent has registered no locality, so there is nothing to prove
			// reachability against.
			logger.warn("Workload token refresh with no locality registered by parent: sub={}, parent={}",
					subject, parentSub);
			return;
		}

		if (localityToken == null || localityToken.isEmpty()) {
			logger.warn("Workload token refresh without locality_token: sub={}, parent={}", subject, parentSub);
			throw new StatusException(Status.INVALID_ARGUMENT,
					"workload " + subject + " must present a locality_token proving it can still reach "
							+ parentSub);
		}
		if (!MessageDigest.isEqual(localityToken.getBytes(StandardCharsets.UTF_8),
				expected.getBytes(StandardCharsets.UTF_8))) {
			logger.warn("Workload token refresh with stale or foreign locality_token: sub={}, parent={}",
					subject, parentSub);
			throw new StatusException(Status.PERMISSION_DENIED,
					"locality_token does not match the locality registered by " + parentSub);
		}
	}

	/**
	 * Fails closed if {@code spiffeId} — or any SPIFFE ancestor of it — carries a
	 * {@code WorkloadState.revocations} record, per the proto contract on
	 * {@code WorkloadRevocation}: revoking a parent revokes everything beneath it.
	 *
	 * <p>Non-SPIFFE subjects (user tokens) are not workloads and are not checked
	 * here. The walk stops at the trust-domain authority, so a revocation can
	 * never be recorded at a level that would deny the whole cluster.
	 *
	 * @param spiffeId the identity a token is being minted or exchanged for
	 * @param what     call-site noun for the error message, e.g. "workload"
	 */
	private void assertNotRevoked(String spiffeId, String what) throws StatusException {
		if (!SpiffeIds.isSpiffeUri(spiffeId)) return;
		int authorityEnd = spiffeId.indexOf('/', SPIFFE_PREFIX.length());
		if (authorityEnd < 0) return; // bare trust domain — no workload path to revoke

		String candidate = spiffeId;
		while (candidate.length() > authorityEnd) {
			Kernel.WorkloadRevocation revocation = workloadMap.getRevocations(candidate);
			if (!revocation.getSpiffeId().isEmpty()) {
				logger.warn("Rejected revoked {}: sub={}, revocation={} by {}",
						what, spiffeId, candidate, revocation.getRevokedBy());
				throw new StatusException(Status.PERMISSION_DENIED,
						what + " " + spiffeId + " is revoked (revocation recorded on "
								+ candidate + " by " + revocation.getRevokedBy() + ")");
			}
			candidate = candidate.substring(0, candidate.lastIndexOf('/'));
		}
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

		// Stamp token_use = external — categorically rejected by all Schematic authorizers.
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
