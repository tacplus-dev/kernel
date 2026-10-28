// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.jwk.ImmutableJwk;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.grants.Grants;
import com.github.tacplusdev.kernel.model.chassis.x509.ImmutableCertChain;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.token.Helpers;
import com.github.tacplusdev.kernel.model.types.sys.token.TokenOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.token.TokenOuterClass.JwtPayloadType;
import com.github.tacplusdev.kernel.model.types.sys.token.TokenOuterClass.TokenUse;
import com.github.tacplusdev.kernel.model.types.sys.token.TokenOuterClass.SubType;
import com.github.tacplusdev.kernel.model.types.sys.x509.X509;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.servers.sys.minter.Minter;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.servers.services.kernel.UserMint;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.spec.Spec;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.github.tacplusdev.kernel.model.types.generated.entitlements.Entitlements;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.github.tacplusdev.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.github.tacplusdev.kernel.model.types.common.credentials.Credentials;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import io.grpc.Status;

import com.google.protobuf.Descriptors;
import com.google.protobuf.Message;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
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
public class IdentityServiceImpl implements Mint.MintHandler, UserMint.UserMintHandler, Minter.MinterHandler {

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

	/**
	 * The claim that makes a person's token a DEVICE token: the credential id of
	 * the device credential ({@code Person.devices}) whose proof minted it.
	 */
	static final String CLAIM_DEVICE = "device";

	/**
	 * The claim names kernel synthesizes (the device arm's {@code principal_id}
	 * and {@code device}, and the names the retired personal-principal tenant
	 * exchange handed OPA), which a policy may decide roles from and which
	 * {@code device} names a device token by. A relayed claim set must never
	 * carry them: oauth forwards any non-well-known IdP claim under its own
	 * name, so a tenant IdP could otherwise put {@code device} in an id_token
	 * and have its token read as a device's.
	 */
	static final Set<String> SYNTHESIZED_CLAIMS = Set.of(
			"principal_id", CLAIM_DEVICE, "tenant_namespace", "proof_kind", "customer");


	// Legacy typ claim value — kept for backwards compatibility during rollout.
	private static final String TOKEN_TYPE_REFRESH = Helpers.tokenUseToString(TokenUse.TOKEN_USE_REFRESH);

	// Claim values — derived from proto-defined enums.
	private static final String TOKEN_USE_REFRESH = Helpers.tokenUseToString(TokenUse.TOKEN_USE_REFRESH);
	private static final String TOKEN_USE_ACCESS = Helpers.tokenUseToString(TokenUse.TOKEN_USE_ACCESS);
	private static final String TOKEN_USE_SERVICE = Helpers.tokenUseToString(TokenUse.TOKEN_USE_SERVICE);
	private static final String TOKEN_USE_BOOTSTRAP = Helpers.tokenUseToString(TokenUse.TOKEN_USE_BOOTSTRAP);
	private static final String TOKEN_USE_OFFLINE = Helpers.tokenUseToString(TokenUse.TOKEN_USE_OFFLINE);
	static final String SUB_TYPE_SERVICE = Helpers.subTypeToString(SubType.SUB_TYPE_SERVICE);
	private static final String SUB_TYPE_USER = Helpers.subTypeToString(SubType.SUB_TYPE_USER);

	// Claim names — derived from proto-defined JwtPayloadType enum.
	private static final String TERMINAL = Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_TERMINAL);
	private static final String PARENT_SUB =
			Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_PARENT_SUB);
	private static final String LOCALITY = Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_LOCALITY);
	private static final String SERVICE_ENTITLEMENTS = Helpers.jwtPayloadTypeToString(JwtPayloadType.JWT_PAYLOAD_TYPE_SERVICE_ENTITLEMENTS);

	private static final Pattern WORKLOAD_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_-]+");

	/** SPIFFE URI scheme prefix — the authority follows it. */
	private static final String SPIFFE_PREFIX = Spiffe.SCHEME + "://";

	// Plausible-kid gate, mirroring SecurityInterceptor/SecurityAuthenticator (Phase 0.1
	// DoS-hardening). Kernel's own kids are UUIDs — 36 chars of [0-9a-f-], see
	// KeyRotator.newKey — and a cred_pair's kid is whatever id the tenant config gave it,
	// so the charset stays the permissive-but-safe [A-Za-z0-9_-] superset rather than
	// anything UUID-shaped. Length is gated by KID_MAX_LENGTH alone; the pattern carries
	// no bound of its own, which previously read {1,512} and was dead against the
	// 128-char cap checked beside it.
	private static final int KID_MAX_LENGTH =
			Integer.getInteger("tacplus.auth.kidMaxLength", 128);
	private static final Pattern KID_FORMAT = Pattern.compile("^[A-Za-z0-9_-]+$");

	/**
	 * Phase 0.1 fast-rejection gate: is {@code kid} a plausible key id worth scanning
	 * the verifying-key set for? Cheap format + length check (configurable cap via
	 * {@code tacplus.auth.kidMaxLength}, permissive {@code [A-Za-z0-9_-]} charset) so an
	 * attacker-supplied bogus/oversized kid is rejected before any O(keys) lookup. This
	 * is the single implementation; every externally-influenced kid scan calls it and
	 * then throws its own call-site-appropriate status on {@code false}. Validation only:
	 * deliberately NO sleep/retry/semaphore — the blocking just-published-key retry lives
	 * exclusively on the cross-kernel propagation (data-plane interceptor) path.
	 *
	 * <p>Package-visible because {@code TlsCertServiceImpl.ManageCert} authenticates
	 * its own callers and scans the same verifying-key set, so it goes through the
	 * same gate rather than growing a second copy.
	 */
	static boolean isPlausibleKid(String kid) {
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


	private static final long DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS = 900; // 15 minutes
	private static final long DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS = 86400; // 24 hours
	private static final long DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 2592000; // 30 days
	private static final long DEFAULT_OFFLINE_TOKEN_LIFETIME_SECONDS = 7776000; // 90 days

	/** Default cred_pair → C2S token lifetime (MintClientToken). */
	private static final long DEFAULT_TOKEN_TTL_SECONDS = 3600; // 1 hour

	/**
	 * Longest lifetime kernel will accept on a CLIENT-minted proof JWT, whatever
	 * the client put in {@code exp} — see {@link #proofReplayRefusal}. A proof
	 * asserts possession of a key right now; it is not a credential to carry
	 * around, and its lifetime is the window a captured one could be replayed in.
	 */
	private static final long MAX_PROOF_LIFETIME_SECONDS = 60;

	/** Clock-skew allowance on the proof cap, matching {@code TokenWrapper.verify}. */
	private static final long PROOF_CLOCK_SKEW_SECONDS = 60;

	/** Size at which {@link #seenProofJtis} is swept for expired entries. */
	private static final int PROOF_JTI_PURGE_THRESHOLD = 1024;

	/** Maximum lifetime of an externally-minted token (MintExternalToken). */
	private static final long EXTERNAL_TOKEN_MAX_TTL_SECONDS = 300;

	/** Maximum lifetime of a service's own external token (MintExternalServiceToken). */
	static final long EXTERNAL_SERVICE_TOKEN_MAX_TTL_SECONDS = 600;

	/**
	 * Separates the two halves of a person key ({@link #linkKey}). Neither a namespace nor a
	 * SPIFFE id may contain it, so the pair can never be ambiguous.
	 */
	private static final String LINK_KEY_SEPARATOR = "|";

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
			KeyOuterClass.KeyType requestedKeyType,
			long tokenExp) throws ProtoException {
		KeyRotator.SigAlg signingAlg = externalSigningAlgForKeyType(requestedKeyType);
		ImmutableKey signingKey = keyRotator.reserve(signingAlg, tokenExp);
		if (signingKey == null) {
			throw ProtoException.newErrGeneral(null,
					"no active signing key for requested_signing_key_type "
							+ requestedKeyType + " (" + signingAlg + ")");
		}

		return new ExternalSigningSelection(signingAlg, signingKey);
	}

	/**
	 * Seen {@code jti}s of accepted client-minted proofs → the epoch second past
	 * which the entry is dead. A proof is single-use; see
	 * {@link #proofReplayRefusal} for why this is node-local.
	 */
	private final java.util.concurrent.ConcurrentMap<String, Long> seenProofJtis =
			new java.util.concurrent.ConcurrentHashMap<>();

	/**
	 * The identity graph — XIDs, links, memberships — behind the people
	 * service's contract. Kernel state backs it until the people service exists
	 * (stratum-per-tenant-2026-10-25); nothing else here touches those rows.
	 */
	private final IdentityGraph identityGraph;

	/**
	 * The effective {@code Config.people_signups_paused}, read on every first
	 * login; see {@link IdentityGraph#resolveOrCreate}. Off until kernel wires in the
	 * runtime override ({@code ConfigOverrides}).
	 */
	private volatile java.util.function.BooleanSupplier peopleSignupsPaused = () -> false;

	/**
	 * Serializes a pending approval's read-check-write. Static and
	 * package-private, not an instance field, because
	 * {@code PersonalIdentityServiceImpl.createPendingApproval} writes the same
	 * collection from the other side of the C2S boundary and a second lock would
	 * serialize nothing.
	 *
	 * <p>It is what makes an approval SINGLE-USE, and it is node-local with the
	 * same limitation every other guard in this file has: two kernel nodes
	 * serving two copies of the same request could each consume the same approval
	 * once. Recorded in the slice's decision doc rather than papered over — the
	 * absent cluster CAS is the same gap {@code seenProofJtis} has for proof
	 * replay, and closing it needs the FencedLock, not a second mutex.
	 */
	static final Object PENDING_APPROVAL_LOCK = new Object();

	private final long defaultTokenExpirySeconds;
	private final long accessTokenLifetimeSeconds;
	private final long refreshTokenLifetimeSeconds;
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
	private final com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient;
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
	private final Runnable writeIdentitySnapshot;
	/**
	 * PrincipalState boundary access — the people registry whose device
	 * credentials the {@code AUTH_BROKER_KIND_DEVICE} mint reads. Required, never null, for the same reason as {@link #workloadMap}:
	 * a kernel that cannot read the registry would refuse every device login as an
	 * unknown credential, which is indistinguishable from a real refusal.
	 */
	private final PrincipalMap principalMap;
	/**
	 * The WebAuthn relying party both device flows check an assertion against —
	 * §3's link proof and §5's approval. Never null: an absent configuration
	 * becomes an unconfigured relying party that refuses every assertion, the
	 * same fail-closed default as {@link #kubernetesTokenVerifier}.
	 */
	private final WebauthnProof.RelyingParty webauthnRelyingParty;

	public IdentityServiceImpl(
			long defaultTokenExpirySeconds,
			long accessTokenLifetimeSeconds,
			long refreshTokenLifetimeSeconds,
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
			@Nullable com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient,
			ConfigMap configMap,
			WorkloadMap workloadMap,
			PrincipalMap principalMap,
			Runnable writeIdentitySnapshot,
			@Nullable KubernetesTokenVerifier kubernetesTokenVerifier,
			@Nullable String kubernetesTokenAudience,
			@Nullable WebauthnProof.RelyingParty webauthnRelyingParty) {
		this.defaultTokenExpirySeconds = defaultTokenExpirySeconds > 0 ? defaultTokenExpirySeconds : 3600;
		this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds > 0 ? accessTokenLifetimeSeconds : DEFAULT_ACCESS_TOKEN_LIFETIME_SECONDS;
		this.refreshTokenLifetimeSeconds = refreshTokenLifetimeSeconds > 0 ? refreshTokenLifetimeSeconds : DEFAULT_REFRESH_TOKEN_LIFETIME_SECONDS;
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
		this.principalMap = java.util.Objects.requireNonNull(principalMap,
				"principalMap is required — the personal-principal registry backs device login");
		this.writeIdentitySnapshot = writeIdentitySnapshot != null ? writeIdentitySnapshot : () -> { };
		this.identityGraph = new KernelIdentityGraph(this.principalMap, this.writeIdentitySnapshot,
				() -> peopleSignupsPaused.getAsBoolean());
		// Default to the fail-closed UNIMPLEMENTED verifier so an un-wired kernel
		// never silently accepts a kubernetes_token.
		this.kubernetesTokenVerifier =
				kubernetesTokenVerifier != null ? kubernetesTokenVerifier : new UnwiredKubernetesTokenVerifier();
		this.kubernetesTokenAudience = kubernetesTokenAudience != null ? kubernetesTokenAudience : "";
		this.webauthnRelyingParty = webauthnRelyingParty != null
				? webauthnRelyingParty
				: WebauthnProof.RelyingParty.NONE;
	}

	/** The identity graph this service writes through; XID ageing sweeps it ({@link XidAgeing}). */
	IdentityGraph identityGraph() {
		return identityGraph;
	}

	/** Wires the sign-ups kill switch; see {@link IdentityGraph#resolveOrCreate}. */
	void setPeopleSignupsPaused(java.util.function.BooleanSupplier peopleSignupsPaused) {
		this.peopleSignupsPaused = peopleSignupsPaused;
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
		String spiffeId = serviceSubject(matchedDelegate);

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
					request.getContinuityToken(), spiffeId, nameFormSubject(matchedDelegate));
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

	/**
	 * The subject kernel mints for {@code delegate}. Its root comes from the
	 * delegate's tenant_namespace: {@code /system} for a shared platform
	 * service, and for a tenant-owned instance the tenant's tid,
	 * {@code /tenants/<tid>} (kernel#23), read from the tenant's record, so the
	 * gateway matches a request's target tid to the instance with no lookup and
	 * the identity outlives a rename. The service path segment is the delegate
	 * name either way. A delegate whose tenant kernel holds no record of, with a
	 * tid, mints nothing.
	 */
	private String serviceSubject(Kernel.Delegate delegate) throws StatusException {
		String tenantNamespace = delegate.getTenantNamespace();
		if (tenantNamespace.isEmpty()) {
			return SpiffeIds.build(trustDomainReader.get(), "", delegate.getName());
		}
		refuseDeletedTenant(tenantNamespace);
		String tid;
		try {
			tid = configMap == null ? "" : configMap.getTenants(tenantNamespace).getTid();
		} catch (ProtoException e) {
			throw new StatusException(Status.UNAVAILABLE, "tenant records unavailable: " + e.getMessage());
		}
		if (tid.isEmpty()) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"delegate " + delegate.getName() + " names tenant " + tenantNamespace
							+ ", which has no tenant record with a tid: it mints nothing");
		}
		return SpiffeIds.build(trustDomainReader.get(), SpiffeIds.tenantRoot(tid), delegate.getName());
	}

	/**
	 * The subject kernel minted for a tenant-owned {@code delegate} before
	 * kernel#23, rooted at the tenant's name, or null for a {@code /system}
	 * delegate, whose subject did not change. Only a continuity token may still
	 * carry it.
	 */
	@Nullable
	private String nameFormSubject(Kernel.Delegate delegate) {
		return delegate.getTenantNamespace().isEmpty() ? null
				: SpiffeIds.build(trustDomainReader.get(), delegate.getTenantNamespace(), delegate.getName());
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

		// Authenticate the calling broker via its bearer token, and require it to be
		// a delegate trusted to broker THIS class of user authentication proof.
		String callerSub = verifiedCallerToken("MintUserToken").getSubject();
		Tokenrequest.AuthBrokerKind brokerKind = request.getBrokerKind();
		Kernel.Delegate broker = requireBrokerDelegate(callerSub, brokerKind);
		switch (brokerKind) {
			case AUTH_BROKER_KIND_IDP:
				// The broker validated the IdP assertion itself; kernel trusts the
				// attestation and carries the broker in azp.
				//
				// A login through one of the people providers (PeopleTenant's fixed
				// table, matched on the verified origin_iss) is a PERSON: the subject
				// is the XID the (idp_id, sub) link resolves to — created on first
				// sight — never request.subject. The issuer selects the arm, not the
				// broker's own namespace: a fleet runs ONE oauth instance, rooted at
				// /system, and it brokers every login (identity decision record
				// 2026-10-25, step 1). Any other issuer is an ordinary tenant login
				// on the path below, unchanged, until tenant IdPs carry an idp_id.
				if (PeopleTenant.providerForIssuer(claimString(request.getClaims(), "origin_iss")) != null) {
					return mintPersonToken(request, callerSub);
				}
				break;
			case AUTH_BROKER_KIND_DEVICE:
				// Kernel verifies the device proof ITSELF against the principal's own
				// credential list, so nothing here rests on the broker's word: the
				// broker routed the call, it did not attest the identity.
				return mintDevicePersonalToken(request, callerSub);
			default:
				// PERSONAL_LINK requires kernel to verify request.proof_token
				// itself, which is not implemented. EMAIL_LINK is mail link, which
				// was removed upstream (2026-10-20); tacplus still defines the
				// value. UNSPECIFIED is the zero value and names no proof at all.
				// Refuse rather than mint on an unverified proof.
				throw new StatusException(Status.PERMISSION_DENIED,
						"broker kind " + brokerKind.name() + " is not supported by MintUserToken");
		}

		// Resolve and mint via shared internal method. The caller's own verified
		// subject is threaded through rather than the bare delegate name, which
		// no longer identifies one delegate on its own.
		return mintUserTokenInternal(request.getSubject(), withoutSynthesizedClaims(request.getClaims()),
				request.getExp(), request.getTraceId(), callerSub,
				request.getOfflineAccess(), null);
	}

	/**
	 * The {@code AUTH_BROKER_KIND_DEVICE} arm: possession of a device key
	 * enrolled on a person ({@code Person.devices}), verified by kernel, mints
	 * that PERSON's token — {@code sub = spiffe://<td>/users/<xid>}, namespace
	 * {@code /tenants/people}, the people tenant every person belongs to — with
	 * the device named by the {@code device} claim. A device is a credential of
	 * the XID, not a principal of its own (tacplus#131 retired {@code /people}).
	 *
	 * <p>Everything identifying comes out of the proof, not out of the request.
	 * {@code request.subject} is an IdP-path field and is deliberately ignored
	 * here — a broker naming person B while relaying a proof signed by person
	 * A's device key mints for A, because the kid resolves to A's credential and
	 * the signature is checked against the key stored ON it. There is no field
	 * an attacker can point at somebody else.
	 *
	 * <p>The claims are synthesized, not relayed, for the same reason: the broker
	 * attests nothing on this path, so letting it hand OPA a claim set would put
	 * the entitlements of a kernel-verified identity back under the broker's
	 * control.
	 */
	private Tokenrequest.TokenMintResponse mintDevicePersonalToken(
			Tokenrequest.MintUserTokenRequest request, String callerSub) throws StatusException {
		EnrolledDevice device = verifyDeviceProof(request.getProofToken());
		String xid = device.person().getXid();
		// The person's generation rides the token, as it rides a session
		// credential, so signing out everywhere reaches a device token too.
		Struct claims = Struct.newBuilder()
				.putFields("principal_id", Value.newBuilder().setStringValue(xid).build())
				.putFields(CLAIM_DEVICE, Value.newBuilder()
						.setStringValue(device.credential().getCredentialId()).build())
				.putFields(SessionCredential.CLAIM_GENERATION, Value.newBuilder()
						.setStringValue(Long.toString(device.person().getGeneration())).build())
				.build();
		return mintUserTokenInternal(
				SpiffeIds.userSubject(trustDomainReader.get(), xid),
				claims, request.getExp(), request.getTraceId(), callerSub,
				request.getOfflineAccess(), PeopleTenant.NAMESPACE);
	}

	/**
	 * The people arm of the IdP mint (identity decision record 2026-10-25,
	 * step 1): a login through one of the fixed people providers resolves to a
	 * PERSON — {@code spiffe://<td>/users/<xid>} — through the
	 * {@code (idp_id, provider_subject)} link, created on first sight together
	 * with the XID and its {@code people} membership. Same human, same XID, from
	 * any device, browser or provider identity linked to it.
	 *
	 * <p>Nothing identifying is taken from the request except the claims the
	 * broker already verified. {@code request.subject} is ignored the way the
	 * device arm ignores it: the link key is derived from {@code origin_iss} and
	 * {@code origin_sub} — the IdP's own issuer and subject, which oauth copies
	 * verbatim out of the id_token it verified — so there is no field a broker
	 * could point at somebody else's person.
	 *
	 * <p>OPA is asked ONCE, for the tenant the login routes to (the claim
	 * matchers) and for entitlements. The tenants this login vouches for are
	 * that tenant, if any, plus {@code people}, which every login activates. The
	 * token minted is the org's when one is routed — an org login activates the
	 * org AND people — and {@code people}'s otherwise: a login no tenant routes
	 * is a person, not a refusal. The namespace is stamped here from kernel's
	 * own resolution, never read back out of OPA by mintUserTokenInternal.
	 */
	private Tokenrequest.TokenMintResponse mintPersonToken(
			Tokenrequest.MintUserTokenRequest request, String callerSub) throws StatusException {
		Struct claims = withoutSynthesizedClaims(request.getClaims());
		String issuer = claimString(claims, "origin_iss");
		Kernel.PeopleIdpProvider provider = issuer == null ? null : PeopleTenant.providerForIssuer(issuer);
		String providerSubject = provider == null ? null
				: PeopleTenant.providerSubject(provider, issuer, key -> claimString(claims, key));
		if (provider == null || providerSubject == null) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"people login carries no verified subject claims for its provider");
		}
		String idpId = PeopleTenant.idpId(provider);

		Userentitlements.EntitlementEvalResult opaResult =
				resolveEntitlementsViaOpa(claims, request.getTraceId());
		String routedTenant = opaResult.getNamespace();
		String namespace = routedTenant.isEmpty() ? PeopleTenant.NAMESPACE : routedTenant;
		// Before any write: a login routed into a deleted tenant (a claim matcher
		// left behind in policy) creates no person and no membership.
		refuseDeletedTenant(routedTenant);

		IdentityGraph.Resolved resolved = identityGraph.resolveOrCreate(idpId, providerSubject);
		Kernel.Person person = resolved.person();
		boolean first = resolved.created();
		if (!routedTenant.isEmpty()) {
			person = identityGraph.addMembership(person.getXid(), routedTenant);
		}

		// The proof records what this login vouched for, now, never re-derived
		// at the exchange: an org login vouches the org AND people; a personal
		// login vouches people only.
		List<String> tenants = routedTenant.isEmpty()
				? List.of(PeopleTenant.NAMESPACE) : List.of(routedTenant, PeopleTenant.NAMESPACE);
		return mintSessionCredential(person, idpId, providerSubject, tenants, namespace, claims,
				first, request, callerSub, opaResult);
	}

	/** The login's person, created on first sight; see {@link IdentityGraph#resolveOrCreate}. */
	Kernel.Person resolveOrCreatePerson(String idpId, String providerSubject) throws StatusException {
		return identityGraph.resolveOrCreate(idpId, providerSubject).person();
	}

	/** The link index key: {@code <idp_id>|<provider_subject>}. */
	static String identityLinkKey(String idpId, String providerSubject) {
		return KernelIdentityGraph.linkKey(idpId, providerSubject);
	}

	/** A relayed claim set without the names only kernel may set ({@link #SYNTHESIZED_CLAIMS}). */
	static Struct withoutSynthesizedClaims(Struct relayed) {
		Struct.Builder stripped = relayed.toBuilder();
		SYNTHESIZED_CLAIMS.forEach(stripped::removeFields);
		return stripped.build();
	}

	/** The value of a string claim, or null when it is absent or not a non-empty string. */
	@Nullable
	private static String claimString(@Nullable Struct claims, String key) {
		if (claims == null) {
			return null;
		}
		Value value = claims.getFieldsMap().get(key);
		if (value == null || value.getKindCase() != Value.KindCase.STRING_VALUE
				|| value.getStringValue().isEmpty()) {
			return null;
		}
		return value.getStringValue();
	}

	// ========================================================================
	// The session credential (identity decision record 2026-10-25, step 2)
	// ========================================================================

	/**
	 * Mint (login): the broker's verified assertion becomes a credential with one
	 * proof, plus the first access token. The credential is a kernel-signed
	 * refresh-class token (or offline-class when the broker asked for offline
	 * access, so the existing lifetime rules apply unchanged) whose shape is the
	 * {@code xid_gen} and {@code proofs} claims — see {@link SessionCredential}.
	 * Nothing is written here; the credential IS the session.
	 *
	 * <p>{@code tenants} is what this login vouches for, fixed now and carried in
	 * the proof: an org login the claim matchers routed vouches the org AND
	 * {@code people}; a personal login vouches {@code people} only. The first AT
	 * is the org's when there is one, else {@code people}'s.
	 */
	private Tokenrequest.TokenMintResponse mintSessionCredential(Kernel.Person person, String idpId,
			String providerSubject, List<String> tenants, String firstTenant, Struct claims,
			boolean first, Tokenrequest.MintUserTokenRequest request, String callerSub,
			Userentitlements.EntitlementEvalResult opaResult) throws StatusException {
		Kernel.Delegate delegate = findDelegateBySubject(callerSub);
		if (delegate == null) {
			throw new StatusException(Status.INTERNAL, "delegate not found: " + callerSub);
		}
		long now = Instant.now().getEpochSecond();
		boolean offline = request.getOfflineAccess();
		// The proof lives as long as the login would have: the broker's requested
		// exp, else the refresh (or offline) lifetime, under the same ceilings the
		// legacy refresh token had. No tenant configures a max proof age yet.
		long maxExp = now + (offline ? offlineTokenLifetimeSeconds : maxTokenLifetimeSeconds);
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
			exp = now + (offline ? offlineTokenLifetimeSeconds : refreshTokenLifetimeSeconds);
		}
		long authTime = claimLong(claims, "origin_auth_time", claimLong(claims, "origin_iat", now));
		SessionCredential.Proof proof = new SessionCredential.Proof(
				idpId, providerSubject, authTime, exp, tenants, claims, first);

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}
		TokenWrapper credential = signCredential(
				SpiffeIds.userSubject(trustDomainReader.get(), person.getXid()), person.getGeneration(),
				delegate.getName(), offline, List.of(proof), now, exp, signingKey);
		long accessExp = Math.min(exp, now + accessTokenLifetimeSeconds);
		TokenOuterClass.Token accessToken = accessTokenFromProof(
				credential, proof, firstTenant, opaResult, now, accessExp, signingKey);

		logger.info("Mint: credential for xid={} vouching {} via {}, first AT in {}, exp={}, offline={}",
				person.getXid(), tenants, idpId, firstTenant, exp, offline);
		return Tokenrequest.TokenMintResponse.newBuilder()
				.setRefreshToken(credential.getProto())
				.setAccessToken(accessToken)
				.build();
	}

	/** Signs a credential: the identity, its generation and the proofs; the tenant is the exchange's to choose. */
	/**
	 * Signs {@code token} unless its namespace lies in a deleted tenant
	 * (kernel#19, tenant-deletion record): a deleted tenant mints no new token,
	 * by any path. Every kernel-signed token carries the namespace it is for, so
	 * this one check at the signature covers every mint path, the ones to come
	 * included. Tokens issued before the deletion are left to expire.
	 */
	private void signLive(TokenWrapper token, ImmutableKey signingKey) throws StatusException {
		refuseDeletedTenant(token.getNamespace());
		token.sign(signingKey);
	}

	/** PERMISSION_DENIED when {@code namespace} lies in a deleted tenant; see {@link #signLive}. */
	private void refuseDeletedTenant(String namespace) throws StatusException {
		refuseDeletedTenant(configMap, namespace);
	}

	/**
	 * PERMISSION_DENIED when {@code namespace} lies in a deleted tenant, for the
	 * paths that do not sign a token (ManageCert); see {@link #signLive}.
	 */
	static void refuseDeletedTenant(@Nullable ConfigMap configMap, String namespace) throws StatusException {
		String deleted;
		try {
			deleted = TenantIds.deletedTenantOf(configMap, namespace);
		} catch (ProtoException e) {
			throw new StatusException(Status.UNAVAILABLE, "tenant records unavailable: " + e.getMessage());
		}
		if (deleted != null) {
			logger.info("Refused a mint into deleted tenant {} (namespace {})", deleted, namespace);
			throw new StatusException(Status.PERMISSION_DENIED,
					"tenant " + deleted + " was deleted: it mints no tokens");
		}
	}

	/** The namespace {@code subject} acts in; see {@link #namespaceOfSubject(ConfigMap, String)}. */
	private String namespaceOfSubject(String subject) throws StatusException {
		return namespaceOfSubject(configMap, subject);
	}

	/**
	 * The authorization namespace {@code subject} acts in (kernel#23): a
	 * tenant-owned service or workload is rooted at its tenant's tid, and acts in
	 * that tenant's name, {@code /tenants/<name>} ({@link TenantIds#namespaceOfSubject}).
	 * PERMISSION_DENIED when the tid names no live tenant: a deleted tenant is
	 * refused as {@link #signLive} refuses it, and a tenant-owned subject spelled
	 * by name, as kernel minted before kernel#23, is refused too.
	 */
	static String namespaceOfSubject(@Nullable ConfigMap configMap, String subject) throws StatusException {
		String namespace;
		try {
			namespace = TenantIds.namespaceOfSubject(configMap, subject);
			if (namespace == null) {
				refuseDeletedTenant(configMap, TenantIds.mintedNamespaceOfSubject(configMap, subject));
			}
		} catch (ProtoException e) {
			throw new StatusException(Status.UNAVAILABLE, "tenant records unavailable: " + e.getMessage());
		}
		if (namespace == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					subject + " names no live tenant by its tid");
		}
		return namespace;
	}

	private TokenWrapper signCredential(String subject, long generation, String azp, boolean offline,
			List<SessionCredential.Proof> proofs, long now, long exp, ImmutableKey signingKey)
			throws StatusException {
		TokenWrapper credential = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(subject)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		credential.setAzp(azp);
		credential.setSubType(SUB_TYPE_USER);
		// The default tenant, which every person belongs to. A signed user token
		// must carry a namespace; this one never selects what the credential
		// mints — the tenant comes from the exchange, against the proofs.
		credential.setNamespace(PeopleTenant.NAMESPACE);
		if (offline) {
			credential.setTokenUse(TOKEN_USE_OFFLINE);
		} else {
			credential.setTokenUse(TOKEN_USE_REFRESH);
			credential.setCustomField("typ", TOKEN_TYPE_REFRESH);
		}
		credential.setCustomField(SessionCredential.CLAIM_GENERATION, Long.toString(generation));
		credential.setCustomField(SessionCredential.CLAIM_PROOFS, SessionCredential.encode(proofs));
		signLive(credential, signingKey);
		return credential;
	}

	/**
	 * An access token for one tenant, minted from one proof: {@code sub} is the
	 * person, {@code namespace} the tenant, the claims are the proof's (the IdP
	 * claims the broker verified at that login), entitlements OPA's, and
	 * {@code parent_jti} the credential's so lineage reads as it does for a
	 * refresh token.
	 */
	private TokenOuterClass.Token accessTokenFromProof(TokenWrapper credential,
			SessionCredential.Proof proof, String tenantNamespace,
			Userentitlements.EntitlementEvalResult opaResult, long now, long exp,
			ImmutableKey signingKey) throws StatusException {
		TokenWrapper accessToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(credential.getSubject())
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		accessToken.setAzp(credential.getAzp());
		accessToken.setSubType(SUB_TYPE_USER);
		accessToken.setTokenUse(TOKEN_USE_ACCESS);
		accessToken.setNamespace(tenantNamespace);
		accessToken.setClaimsFromStruct(proof.claims(), STANDARD_JWT_CLAIMS, WELL_KNOWN_JWT_CLAIMS);
		accessToken.setCustomField("parent_jti", credential.getJTI());
		setFlatServiceEntitlements(accessToken, expandEntitlements(opaResult));
		signLive(accessToken, signingKey);
		return accessToken.getProto();
	}

	/**
	 * The per-tenant exchange: a credential and a tenant in, that tenant's access
	 * token out — only when a live proof vouches for the tenant (or the tenant is
	 * {@code people}, which any proof activates); otherwise PERMISSION_DENIED
	 * with the step-up. No tenant named means {@code people}.
	 *
	 * <p>Checks, not lookups, except the record's two reads: the proof's link
	 * still maps to this XID (an Unlink reaches the session here), and the
	 * membership still exists and is not revoked (an org removing a member
	 * reaches it here). Plus the generation: sign-out-everywhere is one bump.
	 * Every miss is ONE PERMISSION_DENIED shape, so the exchange is not an
	 * oracle for which tenants a person belongs to; the step-up is the one
	 * distinguished answer, because it is the one the client acts on.
	 *
	 * <p>{@code offline_access} hands the same credential back beside the AT: a
	 * credential is not renewed, a proof lives on its IdP's policy and a new
	 * login is what extends a session.
	 */
	private Tokenrequest.TokenMintResponse mintFromSessionCredential(
			Tokenrequest.TokenMintRequest request, TokenWrapper credential) throws StatusException {
		if (!request.getAud().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"a session credential mints service tokens via service_auds, not aud");
		}
		String tenantNamespace = request.getTenantNamespace().isEmpty()
				? PeopleTenant.NAMESPACE : request.getTenantNamespace();
		if (SpiffeIds.namespaceRoot().equals(tenantNamespace)) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"tenant_namespace must name a tenant, not the authorization-tree root");
		}
		long now = Instant.now().getEpochSecond();
		Kernel.Person person = livePersonOf(credential);

		SessionCredential.Proof proof =
				liveProofFor(SessionCredential.proofsOf(credential), person, tenantNamespace, now);
		if (proof == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no live proof vouches for " + tenantNamespace
							+ ": sign in with that tenant's identity provider");
		}
		if (!hasLiveMembership(person, tenantNamespace)) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no live proof vouches for " + tenantNamespace
							+ ": sign in with that tenant's identity provider");
		}

		Userentitlements.EntitlementEvalResult opaResult =
				resolveEntitlementsViaOpa(proof.claims(), request.getTraceId());

		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > now + maxTokenLifetimeSeconds) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + (now + maxTokenLifetimeSeconds));
			}
		} else {
			exp = now + accessTokenLifetimeSeconds;
		}
		// The AT never outlives the proof that vouched for it, nor the credential.
		exp = Math.min(exp, Math.min(proof.exp(), credential.getExpiration()));
		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}
		TokenOuterClass.Token accessToken = accessTokenFromProof(
				credential, proof, tenantNamespace, opaResult, now, exp, signingKey);

		logger.info("MintToken (session credential): xid={}, tenant={}, via={}, exp={}",
				person.getXid(), tenantNamespace, proof.idpId(), exp);
		Tokenrequest.TokenMintResponse.Builder resp = Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(accessToken);
		if (request.getOfflineAccess()) {
			resp.setRefreshToken(credential.getProto());
		}
		if (!request.getServiceAudsList().isEmpty()) {
			TokenWrapper accessWrapper = TokenWrapper.from(accessToken);
			for (String svcAud : request.getServiceAudsList()) {
				if (svcAud.isEmpty()) {
					throw new StatusException(Status.INVALID_ARGUMENT, "service_auds entries must be non-empty");
				}
				resp.addServiceTokens(exchangeKernelToken(Tokenrequest.TokenMintRequest.newBuilder()
						.setAud(svcAud)
						.setExp(request.getExp())
						.build(), accessWrapper).getAccessToken());
			}
		}
		return resp.build();
	}

	/**
	 * The person a verified credential names, if they still exist, are not
	 * disabled, and the credential's generation is theirs. One refusal shape for
	 * every miss, for the reason {@link #mintFromSessionCredential} gives.
	 */
	private Kernel.Person livePersonOf(TokenWrapper credential) throws StatusException {
		String xid = SessionCredential.xidOf(credential);
		Kernel.Person person = xid == null ? Kernel.Person.getDefaultInstance() : identityGraph.person(xid);
		if (person.getXid().isEmpty() || person.getDisabledAtMs() != 0 || person.getDeletedAtMs() != 0
				|| !person.getMergedIntoXid().isEmpty()
				|| SessionCredential.generationOf(credential) != person.getGeneration()) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"this session is no longer valid: sign in again");
		}
		return person;
	}

	/**
	 * The first of {@code proofs} that is live, vouches {@code tenantNamespace},
	 * and whose link still maps to the person; null when none does.
	 */
	@Nullable
	private SessionCredential.Proof liveProofFor(List<SessionCredential.Proof> proofs,
			Kernel.Person person, String tenantNamespace, long now) {
		for (SessionCredential.Proof proof : proofs) {
			if (proof.isLive(now) && proof.vouches(tenantNamespace) && linkStillMapsTo(proof, person.getXid())) {
				return proof;
			}
		}
		return null;
	}

	/** The record's first read: the proof's link still resolves to this person. */
	private boolean linkStillMapsTo(SessionCredential.Proof proof, String xid) {
		return xid.equals(identityGraph.xidForLink(proof.idpId(), proof.providerSubject()));
	}

	/** The record's second read: the membership exists and is not revoked. */
	private static boolean hasLiveMembership(Kernel.Person person, String tenantNamespace) {
		for (Kernel.PersonMembership membership : person.getMembershipsList()) {
			if (tenantNamespace.equals(membership.getTenantNamespace())) {
				return membership.getRevokedAtMs() == 0;
			}
		}
		return false;
	}

	/**
	 * A credential presented in a request body: parsed, verified against
	 * kernel's own keys, and of the credential shape. Anything else — a legacy
	 * refresh token, an access token, a token kernel did not sign — is refused
	 * before a single proof is read.
	 */
	private TokenWrapper verifiedSessionCredential(String raw) throws StatusException {
		TokenWrapper token;
		try {
			token = TokenWrapper.parse(raw);
		} catch (Exception e) {
			throw new StatusException(Status.INVALID_ARGUMENT, "invalid credential: " + e.getMessage());
		}
		verifyKernelSigned(token, "credential");
		if (!SessionCredential.isCredential(token) || SessionCredential.xidOf(token) == null) {
			throw new StatusException(Status.INVALID_ARGUMENT, "token is not a session credential");
		}
		return token;
	}

	/** Verifies a kernel-signed token against the current verifying set; {@code label} names it in refusals. */
	private void verifyKernelSigned(TokenWrapper token, String label) throws StatusException {
		String kid = token.getKid();
		if (kid == null || kid.isEmpty() || !isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED, label + " signed with unknown key: " + kid);
		}
		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw new StatusException(Status.UNAUTHENTICATED, label + " signed with unknown key: " + kid);
		}
		try {
			token.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, label + " verification failed: " + e.getMessage());
		}
	}

	/** Re-signs {@code template}'s identity with {@code proofs}; exp is the latest proof's. */
	private TokenWrapper resignCredential(TokenWrapper template, long generation,
			List<SessionCredential.Proof> proofs) throws StatusException {
		long now = Instant.now().getEpochSecond();
		long exp = 0;
		for (SessionCredential.Proof proof : proofs) {
			exp = Math.max(exp, proof.exp());
		}
		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}
		return signCredential(template.getSubject(), generation, template.getAzp(),
				TOKEN_USE_OFFLINE.equals(template.getTokenUse()), proofs, now, exp, signingKey);
	}

	@Override
	public Kernel.MergeCredentialsResponse mergeCredentials(Caller caller,
			Kernel.MergeCredentialsRequest request) throws ProtoException {
		try {
			return doMergeCredentials(caller, request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MergeCredentials failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "merge failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Merge: all credentials must name the caller's own XID and its current
	 * generation; the result carries the union of their proofs, deduplicated by
	 * (idp_id, subject) keeping the fresher. Stateless. Two credentials naming
	 * two people are refused — joining two people is Link, the write, with its
	 * own warning path.
	 */
	private Kernel.MergeCredentialsResponse doMergeCredentials(Caller caller,
			Kernel.MergeCredentialsRequest request) throws StatusException {
		if (request.getCredentialsCount() == 0) {
			throw new StatusException(Status.INVALID_ARGUMENT, "no credentials to merge");
		}
		TokenWrapper first = null;
		Kernel.Person person = null;
		List<SessionCredential.Proof> proofs = List.of();
		for (String raw : request.getCredentialsList()) {
			TokenWrapper credential = verifiedSessionCredential(raw);
			if (first == null) {
				first = credential;
				requireCallerIs(caller, credential.getSubject());
				person = livePersonOf(credential);
			} else if (!first.getSubject().equals(credential.getSubject())) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"credentials name different people; Link, not Merge, joins two people");
			} else {
				livePersonOf(credential);
			}
			proofs = SessionCredential.merge(proofs, SessionCredential.proofsOf(credential));
		}
		TokenWrapper merged = resignCredential(first, person.getGeneration(), proofs);
		logger.info("MergeCredentials: xid={}, {} credential(s) -> {} proof(s)",
				person.getXid(), request.getCredentialsCount(), proofs.size());
		return Kernel.MergeCredentialsResponse.newBuilder().setCredential(merged.getProto()).build();
	}

	@Override
	public Kernel.MergePeopleResponse mergePeople(Caller caller,
			Kernel.MergePeopleRequest request) throws ProtoException {
		try {
			return doMergePeople(caller, request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MergePeople failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "merge failed: " + e.getMessage(), e);
		}
	}

	/**
	 * The record's Link: two credentials of two people, both presented, become
	 * one person. The older XID survives (identity graph huddle item 13); the
	 * other's links and memberships move to it, its index rows are repointed,
	 * and it is tombstoned with a redirect. The response is the survivor's
	 * credential carrying both credentials' proofs, so the session that asked
	 * now holds every sign-in it just proved.
	 *
	 * <p>The warning path: the absorbed person must be nothing but the identity
	 * its credential just proved — one link, that link's proof marked
	 * {@code first} (the XID began at that login), and no membership beyond
	 * {@code people}. Anything more is somebody's existing account, and moving it
	 * takes {@code confirm}.
	 */
	private Kernel.MergePeopleResponse doMergePeople(Caller caller, Kernel.MergePeopleRequest request)
			throws StatusException {
		TokenWrapper a = verifiedSessionCredential(request.getCredentialA());
		TokenWrapper b = verifiedSessionCredential(request.getCredentialB());
		if (!caller.getSubject().equals(a.getSubject()) && !caller.getSubject().equals(b.getSubject())) {
			throw new StatusException(Status.PERMISSION_DENIED, "neither credential is the caller's own");
		}
		Kernel.Person personA = livePersonOf(a);
		Kernel.Person personB = livePersonOf(b);
		List<SessionCredential.Proof> proofs =
				SessionCredential.merge(SessionCredential.proofsOf(a), SessionCredential.proofsOf(b));
		if (personA.getXid().equals(personB.getXid())) {
			// Same person: this is Merge, and writes nothing.
			return Kernel.MergePeopleResponse.newBuilder()
					.setCredential(resignCredential(a, personA.getGeneration(), proofs).getProto())
					.build();
		}
		boolean aSurvives = personA.getCreatedAtMs() <= personB.getCreatedAtMs();
		TokenWrapper survivorCredential = aSurvives ? a : b;
		TokenWrapper loserCredential = aSurvives ? b : a;

		Kernel.Person survivor = identityGraph.mergePeople(
				(aSurvives ? personA : personB).getXid(), (aSurvives ? personB : personA).getXid(),
				loser -> request.getConfirm() || isFreshFromCredential(loser, loserCredential));
		return Kernel.MergePeopleResponse.newBuilder()
				.setCredential(resignCredential(survivorCredential, survivor.getGeneration(), proofs).getProto())
				.build();
	}

	/**
	 * Whether {@code person} is nothing but the one identity {@code credential}
	 * just proved: a single link, whose proof in the credential is marked
	 * {@code first}, and no membership beyond {@code people}.
	 */
	private static boolean isFreshFromCredential(Kernel.Person person, TokenWrapper credential) {
		if (person.getLinksCount() != 1 || person.getMembershipsCount() != 1
				|| !PeopleTenant.NAMESPACE.equals(person.getMemberships(0).getTenantNamespace())) {
			return false;
		}
		Kernel.IdentityLink only = person.getLinks(0);
		for (SessionCredential.Proof proof : SessionCredential.proofsOf(credential)) {
			if (proof.first() && proof.sameIdentity(only.getIdpId(), only.getProviderSubject())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Kernel.GetLinkedAccountsResponse getLinkedAccounts(Caller caller,
			Kernel.GetLinkedAccountsRequest request) throws ProtoException {
		try {
			String xid = SessionCredential.xidOfSubject(caller.getSubject());
			Kernel.Person person = xid == null ? Kernel.Person.getDefaultInstance() : identityGraph.person(xid);
			if (person.getXid().isEmpty() || person.getDisabledAtMs() != 0 || person.getDeletedAtMs() != 0
					|| !person.getMergedIntoXid().isEmpty()) {
				throw new StatusException(Status.PERMISSION_DENIED, "this session is no longer valid: sign in again");
			}
			return Kernel.GetLinkedAccountsResponse.newBuilder()
					.setXid(person.getXid())
					.addAllLinks(person.getLinksList())
					.addAllMemberships(person.getMembershipsList())
					.addAllDevices(person.getDevicesList())
					.build();
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}
	}

	/**
	 * Unlink. The link whose proof the presenting credential carries is refused —
	 * "not the one you are signed in with" — which also means the last link can
	 * never be unlinked: removing the whole account is DeleteAccount.
	 */
	@Override
	public Kernel.DeleteIdentityLinkResponse deleteIdentityLink(Caller caller,
			Kernel.DeleteIdentityLinkRequest request) throws ProtoException {
		try {
			TokenWrapper credential = verifiedSessionCredential(request.getCredential());
			requireCallerIs(caller, credential.getSubject());
			Kernel.Person person = livePersonOf(credential);
			for (SessionCredential.Proof proof : SessionCredential.proofsOf(credential)) {
				if (proof.sameIdentity(request.getIdpId(), request.getProviderSubject())) {
					throw new StatusException(Status.FAILED_PRECONDITION,
							"that is the sign-in this session uses; sign in with another to remove it");
				}
			}
			identityGraph.removeLink(person.getXid(), request.getIdpId(), request.getProviderSubject());
			return Kernel.DeleteIdentityLinkResponse.getDefaultInstance();
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}
	}

	/** Delete account, warned and two-step: without {@code confirm} it only says what would go. */
	@Override
	public Kernel.DeleteAccountResponse deleteAccount(Caller caller,
			Kernel.DeleteAccountRequest request) throws ProtoException {
		try {
			TokenWrapper credential = verifiedSessionCredential(request.getCredential());
			requireCallerIs(caller, credential.getSubject());
			Kernel.Person person = livePersonOf(credential);
			if (!request.getConfirm()) {
				throw new StatusException(Status.FAILED_PRECONDITION,
						"deleting this account removes its " + person.getLinksCount() + " sign-in(s) and "
								+ person.getMembershipsCount() + " tenant membership(s) and signs out every "
								+ "session; it cannot be undone — confirm to proceed");
			}
			identityGraph.deleteAccount(person.getXid());
			return Kernel.DeleteAccountResponse.getDefaultInstance();
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}
	}

	/**
	 * Removes a device from the caller's person: the credential is marked
	 * revoked, so it mints no device token and approves nothing from now on. No
	 * proof from the device is asked — it is most often removed because it is
	 * lost — but the caller's own session credential is, as for every write here.
	 */
	@Override
	public Kernel.RevokeDeviceCredentialResponse revokeDeviceCredential(Caller caller,
			Kernel.RevokeDeviceCredentialRequest request) throws ProtoException {
		try {
			TokenWrapper credential = verifiedSessionCredential(request.getCredential());
			requireCallerIs(caller, credential.getSubject());
			Kernel.PersonalCredential revoked =
					identityGraph.revokeDevice(livePersonOf(credential).getXid(), request.getCredentialId());
			return Kernel.RevokeDeviceCredentialResponse.newBuilder()
					.setRevokedAtMs(revoked.getRevokedAtMs())
					.build();
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}
	}

	/** Sign out everywhere: one generation bump; every outstanding credential fails at its next mint. */
	@Override
	public Kernel.RevokeSessionsResponse revokeSessions(Caller caller,
			Kernel.RevokeSessionsRequest request) throws ProtoException {
		try {
			TokenWrapper credential = verifiedSessionCredential(request.getCredential());
			requireCallerIs(caller, credential.getSubject());
			identityGraph.bumpGeneration(livePersonOf(credential).getXid());
			return Kernel.RevokeSessionsResponse.getDefaultInstance();
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}
	}

	@Override
	public Kernel.RevokeCredentialProofResponse revokeCredentialProof(Caller caller,
			Kernel.RevokeCredentialProofRequest request) throws ProtoException {
		try {
			return doRevokeCredentialProof(caller, request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("RevokeCredentialProof failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "unmerge failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Unmerge, and sign out of one provider: drop the provider's proofs (or the
	 * one sign-in, when the subject is named), re-sign, and mint an access token
	 * from what remains — in the bearer's tenant if a remaining proof still
	 * activates it, else {@code people}. Dropping the last proof is a sign-out
	 * and returns nothing. Stateless: the link the proof names stays on the
	 * person; only what this credential can mint changes.
	 */
	private Kernel.RevokeCredentialProofResponse doRevokeCredentialProof(Caller caller,
			Kernel.RevokeCredentialProofRequest request) throws StatusException {
		TokenWrapper credential = verifiedSessionCredential(request.getCredential());
		requireCallerIs(caller, credential.getSubject());
		Kernel.Person person = livePersonOf(credential);
		List<SessionCredential.Proof> remaining = new java.util.ArrayList<>();
		boolean found = false;
		for (SessionCredential.Proof proof : SessionCredential.proofsOf(credential)) {
			boolean named = request.getProviderSubject().isEmpty()
					? proof.idpId().equals(request.getIdpId())
					: proof.sameIdentity(request.getIdpId(), request.getProviderSubject());
			if (named) {
				found = true;
			} else {
				remaining.add(proof);
			}
		}
		if (!found) {
			throw new StatusException(Status.NOT_FOUND, "the credential carries no such proof");
		}
		if (remaining.isEmpty()) {
			logger.info("RevokeCredentialProof: xid={} dropped its last proof — signed out", person.getXid());
			return Kernel.RevokeCredentialProofResponse.getDefaultInstance();
		}
		TokenWrapper resigned = resignCredential(credential, person.getGeneration(), remaining);
		String bearerTenant = caller.getNamespace();
		String tenant = hasLiveMembership(person, bearerTenant)
				&& liveProofFor(remaining, person, bearerTenant, Instant.now().getEpochSecond()) != null
				? bearerTenant : PeopleTenant.NAMESPACE;
		Tokenrequest.TokenMintResponse minted = mintFromSessionCredential(
				Tokenrequest.TokenMintRequest.newBuilder()
						.setTenantNamespace(tenant)
						.setTraceId(request.getTraceId())
						.build(),
				resigned);
		logger.info("RevokeCredentialProof: xid={} signed out of {}, {} proof(s) left, AT in {}",
				person.getXid(), request.getIdpId(), remaining.size(), tenant);
		return Kernel.RevokeCredentialProofResponse.newBuilder()
				.setCredential(resigned.getProto())
				.setAccessToken(minted.getAccessToken())
				.build();
	}

	/** A credential is the caller's own: the bearer and the credential name the same person. */
	private static void requireCallerIs(Caller caller, String subject) throws StatusException {
		if (!subject.equals(caller.getSubject())) {
			throw new StatusException(Status.PERMISSION_DENIED, "the credential is not the caller's own");
		}
	}

	/** The value of an integer claim, or {@code fallback} when absent or not a number. */
	private static long claimLong(@Nullable Struct claims, String key, long fallback) {
		if (claims == null) {
			return fallback;
		}
		Value value = claims.getFieldsMap().get(key);
		if (value == null) {
			return fallback;
		}
		if (value.getKindCase() == Value.KindCase.NUMBER_VALUE) {
			return (long) value.getNumberValue();
		}
		if (value.getKindCase() == Value.KindCase.STRING_VALUE) {
			try {
				return Long.parseLong(value.getStringValue());
			} catch (NumberFormatException e) {
				return fallback;
			}
		}
		return fallback;
	}

	// ========================================================================
	// CreateTenantUserLink RPC (device enrolment; tenant-user links retired, kernel#4)
	// ========================================================================

	@Override
	public Kernel.CreateTenantUserLinkResponse createTenantUserLink(Caller caller,
			Kernel.CreateTenantUserLinkRequest request) throws ProtoException {
		try {
			return doCreateTenantUserLink(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("CreateTenantUserLink failed", e);
			throw new ProtoException(ProtoException.INTERNAL,
					"tenant user link failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Enrols a device onto a person's XID: one device side and one people login,
	 * proved together in one request (see {@link #bindSides}).
	 *
	 * <p>Linking two tenant users is retired with the {@code linked} claim it fed
	 * (kernel#4): who the caller is comes from the person, which tenant a call is
	 * for from the request, and whether it is allowed is policy at the target. A
	 * request with no device side is refused before either side is resolved, so
	 * it writes nothing, not even the person its login would create.
	 */
	private Kernel.CreateTenantUserLinkResponse doCreateTenantUserLink(
			Kernel.CreateTenantUserLinkRequest request) throws StatusException {
		String callerSub = verifiedCallerToken("CreateTenantUserLink").getSubject();
		Kernel.TenantUserLinkSide a = request.getA();
		Kernel.TenantUserLinkSide b = request.getB();
		if (!a.hasDeviceAssertion() && !b.hasDeviceAssertion()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"linking two tenant users is retired (kernel#4); CreateTenantUserLink "
							+ "enrols a device, and one side must be a device assertion");
		}
		// A device side is a WebAuthn assertion, which is AUTH_BROKER_KIND_DEVICE's
		// proof, not an IdP assertion, so only a device broker may present one.
		requireBrokerDelegate(callerSub, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE);

		// Every binding check runs before anything is resolved, because resolving
		// the login side can CREATE a person. An unbound proof must write nothing
		// at all.
		bindSides(a, b);
		return enrolDevice(a.hasDeviceAssertion() ? a : b, a.hasDeviceAssertion() ? b : a);
	}

	// ------------------------------------------------------------------
	// The device side of an enrolment (identity decision doc §3, WebAuthn arm)
	// ------------------------------------------------------------------

	/**
	 * Checks that the device side and the people login were obtained together,
	 * before either is resolved and before anything is written.
	 *
	 * <p>They are bound by a pair of checks in opposite directions, because a
	 * device has no nonce of its own to share — the id_token's nonce is the
	 * device key's thumbprint, and the assertion's challenge names that
	 * id_token's login. See {@link WebauthnProof} for why the two orderings are
	 * what make the pair unforgeable rather than circular.
	 */
	private void bindSides(Kernel.TenantUserLinkSide a, Kernel.TenantUserLinkSide b)
			throws StatusException {
		if (a.hasDeviceAssertion() && b.hasDeviceAssertion()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"a device links to a person, not to another device");
		}

		Kernel.TenantUserLinkSide device = a.hasDeviceAssertion() ? a : b;
		Kernel.TenantUserLinkSide login = a.hasDeviceAssertion() ? b : a;

		String issuer = claimString(login.getClaims(), "origin_iss");
		String providerSubject = claimString(login.getClaims(), "origin_sub");
		String nonce = claimString(login.getClaims(), "origin_nonce");
		if (issuer == null || providerSubject == null || nonce == null) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"the login side of a device link carries no verified "
							+ "origin_iss/origin_sub/origin_nonce claims");
		}
		// §3 is "linking device → person": the other half is a person, proved by
		// one of the people tenant's two fixed providers. A device linked to an
		// ordinary tenant user would be a credential for an account kernel did not
		// create and cannot re-derive.
		if (PeopleTenant.providerForIssuer(issuer) == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"a device links to a person; the other side is not a people-tenant login");
		}

		DeviceCredential credential = deviceCredential(device);
		try {
			// BINDING ONE: the login names this key. An id_token obtained in any
			// other ceremony carries some other key's thumbprint, so a stolen one
			// cannot be presented alongside a device the thief does hold.
			if (!nonce.equals(WebauthnProof.thumbprint(credential.publicKey()))) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"the login's nonce is not this device key's thumbprint");
			}
			// BINDING TWO: this assertion names that login. An assertion captured
			// from any other ceremony carries some other challenge, so possession of
			// one does not let it be replayed against a login the attacker controls.
			WebauthnProof.verify(device.getDeviceAssertion(), credential.publicKey(),
					WebauthnProof.loginBinding(issuer, providerSubject, nonce),
					webauthnRelyingParty);
		} catch (WebauthnProof.Invalid e) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"device assertion refused: " + e.getMessage());
		}
	}

	/**
	 * The credential a device side presents: its id, the key to check against,
	 * and the person it is already enrolled on (null on a first enrolment).
	 */
	private record DeviceCredential(String credentialId, JwkOuterClass.Jwk publicKey,
			@Nullable Kernel.Person owner) {
	}

	/**
	 * The credential id a device side names, and the key its assertion must
	 * verify under.
	 *
	 * <p>The STORED key once the credential is enrolled, and the key out of the
	 * request only on a first enrolment, when there is no stored key to consult
	 * instead. Without that split a broker could re-present an existing
	 * credential id under a key of its own choosing.
	 */
	private DeviceCredential deviceCredential(Kernel.TenantUserLinkSide side)
			throws StatusException {
		String credentialId = side.getDeviceAssertion().getCredentialId();
		if (credentialId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"device assertion names no credential");
		}
		Kernel.Person owner = identityGraph.deviceOwner(credentialId);
		for (Kernel.PersonalCredential credential : owner.getDevicesList()) {
			if (credentialId.equals(credential.getCredentialId())) {
				if (credential.getRevokedAtMs() != 0) {
					throw new StatusException(Status.PERMISSION_DENIED,
							"device assertion refused: the credential is revoked");
				}
				return new DeviceCredential(credentialId, credential.getPublicKey(), owner);
			}
		}
		if (!side.hasDevicePublicKey()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"an unregistered device must present its public key");
		}
		return new DeviceCredential(credentialId, side.getDevicePublicKey(), null);
	}

	/**
	 * Device enrolment (kernel#18): the device side's credential goes onto the
	 * XID the login side resolves to. Called once {@link #bindSides} has verified
	 * both bindings, so the caller holds the device's private half AND that
	 * person's login, obtained together.
	 *
	 * <p>A device is a credential of the person, not an identity of its own: no
	 * link edge is written, and its token is the person's (see
	 * {@link #mintDevicePersonalToken}). Enrolling a device the person already
	 * holds changes nothing. A device already enrolled on ANOTHER person is
	 * refused before anything is written — the login's person included — since
	 * moving a key between people is a merge, not an enrolment.
	 */
	private Kernel.CreateTenantUserLinkResponse enrolDevice(Kernel.TenantUserLinkSide device,
			Kernel.TenantUserLinkSide login) throws StatusException {
		Struct claims = login.getClaims();
		String issuer = claimString(claims, "origin_iss");
		Kernel.PeopleIdpProvider provider = PeopleTenant.providerForIssuer(issuer);
		String providerSubject = PeopleTenant.providerSubject(provider, issuer, key -> claimString(claims, key));
		if (providerSubject == null) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"the login side of a device link carries no verified subject claims for its provider");
		}
		String idpId = PeopleTenant.idpId(provider);
		DeviceCredential credential = deviceCredential(device);
		if (credential.owner() != null
				&& !credential.owner().getXid().equals(identityGraph.xidForLink(idpId, providerSubject))) {
			throw new StatusException(Status.PERMISSION_DENIED, "that device belongs to another account");
		}

		Kernel.Person person = resolveOrCreatePerson(idpId, providerSubject);
		long nowMs = System.currentTimeMillis();
		Kernel.Person enrolled = identityGraph.addDevice(person.getXid(), Kernel.PersonalCredential.newBuilder()
				.setCredentialId(credential.credentialId())
				.setPublicKey(credential.publicKey())
				.setLabel(device.getDeviceLabel())
				.setPlatformSynced(device.getDevicePlatformSynced())
				.setCreatedAtMs(nowMs)
				.build());
		long enrolledAt = nowMs;
		for (Kernel.PersonalCredential held : enrolled.getDevicesList()) {
			if (held.getCredentialId().equals(credential.credentialId())) {
				enrolledAt = held.getCreatedAtMs();
			}
		}
		String personKey = linkKey(PeopleTenant.NAMESPACE,
				SpiffeIds.userSubject(trustDomainReader.get(), person.getXid()));
		logger.info("Device enrolled: xid={} platform_synced={}", person.getXid(), device.getDevicePlatformSynced());
		return Kernel.CreateTenantUserLinkResponse.newBuilder()
				.setAUserKey(personKey)
				.setBUserKey(personKey)
				.setCreatedAtMs(enrolledAt)
				.build();
	}

	/**
	 * The key one minted identity is named by in {@code PendingApproval.person_user_key}
	 * and {@code CreateTenantUserLinkResponse}: the {@code namespace} and
	 * {@code sub} claims kernel mints for it, in that order (the shape the
	 * retired tenant-user link registry was keyed by, kernel#4).
	 */
	static String linkKey(String namespace, String subject) {
		return namespace + LINK_KEY_SEPARATOR + subject;
	}

	// ========================================================================
	// Pending approvals (identity decision doc §5)
	// ========================================================================

	/**
	 * The person a caller is — the key {@code PendingApproval.person_user_key}
	 * holds: {@code "/tenants/people|<sub>"} for a caller whose {@code sub} is a
	 * person, {@code spiffe://<td>/users/<xid>}, in whichever tenant the token is
	 * for (a person's subject is the same XID in every tenant). Null for any other
	 * caller: a tenant user who is not an XID has no devices to approve with.
	 *
	 * <p>No link registry is read. Which person a device belongs to is the
	 * person's own record ({@code Person.devices}), so the approving device is
	 * checked against the XID directly (kernel#18).
	 */
	@Nullable
	static String personUserKey(String subject) {
		if (SpiffeIds.xidOf(subject) == null) {
			return null;
		}
		return linkKey(PeopleTenant.NAMESPACE, subject);
	}

	/**
	 * The §5 check the generated {@code (spec.rpc).requires_device} will call:
	 * this approval, this request, this person, signed by one of this person's
	 * devices — and then burned.
	 *
	 * <p>Kernel is not writing that generated check; this is the primitive it
	 * calls into, and everything the check cannot be trusted to have done is done
	 * here. In particular the RPC name and the request hash it presents are
	 * compared against the record AND are inside the challenge the device signed,
	 * so an approval for one request cannot be spent on another however the
	 * calling service behaves.
	 */
	@Override
	public Kernel.BrokerPendingApprovalResponse brokerPendingApproval(Caller caller,
			Kernel.BrokerPendingApprovalRequest request) throws ProtoException {
		try {
			return doBrokerPendingApproval(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("BrokerPendingApproval failed", e);
			throw new ProtoException(ProtoException.INTERNAL,
					"pending approval check failed: " + e.getMessage(), e);
		}
	}

	private Kernel.BrokerPendingApprovalResponse doBrokerPendingApproval(
			Kernel.BrokerPendingApprovalRequest request) throws StatusException {
		long nowMs = System.currentTimeMillis();
		// The whole check runs under the lock, because "verify then consume" with a
		// gap in the middle is not single-use.
		synchronized (PENDING_APPROVAL_LOCK) {
			Kernel.PendingApproval approval =
					principalMap.getPendingApprovals(request.getApprovalId());
			// An absent row reads back as the default instance, so the key/field
			// agreement check answers "no such approval" the same way
			// GetMyIdentity's does.
			if (!approval.getApprovalId().equals(request.getApprovalId())) {
				throw new StatusException(Status.NOT_FOUND, "no such pending approval");
			}
			if (approval.getConsumedAtMs() != 0) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"that approval has already been used");
			}
			if (approval.getExpiresAtMs() <= nowMs) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"that approval has expired");
			}
			if (!approval.getRpcMethod().equals(request.getRpcMethod())) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"that approval is for a different RPC");
			}
			// THE EXACT-REQUEST PIN. Everything else here is about WHO approved;
			// this line is what makes it an approval of one call rather than a
			// standing permission for a shape of call. A same-shaped request with
			// one field changed hashes differently and stops here.
			if (!approval.getRequestHash().equals(request.getRequestHash())) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"that approval is for a different request");
			}
			// The caller the guarded service is serving must be the person the
			// approval was created for. Without it a service could spend an
			// approval one of its users proposed on a call it is serving for
			// another.
			String callerPerson = personUserKey(request.getCallerSubject());
			if (callerPerson == null || !callerPerson.equals(approval.getPersonUserKey())) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"that approval belongs to a different person");
			}

			DeviceApprover approver = verifyApprovingDevice(request, approval);

			try {
				principalMap.putPendingApprovals(approval.getApprovalId(),
						approval.toBuilder().setConsumedAtMs(nowMs).build());
			} catch (ProtoException e) {
				throw new StatusException(Status.INTERNAL,
						"approval could not be consumed: " + e.getMessage());
			}
			logger.info("Device approval accepted: rpc={} person={} device={}",
					approval.getRpcMethod(), approval.getPersonUserKey(), approver.credentialId());
			return Kernel.BrokerPendingApprovalResponse.newBuilder()
					.setConsumedAtMs(nowMs)
					.setPersonUserKey(approval.getPersonUserKey())
					.setDeviceCredentialId(approver.credentialId())
					.build();
		}
	}

	/** The device an approval was signed by: its credential, once it has stood up. */
	private record DeviceApprover(String credentialId) {
	}

	/**
	 * Verifies the tap: this assertion, under a credential kernel stores, of the
	 * XID the approval names.
	 *
	 * <p><b>The stored key, and only the stored key.</b> A first enrolment has a
	 * bootstrap moment where the request's copy of the key is the only thing
	 * there is to check against ({@code deviceCredential}); an approval has no
	 * such moment, because an approving device is by definition already
	 * enrolled. A key out of this request would let its sender choose what the
	 * signature is verified with, so none is accepted — the proto carries no
	 * field for one.
	 *
	 * <p><b>The ownership check</b> is the last step and the one §5 is about:
	 * "signed by a key of the caller's person. Nothing else counts." A device
	 * enrolled on somebody else — or revoked — gets as far as a valid signature
	 * and no further.
	 */
	private DeviceApprover verifyApprovingDevice(Kernel.BrokerPendingApprovalRequest request,
			Kernel.PendingApproval approval) throws StatusException {
		String credentialId = request.getDeviceAssertion().getCredentialId();
		if (credentialId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"device assertion names no credential");
		}
		Kernel.Person owner = identityGraph.deviceOwner(credentialId);
		Kernel.PersonalCredential credential = null;
		for (Kernel.PersonalCredential candidate : owner.getDevicesList()) {
			if (credentialId.equals(candidate.getCredentialId())) {
				credential = candidate;
				break;
			}
		}
		// One refusal for every way the credential does not stand — unknown,
		// revoked, a person no longer live — so this is not an oracle for which
		// credentials exist, the same rule verifyDeviceProof states.
		if (credential == null || credential.getRevokedAtMs() != 0 || !isLive(owner)) {
			throw new StatusException(Status.PERMISSION_DENIED, "device approval refused");
		}
		try {
			WebauthnProof.verify(request.getDeviceAssertion(), credential.getPublicKey(),
					WebauthnProof.approvalBinding(approval.getApprovalId(),
							request.getRpcMethod(), request.getRequestHash().toByteArray()),
					webauthnRelyingParty);
		} catch (WebauthnProof.Invalid e) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"device approval refused: " + e.getMessage());
		}

		if (!approval.getPersonUserKey().equals(
				personUserKey(SpiffeIds.userSubject(trustDomainReader.get(), owner.getXid())))) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"that device is not one of the devices of the person the approval names");
		}
		return new DeviceApprover(credentialId);
	}

	/**
	 * A device token ({@code device} claim set) is exchangeable only while the
	 * credential it names is still enrolled, unrevoked, on the live person its
	 * {@code sub} names, at the generation it was minted under — so removing the
	 * device, deleting the account and signing out everywhere all reach a device
	 * token already out, at its next exchange. Any other token passes untouched.
	 */
	private void assertDeviceStillEnrolled(TokenWrapper token) throws StatusException {
		String credentialId = token.getCustomField(CLAIM_DEVICE);
		if (credentialId == null) {
			return;
		}
		Kernel.Person person = identityGraph.deviceOwner(credentialId);
		boolean enrolled = isLive(person)
				&& person.getXid().equals(SpiffeIds.xidOf(token.getSubject()))
				&& Long.toString(person.getGeneration())
						.equals(token.getCustomField(SessionCredential.CLAIM_GENERATION));
		for (Kernel.PersonalCredential device : person.getDevicesList()) {
			if (credentialId.equals(device.getCredentialId()) && device.getRevokedAtMs() != 0) {
				enrolled = false;
			}
		}
		if (!enrolled) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"this device is no longer signed in to this account");
		}
	}

	/** A person who may still authenticate: present, not disabled, deleted or merged away. */
	private static boolean isLive(Kernel.Person person) {
		return !person.getXid().isEmpty() && person.getDisabledAtMs() == 0 && person.getDeletedAtMs() == 0
				&& person.getMergedIntoXid().isEmpty();
	}

	/** A device credential that has just proved possession, and the person it is enrolled on. */
	private record EnrolledDevice(Kernel.Person person, Kernel.PersonalCredential credential) {
	}

	/**
	 * The four steps {@code MintClientToken} already runs for a cred_pair, against
	 * the people's device credentials ({@code Person.devices}) instead of
	 * {@code KernelTenantConfig.cred_pairs}: parse the proof, read its {@code kid},
	 * find the credential the kid names, verify the signature against that
	 * credential's stored public key.
	 *
	 * <p>The {@code kid} is the only pre-verification handle there is, and it is
	 * the right one: a second device holding the same platform-synced key knows
	 * the key and nothing else — not the XID — and §5.4 requires it to present
	 * the same person with no sign-in.
	 *
	 * <p>Every failure — malformed proof, missing or unknown kid, revoked
	 * credential, a person no longer live, bad signature — is one
	 * PERMISSION_DENIED with one message. Distinguishing them would turn this
	 * into an oracle for which credentials exist, and the mint path does not
	 * enumerate anywhere else either (see {@code doMintDelegatedToken}'s
	 * missing-grant refusal).
	 */
	private EnrolledDevice verifyDeviceProof(String proofToken) throws StatusException {
		TokenWrapper proof;
		try {
			proof = TokenWrapper.parse(proofToken);
		} catch (Exception e) {
			throw deviceProofRefused();
		}
		String credentialId = proof.getKid();
		if (credentialId == null || credentialId.isEmpty()) {
			throw deviceProofRefused();
		}
		Kernel.Person person = identityGraph.deviceOwner(credentialId);
		if (!isLive(person)) {
			throw deviceProofRefused();
		}
		for (Kernel.PersonalCredential credential : person.getDevicesList()) {
			if (!credentialId.equals(credential.getCredentialId())
					|| credential.getRevokedAtMs() != 0) {
				continue;
			}
			try {
				proof.verify(ImmutableJwk.from(credential.getPublicKey()));
			} catch (Exception e) {
				throw deviceProofRefused();
			}
			// Same anti-replay binding MintClientToken applies to a cred_pair
			// proof. Folded into the single refusal for the same reason every
			// other failure here is: distinguishing them turns this into an
			// oracle for which credentials exist.
			if (proofReplayRefusal(proof, Instant.now().getEpochSecond()) != null) {
				throw deviceProofRefused();
			}
			return new EnrolledDevice(person, credential);
		}
		throw deviceProofRefused();
	}

	private static StatusException deviceProofRefused() {
		return new StatusException(Status.PERMISSION_DENIED, "device proof verification failed");
	}

	/**
	 * Anti-replay binding for the two CLIENT-minted proof JWTs kernel accepts —
	 * a cred_pair proof ({@code MintClientToken}) and a device possession proof
	 * ({@link #verifyDeviceProof}). Every kernel-MINTED token gets a fresh
	 * {@code jti} at the point it is signed; these two are the one credential
	 * class where the client chooses the whole payload, and they used to be
	 * nothing but {@code parse} then {@code verify}.
	 *
	 * <p>{@code TokenWrapper.verify} does enforce {@code exp}, so replay was
	 * bounded by the proof's own expiry — but the CLIENT set that expiry, with
	 * nothing constraining how far out, and nothing tied the proof to kernel or
	 * noticed the same proof arriving twice. Anyone who captured one proof could
	 * replay it verbatim for fresh tokens and fresh registrations. Three checks
	 * close that, and the caller decides what to say about a failure:
	 *
	 * <ul>
	 *   <li>{@code aud} must be kernel's audience, so a proof minted for some
	 *       other relying party is not accepted here.</li>
	 *   <li>the accepted lifetime is capped independently of what the client
	 *       asked for, which bounds the replay window and bounds how long the
	 *       {@code jti} below has to be remembered.</li>
	 *   <li>the {@code jti} must be present and unseen. A proof is single-use.</li>
	 * </ul>
	 *
	 * <p>Called only AFTER the signature verifies, so an unauthenticated caller
	 * cannot burn a {@code jti} it does not hold the key for.
	 *
	 * <p><b>Node-local seen-set.</b> {@link #seenProofJtis} is per-JVM, so a
	 * replay aimed at a different kernel pod inside the cap window is not caught.
	 * A cluster-wide TTL map would need a Hazelcast handle these services are not
	 * given; tracked as a follow-up. The audience and lifetime checks are
	 * unaffected.
	 *
	 * @return null when the proof is acceptable, else why it was refused
	 */
	@Nullable
	private String proofReplayRefusal(TokenWrapper proof, long now) {
		if (!Kernel.getDescriptor().getPackage().equals(proof.getAudience())) {
			return "proof audience is not " + Kernel.getDescriptor().getPackage();
		}
		// verify() has already established exp > 0 and not-yet-expired; this bounds
		// the other end. The skew allowance is the same 60s TokenWrapper.verify
		// applies, so a client whose clock runs fast is not refused for it.
		long expCeiling = now + MAX_PROOF_LIFETIME_SECONDS + PROOF_CLOCK_SKEW_SECONDS;
		if (proof.getExpiration() > expCeiling) {
			return "proof lifetime exceeds the " + MAX_PROOF_LIFETIME_SECONDS + "s cap";
		}
		String jti = proof.getJTI();
		if (jti == null || jti.isEmpty()) {
			return "proof has no jti";
		}
		// Entries live at most as long as a proof may, so the set is bounded by the
		// proof rate over that window; purge the expired ones rather than let a
		// burst leave them behind.
		if (seenProofJtis.size() >= PROOF_JTI_PURGE_THRESHOLD) {
			seenProofJtis.values().removeIf(seenUntil -> seenUntil <= now);
		}
		if (seenProofJtis.putIfAbsent(jti, expCeiling) != null) {
			return "proof jti has already been used";
		}
		return null;
	}

	/**
	 * Internal token minting: resolves entitlements via OPA, creates refresh + access tokens.
	 * Used by both MintUserToken (broker-authenticated) and CliTokenBroker (kernel-internal).
	 */
	Tokenrequest.TokenMintResponse mintUserTokenInternal(
			String subject, com.google.protobuf.Struct claims,
			long requestedExp, String traceId, String delegateSubject,
			boolean offlineAccess, @Nullable String stampedNamespace)
			throws StatusException {
		// Resolve entitlements via UncleOPA.
		return mintUserTokenInternal(subject, claims, requestedExp, delegateSubject,
				offlineAccess, stampedNamespace, resolveEntitlementsViaOpa(claims, traceId));
	}

	/**
	 * As {@link #mintUserTokenInternal(String, Struct, long, String, String, boolean, String)},
	 * with the OPA result already in hand — the people arm evaluates OPA once to
	 * learn which tenant the login routes to and then mints with that answer,
	 * rather than asking twice.
	 */
	private Tokenrequest.TokenMintResponse mintUserTokenInternal(
			String subject, com.google.protobuf.Struct claims,
			long requestedExp, String delegateSubject, boolean offlineAccess,
			@Nullable String stampedNamespace, Userentitlements.EntitlementEvalResult opaResult)
			throws StatusException {

		Kernel.Delegate delegate = findDelegateBySubject(delegateSubject);
		if (delegate == null) {
			throw new StatusException(Status.INTERNAL,
					"delegate not found: " + delegateSubject);
		}

		Entitlements.TokenEntitlements expanded = expandEntitlements(opaResult);

		// Mint the token.
		long now = Instant.now().getEpochSecond();
		// Long-lived token: an Offline Token (OT) when offline_access is requested
		// (months), otherwise a refresh token (RT). The OT is exempt from the
		// short-lived max_token_lifetime ceiling and uses the offline ceiling.
		long longLivedDefault = offlineAccess ? offlineTokenLifetimeSeconds : refreshTokenLifetimeSeconds;
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

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
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
		// they belong to. A policy that cannot name one refuses the mint.
		//
		// A stampedNamespace short-circuits that entirely, and must: it is set only
		// where kernel authorized the identity itself (the device arm's person, in
		// /tenants/people), and there OPA sees no IdP claims at all, so asking it for
		// a namespace would be asking it to guess. OPA still supplies the
		// entitlements below — it remains the sole entitlement authority — it just
		// does not get to name the subtree kernel already resolved.
		newToken.setNamespace(
				stampedNamespace != null ? stampedNamespace : requireNamespaceFromOpa(opaResult));

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

		signLive(newToken, signingKey);

		logger.info("MintUserToken: sub={}, azp={}, exp={}, offline={}",
				subject, delegate.getName(), exp, offlineAccess);

		// The access token is always short-lived and never outlives its parent.
		// A long-lived OT must not be mirrored into a long-lived AT.
		long accessExp = Math.min(exp, now + accessTokenLifetimeSeconds);
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

		// The caller's own verified identity, as the (name, namespace) pair that
		// keys a delegate. A service token's sub may arrive as a full SPIFFE URI,
		// resolved exactly as findDelegateBySubject does; a bare sub can only be
		// a /system delegate.
		String rawCallerSub = callerToken.getSubject();
		boolean callerIsSpiffe = SpiffeIds.isSpiffeUri(rawCallerSub);
		String callerDelegateName = callerIsSpiffe
				? SpiffeIds.serviceName(rawCallerSub) : rawCallerSub;
		String callerDelegateNamespace = callerIsSpiffe
				? namespaceOfSubject(rawCallerSub) : SpiffeIds.SYSTEM_NAMESPACE;

		// Paired negative control: no live Grant record authorizes the
		// (caller identity, grant_id) pair presented. Three candidate misses —
		// id doesn't exist, id exists but names a different delegate, id
		// exists and matches but has expired — collapse to the SAME
		// status/message shape (non-enumerating, mirroring
		// findDelegateBySubject's own PERMISSION_DENIED), except expiry gets a
		// distinguishable suffix since that is not a confused-identity case.
		// Run before any OPA call — cheapest-check-first, mirroring
		// doMintUserToken's ordering.
		String grantId = request.getGrantId();
		Kernel.Grant grant = findGrantById(grantId);
		if (grant == null
				|| !grantNamesDelegate(grant, callerDelegateName, callerDelegateNamespace)) {
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

		long now = Instant.now().getEpochSecond();
		long exp = now + defaultTokenExpirySeconds;

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

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
		// Namespace: the fresh OPA replay of the grant's recorded claims maps the
		// consenting user's IdP to their tenant subtree, exactly as on the user
		// mint path. A policy that cannot name one refuses the mint.
		newToken.setNamespace(requireNamespaceFromOpa(opaResult));

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

		signLive(newToken, signingKey);

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

	// ========================================================================
	// Runtime delegation — delegate-bound Offline Token via a one-time code
	// (MintDelegateOfflineToken / BrokerDelegateOfflineToken)
	// ========================================================================

	/**
	 * One Offline Token kernel minted for a delegate and is WITHHOLDING until
	 * that delegate redeems the code it is filed under.
	 */
	static final class WithheldOfflineToken {
		final TokenWrapper token;
		/** The delegate the token's {@code act} names; redemption must match it. */
		final String act;
		final long expiresAtMs;

		WithheldOfflineToken(TokenWrapper token, String act, long expiresAtMs) {
			this.token = token;
			this.act = act;
			this.expiresAtMs = expiresAtMs;
		}
	}

	/**
	 * How long a one-time code stays redeemable. Five minutes: this is the
	 * window in which a person copies a code out of one screen and into their
	 * agent, not a security boundary on its own — redemption re-checks that the
	 * redeeming identity IS the delegate the token was minted for, so a leaked
	 * code buys nothing without that identity.
	 */
	static final long DELEGATE_OFFLINE_CODE_TTL_MS = 5 * 60 * 1000L;

	/** Size at which {@link #withheldOfflineTokens} is swept for dead entries. */
	private static final int WITHHELD_TOKEN_PURGE_THRESHOLD = 1024;

	/**
	 * code → the Offline Token minted against it, node-local and in-memory, the
	 * same durability class as {@code CliTokenBroker}'s nonce registry: a kernel
	 * restart clears it and the user mints a fresh code. Nothing here is durable
	 * state — the code lives minutes and is burned on first use.
	 *
	 * <p>Package-private so tests can age an entry rather than sleep through the
	 * TTL.
	 */
	final java.util.concurrent.ConcurrentMap<String, WithheldOfflineToken> withheldOfflineTokens =
			new java.util.concurrent.ConcurrentHashMap<>();

	/** Source of one-time codes. 48 random bytes → 64 base64url characters. */
	private static final java.security.SecureRandom CODE_RANDOM = new java.security.SecureRandom();

	@Override
	public Tokenrequest.MintDelegateOfflineTokenResponse mintDelegateOfflineToken(Caller caller,
			Tokenrequest.MintDelegateOfflineTokenRequest request) throws ProtoException {
		try {
			return doMintDelegateOfflineToken(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MintDelegateOfflineToken failed", e);
			throw new ProtoException(ProtoException.INTERNAL,
					"delegate offline token mint failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Runtime delegation, user half. The USER calls this with their own bearer
	 * token to connect an agent they own. Kernel resolves the
	 * ({@code delegate_name}, {@code delegate_namespace}) pair, mints an Offline
	 * Token with sub = the calling user, act = the delegate name, and the user's
	 * fresh OPA entitlements narrowed by the request's optional scope — and does
	 * NOT return it. The OT never transits the user's client: the response
	 * carries only a short-lived single-use code the user hands to the delegate,
	 * which redeems it S2S via {@link #doBrokerDelegateOfflineToken}.
	 */
	private Tokenrequest.MintDelegateOfflineTokenResponse doMintDelegateOfflineToken(
			Tokenrequest.MintDelegateOfflineTokenRequest request) throws StatusException {

		TokenWrapper callerToken = verifiedCallerToken("MintDelegateOfflineToken");
		String userSubject = callerToken.getSubject();

		// The delegate this OT is bound to, keyed by (name, namespace) — the name
		// alone is not a key, exactly as findDelegateBySubject spells out. An
		// empty delegate_namespace means the /system delegate of that name.
		String delegateName = request.getDelegateName();
		String delegateNamespace = request.getDelegateNamespace().isEmpty()
				? SpiffeIds.SYSTEM_NAMESPACE : request.getDelegateNamespace();
		Kernel.Delegate delegate = findDelegateByName(delegateName, delegateNamespace);
		if (delegate == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no delegate " + delegateName + " in " + delegateNamespace);
		}

		// The user's CURRENT authority, computed the same way every other user
		// mint computes it, then narrowed by the request's optional scope. The
		// request can only ever narrow: intersectAuthorizedScope is the same
		// narrow-only intersection doMintDelegatedToken applies to a Grant's
		// recorded authorized_scope, and every later mint from this OT intersects
		// fresh OPA output with what is embedded here.
		Userentitlements.EntitlementEvalResult opaResult =
				resolveEntitlementsViaOpa(buildClaimsStruct(callerToken), request.getTraceId());
		Entitlements.TokenEntitlements fresh = expandEntitlements(opaResult);
		Entitlements.TokenEntitlements scoped = request.hasScope()
				? intersectAuthorizedScope(fresh, request.getScope()) : fresh;

		long now = Instant.now().getEpochSecond();
		long exp = now + offlineTokenLifetimeSeconds;

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(userSubject)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		// azp is kernel: this OT is minted directly from the user's own verified
		// token, not on a broker's attestation, exactly as on the Grant path.
		newToken.setAzp(Kernel.getDescriptor().getPackage());
		// act is the BARE delegate name, pre-normalized, per the act-claim-format
		// decision — the same shape doMintDelegatedToken stamps from a Grant.
		newToken.setAct(delegate.getName());
		newToken.setSubType(SUB_TYPE_USER);
		newToken.setTokenUse(TOKEN_USE_OFFLINE);
		newToken.setNamespace(requireNamespaceFromOpa(opaResult));
		newToken.setClaimsFromStruct(buildClaimsStruct(callerToken),
				STANDARD_JWT_CLAIMS, WELL_KNOWN_JWT_CLAIMS);
		setFlatServiceEntitlements(newToken, scoped);
		signLive(newToken, signingKey);

		// Withhold it. Entries live at most the TTL, so the map is bounded by the
		// mint rate over that window; purge the dead ones rather than let a burst
		// leave them behind, the same sweep seenProofJtis does.
		long nowMs = Instant.now().toEpochMilli();
		if (withheldOfflineTokens.size() >= WITHHELD_TOKEN_PURGE_THRESHOLD) {
			withheldOfflineTokens.values().removeIf(held -> held.expiresAtMs <= nowMs);
		}
		long codeExpiresAtMs = nowMs + DELEGATE_OFFLINE_CODE_TTL_MS;
		String code = newOneTimeCode();
		withheldOfflineTokens.put(code,
				new WithheldOfflineToken(newToken, delegate.getName(), codeExpiresAtMs));

		logger.info("MintDelegateOfflineToken: sub={}, act={}, exp={}, code_expires_at_ms={}",
				userSubject, delegate.getName(), exp, codeExpiresAtMs);

		return Tokenrequest.MintDelegateOfflineTokenResponse.newBuilder()
				.setCode(code)
				.setExpiresAtMs(codeExpiresAtMs)
				.build();
	}

	@Override
	public Tokenrequest.RedeemDelegateOfflineTokenResponse brokerDelegateOfflineToken(Caller caller,
			Tokenrequest.RedeemDelegateOfflineTokenRequest request) throws ProtoException {
		try {
			return doBrokerDelegateOfflineToken(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("BrokerDelegateOfflineToken failed", e);
			throw new ProtoException(ProtoException.INTERNAL,
					"delegate offline token redemption failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Runtime delegation, delegate half. The delegate presents its OWN S2S bearer
	 * token plus the code the user handed it. The code alone is not sufficient:
	 * the caller's verified identity must equal the withheld token's {@code act}
	 * claim, which is the actual security boundary here — the code is a handoff
	 * convenience with a UX-length TTL.
	 *
	 * <p>Single-use: the entry is removed under a compare-and-remove, so of two
	 * concurrent redemptions of the same code exactly one wins and the loser sees
	 * the same refusal a second, later redemption would.
	 *
	 * <p>The misses — no such code, expired, or not this delegate's code —
	 * collapse to ONE non-enumerating message, mirroring
	 * {@code doMintDelegatedToken}'s paired negative control, so redemption
	 * cannot be used to probe which codes exist.
	 */
	private Tokenrequest.RedeemDelegateOfflineTokenResponse doBrokerDelegateOfflineToken(
			Tokenrequest.RedeemDelegateOfflineTokenRequest request) throws StatusException {

		TokenWrapper callerToken = verifiedCallerToken("BrokerDelegateOfflineToken");

		// The caller's own verified identity as the act claim spells it: the bare
		// delegate name, resolved from a SPIFFE subject exactly as
		// doMintDelegatedToken resolves it.
		String rawCallerSub = callerToken.getSubject();
		String callerDelegateName = SpiffeIds.isSpiffeUri(rawCallerSub)
				? SpiffeIds.serviceName(rawCallerSub) : rawCallerSub;

		String code = request.getCode();
		WithheldOfflineToken held = withheldOfflineTokens.get(code);
		if (held == null
				|| held.expiresAtMs <= Instant.now().toEpochMilli()
				|| !held.act.equals(callerDelegateName)) {
			// An expired entry is dead whoever asks; drop it on the way past
			// rather than wait for the next purge sweep.
			if (held != null && held.expiresAtMs <= Instant.now().toEpochMilli()) {
				withheldOfflineTokens.remove(code, held);
			}
			throw new StatusException(Status.PERMISSION_DENIED,
					"no redeemable delegate offline token for delegate " + callerDelegateName);
		}

		// Burn it. Compare-and-remove: the entry this call validated is the entry
		// it removes, so a concurrent redemption of the same code cannot also win.
		if (!withheldOfflineTokens.remove(code, held)) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no redeemable delegate offline token for delegate " + callerDelegateName);
		}

		logger.info("BrokerDelegateOfflineToken: sub={}, act={}", held.token.getSubject(), held.act);

		return Tokenrequest.RedeemDelegateOfflineTokenResponse.newBuilder()
				.setToken(held.token.getProto())
				.build();
	}

	/**
	 * A fresh one-time code: 48 bytes of {@link java.security.SecureRandom} in
	 * base64url, which is 64 characters — the minimum the request/response
	 * protos assert, and the same entropy class as a {@code CliTokenBroker}
	 * nonce.
	 */
	private static String newOneTimeCode() {
		byte[] raw = new byte[48];
		CODE_RANDOM.nextBytes(raw);
		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
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
	 * Resolves the namespace claim for a user token from the OPA result, or
	 * refuses the mint. OPA maps the caller's IdP (issuer/claims) to the tenant
	 * subtree they belong to, as a leading-slash absolute path (e.g.
	 * "/tenants/drpepper").
	 *
	 * <p>There is deliberately NO fallback to the cluster root anywhere. The
	 * operator-generated policy emitted no namespace at all until the matching
	 * generator change (operator {@code pkg/bootstrap/opa.go}, tenants/namespace.rego),
	 * so every IdP user in every bootstrapped cluster was being minted at "/" —
	 * fleet-wide root — by the fallback this replaced. A policy that cannot name
	 * the caller's tenant has not authorized a login; it is refused.
	 *
	 * <p>{@link #doMintDelegatedToken} uses this too: its fresh OPA replay of the
	 * grant's recorded claims resolves the consenting user's namespace the same
	 * way, so the same silence refuses the same way.
	 */
	private String requireNamespaceFromOpa(Userentitlements.EntitlementEvalResult result)
			throws StatusException {
		String ns = result.getNamespace();
		if (ns == null || ns.isEmpty()) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"entitlements policy returned no namespace for this caller — "
							+ "no tenant is bound to their IdP, so no token can be minted");
		}
		return ns;
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
		// MintUserToken's restrictions (auth-broker delegates only, OPA entitlement
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

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
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
				? namespaceOfSubject(subject)
				: SpiffeIds.namespaceRoot());

		for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
			newToken.setCustomField(entry.getKey(), entry.getValue());
		}

		signLive(newToken, signingKey);

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
		assertNotRevoked(workloadMap, inputToken.getSubject(), "workload");

		// Same choke point, for standing delegations: a token that derives from a
		// Grant is only exchangeable while that Grant is still live.
		assertGrantStillActive(inputToken);

		// And for devices: a device token buys more only while its device is
		// still enrolled on the live person it names.
		assertDeviceStillEnrolled(inputToken);

		// Session-credential arm (identity decision record 2026-10-25). Selected by
		// claim SHAPE — the xid_gen and proofs claims — never by token_use, so a
		// legacy refresh token can never be read as a proof set, and a credential
		// never reaches the legacy clone path below without the proof, generation,
		// link and membership checks.
		if (SessionCredential.isCredential(inputToken)) {
			return mintFromSessionCredential(request, inputToken);
		}

		if (!request.getTenantNamespace().isEmpty()) {
			// DECISIONS.md item 2: a service's tenant comes from its SPIFFE
			// subject and from nothing else. tenant_namespace is a selector among
			// a PERSON'S proofs, read by the session-credential arm above;
			// honouring it here — or even ignoring it silently — would be the
			// tenant escape the whole field is designed not to be.
			throw new StatusException(Status.INVALID_ARGUMENT,
					"tenant_namespace is only meaningful on a session credential; "
							+ "a service's tenant comes from its SPIFFE subject");
		}

		// Bootstrap tokens are exchanged for real refresh+access pairs (workload bootstrap).
		if (TOKEN_USE_BOOTSTRAP.equals(tokenUse)) {
			long bsNow = Instant.now().getEpochSecond();
			long bsExp = bsNow + defaultTokenExpirySeconds;
			ImmutableKey bsSigningKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, bsExp);
			if (bsSigningKey == null) {
				throw new StatusException(Status.UNAVAILABLE, "no active signing key");
			}
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
			long otNow = Instant.now().getEpochSecond();
			if (request.getOfflineAccess()) {
				return renewOfflineToken(inputToken, otNow, request);
			}
			// Data plane: OT → AT (mintAccessFromRefresh stamps AT.parent_jti = OT.jti).
			// The AT is scoped to the requested (or default) project — this is the
			// project-switch path for offline-token holders.
			// The AT never outlives the OT it came from.
			long otAccessExp = Math.min(inputToken.getExpiration(), otNow + accessTokenLifetimeSeconds);
			ImmutableKey otSigningKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, otAccessExp);
			if (otSigningKey == null) {
				throw new StatusException(Status.UNAVAILABLE, "no active signing key");
			}
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

		long now = Instant.now().getEpochSecond();
		long maxExp = now + maxTokenLifetimeSeconds;
		long exp;
		if (request.getExp() == 0) {
			// A user's refresh → access exchange mints a user access token; every
			// other exchange (service/workload refresh, access → service) keeps the
			// default.
			boolean userAccess = isRefresh && SUB_TYPE_USER.equals(inputToken.getSubType());
			exp = now + (userAccess ? accessTokenLifetimeSeconds : defaultTokenExpirySeconds);
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
		// An exchange may shrink a lifetime, never extend one: the token minted here
		// cannot outlive the credential presented for it, or a caller could renew its
		// way past what the original credential had left. Same cap MintExternalToken
		// applies against the user token it derives from. verify() above has already
		// established the input token carries a live exp.
		exp = Math.min(exp, inputToken.getExpiration());

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		String subject = inputToken.getSubject();

		Kernel.Delegate delegate = findDelegateBySubject(subject);
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
			// Service namespace = the tenant the SPIFFE-URI subject names.
			newToken.setNamespace(namespaceOfSubject(subject));
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

		signLive(newToken, signingKey);
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
		signLive(accessToken, signingKey);
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
			long now, Tokenrequest.TokenMintRequest request)
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
		// The AT never outlives the fresh OT it came from.
		long accessExp = Math.min(exp, now + accessTokenLifetimeSeconds);

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, Math.max(exp, accessExp));
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
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
		signLive(freshOt, signingKey);

		// Also hand back a fresh short-lived AT for immediate data-plane use.
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
	 * <p>A tenant-owned instance whose prior refresh token was minted before
	 * kernel#23 carries the subject rooted at its tenant's name, not its tid.
	 * That token is still bound to the same delegate, so it keeps the instance's
	 * {@code instance_id} once; the name form is accepted here and nowhere else.
	 *
	 * @param rawContinuityToken the raw continuity (prior refresh) token.
	 * @param resolvedSubject    the resolved delegate's canonical SPIFFE subject
	 *                           (what the prior refresh token's {@code sub} carries).
	 * @param nameFormSubject    the same delegate's subject as minted before
	 *                           kernel#23, or null when it did not change.
	 */
	private String resolveInstanceIdFromContinuityToken(String rawContinuityToken,
			String resolvedSubject, @Nullable String nameFormSubject) throws StatusException {

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

		boolean nameForm = nameFormSubject != null && nameFormSubject.equals(continuityToken.getSubject());
		if (!resolvedSubject.equals(continuityToken.getSubject()) && !nameForm) {
			throw new StatusException(
					Status.INVALID_ARGUMENT,
					"continuity_token subject '" + continuityToken.getSubject()
							+ "' does not match the resolved delegate identity '" + resolvedSubject + "'");
		}

		String instanceId = continuityToken.getCustomField("instance_id");
		if (instanceId == null || instanceId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "continuity_token missing instance_id claim");
		}
		if (nameForm) {
			logger.info("Continuity token for sub={} carries the name-form subject {} minted before kernel#23",
					resolvedSubject, nameFormSubject);
		}
		logger.info("Preserved instance_id={} via continuity token for sub={}", instanceId, resolvedSubject);
		return instanceId;
	}

	/**
	 * The authorization namespace a delegate's minted identity is rooted at.
	 * An empty {@code tenant_namespace} — every shared platform service — is
	 * the {@code /system} root.
	 */
	private static String delegateNamespace(Kernel.Delegate delegate) {
		String ns = delegate.getTenantNamespace();
		return ns.isEmpty() ? SpiffeIds.SYSTEM_NAMESPACE : ns;
	}

	/**
	 * Resolves the Delegate a token subject names, keyed by (name, namespace).
	 * The name alone is not a key: a tenant-owned service has one delegate per
	 * tenant, all named for the same service path, so N delegates named
	 * {@code docmanager} coexist and only the namespace tells them apart.
	 *
	 * <p>A SPIFFE-URI subject carries both halves. A bare name — the broker/CLI
	 * form — can only ever name a {@code /system} delegate, since nothing in it
	 * could address a tenant.
	 */
	private Kernel.Delegate findDelegateBySubject(String subject) throws StatusException {
		String name;
		String namespace;
		if (SpiffeIds.isSpiffeUri(subject)) {
			try {
				name = SpiffeIds.serviceName(subject);
				namespace = namespaceOfSubject(subject);
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
			name = subject;
			namespace = SpiffeIds.SYSTEM_NAMESPACE;
		}
		return findDelegateByName(name, namespace);
	}

	/**
	 * Resolves the Delegate named by an explicit ({@code name}, {@code namespace})
	 * pair — the key {@link #findDelegateBySubject} derives from a subject, and
	 * the one a request that names a delegate by field carries directly.
	 */
	private Kernel.Delegate findDelegateByName(String name, String namespace) {
		for (Kernel.Delegate d : delegatesReader.get()) {
			if (name.equals(d.getName()) && namespace.equals(delegateNamespace(d))) {
				return d;
			}
		}
		return null;
	}

	/**
	 * True when the grant names exactly this delegate. Delegate names repeat
	 * across tenants, so the grant's ({@code delegate_name},
	 * {@code delegate_namespace}) pair — an empty namespace meaning
	 * {@code /system} — is what has to match, not the name alone.
	 */
	private static boolean grantNamesDelegate(Kernel.Grant grant, String name, String namespace) {
		String grantNamespace = grant.getDelegateNamespace().isEmpty()
				? SpiffeIds.SYSTEM_NAMESPACE : grant.getDelegateNamespace();
		return name.equals(grant.getDelegateName()) && namespace.equals(grantNamespace);
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
		// act carries the bare delegate name, not the (name, namespace) pair. It
		// need not: the token can only exist because doMintDelegatedToken already
		// matched the full pair, so this is a liveness re-check on a grant whose
		// holder is already established, not an identity check.
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
		// `sub` claim (e.g. "spiffe://local.dev/system/services/oauth"). That URI IS the
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

		// A deleted tenant's services get no new certificate either.
		namespaceOfSubject(spiffeId);

		// Intermediate CA state is keyed by bare service name, matching the
		// ManageCert path. The full SPIFFE URI remains the leaf cert identity.
		String serviceName = SpiffeIds.serviceName(spiffeId);
		if (serviceName.isEmpty()) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"X509Mint requires a service SPIFFE URI; sub has no service path: " + spiffeId);
		}
		logger.info("X509Mint[{}] resolving intermediate CA service={}, spiffeId={}",
				traceId, serviceName, spiffeId);
		ImmutableCertChain intermediateCa = getOrCreateIntermediateCa(traceId, serviceName, signingCa);
		logger.info("X509Mint[{}] intermediate CA ready service={} in {}ms",
				traceId, serviceName, elapsedMillis(startNanos));

		// Build the cert request kernel signs from kernel's own verified view of
		// the caller. Nothing identity- or constraint-bearing is carried over from
		// the request body: the caller supplies a public key and a requested
		// expiry, and kernel decides everything the certificate asserts.
		long now = Instant.now().getEpochSecond();
		X509.X509CertRequest kernelRequest = kernelCertRequest(
				originalCertRequest, spiffeId, serviceName, now,
				maxTokenLifetimeSeconds, defaultTokenExpirySeconds);

		// Sign the kernel-built cert request with the intermediate CA.
		logger.info("X509Mint[{}] signing leaf service={}, keyId={}, issuer={}, exp={}, dnsSans={}, uriSans={}",
				traceId,
				serviceName,
				kernelRequest.hasKey() ? kernelRequest.getKey().getId() : "",
				kernelRequest.getIssuer(),
				kernelRequest.getExp(),
				kernelRequest.getDnsNamesCount(),
				kernelRequest.getUriSansCount());
		X509.X509Cert leafCert = intermediateCa.sign(kernelRequest);
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

	/**
	 * Builds the X509CertRequest kernel actually signs for an X509Mint call.
	 *
	 * <p>Everything the certificate asserts is kernel's, not the caller's: the URI
	 * SAN is the SPIFFE id kernel just verified from the presented token, the
	 * subject CN (carried in {@code issuer}) and the base DNS SANs are derived
	 * from that same identity, key usage is a leaf mTLS usage, and the CA flag and
	 * path-length constraint are never honored from the request body. Otherwise
	 * any service holding a valid token of its own could have a cert signed
	 * carrying another service's identity, or a CA cert.
	 *
	 * <p>The one caller-supplied field kept is a DNS SAN the caller demonstrably
	 * owns — its pod hostname, which the generated service managers send so peers
	 * connecting by hostname pass hostname verification. "Owns" means the name is
	 * the service name itself or is under it ({@code svc-0}, {@code svc.ns.svc}),
	 * which is the shape every k8s workload name in this platform takes; anything
	 * else is another service's name and is dropped.
	 *
	 * <p>The requested expiry is bounded by the same max-token-lifetime ceiling
	 * every other mint path in this class applies, with the same INVALID_ARGUMENT
	 * on breach.
	 */
	static X509.X509CertRequest kernelCertRequest(
			X509.X509CertRequest requested,
			String spiffeId,
			String serviceName,
			long now,
			long maxLifetimeSeconds,
			long defaultLifetimeSeconds) throws StatusException {
		long maxExp = now + maxLifetimeSeconds;
		long exp;
		if (requested.getExp() > 0) {
			exp = requested.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		} else {
			exp = now + defaultLifetimeSeconds;
		}

		// DNS SANs kernel grants unconditionally, matching the ManageCert path.
		LinkedHashSet<String> dnsNames = new LinkedHashSet<>();
		dnsNames.add(serviceName);
		dnsNames.add("*." + serviceName);
		for (String dns : requested.getDnsNamesList()) {
			if (dns.equals(serviceName)
					|| dns.startsWith(serviceName + "-")
					|| dns.startsWith(serviceName + ".")
					|| dns.equals("*." + serviceName)
					// <service><replica-index> with no separator, e.g. "letsencrypt0" —
					// the pod hostname convention every chart uses; same rule as
					// TlsCertServiceImpl.kernelCertRequest (ManageCert path).
					|| dns.matches(java.util.regex.Pattern.quote(serviceName) + "[0-9]+")) {
				dnsNames.add(dns);
			} else {
				logger.warn("X509Mint: dropping DNS SAN '{}' requested by {} — not a name that service owns",
						dns, spiffeId);
			}
		}

		for (String uri : requested.getUriSansList()) {
			if (!uri.equals(spiffeId)) {
				logger.warn("X509Mint: dropping URI SAN '{}' requested by {} — the signed identity is the "
						+ "caller's verified SPIFFE id", uri, spiffeId);
			}
		}
		if (requested.getIsCa() || requested.getPathLenConstraint() != 0) {
			logger.warn("X509Mint: dropping CA constraints requested by {} (is_ca={}, path_len_constraint={}) "
					+ "— X509Mint signs leaf certs only",
					spiffeId, requested.getIsCa(), requested.getPathLenConstraint());
		}

		return X509.X509CertRequest.newBuilder()
				.setKey(requested.getKey())
				.setExp(exp)
				.setIssuer(serviceName)
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_DIGITAL_SIGNATURE)
				.addExtKeyUsage(X509.X509ExtKeyUsage.X509_EXT_KEY_USAGE_SERVER_AUTH)
				.addExtKeyUsage(X509.X509ExtKeyUsage.X509_EXT_KEY_USAGE_CLIENT_AUTH)
				.addUriSans(spiffeId)
				.addAllDnsNames(dnsNames)
				.build();
	}

	private static long elapsedMillis(long startNanos) {
		return (System.nanoTime() - startNanos) / 1_000_000L;
	}

	/**
	 * Gets or creates a per-service intermediate CA.
	 *
	 * <p>Delegates to {@link ServiceIntermediateCa}, which is the single
	 * implementation shared with {@code TlsCertServiceImpl.ManageCert}. The two
	 * services each used to carry their own copy guarded by {@code synchronized}
	 * on their own instance, so nothing serialized a concurrent X509Mint and
	 * ManageCert for the same service and both could sign an intermediate the
	 * other's write then dropped.
	 */
	private ImmutableCertChain getOrCreateIntermediateCa(
			String traceId, String serviceName, ImmutableCertChain rootCa) throws Exception {
		return ServiceIntermediateCa.getOrCreate(
				serviceName, serviceCaReader, serviceCaWriter, rootCa, traceId, logger);
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

		// The parent is the caller, unless the caller is a workload broker (the
		// coop) naming the service the child is minted for (the dog), so the
		// child is that service's — and that tenant's — by construction.
		String parentSub = callerSub;
		String requestedParent = request.getParentSpiffeId();
		if (requestedParent != null && !requestedParent.isEmpty()) {
			Kernel.Delegate callerDelegate = findDelegateBySubject(callerSub);
			if (callerDelegate == null || !callerDelegate.getWorkloadBroker()) {
				throw new StatusException(Status.PERMISSION_DENIED,
						callerSub + " is not a workload broker; it can mint workloads only under itself");
			}
			if (!SpiffeIds.isSpiffeUri(requestedParent) || requestedParent.contains("/workloads/")) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"parent_spiffe_id must be a service SPIFFE URI");
			}
			parentSub = requestedParent;
		}
		// Construct child SPIFFE URI via the generated self-describing helper.
		String childSub = Spiffe.workloadSpiffeId(parentSub, workloadName);

		// A revoked identity cannot be re-minted under the same SPIFFE ID, and the
		// ancestor walk covers the caller too: a revoked parent can mint nothing.
		assertNotRevoked(workloadMap, childSub, "workload");

		// Mint bootstrap token (short-lived).
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

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, bootstrapExp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		TokenWrapper bootstrapToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(childSub)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(bootstrapExp)
				.setJTI(UUID.randomUUID().toString());

		bootstrapToken.setCustomField(PARENT_SUB, parentSub);
		bootstrapToken.setCustomField(TERMINAL, request.getTerminal() ? "true" : "false");
		bootstrapToken.setTokenUse(TOKEN_USE_BOOTSTRAP);
		bootstrapToken.setSubType(SUB_TYPE_SERVICE);
		// Service namespace = the tenant the SPIFFE-URI childSub names.
		bootstrapToken.setNamespace(namespaceOfSubject(childSub));

		signLive(bootstrapToken, signingKey);

		logger.info("WorkloadMint: parent={}, child={}, terminal={}, broker={}",
				parentSub, childSub, request.getTerminal(), parentSub.equals(callerSub) ? "" : callerSub);

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
		// Service namespace = the tenant the SPIFFE-URI sub (validated above) names.
		refreshToken.setNamespace(namespaceOfSubject(sub));
		refreshToken.setAzp(Kernel.getDescriptor().getPackage());
		refreshToken.setInstanceId(instanceId);
		if (parentSub != null) refreshToken.setCustomField(PARENT_SUB, parentSub);
		if (terminal != null) refreshToken.setCustomField(TERMINAL, terminal);

		signLive(refreshToken, signingKey);

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
			// A workload broker may revoke any workload: it minted pigeons under
			// other services, which are not its descendants.
			Kernel.Delegate callerDelegate = findDelegateBySubject(callerSub);
			boolean broker = callerDelegate != null && callerDelegate.getWorkloadBroker();
			if (!broker || !targetSpiffeId.contains("/workloads/")) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"cannot revoke " + targetSpiffeId + " — not a descendant of " + callerSub);
			}
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
		writeIdentitySnapshot.run();

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
	 * delegate holding it (caller identity == the grant's
	 * {@code (delegate_name, delegate_namespace)} pair). Both
	 * are withdrawing authority they already hold, so this needs no authorization
	 * model beyond the caller's own verified identity — the same reasoning that
	 * limits {@code RevokeWorkload} to the identity's own ancestor.
	 *
	 * <p>The record is MARKED ({@code revoked_at_ms}), never deleted, so the
	 * delegation that existed and the moment it was withdrawn stay auditable.
	 * The write goes to the live grants store and then into the identity snapshot
	 * through the same hook {@code RevokeWorkload} uses, so the
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

		// The caller's own verified identity, as the (name, namespace) pair that
		// keys a delegate. A service token's sub may arrive as a full SPIFFE URI,
		// resolved exactly as doMintDelegatedToken does; a user token carries the
		// IDP subject a Grant records at consent time verbatim.
		String rawCallerSub = callerToken.getSubject();
		boolean callerIsSpiffe = SpiffeIds.isSpiffeUri(rawCallerSub);
		String callerDelegateName = callerIsSpiffe
				? SpiffeIds.serviceName(rawCallerSub) : rawCallerSub;
		String callerDelegateNamespace = callerIsSpiffe
				? namespaceOfSubject(rawCallerSub) : SpiffeIds.SYSTEM_NAMESPACE;

		String grantId = request.getGrantId();
		if (grantId == null || grantId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "grant_id is required");
		}

		// Non-enumerating, same shape as the mint path: "no such id" and "not your
		// grant" are one message, so revoke cannot be used to probe which ids exist.
		Kernel.Grant grant = findGrantById(grantId);
		if (grant == null
				|| !(rawCallerSub.equals(grant.getSubject())
						|| grantNamesDelegate(grant, callerDelegateName, callerDelegateNamespace))) {
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
		writeIdentitySnapshot.run();

		logger.info("RevokeGrant: grant_id={}, caller={}, subject={}, delegate={}, revoked_at_ms={}",
				grantId, rawCallerSub, grant.getSubject(), grant.getDelegateName(), revokedAtMs);
	}

	// ========================================================================
	// Tenant deletion (kernel#19, tenant-deletion record)
	// ========================================================================

	/**
	 * Removes what this service holds for {@code tenantNamespace}, a tenant
	 * {@code TenantAdmin.DeleteTenant} has just deleted (its records gone, its
	 * tid tombstoned, so nothing mints into it from then on; see
	 * {@link #signLive}). Idempotent. Returns one line per kind of state, what
	 * was found and what was done with it:
	 *
	 * <ul>
	 *   <li><b>Memberships</b>: removed from every person, through the identity
	 *       graph. The people stay: a person exists outside every tenant.</li>
	 *   <li><b>Pending approvals</b> naming the tenant: deleted. An approval is
	 *       keyed to a person, never a tenant, so there are none today.</li>
	 *   <li><b>Grants</b> whose delegate is the tenant's: revoked. They come
	 *       from {@code Config.grants}, which the deployment owns and kernel
	 *       reseeds at every boot; the revocation rides the snapshot, so they
	 *       stay revoked.</li>
	 *   <li><b>Workload localities</b> of the tenant's services: deleted.
	 *       Workload revocations are kept: they are a deny list, and dropping
	 *       one would un-revoke the workload if a tenant of the same name came
	 *       back.</li>
	 *   <li><b>Withheld offline tokens</b> for the tenant: dropped, so no code
	 *       redeems one.</li>
	 *   <li><b>Delegates</b> (and their Kubernetes service-account matchers)
	 *       for the tenant: counted only. They are {@code Config.delegates},
	 *       the deployment's; every mint through one is refused.</li>
	 * </ul>
	 */
	List<String> purgeDeletedTenant(String tenantNamespace) throws ProtoException {
		List<String> report = new java.util.ArrayList<>();
		try {
			int people = identityGraph.removeTenantMemberships(tenantNamespace);
			report.add("memberships: removed from " + people + " person(s); the people are kept");
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(),
					"memberships of " + tenantNamespace + " could not be removed: " + e.getMessage());
		}

		int approvals = 0;
		for (Kernel.PendingApproval approval : principalMap.proto().getPendingApprovalsList()) {
			if (approval.getPersonUserKey().startsWith(tenantNamespace + LINK_KEY_SEPARATOR)) {
				principalMap.deletePendingApprovals(approval.getApprovalId());
				approvals++;
			}
		}
		report.add("pending approvals: deleted " + approvals);

		int grants = 0;
		long nowMs = Instant.now().toEpochMilli();
		for (Kernel.Grant grant : grantsReader.get()) {
			if (grant.getRevokedAtMs() != 0
					|| !TenantIds.isWithin(grant.getDelegateNamespace(), tenantNamespace)) {
				continue;
			}
			if (grantsWriter == null) {
				throw new ProtoException(ProtoException.UNIMPLEMENTED,
						"grant " + grant.getId() + " of " + tenantNamespace
								+ " cannot be revoked: this kernel has no writable grants store");
			}
			grantsWriter.accept(grant.toBuilder().setRevokedAtMs(nowMs).build());
			grants++;
		}
		report.add("grants: revoked " + grants + " (Config.grants is the deployment's to edit)");

		int localities = 0;
		for (Kernel.WorkloadLocality locality : workloadMap.proto().getLocalitiesList()) {
			if (SpiffeIds.isSpiffeUri(locality.getSpiffeId()) && TenantIds.isWithin(
					TenantIds.mintedNamespaceOfSubject(configMap, locality.getSpiffeId()), tenantNamespace)) {
				workloadMap.deleteLocalities(locality.getSpiffeId());
				localities++;
			}
		}
		report.add("workload localities: deleted " + localities + "; workload revocations are kept");

		int withheld = 0;
		for (Map.Entry<String, WithheldOfflineToken> entry : withheldOfflineTokens.entrySet()) {
			if (TenantIds.isWithin(entry.getValue().token.getNamespace(), tenantNamespace)
					&& withheldOfflineTokens.remove(entry.getKey(), entry.getValue())) {
				withheld++;
			}
		}
		report.add("withheld offline tokens: dropped " + withheld);

		int delegates = 0;
		for (Kernel.Delegate delegate : delegatesReader.get()) {
			if (TenantIds.isWithin(delegate.getTenantNamespace(), tenantNamespace)) {
				delegates++;
			}
		}
		report.add("delegates: " + delegates + " in Config.delegates (the deployment's to remove); "
				+ "every mint through them is refused");
		return report;
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
	 * Requires the verified caller to be a registered delegate that is trusted to
	 * broker this class of user authentication proof. Who may attest a human login
	 * is per-delegate config ({@code Delegate.auth_broker_kinds}), not a
	 * compile-time {@code auth_services} allowlist on the RPC — the RPCs that use
	 * this are declared {@code auth_services: ["*"]} and do the real check here.
	 *
	 * <p>Fail-closed: an empty {@code auth_broker_kinds} — the default, and every
	 * delegate that has not been migrated — is not an auth broker and is refused.
	 *
	 * @param callerSub     the subject of an already-verified caller token
	 * @param requiredKind  the broker kind the calling RPC requires
	 */
	private Kernel.Delegate requireBrokerDelegate(String callerSub, Tokenrequest.AuthBrokerKind requiredKind)
			throws StatusException {
		Kernel.Delegate delegate = findDelegateBySubject(callerSub);
		if (delegate == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"caller " + callerSub + " is not a registered delegate");
		}
		if (!delegate.getAuthBrokerKindsList().contains(requiredKind)) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"delegate " + delegate.getName() + " is not authorized to broker "
							+ requiredKind.name() + " user authentication");
		}
		return delegate;
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
	 * <p>Static and {@code workloadMap}-parameterized because this is the one
	 * revocation gate for every kernel-issued credential, not just tokens:
	 * {@link TlsCertServiceImpl} calls it on the ManageCert issuance path so a
	 * revoked workload cannot keep renewing its mTLS cert either.
	 *
	 * @param workloadMap WorkloadState boundary access holding the revocations
	 * @param spiffeId the identity a token is being minted or exchanged for
	 * @param what     call-site noun for the error message, e.g. "workload"
	 */
	static void assertNotRevoked(WorkloadMap workloadMap, String spiffeId, String what)
			throws StatusException {
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

		// The external token is minted for the user token's namespace; a deleted
		// tenant's mints none (see signLive, which this one does not go through).
		try {
			refuseDeletedTenant(userToken.getNamespace());
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
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
				externalSigningKeyForRequest(keyRotator, request.getRequestedSigningKeyType(), exp);
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
	// MintExternalServiceToken RPC (a service's OWN identity for an off-cluster audience)
	// ========================================================================

	@Override
	public Tokenrequest.TokenMintResponse mintExternalServiceToken(Caller caller,
			Tokenrequest.MintExternalServiceTokenRequest request) throws ProtoException {
		try {
			return doMintExternalServiceToken(request);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		} catch (Exception e) {
			logger.error("MintExternalServiceToken failed", e);
			throw new ProtoException(ProtoException.INTERNAL, "external service token mint failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Mints a NEW ES256 token bearing the caller's own identity for an external
	 * audience. The credential is the caller's kernel-signed service token; sub
	 * comes from it, never from the request. aud must exactly match an entry in
	 * the caller Delegate's {@code external_audiences}. Never calls OPA.
	 */
	private Tokenrequest.TokenMintResponse doMintExternalServiceToken(
			Tokenrequest.MintExternalServiceTokenRequest request) throws StatusException {
		if (request.getInputToken().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "input_token is required");
		}
		if (request.getAud().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "aud is required");
		}

		TokenWrapper inputToken;
		try {
			inputToken = TokenWrapper.parse(request.getInputToken());
		} catch (Exception e) {
			throw new StatusException(Status.INVALID_ARGUMENT, "invalid input_token: " + e.getMessage());
		}

		String kid = inputToken.getKid();
		if (kid.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "input_token missing kid header");
		}
		if (!isPlausibleKid(kid)) {
			throw new StatusException(Status.UNAUTHENTICATED, "input_token signed with unknown key: " + kid);
		}
		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
			if (kid.equals(jwk.getKid())) {
				matchingKey = jwk;
				break;
			}
		}
		if (matchingKey == null) {
			throw new StatusException(Status.UNAUTHENTICATED, "input_token signed with unknown key: " + kid);
		}
		try {
			inputToken.verify(ImmutableJwk.from(matchingKey));
		} catch (Exception e) {
			throw new StatusException(Status.UNAUTHENTICATED, "input_token verification failed: " + e.getMessage());
		}

		// Users go through MintExternalToken; this path is a service's own identity.
		if (!SUB_TYPE_SERVICE.equals(inputToken.getSubType())) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"MintExternalServiceToken requires a service token; users mint external tokens via MintExternalToken");
		}

		String subject = inputToken.getSubject();
		assertNotRevoked(workloadMap, subject, "workload");

		Kernel.Delegate delegate = findDelegateBySubject(subject);
		if (delegate == null) {
			throw new StatusException(Status.PERMISSION_DENIED, "no delegate registered for " + subject);
		}
		if (!delegate.getExternalAudiencesList().contains(request.getAud())) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"delegate " + delegate.getName() + " is not allowed external audience " + request.getAud());
		}

		long now = Instant.now().getEpochSecond();
		long maxExp = now + EXTERNAL_SERVICE_TOKEN_MAX_TTL_SECONDS;
		long exp;
		if (request.getExp() == 0) {
			exp = maxExp;
		} else {
			exp = request.getExp();
			if (exp <= now) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"exp must be a future Unix timestamp, got " + exp + " (now is " + now + ")");
			}
			if (exp > maxExp) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds external service token ceiling " + maxExp);
			}
		}
		// The derived token never outlives the credential presented for it.
		exp = Math.min(exp, inputToken.getExpiration());

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ES256, exp);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active ES256 signing key");
		}

		TokenWrapper externalToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(subject)
				.setAudience(request.getAud())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		externalToken.setTokenUse(TOKEN_USE_EXTERNAL);
		// TokenWrapper.sign refuses a token with no namespace; carry the verified
		// caller's own, which kernel stamped when it minted the input token.
		externalToken.setNamespace(inputToken.getNamespace());
		signLive(externalToken, signingKey);

		logger.info("external service token minted: sub={}, aud={}, exp={}", subject, request.getAud(), exp);

		return Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(externalToken.getProto())
				.build();
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
		//
		// Nothing — not the proto, not updateTenantConfig — enforces that cred_pair
		// ids are unique ACROSS tenants, so this used to break on the first id match
		// and let `tenant_configs` iteration order decide which tenant's namespace a
		// token was scoped to. The loser's credential would mint tokens into somebody
		// else's namespace. Collect every match instead and refuse an ambiguous id:
		// there is no correct answer to pick, and picking one silently is the bug.
		Credentials.CredPair matched = null;
		String namespace = null;
		List<String> owningTenants = new java.util.ArrayList<>();
		for (Kernel.TenantConfigEntry e : configMap.proto().getTenantConfigsList()) {
			for (Credentials.CredPair cp : e.getConfig().getKernel().getCredPairsList()) {
				if (credPairId.equals(cp.getId())) {
					matched = cp;
					namespace = e.getTenantName();
					owningTenants.add(e.getTenantName());
					break;
				}
			}
		}
		if (matched == null) {
			throw new ProtoException(ProtoException.UNAUTHENTICATED,
					"unknown cred_pair: " + credPairId);
		}
		if (owningTenants.size() > 1) {
			logger.error("cred_pair {} is configured under {} tenants: {} — refusing to mint",
					credPairId, owningTenants.size(), owningTenants);
			throw new ProtoException(ProtoException.FAILED_PRECONDITION,
					"cred_pair " + credPairId + " is configured under more than one tenant");
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
		String replayRefusal = proofReplayRefusal(proof, now);
		if (replayRefusal != null) {
			throw new ProtoException(ProtoException.UNAUTHENTICATED,
					"cred_pair proof verification failed: " + replayRefusal);
		}

		// The C2S token is a short-lived access token, so it takes the same
		// max-token-lifetime ceiling (not the offline one) every other
		// short-lived mint path in this class applies, with the same
		// INVALID_ARGUMENT on breach.
		//
		// The cred_pair's own expires_at is the second ceiling, and it was missing:
		// expires_at gated the credential at mint time (above) but never bounded the
		// token's exp, so a holder minting one second before the credential expired
		// got a token good for the full max_token_lifetime. Expiring or revoking the
		// credential then left up to that whole window of live access. Both ceilings
		// are the same INVALID_ARGUMENT shape so they read identically to a caller.
		long maxExp = now + maxTokenLifetimeSeconds;
		if (matched.hasExpiresAt() && matched.getExpiresAt().getSeconds() > 0) {
			maxExp = Math.min(maxExp, matched.getExpiresAt().getSeconds());
		}
		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
			if (exp <= now) {
				throw new ProtoException(ProtoException.INVALID_ARGUMENT, "exp must be in the future");
			}
			if (exp > maxExp) {
				throw new ProtoException(ProtoException.INVALID_ARGUMENT,
						"requested exp " + exp + " exceeds max token lifetime ceiling " + maxExp);
			}
		} else {
			exp = Math.min(now + DEFAULT_TOKEN_TTL_SECONDS, maxExp);
		}

		ImmutableKey signingKey = keyRotator.reserve(KeyRotator.SigAlg.ED25519, exp);
		if (signingKey == null) {
			throw new ProtoException(ProtoException.UNAVAILABLE, "no active signing key");
		}

		// Mint a C2S token carrying the cred_pair's entitlements + namespace.
		// No P2S/capability: the single C2S authorizer checks service_entitlements
		// against (method, target namespace), identically to IDP-user tokens.
		TokenWrapper token = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject("cred-pair:" + credPairId)
				// The caller identity the authenticators read (principal, falling back
				// to service_name): a cred_pair token is the pair, not a person or a
				// service, and without this every authenticated RPC refuses it.
				.setPrincipal("cred-pair:" + credPairId)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		token.setNamespace(namespace);
		setFlatServiceEntitlements(token, matched.getEntitlements());
		try {
			signLive(token, signingKey);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}

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
