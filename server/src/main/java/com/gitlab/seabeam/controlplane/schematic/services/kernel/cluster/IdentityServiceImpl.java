// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.jwk.ImmutableJwk;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.grants.Grants;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.token.Helpers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass.JwtPayloadType;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass.TokenUse;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.token.TokenOuterClass.SubType;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.UserMint;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.spec.Spec;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
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
public class IdentityServiceImpl implements Mint.MintHandler, UserMint.UserMintHandler {

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

	/**
	 * The registry's own ceiling — {@code PrincipalState.personal_principals}
	 * carries {@code (spec.assert_max_size) = 65536}. It is repeated here because
	 * {@code PrincipalMap.putPersonalPrincipals} validates the ROW it is handed
	 * and nothing validates the collection on the way in: the cap is only checked
	 * by {@code Helpers.validateKernelDiskState}, inside {@code IdentitySnapshot.save()},
	 * which logs and swallows. Over the cap without this check, registration would
	 * appear to succeed and every subsequent snapshot — signing keys, CAs, tenants,
	 * grants and all — would be silently lost. Refuse the registration instead.
	 */
	private static final int MAX_PERSONAL_PRINCIPALS = 65536;

	/**
	 * Cap on {@code PrincipalState.people}, matching the proto's
	 * {@code assert_max_size} for the same reason {@link #MAX_PERSONAL_PRINCIPALS}
	 * does: a registry grown past the bound fails validation on the way into the
	 * disk snapshot, so every later write would be lost rather than the one that
	 * overflowed.
	 */
	private static final int MAX_PEOPLE = 65536;

	/**
	 * Cap on one user's links, matching {@code TenantUserLinks.links}'s
	 * {@code assert_max_size} for the same reason {@link #MAX_PEOPLE} matches its
	 * own: a row grown past the bound fails validation on the way into the disk
	 * snapshot, losing every later write rather than the one that overflowed.
	 */
	private static final int MAX_LINKS_PER_USER = 64;

	/**
	 * Separates the two halves of a link registry key. Neither a namespace nor a
	 * SPIFFE id may contain it, so the pair can never be ambiguous.
	 */
	private static final String LINK_KEY_SEPARATOR = "|";

	/** Canonical root of the personal-principal subtree ({@code /people/<pid>}). */
	private static final String PEOPLE_PREFIX = "/" + Spiffe.PEOPLE_SEGMENT + "/";

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

	/**
	 * Seen {@code jti}s of accepted client-minted proofs → the epoch second past
	 * which the entry is dead. A proof is single-use; see
	 * {@link #proofReplayRefusal} for why this is node-local.
	 */
	private final java.util.concurrent.ConcurrentMap<String, Long> seenProofJtis =
			new java.util.concurrent.ConcurrentHashMap<>();

	/** Serializes CreatePersonalPrincipal's read-check-write; see the call site. */
	private final Object personalPrincipalRegistryLock = new Object();

	/** Serializes the people-tenant mint's find-or-create; see {@link #mintPersonToken}. */
	private final Object personRegistryLock = new Object();

	/**
	 * Serializes the link registry's read-modify-write; see
	 * {@link #doCreateTenantUserLink}.
	 *
	 * <p>Static and package-private, not an instance field, because
	 * {@code PersonalIdentityServiceImpl.revokeTenantUserLink} writes the same
	 * two rows from the other side of the C2S boundary and a second lock would
	 * serialize nothing. Node-local, with the same limitation every other guard
	 * in this file has and for the same reason: no cluster CAS is available to
	 * these services.
	 */
	static final Object LINK_REGISTRY_LOCK = new Object();

	/**
	 * Serializes a pending approval's read-check-write. Static and
	 * package-private for the same reason {@link #LINK_REGISTRY_LOCK} is:
	 * {@code PersonalIdentityServiceImpl.createPendingApproval} writes the same
	 * collection from the other side of the C2S boundary.
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
	private final com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient;
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
	 * PrincipalState boundary access — the personal-principal registry that
	 * {@code CreatePersonalPrincipal} writes and the {@code AUTH_BROKER_KIND_DEVICE}
	 * mint reads. Required, never null, for the same reason as {@link #workloadMap}:
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
			@Nullable com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.proxypolicy.OpaEvalGrpcClient proxyPolicyOpaClient,
			ConfigMap configMap,
			WorkloadMap workloadMap,
			PrincipalMap principalMap,
			Runnable writeIdentitySnapshot,
			@Nullable KubernetesTokenVerifier kubernetesTokenVerifier,
			@Nullable String kubernetesTokenAudience,
			@Nullable WebauthnProof.RelyingParty webauthnRelyingParty) {
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
		this.principalMap = java.util.Objects.requireNonNull(principalMap,
				"principalMap is required — the personal-principal registry backs device login");
		this.writeIdentitySnapshot = writeIdentitySnapshot != null ? writeIdentitySnapshot : () -> { };
		// Default to the fail-closed UNIMPLEMENTED verifier so an un-wired kernel
		// never silently accepts a kubernetes_token.
		this.kubernetesTokenVerifier =
				kubernetesTokenVerifier != null ? kubernetesTokenVerifier : new UnwiredKubernetesTokenVerifier();
		this.kubernetesTokenAudience = kubernetesTokenAudience != null ? kubernetesTokenAudience : "";
		this.webauthnRelyingParty = webauthnRelyingParty != null
				? webauthnRelyingParty
				: WebauthnProof.RelyingParty.NONE;
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
		// The subject's root comes from the delegate's tenant_namespace: /system
		// for a shared platform service, /tenants/<tenant> for a tenant-owned
		// instance. The service path segment is the delegate name either way.
		String spiffeId = SpiffeIds.build(
				trustDomainReader.get(), matchedDelegate.getTenantNamespace(), delegateName);

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

		// Authenticate the calling broker via its bearer token, and require it to be
		// a delegate trusted to broker THIS class of user authentication proof.
		String callerSub = verifiedCallerToken("MintUserToken").getSubject();
		Tokenrequest.AuthBrokerKind brokerKind = request.getBrokerKind();
		Kernel.Delegate broker = requireBrokerDelegate(callerSub, brokerKind);
		switch (brokerKind) {
			case AUTH_BROKER_KIND_IDP:
				// The broker validated the IdP assertion itself; kernel trusts the
				// attestation and carries the broker in azp. Today's path.
				//
				// One exception: a broker whose own identity is rooted at the
				// reserved `people` tenant mints PEOPLE, not tenant users — the
				// subject is derived from the verified IdP claims rather than taken
				// from request.subject, and the row is created on first sight. The
				// delegate's own tenant_namespace is what selects the arm, per the
				// 2026-09-08 ruling that the namespace is stamped from the minting
				// delegate's identity and never from OPA output.
				if (PeopleTenant.NAMESPACE.equals(broker.getTenantNamespace())) {
					return mintPersonToken(request, callerSub);
				}
				break;
			case AUTH_BROKER_KIND_DEVICE:
				// Kernel verifies the device proof ITSELF against the principal's own
				// credential list, so nothing here rests on the broker's word: the
				// broker routed the call, it did not attest the identity.
				return mintDevicePersonalToken(request, callerSub);
			default:
				// EMAIL_LINK / PERSONAL_LINK each require kernel to verify
				// request.proof_token itself, which is not implemented. UNSPECIFIED
				// is the zero value and names no proof at all. Refuse rather than
				// mint on an unverified proof.
				throw new StatusException(Status.PERMISSION_DENIED,
						"broker kind " + brokerKind.name() + " is not supported by MintUserToken");
		}

		// Resolve and mint via shared internal method. The caller's own verified
		// subject is threaded through rather than the bare delegate name, which
		// no longer identifies one delegate on its own.
		return mintUserTokenInternal(request.getSubject(), request.getClaims(),
				request.getExp(), request.getTraceId(), callerSub,
				request.getOfflineAccess(), null);
	}

	/**
	 * The {@code AUTH_BROKER_KIND_DEVICE} arm: possession of a personal
	 * principal's device key, verified by kernel, mints that principal's own
	 * {@code /people/<pid>} token and nothing else.
	 *
	 * <p>Everything identifying comes out of the proof, not out of the request.
	 * {@code request.subject} is an IdP-path field and is deliberately ignored
	 * here — a broker naming principal B while relaying a proof signed by
	 * principal A's key mints for A, because A's kid resolves to A's row and the
	 * signature is checked against the key stored ON that row. There is no field
	 * an attacker can point at somebody else, which is the same property
	 * {@code GetMyIdentity} gets by taking no arguments at all.
	 *
	 * <p>The claims are synthesized, not relayed, for the same reason: the broker
	 * attests nothing on this path, so letting it hand OPA a claim set would put
	 * the entitlements of a kernel-verified identity back under the broker's
	 * control.
	 */
	private Tokenrequest.TokenMintResponse mintDevicePersonalToken(
			Tokenrequest.MintUserTokenRequest request, String callerSub) throws StatusException {
		Kernel.PersonalPrincipal principal = verifyDeviceProof(request.getProofToken());
		String principalId = principal.getPrincipalId();
		String namespace = PEOPLE_PREFIX + principalId;
		Struct claims = Struct.newBuilder()
				.putFields("principal_id", Value.newBuilder().setStringValue(principalId).build())
				.build();
		return mintUserTokenInternal(
				Spiffe.userSpiffeId(trustDomainReader.get(), namespace, principalId),
				claims, request.getExp(), request.getTraceId(), callerSub,
				request.getOfflineAccess(), namespace);
	}

	/**
	 * The {@code people}-tenant arm of the IdP mint: the first login for a
	 * (provider, subject) pair CREATES that person's user row, and every login
	 * after it finds the same row. Same human, same user, from any device or
	 * browser.
	 *
	 * <p>Nothing identifying is taken from the request except the claims the
	 * broker already verified. {@code request.subject} is ignored the way the
	 * device arm ignores it: the subject minted here is derived from
	 * {@code origin_iss} and {@code origin_sub} — the IdP's own issuer and
	 * subject, which oauth copies verbatim out of the id_token it verified — so
	 * there is no field a broker could point at somebody else's person.
	 *
	 * <p>The issuer is matched against {@link PeopleTenant}'s fixed table rather
	 * than against the tenant's configured providers. The tenant's IdP set is
	 * fixed in the proto enum, and checking it here means a broker misconfigured
	 * with a third issuer mints nothing rather than minting a person keyed to an
	 * issuer this tenant does not recognise.
	 *
	 * <p>The claims ARE relayed into OPA, unlike the device arm: on this path the
	 * broker attested the login, so OPA is entitled to see what it attested. The
	 * NAMESPACE is not OPA's to name — it is stamped {@code /tenants/people}
	 * from the delegate's own identity, per the 2026-09-08 ruling.
	 */
	private Tokenrequest.TokenMintResponse mintPersonToken(
			Tokenrequest.MintUserTokenRequest request, String callerSub) throws StatusException {
		Struct claims = request.getClaims();
		String issuer = claimString(claims, "origin_iss");
		String providerSubject = claimString(claims, "origin_sub");
		if (issuer == null || providerSubject == null) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"people-tenant login carries no verified origin_iss/origin_sub claims");
		}
		Kernel.PeopleIdpProvider provider = PeopleTenant.providerForIssuer(issuer);
		if (provider == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"issuer " + issuer + " is not one of the people tenant's fixed providers");
		}
		String userId = PeopleTenant.userId(provider, providerSubject);
		String subject = Spiffe.userSpiffeId(trustDomainReader.get(), PeopleTenant.NAMESPACE, userId);

		// Read-check-write, serialized, for the same reason CreatePersonalPrincipal
		// serializes registration: two concurrent first logins for one pair both
		// see the row absent. Here they would both write the SAME key, so nothing
		// is duplicated — but the later write would reset created_at_ms, and the
		// cap check could be overshot. Node-local, like the other guards in this
		// file that want a cluster lock and have none.
		synchronized (personRegistryLock) {
			findOrCreatePerson(userId, provider, providerSubject);
		}

		return mintUserTokenInternal(subject, claims, request.getExp(), request.getTraceId(),
				callerSub, request.getOfflineAccess(), PeopleTenant.NAMESPACE);
	}

	/**
	 * Returns the person keyed by {@code userId}, creating the row on first
	 * sight. Call under {@link #personRegistryLock}.
	 *
	 * <p>A disabled person mints nothing: the row is marked, never deleted (the
	 * same audit rule {@code PersonalPrincipal.disabled_at_ms} states), so the
	 * only thing that keeps a disabled person from signing straight back in is
	 * this check.
	 *
	 * <p>Package-private so the create/find behaviour can be proven directly:
	 * the mint that wraps it cannot complete until tacplus stops reserving
	 * {@code people} as a tenant name (see the slice's decision doc), and the
	 * storage semantics are not the thing that blocker is about.
	 */
	void findOrCreatePerson(String userId, Kernel.PeopleIdpProvider provider,
			String providerSubject) throws StatusException {
		Kernel.PrincipalState registry;
		try {
			registry = principalMap.proto();
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL, "principal registry unavailable");
		}
		Kernel.Person existing = null;
		for (Kernel.Person person : registry.getPeopleList()) {
			if (userId.equals(person.getUserId())) {
				existing = person;
				break;
			}
		}
		if (existing != null) {
			if (existing.getDisabledAtMs() != 0) {
				throw new StatusException(Status.PERMISSION_DENIED, "person is disabled");
			}
			return;
		}
		if (registry.getPeopleCount() >= MAX_PEOPLE) {
			throw new StatusException(Status.RESOURCE_EXHAUSTED, "people registry is full");
		}
		Kernel.Person person = Kernel.Person.newBuilder()
				.setUserId(userId)
				.setProvider(provider)
				.setProviderSubject(providerSubject)
				.setCreatedAtMs(System.currentTimeMillis())
				.build();
		try {
			principalMap.putPeople(userId, person);
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL, "person could not be recorded: " + e.getMessage());
		}
		// The registry's durability is the disk snapshot, and nothing else on this
		// path triggers one — the same reason CreatePersonalPrincipal fires it.
		if (writeIdentitySnapshot != null) {
			writeIdentitySnapshot.run();
		}
		logger.info("Created person: user_id={} provider={}", userId, provider.name());
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
	// CreateTenantUserLink RPC (tenant-user ↔ tenant-user links)
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
	 * Records that two tenant-user identities are the same human, proved by BOTH
	 * logins in one request.
	 *
	 * <p>The proof is the shared nonce. Each side carries the IdP's own
	 * {@code nonce} claim, verified by the broker and relayed as
	 * {@code origin_nonce}; the client generated one value and sent it into both
	 * logins, so two id_tokens carrying it were obtained together by somebody
	 * holding both accounts. Without that binding a single stolen token could be
	 * replayed on its own against a login the attacker does control, and the
	 * result would be a link to somebody else's account — which is the whole of
	 * what a link authorizes.
	 *
	 * <p>Neither side's namespace is taken from the request. A {@code people}
	 * side is derived from the verified issuer/subject, exactly as
	 * {@link #mintPersonToken} derives it; any other side's namespace comes from
	 * OPA, the same authority that names it at mint.
	 */
	private Kernel.CreateTenantUserLinkResponse doCreateTenantUserLink(
			Kernel.CreateTenantUserLinkRequest request) throws StatusException {
		String callerSub = verifiedCallerToken("CreateTenantUserLink").getSubject();
		// Which class of proof the caller must be trusted to broker follows from
		// which class of proof the request carries: a device side is a WebAuthn
		// assertion, which is AUTH_BROKER_KIND_DEVICE's proof, not an IdP
		// assertion. The people-side gate in resolveLinkSide still applies on top,
		// so a device link needs a broker that is BOTH a device broker AND rooted
		// at the people tenant.
		boolean deviceLink = request.getA().hasDeviceAssertion() || request.getB().hasDeviceAssertion();
		Kernel.Delegate broker = requireBrokerDelegate(callerSub, deviceLink
				? Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE
				: Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP);

		// Every binding check runs before anything is resolved, because resolving a
		// side can CREATE a row — a person on the people side, a personal principal
		// on a device side. An unbound proof must write nothing at all.
		bindSides(request.getA(), request.getB(), broker);

		LinkedUser a = resolveLinkSide(request.getA(), broker, request.getTraceId(), "a");
		LinkedUser b = resolveLinkSide(request.getB(), broker, request.getTraceId(), "b");
		if (a.namespace().equals(b.namespace())) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"a link joins users in two different tenants; both sides resolved to "
							+ a.namespace());
		}

		long createdAt;
		synchronized (LINK_REGISTRY_LOCK) {
			// Both directions, because the mint reads this by the caller's own key
			// and must not scan for a row that happens to mention them. The
			// timestamp of the first edge written is reused for the mirror so the
			// two halves of one link never disagree about when it was made.
			createdAt = recordLink(a, b, System.currentTimeMillis());
			recordLink(b, a, createdAt);
		}
		// The registry's durability is the disk snapshot, and nothing else on this
		// path triggers one — the same reason findOrCreatePerson fires it.
		if (writeIdentitySnapshot != null) {
			writeIdentitySnapshot.run();
		}
		logger.info("Linked tenant users: {} <-> {}", a.key(), b.key());
		return Kernel.CreateTenantUserLinkResponse.newBuilder()
				.setAUserKey(a.key())
				.setBUserKey(b.key())
				.setCreatedAtMs(createdAt)
				.build();
	}

	/** One resolved half of a link: the identity kernel would mint for that login. */
	private record LinkedUser(String namespace, String subject) {
		String key() {
			return linkKey(namespace, subject);
		}
	}

	/**
	 * Resolves one side of a link to the identity kernel would mint for it.
	 *
	 * <p>{@code which} names the side in refusals only — {@code a} or {@code b} —
	 * so a broker can tell which half it got wrong without kernel echoing any of
	 * the claims back.
	 */
	private LinkedUser resolveLinkSide(Kernel.TenantUserLinkSide side, Kernel.Delegate broker,
			String traceId, String which) throws StatusException {
		if (side.hasDeviceAssertion()) {
			// A device side names no login and reaches no OPA: its identity is the
			// personal principal that holds the credential the assertion is signed
			// by, which is exactly what the DEVICE mint arm resolves from a proof.
			// bindSides has already verified the assertion, so by here the caller is
			// known to hold the private half.
			return resolveDeviceSide(side);
		}
		Struct claims = side.getClaims();
		String issuer = claimString(claims, "origin_iss");
		String providerSubject = claimString(claims, "origin_sub");
		if (issuer == null || providerSubject == null) {
			throw new StatusException(Status.UNAUTHENTICATED,
					"link side " + which + " carries no verified origin_iss/origin_sub claims");
		}

		Kernel.PeopleIdpProvider provider = PeopleTenant.providerForIssuer(issuer);
		if (provider != null) {
			// A people side is a login into the reserved tenant, and only that
			// tenant's own broker may attest one — the same gate doMintUserToken
			// uses to reach the people arm, for the same reason. Without it any
			// delegate trusted to broker some other tenant's IdP could name an
			// Apple subject and link itself to a person it never authenticated.
			if (!PeopleTenant.NAMESPACE.equals(broker.getTenantNamespace())) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"only the people tenant's own broker may attest a people-tenant link side");
			}
			String userId = PeopleTenant.userId(provider, providerSubject);
			// A link may be the first time this person has been seen. Creating the
			// row here is still "only an IdP creates a person": the claims this
			// derives from are an IdP login the broker just verified.
			synchronized (personRegistryLock) {
				findOrCreatePerson(userId, provider, providerSubject);
			}
			return new LinkedUser(PeopleTenant.NAMESPACE,
					Spiffe.userSpiffeId(trustDomainReader.get(), PeopleTenant.NAMESPACE, userId));
		}

		// Any other side is an ordinary tenant login, and its namespace is OPA's
		// to name, exactly as it is at mint. The broker therefore names neither
		// the tenant nor, through it, whose account is being linked.
		if (side.getSubject().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"link side " + which + " names no subject");
		}
		return new LinkedUser(
				requireNamespaceFromOpa(resolveEntitlementsViaOpa(claims, traceId)),
				side.getSubject());
	}

	// ------------------------------------------------------------------
	// The device side of a link (identity decision doc §3, WebAuthn arm)
	// ------------------------------------------------------------------

	/**
	 * Checks that the two sides were obtained together, before either is
	 * resolved and before anything is written.
	 *
	 * <p>Two shapes, one property. <b>Two IdP sides</b> are bound by the shared
	 * nonce §2 built: one value the client generated and sent into both logins.
	 * <b>One device side and one people side</b> are bound by a pair of checks in
	 * opposite directions, because a device has no nonce of its own to share —
	 * the id_token's nonce is the device key's thumbprint, and the assertion's
	 * challenge names that id_token's login. See {@link WebauthnProof} for why
	 * the two orderings are what make the pair unforgeable rather than circular.
	 */
	private void bindSides(Kernel.TenantUserLinkSide a, Kernel.TenantUserLinkSide b,
			Kernel.Delegate broker) throws StatusException {
		if (a.hasDeviceAssertion() && b.hasDeviceAssertion()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"a device links to a person, not to another device");
		}
		if (!a.hasDeviceAssertion() && !b.hasDeviceAssertion()) {
			String nonceA = claimString(a.getClaims(), "origin_nonce");
			String nonceB = claimString(b.getClaims(), "origin_nonce");
			if (nonceA == null || nonceB == null) {
				throw new StatusException(Status.UNAUTHENTICATED,
						"both sides of a link must carry a verified origin_nonce");
			}
			if (!nonceA.equals(nonceB)) {
				throw new StatusException(Status.PERMISSION_DENIED,
						"the two sides of a link do not share a nonce");
			}
			return;
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
		// The people-side gate, applied HERE and not left to resolveLinkSide.
		// Resolving a device side REGISTERS its credential, and resolution runs
		// side a before side b — so a device broker outside the people tenant
		// would get a row written before the gate that refuses it ever fired.
		// Same check, same reason as resolveLinkSide's; only the moment differs.
		if (!PeopleTenant.NAMESPACE.equals(broker.getTenantNamespace())) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"only the people tenant's own broker may attest a people-tenant link side");
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

	/** The credential a device side presents: its id, and the key to check against. */
	private record DeviceCredential(String credentialId, JwkOuterClass.Jwk publicKey,
			@Nullable Kernel.PersonalPrincipal principal) {
	}

	/**
	 * The credential id a device side names, and the key its assertion must
	 * verify under.
	 *
	 * <p>The STORED key once the credential is registered, and the key out of the
	 * request only on a first link. That is the same bootstrap split
	 * {@code CreatePersonalPrincipal} already makes — the request's copy is
	 * consulted exactly once, when there is no row to consult instead, and never
	 * again. Without it a broker could re-present an existing credential id under
	 * a key of its own choosing.
	 */
	private DeviceCredential deviceCredential(Kernel.TenantUserLinkSide side)
			throws StatusException {
		String credentialId = side.getDeviceAssertion().getCredentialId();
		if (credentialId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"device assertion names no credential");
		}
		Kernel.PersonalPrincipal principal = findPrincipalByCredentialId(credentialId);
		if (principal != null) {
			for (Kernel.PersonalCredential credential : principal.getCredentialsList()) {
				if (credentialId.equals(credential.getCredentialId())) {
					if (credential.getRevokedAtMs() != 0) {
						throw new StatusException(Status.PERMISSION_DENIED,
								"device assertion refused: the credential is revoked");
					}
					return new DeviceCredential(credentialId, credential.getPublicKey(), principal);
				}
			}
		}
		if (!side.hasDevicePublicKey()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"an unregistered device must present its public key");
		}
		return new DeviceCredential(credentialId, side.getDevicePublicKey(), null);
	}

	/**
	 * The personal principal a device side is, registering the credential on a
	 * first link.
	 *
	 * <p>Registration is folded into the link rather than given an RPC of its own,
	 * and that is a decision, not a shortcut: a passkey nobody has linked
	 * authorizes nothing and belongs to nobody, so a standalone registration
	 * would be an unauthenticated write with no owner to attribute it to. Here
	 * the row is written only once both halves of §3's proof hold.
	 *
	 * <p>The namespace is {@code /people/<pid>} — the shape
	 * {@link #mintDevicePersonalToken} already mints — so the device logs in the
	 * way every other registered device does, and what the link adds is the
	 * {@code linked: /tenants/people} claim on that token.
	 */
	private LinkedUser resolveDeviceSide(Kernel.TenantUserLinkSide side) throws StatusException {
		String principalId;
		synchronized (personalPrincipalRegistryLock) {
			DeviceCredential credential = deviceCredential(side);
			if (credential.principal() != null) {
				if (credential.principal().getDisabledAtMs() != 0) {
					throw new StatusException(Status.PERMISSION_DENIED,
							"device assertion refused: the principal is disabled");
				}
				principalId = credential.principal().getPrincipalId();
			} else {
				principalId = registerWebauthnPrincipal(credential, side);
			}
		}
		String namespace = PEOPLE_PREFIX + principalId;
		return new LinkedUser(namespace,
				Spiffe.userSpiffeId(trustDomainReader.get(), namespace, principalId));
	}

	/** Call under {@link #personalPrincipalRegistryLock}. */
	private String registerWebauthnPrincipal(DeviceCredential credential,
			Kernel.TenantUserLinkSide side) throws StatusException {
		Kernel.PrincipalState registry;
		try {
			registry = principalMap.proto();
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL, "principal registry unavailable");
		}
		if (registry.getPersonalPrincipalsCount() >= MAX_PERSONAL_PRINCIPALS) {
			throw new StatusException(Status.RESOURCE_EXHAUSTED,
					"personal principal registry is full");
		}
		String principalId = UUID.randomUUID().toString();
		long nowMs = System.currentTimeMillis();
		try {
			principalMap.putPersonalPrincipals(principalId, Kernel.PersonalPrincipal.newBuilder()
					.setPrincipalId(principalId)
					.addCredentials(Kernel.PersonalCredential.newBuilder()
							.setCredentialId(credential.credentialId())
							.setPublicKey(credential.publicKey())
							.setLabel(side.getDeviceLabel())
							.setPlatformSynced(side.getDevicePlatformSynced())
							.setCreatedAtMs(nowMs))
					.setCreatedAtMs(nowMs)
					.build());
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL,
					"device credential could not be registered: " + e.getMessage());
		}
		logger.info("Registered WebAuthn device principal: principal_id={} platform_synced={}",
				principalId, side.getDevicePlatformSynced());
		return principalId;
	}

	/**
	 * The personal principal holding a credential id, or null. One key, one
	 * person: {@code registerPersonalPrincipal} refuses a duplicate id precisely
	 * so this never has to choose between two rows.
	 */
	@Nullable
	private Kernel.PersonalPrincipal findPrincipalByCredentialId(String credentialId)
			throws StatusException {
		Kernel.PrincipalState registry;
		try {
			registry = principalMap.proto();
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL, "principal registry unavailable");
		}
		for (Kernel.PersonalPrincipal principal : registry.getPersonalPrincipalsList()) {
			for (Kernel.PersonalCredential credential : principal.getCredentialsList()) {
				if (credentialId.equals(credential.getCredentialId())) {
					return principal;
				}
			}
		}
		return null;
	}

	/**
	 * Adds the edge from {@code owner} to {@code peer} if it is not already
	 * there, and returns its {@code created_at_ms}. Re-proving an existing link
	 * changes nothing — the same two logins presented again are the same fact.
	 *
	 * <p>Call under {@link #linkRegistryLock}: read-modify-write on one row, the
	 * same shape and the same node-local limitation as
	 * {@link #findOrCreatePerson}'s.
	 */
	private long recordLink(LinkedUser owner, LinkedUser peer, long now) throws StatusException {
		Kernel.TenantUserLinks existing = principalMap.getTenantUserLinks(owner.key());
		for (int i = 0; i < existing.getLinksCount(); i++) {
			Kernel.TenantUserLink link = existing.getLinks(i);
			if (!link.getPeerNamespace().equals(peer.namespace())
					|| !link.getPeerSubject().equals(peer.subject())) {
				continue;
			}
			if (link.getRevokedAtMs() == 0) {
				return link.getCreatedAtMs();
			}
			// Re-proved after an unlink. The same pair of credentials is the same
			// fact, so the mark is cleared rather than a second edge added — a row
			// carrying one live and one revoked edge for one peer would make
			// "is this link live?" depend on which the reader saw first.
			// created_at_ms moves to now: the link that exists is the one just
			// proved, not the one that was withdrawn.
			try {
				principalMap.putTenantUserLinks(owner.key(), existing.toBuilder()
						.setLinks(i, link.toBuilder().setRevokedAtMs(0).setCreatedAtMs(now))
						.build());
			} catch (ProtoException e) {
				throw new StatusException(Status.INTERNAL,
						"link could not be recorded: " + e.getMessage());
			}
			return now;
		}
		if (existing.getLinksCount() >= MAX_LINKS_PER_USER) {
			throw new StatusException(Status.RESOURCE_EXHAUSTED,
					"user is at the " + MAX_LINKS_PER_USER + "-link cap");
		}
		try {
			principalMap.putTenantUserLinks(owner.key(), existing.toBuilder()
					.setUserKey(owner.key())
					.addLinks(Kernel.TenantUserLink.newBuilder()
							.setPeerNamespace(peer.namespace())
							.setPeerSubject(peer.subject())
							.setCreatedAtMs(now))
					.build());
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL,
					"link could not be recorded: " + e.getMessage());
		}
		return now;
	}

	/**
	 * The namespaces a token's {@code linked} claim should carry for the identity
	 * about to be minted — empty for an unlinked user, which is every user until
	 * somebody proves otherwise.
	 *
	 * <p>NAMESPACES, not user paths. tacplus's generated namespace backstop
	 * compares this claim against {@code (spec.store_namespace)}, which holds a
	 * namespace, so a user path would never compare equal and a linked caller's
	 * read would never be accepted (tacplus, 2026-09-21).
	 *
	 * <p>One keyed read, because this runs on every user mint. That is why the
	 * registry stores both directions of every link rather than one row per pair.
	 */
	private List<String> linkedNamespaces(String namespace, String subject) {
		if (namespace == null || namespace.isEmpty() || subject == null || subject.isEmpty()) {
			return List.of();
		}
		Kernel.TenantUserLinks row = principalMap.getTenantUserLinks(linkKey(namespace, subject));
		if (row.getLinksCount() == 0) {
			return List.of();
		}
		// One namespace per entry however many users in it this one is linked to:
		// the claim names subtrees, and the backstop compares it to one.
		List<String> namespaces = new java.util.ArrayList<>(row.getLinksCount());
		for (Kernel.TenantUserLink link : row.getLinksList()) {
			// An unlinked edge is marked, not deleted, so the claim has to skip it
			// here. This is the whole read side of unlink: revoking the mark is
			// what stops the peer's namespace reaching the next token, and through
			// it the generated namespace backstop.
			if (link.getRevokedAtMs() != 0) {
				continue;
			}
			if (!namespaces.contains(link.getPeerNamespace())) {
				namespaces.add(link.getPeerNamespace());
			}
		}
		return namespaces;
	}

	/**
	 * The link registry's key for one tenant user: the {@code namespace} and
	 * {@code sub} claims kernel mints for them, in that order. The minted pair
	 * rather than a derived path because an ordinary tenant's {@code sub} is
	 * whatever its IdP broker supplies and need not be a SPIFFE id, so there is
	 * no path to derive; the namespace half is what keeps two tenants'
	 * identically-named users apart.
	 */
	static String linkKey(String namespace, String subject) {
		return namespace + LINK_KEY_SEPARATOR + subject;
	}

	// ========================================================================
	// Pending approvals (identity decision doc §5)
	// ========================================================================

	/**
	 * The person a caller is, or is linked to — the key
	 * {@code PendingApproval.person_user_key} holds, and the key the approving
	 * device's own link edges are compared against.
	 *
	 * <p>A caller already standing in the people tenant IS the person. Anybody
	 * else — a tenant user, or a {@code /people/<pid>} device — is the person at
	 * the far end of their live link into {@code /tenants/people}, which is the
	 * only thing in the platform that says two identities are one human.
	 *
	 * <p>Returns null when there is not EXACTLY ONE such person: none, because an
	 * unlinked user has no device to approve with anyway, and more than one,
	 * because "which human approved this" cannot be answered by picking. Both are
	 * one refusal at each call site, deliberately: a caller cannot tell from the
	 * answer whether somebody else's link exists.
	 */
	@Nullable
	static String personUserKey(PrincipalMap principalMap, String namespace, String subject) {
		if (namespace == null || namespace.isEmpty() || subject == null || subject.isEmpty()) {
			return null;
		}
		if (PeopleTenant.NAMESPACE.equals(namespace)) {
			return linkKey(namespace, subject);
		}
		String person = null;
		for (Kernel.TenantUserLink link
				: principalMap.getTenantUserLinks(linkKey(namespace, subject)).getLinksList()) {
			if (link.getRevokedAtMs() != 0
					|| !PeopleTenant.NAMESPACE.equals(link.getPeerNamespace())) {
				continue;
			}
			String candidate = linkKey(link.getPeerNamespace(), link.getPeerSubject());
			if (person != null && !person.equals(candidate)) {
				return null;
			}
			person = candidate;
		}
		return person;
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
			String callerPerson = personUserKey(principalMap,
					request.getCallerNamespace(), request.getCallerSubject());
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
					approval.getRpcMethod(), approval.getPersonUserKey(), approver.namespace());
			return Kernel.BrokerPendingApprovalResponse.newBuilder()
					.setConsumedAtMs(nowMs)
					.setPersonUserKey(approval.getPersonUserKey())
					.setDeviceNamespace(approver.namespace())
					.build();
		}
	}

	/** The device an approval was signed by: its identity, once it has stood up. */
	private record DeviceApprover(String namespace, String subject) {
	}

	/**
	 * Verifies the tap: this assertion, under a credential kernel stores, by a
	 * device linked to the person the approval names.
	 *
	 * <p><b>The stored key, and only the stored key.</b> A first device→person
	 * link has a bootstrap moment where the request's copy of the key is the only
	 * thing there is to check against ({@code deviceCredential}); an approval has
	 * no such moment, because an approving device is by definition already
	 * registered and linked. A key out of this request would let its sender choose
	 * what the signature is verified with, so none is accepted — the proto carries
	 * no field for one.
	 *
	 * <p><b>The device-link check</b> is the last step and the one §5 is about:
	 * "signed by a key linked to the caller's person. Nothing else counts." A
	 * registered device that is not linked to this person — or was unlinked — gets
	 * as far as a valid signature and no further.
	 */
	private DeviceApprover verifyApprovingDevice(Kernel.BrokerPendingApprovalRequest request,
			Kernel.PendingApproval approval) throws StatusException {
		String credentialId = request.getDeviceAssertion().getCredentialId();
		if (credentialId.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"device assertion names no credential");
		}
		Kernel.PersonalPrincipal principal = findPrincipalByCredentialId(credentialId);
		Kernel.PersonalCredential credential = null;
		if (principal != null) {
			for (Kernel.PersonalCredential candidate : principal.getCredentialsList()) {
				if (credentialId.equals(candidate.getCredentialId())) {
					credential = candidate;
					break;
				}
			}
		}
		// One refusal for every way the credential does not stand — unknown,
		// revoked, disabled principal — so this is not an oracle for which
		// credentials exist, the same rule verifyDeviceProof states.
		if (principal == null || credential == null
				|| credential.getRevokedAtMs() != 0 || principal.getDisabledAtMs() != 0) {
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

		String namespace = PEOPLE_PREFIX + principal.getPrincipalId();
		String subject = Spiffe.userSpiffeId(trustDomainReader.get(), namespace,
				principal.getPrincipalId());
		for (Kernel.TenantUserLink link
				: principalMap.getTenantUserLinks(linkKey(namespace, subject)).getLinksList()) {
			if (link.getRevokedAtMs() == 0 && approval.getPersonUserKey()
					.equals(linkKey(link.getPeerNamespace(), link.getPeerSubject()))) {
				return new DeviceApprover(namespace, subject);
			}
		}
		throw new StatusException(Status.PERMISSION_DENIED,
				"that device is not linked to the person the approval names");
	}

	/**
	 * The four steps {@code MintClientToken} already runs for a cred_pair, against
	 * {@code PersonalPrincipal.credentials} instead of
	 * {@code KernelTenantConfig.cred_pairs}: parse the proof, read its {@code kid},
	 * find the credential the kid names, verify the signature against that
	 * credential's stored public key.
	 *
	 * <p>The {@code kid} is the only pre-verification handle there is, and it is
	 * the right one: a second device holding the same platform-synced key knows
	 * the key and nothing else — not the principal id — and §5.4 requires it to
	 * present the same principal with no sign-in.
	 *
	 * <p>Every failure — malformed proof, missing or unknown kid, revoked
	 * credential, disabled principal, bad signature — is one PERMISSION_DENIED
	 * with one message. Distinguishing them would turn this into an oracle for
	 * which credentials exist, and the mint path does not enumerate anywhere else
	 * either (see {@code doMintDelegatedToken}'s missing-grant refusal).
	 */
	private Kernel.PersonalPrincipal verifyDeviceProof(String proofToken) throws StatusException {
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
		Kernel.PrincipalState registry;
		try {
			registry = principalMap.proto();
		} catch (ProtoException e) {
			throw new StatusException(Status.INTERNAL, "principal registry unavailable");
		}
		for (Kernel.PersonalPrincipal principal : registry.getPersonalPrincipalsList()) {
			if (principal.getDisabledAtMs() != 0) {
				continue;
			}
			for (Kernel.PersonalCredential credential : principal.getCredentialsList()) {
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
				return principal;
			}
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

		Kernel.Delegate delegate = findDelegateBySubject(delegateSubject);
		if (delegate == null) {
			throw new StatusException(Status.INTERNAL,
					"delegate not found: " + delegateSubject);
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
		// they belong to. A policy that cannot name one refuses the mint.
		//
		// A stampedNamespace short-circuits that entirely, and must: it is set only
		// where kernel authorized the identity itself (the device arm's
		// /people/<pid>), and there OPA sees no IdP claims at all, so asking it for
		// a namespace would be asking it to guess. OPA still supplies the
		// entitlements below — it remains the sole entitlement authority — it just
		// does not get to name the subtree kernel already resolved.
		newToken.setNamespace(
				stampedNamespace != null ? stampedNamespace : requireNamespaceFromOpa(opaResult));

		// The `linked` claim: the NAMESPACES of the tenant users this one is
		// linked to (decision doc §2). Set after the namespace, because the
		// registry is keyed on the namespace kernel just resolved, and before the
		// relayed claims are copied in, so a broker that puts a `linked` key in
		// its claim struct cannot name a namespace the registry does not.
		List<String> linked = linkedNamespaces(newToken.getNamespace(), subject);
		if (!linked.isEmpty()) {
			newToken.setLinked(linked);
		}

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

		// The caller's own verified identity, as the (name, namespace) pair that
		// keys a delegate. A service token's sub may arrive as a full SPIFFE URI,
		// resolved exactly as findDelegateBySubject does; a bare sub can only be
		// a /system delegate.
		String rawCallerSub = callerToken.getSubject();
		boolean callerIsSpiffe = SpiffeIds.isSpiffeUri(rawCallerSub);
		String callerDelegateName = callerIsSpiffe
				? SpiffeIds.serviceName(rawCallerSub) : rawCallerSub;
		String callerDelegateNamespace = callerIsSpiffe
				? SpiffeIds.namespaceFromSpiffe(rawCallerSub) : SpiffeIds.SYSTEM_NAMESPACE;

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

		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long exp = now + offlineTokenLifetimeSeconds;

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
		newToken.sign(signingKey);

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
		assertNotRevoked(workloadMap, inputToken.getSubject(), "workload");

		// Same choke point, for standing delegations: a token that derives from a
		// Grant is only exchangeable while that Grant is still live.
		assertGrantStillActive(inputToken);

		// Personal-principal arm. Placed here — after verification, before the
		// bootstrap/offline/access routing below — because a personal token can
		// arrive as an RT, an OT or an AT and the tenant exchange is the same
		// mint for all three; and because tenant_namespace has to be refused on
		// a service token whatever its token_use is.
		if (isPersonalPrincipalToken(inputToken)) {
			if (!request.getTenantNamespace().isEmpty()) {
				return mintTenantTokenForPersonalPrincipal(request, inputToken);
			}
			// No tenant named. A personal token may still be refreshed into a
			// personal AT (design-session §2.2 step 1's parenthetical) — that
			// keeps /people/<pid> and falls through to the normal exchange below.
			// It may NOT reach a service without naming the tenant it is acting
			// in: a service token stamped /people/<pid> would arrive at a tenant
			// service as an identity that is at-or-below no tenant at all.
			if (!request.getAud().isEmpty() || !request.getServiceAudsList().isEmpty()) {
				throw new StatusException(Status.INVALID_ARGUMENT,
						"tenant_namespace is required to mint a service token from a personal-principal token");
			}
		} else if (!request.getTenantNamespace().isEmpty()) {
			// DECISIONS.md item 2: a service's tenant comes from its SPIFFE
			// subject and from nothing else. tenant_namespace is a selector among
			// a PERSON'S memberships; honouring it here — or even ignoring it
			// silently — would be the tenant escape the whole field is designed
			// not to be.
			throw new StatusException(Status.INVALID_ARGUMENT,
					"tenant_namespace is only meaningful on a personal-principal token; "
							+ "a service's tenant comes from its SPIFFE subject");
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
		// An exchange may shrink a lifetime, never extend one: the token minted here
		// cannot outlive the credential presented for it, or a caller could renew its
		// way past what the original credential had left. Same cap MintExternalToken
		// applies against the user token it derives from. verify() above has already
		// established the input token carries a live exp.
		exp = Math.min(exp, inputToken.getExpiration());
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
	 * Whether a verified kernel-signed token is a personal principal's own token:
	 * {@code sub_type=user} AND a namespace under {@code /people/}. Both halves
	 * are required — {@code sub_type} alone is every IdP user, and the namespace
	 * alone would let a claim shape decide the arm.
	 *
	 * <p>The namespace claim is the right source here, not the subject: it is
	 * stamped by kernel on a mint kernel itself authorized (the device arm), and
	 * it is also what changes on the tenant token this arm produces — a
	 * {@code /tenants/<t>} token minted below keeps the person's {@code sub} and
	 * so would still look "personal" if this read the subject, which would let a
	 * tenant token be re-exchanged into a different tenant.
	 */
	private static boolean isPersonalPrincipalToken(TokenWrapper token) {
		return SUB_TYPE_USER.equals(token.getSubType())
				&& token.getNamespace().startsWith(PEOPLE_PREFIX);
	}

	/**
	 * The personal-principal arm of {@code MintToken} (design-session §2.2): one
	 * person, N per-tenant tokens. The presented personal token names a tenant;
	 * kernel authorizes that against the person's own {@code TenantMembership}
	 * records and mints an access token — plus one service token per requested
	 * audience — stamped with the tenant's namespace.
	 *
	 * <p>No refresh or offline token comes back. The personal RT/OT the device
	 * holds stays the only long-lived credential; a tenant token is re-minted
	 * from it, so a revoked membership stops working at the next exchange rather
	 * than at a tenant refresh token's natural expiry.
	 */
	private Tokenrequest.TokenMintResponse mintTenantTokenForPersonalPrincipal(
			Tokenrequest.TokenMintRequest request, TokenWrapper inputToken) throws StatusException {

		// Step 1: a tenant must be named, and it may not be the authorization-tree
		// root. "/" is at-or-below every namespace in the fleet (Spiffe.isAtOrBelow),
		// so a personal token exchanged for one would satisfy every tenant-targeted
		// level-or-below check there is.
		String tenantNamespace = request.getTenantNamespace();
		if (SpiffeIds.namespaceRoot().equals(tenantNamespace)) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"tenant_namespace must name a tenant, not the authorization-tree root");
		}
		// service_auds is the batch mechanism this exchange uses (§2.1); a single
		// aud has no meaning here and dropping it silently would hand back an
		// access token where the caller asked for a service token. Same refusal
		// the offline-token arm gives for the same reason.
		if (!request.getAud().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT,
					"a personal-principal tenant exchange requests services via service_auds, not aud");
		}

		// Step 2: the principal comes out of the presented token's sub, never out
		// of a request field — the same construction PersonalIdentity.GetMyIdentity
		// gets by taking no arguments at all.
		String principalId = personalPrincipalIdFromSubject(inputToken.getSubject());
		Kernel.PersonalPrincipal principal = principalMap.getPersonalPrincipals(principalId);

		// Step 3: a live membership of the named tenant, or nothing. Every miss —
		// no such row, the row under the key is not this principal, the person is
		// disabled, no membership of this tenant, revoked, expired — collapses to
		// ONE PERMISSION_DENIED with ONE message, the same non-enumerating shape
		// doMintDelegatedToken's missing-grant refusal uses. Distinguishing them
		// would turn the mint into an oracle for which tenants a person belongs to.
		Kernel.TenantMembership membership = null;
		if (principal.getPrincipalId().equals(principalId) && principal.getDisabledAtMs() == 0) {
			long nowMs = System.currentTimeMillis();
			for (Kernel.TenantMembership candidate : principal.getMembershipsList()) {
				if (tenantNamespace.equals(candidate.getTenantNamespace())
						&& candidate.getRevokedAtMs() == 0
						&& (candidate.getExpiresAtMs() == 0 || candidate.getExpiresAtMs() > nowMs)) {
					membership = candidate;
					break;
				}
			}
		}
		if (membership == null) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"no usable membership of " + tenantNamespace + " for this principal");
		}

		// Step 4: narrow by designation. The tenant's customer-facing service list
		// comes from per-tenant login configuration (§6 item 4), which does not
		// exist yet — so for a customer membership the list is EMPTY and the
		// intersection is empty. Design-session §4 states the interim behaviour
		// rather than leaving it to chance: a customer membership with no
		// configured customer service mints NO service tokens (an empty
		// service_tokens list, not an error). Fail closed, and visibly inert
		// rather than silently permissive — the access token is still issued, so
		// the person is inside the tenant; they just cannot reach a service until
		// item 4 lands.
		boolean customerNarrowed = membership.getCustomer();

		// Step 5: entitlements come from OPA, through the same pair every other
		// mint uses. The claims are SYNTHESIZED from the membership, not relayed
		// from the request — the caller is a person's runtime, and letting it hand
		// OPA a claim set would put its own entitlements under its own control.
		Struct claims = Struct.newBuilder()
				.putFields("principal_id", Value.newBuilder().setStringValue(principalId).build())
				.putFields("tenant_namespace", Value.newBuilder().setStringValue(tenantNamespace).build())
				.putFields("proof_kind", Value.newBuilder().setStringValue(membership.getProofKind().name()).build())
				.putFields("customer", Value.newBuilder().setBoolValue(membership.getCustomer()).build())
				.build();
		Userentitlements.EntitlementEvalResult opaResult =
				resolveEntitlementsViaOpa(claims, request.getTraceId());
		Entitlements.TokenEntitlements expanded = expandEntitlements(opaResult);

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

		// Step 7: sub and azp are preserved from the presented token — the tenant
		// sees WHICH PERSON is acting, and (spec.store_principal) rows written in
		// the tenant attribute to that person.
		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject(inputToken.getSubject())
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());
		newToken.setAzp(inputToken.getAzp());
		newToken.setSubType(SUB_TYPE_USER);
		newToken.setTokenUse(TOKEN_USE_ACCESS);
		// Step 6: kernel stamps the namespace from the authorization it just
		// performed. OPA is deliberately NOT consulted for it — OPA sees no IdP
		// claims on this path at all, so it could only ever refuse
		// (design-session §0.2).
		newToken.setNamespace(membership.getTenantNamespace());
		newToken.setClaimsFromStruct(claims, STANDARD_JWT_CLAIMS, WELL_KNOWN_JWT_CLAIMS);
		setFlatServiceEntitlements(newToken, expanded);
		newToken.sign(signingKey);

		logger.info("MintToken (personal principal): principal={}, tenant={}, exp={}",
				principalId, tenantNamespace, exp);

		Tokenrequest.TokenMintResponse.Builder resp = Tokenrequest.TokenMintResponse.newBuilder()
				.setAccessToken(newToken.getProto());
		// service_auds is the existing batch mechanism, used unchanged: each
		// service token is minted through the normal access->service exchange from
		// the tenant AT just issued, so the chain stays personal -> tenant AT -> ST
		// and the ST inherits the tenant namespace rather than being stamped again.
		if (!customerNarrowed && !request.getServiceAudsList().isEmpty()) {
			TokenWrapper accessWrapper = TokenWrapper.from(newToken.getProto());
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
	 * The personal principal id inside a person's SPIFFE subject
	 * ({@code spiffe://<td>/people/<pid>/users/<pid>}). Mirrors
	 * {@code PersonalIdentityServiceImpl.callerPrincipalId} — same grammar, same
	 * refusal — because both answer the same question from the same field.
	 */
	private static String personalPrincipalIdFromSubject(String subject) throws StatusException {
		String namespace;
		try {
			namespace = SpiffeIds.namespaceFromSpiffe(subject);
		} catch (IllegalArgumentException e) {
			throw new StatusException(Status.PERMISSION_DENIED, "caller is not a personal principal");
		}
		if (!namespace.startsWith(PEOPLE_PREFIX)) {
			throw new StatusException(Status.PERMISSION_DENIED, "caller is not a personal principal");
		}
		String principalId = namespace.substring(PEOPLE_PREFIX.length());
		if (principalId.isEmpty() || principalId.contains("/")) {
			throw new StatusException(Status.PERMISSION_DENIED, "caller is not a personal principal");
		}
		return principalId;
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
	private Kernel.Delegate findDelegateBySubject(String subject) {
		String name;
		String namespace;
		if (SpiffeIds.isSpiffeUri(subject)) {
			try {
				name = SpiffeIds.serviceName(subject);
				namespace = SpiffeIds.namespaceFromSpiffe(subject);
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

		// Construct child SPIFFE URI via the generated self-describing helper.
		String childSub = Spiffe.workloadSpiffeId(callerSub, workloadName);

		// A revoked identity cannot be re-minted under the same SPIFFE ID, and the
		// ancestor walk covers the caller too: a revoked parent can mint nothing.
		assertNotRevoked(workloadMap, childSub, "workload");

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
				? SpiffeIds.namespaceFromSpiffe(rawCallerSub) : SpiffeIds.SYSTEM_NAMESPACE;

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

		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		if (signingKey == null) {
			throw new ProtoException(ProtoException.UNAVAILABLE, "no active signing key");
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

		// Mint a C2S token carrying the cred_pair's entitlements + namespace.
		// No P2S/capability: the single C2S authorizer checks service_entitlements
		// against (method, target namespace), identically to IDP-user tokens.
		TokenWrapper token = TokenWrapper.create()
				.setIssuer(tokenIssuer)
				.setSubject("cred-pair:" + credPairId)
				.setAudience(Kernel.getDescriptor().getPackage())
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
	// CreatePersonalPrincipal RPC (device-first registration; no session yet)
	// ========================================================================

	/**
	 * First-launch registration. The request is self-attesting: it carries a JWT
	 * signed by the key being registered and the public half of that same key, and
	 * kernel verifies the one against the other. That is the whole of the
	 * authentication, and it is deliberate — anyone may create a personal
	 * principal (device-first, no signup), so the only thing worth proving is that
	 * the caller actually holds the private half of the key it is asking kernel to
	 * trust from here on.
	 *
	 * <p>This is the bootstrap case {@code MintClientToken} does not have: there is
	 * no stored credential to look the key up by, so the key comes out of the
	 * request. Once the row exists, every later proof is checked against the STORED
	 * key ({@link #verifyDeviceProof}) and the request's copy is never consulted
	 * again.
	 *
	 * <p>No token is issued. The device's next call is MintUserToken with
	 * AUTH_BROKER_KIND_DEVICE, which is where {@code Delegate.auth_broker_kinds}
	 * gates who may broker a human login; minting here would route around that gate.
	 *
	 * <p>The body proof is not the whole story any more. Registration is no longer
	 * reachable from outside the cluster — the RPC dropped
	 * {@code RPC_FLAG_SELF_AUTHENTICATES}, so tacplus emits no NoAuth gateway proxy
	 * route for it — and the CALLER must additionally be an authenticated delegate
	 * carrying {@code AUTH_BROKER_KIND_DEVICE}, i.e. the personalauth broker. Two
	 * independent facts are required and neither replaces the other: the broker is
	 * a device broker, and whoever is registering holds the private half. Without
	 * the caller check a client could skip the broker and register against kernel
	 * directly, and azp provenance and rate limiting would land on a path nobody
	 * has to use.
	 */
	@Override
	public Kernel.CreatePersonalPrincipalResponse createPersonalPrincipal(Caller caller,
			Kernel.CreatePersonalPrincipalRequest request) throws ProtoException {
		// Authenticate the calling broker. `caller` is not consulted: every RPC in
		// this file re-parses RAW_AUTH_TOKEN_KEY itself, and a second way to
		// identify a caller is a second thing to keep correct.
		try {
			requireBrokerDelegate(verifiedCallerToken("CreatePersonalPrincipal").getSubject(),
					Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE);
		} catch (StatusException e) {
			throw new ProtoException(e.toGrpcStatus().getCode().value(), e.getMessage());
		}

		TokenWrapper proof;
		try {
			proof = TokenWrapper.parse(request.getProofToken());
		} catch (Exception e) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"invalid proof_token: " + e.getMessage());
		}
		String credentialId = proof.getKid();
		if (credentialId == null || credentialId.isEmpty()) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"proof_token missing kid (credential_id)");
		}
		// Verify against the key carried in THIS request. A proof that does not
		// verify registers nothing — otherwise the row would record a public key
		// whose holder never demonstrated possession.
		try {
			proof.verify(ImmutableJwk.from(request.getPublicKey()));
		} catch (Exception e) {
			throw new ProtoException(ProtoException.UNAUTHENTICATED,
					"proof_token verification failed: " + e.getMessage());
		}

		// Read-check-write, serialized. The cap check and the credential-uniqueness
		// scan below both read principalMap, then the write puts a FRESH random key,
		// so nothing collides and nothing made the three steps atomic: two concurrent
		// registrations of the same credential both saw it absent and both created a
		// principal. verifyDeviceProof would then resolve whichever the map's
		// iteration order yielded first, and the person would silently become two
		// people, which is exactly what the comment below says is forbidden. The cap
		// could be overshot the same way, and that one is worse than it looks — see
		// MAX_PERSONAL_PRINCIPALS for why an over-cap registry loses every later
		// snapshot.
		//
		// Node-local, like the other guards in this file that want a cluster lock and
		// have none: it closes concurrent registrations reaching one kernel, not two
		// pods at once. A cross-node CAS would need either a Hazelcast handle these
		// services are not given or a credential-id index boundary in the proto;
		// tracked as a follow-up.
		synchronized (personalPrincipalRegistryLock) {
			return registerPersonalPrincipal(request, credentialId);
		}
	}

	private Kernel.CreatePersonalPrincipalResponse registerPersonalPrincipal(
			Kernel.CreatePersonalPrincipalRequest request, String credentialId) throws ProtoException {
		Kernel.PrincipalState registry = principalMap.proto();
		if (registry.getPersonalPrincipalsCount() >= MAX_PERSONAL_PRINCIPALS) {
			throw new ProtoException(ProtoException.RESOURCE_EXHAUSTED,
					"personal principal registry is full");
		}
		// One key, one person. Without this, a second registration of the same
		// platform-synced key would create a second principal, and the credential
		// id — the only handle the device mint has — would name two rows. Which one
		// verifyDeviceProof found would then depend on map iteration order, and the
		// person would silently become two people, which is exactly what §5.4's
		// "a synced key presented from a phone and from an iPad is ONE credential
		// presented twice" forbids.
		//
		// This is a correctness guard, not abuse control (§11 QUESTION 3 is open
		// and deliberately untouched here). It does make the RPC an existence
		// oracle for credential ids; accepted, because a credential id is opaque
		// and useless without the private half, and narrowing it further is the
		// broader abuse-prevention design this item does not do.
		for (Kernel.PersonalPrincipal existing : registry.getPersonalPrincipalsList()) {
			for (Kernel.PersonalCredential credential : existing.getCredentialsList()) {
				if (credentialId.equals(credential.getCredentialId())) {
					throw new ProtoException(ProtoException.ALREADY_EXISTS,
							"credential is already registered");
				}
			}
		}

		String principalId = UUID.randomUUID().toString();
		long nowMs = System.currentTimeMillis();
		Kernel.PersonalPrincipal principal = Kernel.PersonalPrincipal.newBuilder()
				.setPrincipalId(principalId)
				.addCredentials(Kernel.PersonalCredential.newBuilder()
						.setCredentialId(credentialId)
						.setPublicKey(request.getPublicKey())
						.setLabel(request.getLabel())
						.setPlatformSynced(request.getPlatformSynced())
						.setCreatedAtMs(nowMs))
				.setCreatedAtMs(nowMs)
				.build();
		principalMap.putPersonalPrincipals(principalId, principal);
		// The registry's durability is the disk snapshot, and nothing else on this
		// path triggers one — the same reason RevokeWorkload fires it.
		writeIdentitySnapshot.run();

		logger.info("Registered personal principal: principal_id={} credential={} platform_synced={}",
				principalId, credentialId, request.getPlatformSynced());
		return Kernel.CreatePersonalPrincipalResponse.newBuilder()
				.setPrincipalId(principalId)
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
