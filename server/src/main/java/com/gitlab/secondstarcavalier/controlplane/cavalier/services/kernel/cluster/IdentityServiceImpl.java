// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.errors.ProtoException;
import io.grpc.Status;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kernel's cluster-internal PKI + workload-identity authority.
 *
 * <p>JWT token minting has moved out of the kernel into the {@code mint}
 * service (now the authoritative {@code (spec.token_minter)}). This class no
 * longer signs JWTs and no longer depends on {@code KeyRotator} or OPA. It
 * implements the slimmed {@code kernel.Mint} surface:
 * <ul>
 * <li><b>X509Mint:</b> signs X.509 certificates under per-service intermediate
 * CAs. Authenticates the caller via a bearer token (which must carry a
 * canonical SPIFFE URI in its {@code sub} claim — see {@link SpiffeIds}),
 * creates a per-SPIFFE-URI intermediate CA (signed by the cluster CA chain,
 * pathlen:0), signs the caller-provided public key with the SPIFFE URI as a
 * URI SAN, and returns an X509CertChain. This uses the cluster CA keys, NOT
 * the (removed) JWT signing key.</li>
 * <li><b>WorkloadMint:</b> mints a child workload bootstrap identity. Token
 * SIGNING has moved to {@code mint}; see TODO(mint-wire) below — this currently
 * returns UNIMPLEMENTED rather than signing locally.</li>
 * <li><b>WorkloadRevoke:</b> records a workload revocation (no signing).</li>
 * </ul>
 */
public class IdentityServiceImpl implements Mint.MintHandler {

	private static final Logger logger = LoggerFactory.getLogger(IdentityServiceImpl.class);

	private static final Pattern WORKLOAD_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_-]+");

	/** Intermediate CA lifetime: 10 years. */
	private static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	// Verifying keys used ONLY to validate inbound caller bearer tokens (read
	// from the published verifying-keys view). Kernel itself no longer signs.
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	private final ImmutableCertChain signingCa;
	private final Function<String, X509.X509CertChain> serviceCaReader;
	private final BiConsumer<String, X509.X509CertChain> serviceCaWriter;

	public IdentityServiceImpl(
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			ImmutableCertChain signingCa,
			Function<String, X509.X509CertChain> serviceCaReader,
			BiConsumer<String, X509.X509CertChain> serviceCaWriter) {
		this.verifyingKeysReader = verifyingKeysReader;
		this.signingCa = signingCa;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
	}

	// ========================================================================
	// X509Mint RPC — certificate signing under per-service intermediate CAs.
	// Uses the cluster CA keys (NOT the removed JWT signing key).
	// ========================================================================

	@Override
	public X509.X509CertChain x509Mint(Caller caller, Tokenrequest.X509MintRequest request)
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

		// Verify token signature against published verifying keys.
		String kid = token.getKid();
		JwkOuterClass.Jwk matchingKey = null;
		for (JwkOuterClass.Jwk jwk : verifyingKeysReader.get()) {
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

		// Minted service tokens encode the canonical SPIFFE URI in the `sub`
		// claim (e.g. "spiffe://local/dev/oauth"). That URI IS the workload
		// identity for this cluster and propagates unchanged through the cert:
		// token sub → URI SAN. No reconstruction.
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

		// Intermediate CA is keyed by the SPIFFE URI itself so naming stays
		// consistent across all cert-issuing paths (X509Mint + TlsCertService).
		ImmutableCertChain intermediateCa = getOrCreateIntermediateCa(spiffeId, signingCa);

		// Enrich cert request with the SPIFFE URI SAN (canonical identity).
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

		logger.info("X509Mint: spiffeId={}, keyId={}",
				spiffeId, request.getCertRequest().getKey().getId());

		return certChain;
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

		// Generate EC P-384 keypair for the intermediate CA.
		// Ed25519 is avoided because Netty (used by Keycloak/Quarkus) has known
		// compatibility issues with Ed25519 in TLS certificate chains.
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp384r1"));
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
	public Tokenrequest.WorkloadMintResponse workloadMint(Caller caller,
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

		// Verify against published verifying keys.
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
		if (!SpiffeIds.isSpiffeUri(callerSub)) {
			throw new StatusException(Status.PERMISSION_DENIED,
					"caller sub is not a SPIFFE URI — only SPIFFE-identified services can mint workloads");
		}

		// Validate workload_name.
		String workloadName = request.getWorkloadName();
		if (workloadName == null || workloadName.isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "workload_name is required");
		}
		if (!WORKLOAD_NAME_PATTERN.matcher(workloadName).matches()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "workload_name must match [a-zA-Z0-9_-]+");
		}

		// Construct child SPIFFE URI (for the log line / future wiring).
		String childSub = callerSub + "/" + workloadName;

		// TODO(mint-wire): the bootstrap-token SIGNING for a child workload has
		// moved to the `mint` service (mint.Mint, the authoritative token_minter).
		// Kernel no longer holds a JWT signing key (KeyRotator deleted), so it
		// cannot sign the bootstrap token locally. Wire this to call the mint
		// service S2S (via the generated mint client) to obtain the child's
		// bootstrap token, then return it. Until that S2S call is wired, fail
		// closed with UNIMPLEMENTED rather than signing locally.
		logger.warn("WorkloadMint not yet wired to mint service (parent={}, child={}) — returning UNIMPLEMENTED",
				callerSub, childSub);
		throw new StatusException(Status.UNIMPLEMENTED,
				"WorkloadMint bootstrap-token signing moved to the mint service; kernel→mint S2S not yet wired (TODO(mint-wire))");
	}

	@Override
	public void workloadRevoke(Caller caller,
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

		// Verify against published verifying keys.
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
