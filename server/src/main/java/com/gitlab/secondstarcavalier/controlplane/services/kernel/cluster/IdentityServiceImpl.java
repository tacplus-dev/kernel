// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.key.ImmutablePublicKey;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.token.TokenOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.MintServiceGrpc;
import com.google.protobuf.Empty;
import com.google.protobuf.Value;
import io.grpc.Context;
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
 * Kernel's identity authority — mints JWT tokens, signs X.509 certificates,
 * and provisions per-service mTLS certificates.
 *
 * <p>Implements three RPCs:
 * <ul>
 * <li><b>TokenMint:</b> mints signed JWTs. Handles both direct credential
 * exchange (delegate presents cred_pair JWT) and delegation (broker
 * authenticates via header, mints on behalf).</li>
 * <li><b>X509Mint:</b> signs X.509 certificates using the node's CA keypair.
 * Same credential/delegation pattern as TokenMint.</li>
 * <li><b>GetServiceCertificate:</b> returns per-service mTLS certificates.
 * Creates an intermediate CA per service (signed by root CA, pathlen:0),
 * then mints fresh leaf certs on each call. Provides per-service trust
 * isolation — only nodes of the same service can verify each other.</li>
 * </ul>
 */
public class IdentityServiceImpl extends MintServiceGrpc.MintServiceImplBase {

	private static final Logger logger = LoggerFactory.getLogger(IdentityServiceImpl.class);

	private static final Set<String> STANDARD_JWT_CLAIMS = Set.of("sub", "iss", "aud", "exp", "iat", "azp", "nbf",
			"jti");

	private static final String TOKEN_TYPE_REFRESH = "refresh";

	/** Intermediate CA lifetime: 10 years. */
	private static final long INTERMEDIATE_CA_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

	/** Leaf certificate lifetime: 24 hours (services re-fetch on restart). */
	private static final long LEAF_CERT_LIFETIME_SECONDS = 24L * 3600;

	private final long defaultTokenExpirySeconds;
	private final ExternalJwkResolver externalJwkResolver;
	private final KeyRotator keyRotator;
	private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
	private final Supplier<List<Kernel.Delegate>> delegatesReader;
	private final Map<String, List<String>> serviceEntitlements;
	private final CaKeyHolder caKeyHolder;
	private final Function<String, X509.X509CertPair> serviceCaReader;
	private final BiConsumer<String, X509.X509CertPair> serviceCaWriter;

	public IdentityServiceImpl(
			long defaultTokenExpirySeconds,
			ExternalJwkResolver externalJwkResolver,
			KeyRotator keyRotator,
			Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
			Supplier<List<Kernel.Delegate>> delegatesReader,
			Map<String, List<String>> serviceEntitlements,
			CaKeyHolder caKeyHolder,
			Function<String, X509.X509CertPair> serviceCaReader,
			BiConsumer<String, X509.X509CertPair> serviceCaWriter) {
		this.defaultTokenExpirySeconds = defaultTokenExpirySeconds > 0 ? defaultTokenExpirySeconds : 3600;
		this.externalJwkResolver = externalJwkResolver;
		this.keyRotator = keyRotator;
		this.verifyingKeysReader = verifyingKeysReader;
		this.delegatesReader = delegatesReader;
		this.serviceEntitlements = serviceEntitlements != null ? serviceEntitlements : Map.of();
		this.caKeyHolder = caKeyHolder;
		this.serviceCaReader = serviceCaReader;
		this.serviceCaWriter = serviceCaWriter;
	}

	// ========================================================================
	// TokenMint RPC
	// ========================================================================

	@Override
	public void tokenMint(Tokenrequest.TokenMintRequest request,
			StreamObserver<TokenOuterClass.Token> responseObserver) {
		try {
			TokenOuterClass.Token result = doTokenMint(request);
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

	private TokenOuterClass.Token doTokenMint(Tokenrequest.TokenMintRequest request) throws StatusException {
		if (request.getInputToken().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "input_token is required");
		}

		TokenWrapper inputToken;
		try {
			inputToken = TokenWrapper.parse(request.getInputToken());
		} catch (Exception e) {
			throw new StatusException(Status.INVALID_ARGUMENT, "invalid input_token: " + e.getMessage());
		}

		Object typ = inputToken.getCustomField("typ");
		if (TOKEN_TYPE_REFRESH.equals(typ)) {
			return exchangeRefreshToService(request, inputToken);
		}

		return exchangeExternalToRefresh(request, inputToken);
	}

	private TokenOuterClass.Token exchangeExternalToRefresh(Tokenrequest.TokenMintRequest request,
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
					delegateName, request, Map.of("instance_id", instanceId));
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

		return mintRefreshToken(subject, request, Map.of());
	}

	private TokenOuterClass.Token mintRefreshToken(
			String subject, Tokenrequest.TokenMintRequest request, Map<String, Object> extraClaims)
			throws StatusException {

		ImmutableKey signingKey = keyRotator.getActiveSigningKey();
		if (signingKey == null) {
			throw new StatusException(Status.UNAVAILABLE, "no active signing key");
		}

		long now = Instant.now().getEpochSecond();
		long exp;
		if (request.getExp() > 0) {
			exp = request.getExp();
		} else {
			exp = now + defaultTokenExpirySeconds;
		}

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer("kernel")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		newToken.setCustomField("typ", TOKEN_TYPE_REFRESH);
		newToken.setCustomField("azp", "kernel");

		for (Map.Entry<String, Object> entry : extraClaims.entrySet()) {
			newToken.setCustomField(entry.getKey(), entry.getValue());
		}

		newToken.sign(signingKey);

		logger.info("Minted refresh token: sub={}, exp={}", subject, exp);
		return newToken.getProto();
	}

	private TokenOuterClass.Token exchangeRefreshToService(Tokenrequest.TokenMintRequest request,
			TokenWrapper inputToken) throws StatusException {

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

		long inputExp = inputToken.getExpiration();
		long exp;
		if (request.getExp() == 0) {
			exp = inputExp;
		} else if (request.getExp() > inputExp) {
			throw new StatusException(
					Status.INVALID_ARGUMENT,
					"requested exp " + request.getExp() + " exceeds refresh token exp " + inputExp);
		} else {
			exp = request.getExp();
		}

		long now = Instant.now().getEpochSecond();
		String subject = inputToken.getSubject();

		Kernel.Delegate delegate = findDelegateByName(subject);
		boolean isS2S = delegate != null;

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

		TokenWrapper newToken = TokenWrapper.create()
				.setIssuer("kernel")
				.setSubject(subject)
				.setAudience(request.getAud())
				.setIssuedAt(now)
				.setExpiration(exp)
				.setJTI(UUID.randomUUID().toString());

		newToken.setCustomField("azp", "kernel");
		newToken.setCustomField("principal", subject);

		if (isS2S) {
			if (inputToken.getProto().hasPayload()) {
				Map<String, Value> fields = inputToken.getProto().getPayload().getFieldsMap();
				Value instanceIdVal = fields.get("instance_id");
				if (instanceIdVal != null && instanceIdVal.getKindCase() == Value.KindCase.STRING_VALUE) {
					newToken.setCustomField("instance_id", instanceIdVal.getStringValue());
				}
			}

			// Profile-based tokens: carry profile names instead of resolved RPCs.
			// Authorizers resolve profiles -> RPCs at request time via EntitlementProfileView.
			List<String> delegateProfiles = delegate.getAuthorizedProfilesList();
			if (delegateProfiles != null && !delegateProfiles.isEmpty()) {
				// Delegate uses profile-based authorization.
				newToken.setCustomField("profiles", delegateProfiles);
			} else {
				// S2S delegate with authorized_services: grant builtin_admin (wildcard).
				newToken.setCustomField("profiles", List.of("builtin_admin"));
			}

			logger.info("Minted service token (S2S): sub={}, aud={}, exp={}", subject, request.getAud(), exp);
		} else {
			// U2S: copy profiles claim from input token (set by Identity after OPA).
			if (inputToken.getProto().hasPayload()) {
				Map<String, Value> fields = inputToken.getProto().getPayload().getFieldsMap();
				for (Map.Entry<String, Value> entry : fields.entrySet()) {
					String key = entry.getKey();
					if (STANDARD_JWT_CLAIMS.contains(key)) {
						continue;
					}
					newToken.setCustomField(key, entry.getValue());
				}
			}

			logger.info("Minted service token (U2S): sub={}, aud={}, exp={}", subject, request.getAud(), exp);
		}

		newToken.sign(signingKey);
		return newToken.getProto();
	}

	private String resolveInstanceIdFromContinuityToken(Tokenrequest.TokenMintRequest request,
			String bootstrapSubject) throws StatusException {

		TokenWrapper continuityToken;
		try {
			continuityToken = TokenWrapper.parse(request.getContinuityToken());
		} catch (Exception e) {
			throw new StatusException(Status.INVALID_ARGUMENT, "invalid continuity_token: " + e.getMessage());
		}

		Object typ = continuityToken.getCustomField("typ");
		if (!TOKEN_TYPE_REFRESH.equals(typ)) {
			throw new StatusException(
					Status.INVALID_ARGUMENT,
					"continuity_token must be a refresh token (expected typ=refresh)");
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

		Object instanceIdObj = continuityToken.getCustomField("instance_id");
		if (instanceIdObj == null || instanceIdObj.toString().isEmpty()) {
			throw new StatusException(Status.INVALID_ARGUMENT, "continuity_token missing instance_id claim");
		}

		String instanceId = instanceIdObj.toString();
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
			StreamObserver<X509.X509Cert> responseObserver) {
		try {
			ImmutableCertPair caPair = caKeyHolder.getActiveCaPair();
			if (caPair == null) {
				responseObserver.onError(Status.UNAVAILABLE
						.withDescription("CA keypair not yet initialized")
						.asRuntimeException());
				return;
			}

			X509.X509Cert signed = caPair.sign(request.getCertRequest());

			logger.info("Signed certificate: issuer={}, exp={}",
					request.getCertRequest().getIssuer(),
					request.getCertRequest().getExp());
			responseObserver.onNext(signed);
			responseObserver.onCompleted();
		} catch (IllegalArgumentException e) {
			responseObserver.onError(Status.INVALID_ARGUMENT
					.withDescription("certificate signing failed: " + e.getMessage())
					.asRuntimeException());
		} catch (Exception e) {
			logger.error("X509Mint failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("certificate signing failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	// ========================================================================
	// GetServiceCertificate RPC
	// ========================================================================

	@Override
	public void getServiceCertificate(Empty request,
			StreamObserver<Kernel.ServiceCertificateResponse> responseObserver) {
		try {
			// Authenticate caller from raw Bearer token (MintService is auth-exempt,
			// so SecurityInterceptor doesn't validate — we do it manually here).
			String rawToken = ClusterServer.RAW_AUTH_TOKEN_KEY.get();
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

			String serviceName = token.getSubject();
			if (serviceName == null || serviceName.isEmpty()) {
				responseObserver.onError(Status.INVALID_ARGUMENT
						.withDescription("token has no sub claim")
						.asRuntimeException());
				return;
			}

			Kernel.ServiceCertificateResponse resp = doGetServiceCertificate(serviceName);
			responseObserver.onNext(resp);
			responseObserver.onCompleted();
		} catch (Exception e) {
			logger.error("GetServiceCertificate failed", e);
			responseObserver.onError(Status.INTERNAL
					.withDescription("service certificate generation failed: " + e.getMessage())
					.asRuntimeException());
		}
	}

	private Kernel.ServiceCertificateResponse doGetServiceCertificate(String serviceName) throws Exception {
		ImmutableCertPair rootCa = caKeyHolder.getActiveCaPair();
		if (rootCa == null) {
			throw new IllegalStateException("CA keypair not yet initialized");
		}

		// Step 1: Get or create the intermediate CA for this service.
		ImmutableCertPair intermediateCa = getOrCreateIntermediateCa(serviceName, rootCa);

		// Step 2: Generate fresh Ed25519 leaf keypair.
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
		KeyPair leafKeyPair = kpg.generateKeyPair();

		String leafId = UUID.randomUUID().toString();
		long now = Instant.now().getEpochSecond();
		long leafExp = now + LEAF_CERT_LIFETIME_SECONDS;

		// Build the public key proto for the cert request.
		byte[] pubKeyBytes = leafKeyPair.getPublic().getEncoded();
		String pubKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubKeyBytes);
		KeyOuterClass.PublicKey leafPubKey = KeyOuterClass.PublicKey.newBuilder()
				.setId(leafId)
				.setBase64(pubKeyBase64)
				.build();

		// Step 3: Sign leaf cert with intermediate CA.
		X509.X509CertRequest leafRequest = X509.X509CertRequest.newBuilder()
				.setKey(leafPubKey)
				.setExp(leafExp)
				.setIssuer(serviceName)
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_DIGITAL_SIGNATURE)
				.addExtKeyUsage(X509.X509ExtKeyUsage.X509_EXT_KEY_USAGE_SERVER_AUTH)
				.addExtKeyUsage(X509.X509ExtKeyUsage.X509_EXT_KEY_USAGE_CLIENT_AUTH)
				.addDnsNames(serviceName)
				.addDnsNames("*." + serviceName)
				.build();

		X509.X509Cert leafCert = intermediateCa.sign(leafRequest);

		// Step 4: Build PEM responses.
		// Leaf cert PEM (from base64url-encoded PEM in the proto).
		String leafCertPem = new String(
				Base64.getUrlDecoder().decode(leafCert.getBase64()));
		// Intermediate CA cert PEM.
		String intermediateCertPem = new String(
				Base64.getUrlDecoder().decode(intermediateCa.getCert().getProto().getBase64()));
		// Cert chain: leaf + intermediate.
		String certChainPem = leafCertPem + intermediateCertPem;

		// Leaf private key PEM.
		byte[] leafPrivKeyBytes = leafKeyPair.getPrivate().getEncoded();
		String leafPrivKeyPem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(leafPrivKeyBytes)
				+ "\n-----END PRIVATE KEY-----\n";

		logger.info("Issued service certificate: service={}, leafId={}, exp={}",
				serviceName, leafId, leafExp);

		return Kernel.ServiceCertificateResponse.newBuilder()
				.setCertChainPem(certChainPem)
				.setPrivateKeyPem(leafPrivKeyPem)
				.setCaCertPem(intermediateCertPem)
				.build();
	}

	/**
	 * Gets or creates a per-service intermediate CA.
	 * The intermediate CA is signed by the root CA with BasicConstraints CA:TRUE, pathlen:0.
	 * It's stored in the Ca state's service_cas collection, keyed by service name.
	 */
	private synchronized ImmutableCertPair getOrCreateIntermediateCa(
			String serviceName, ImmutableCertPair rootCa) throws Exception {

		// Check if intermediate CA already exists for this service.
		X509.X509CertPair existing = serviceCaReader.apply(serviceName);
		if (existing != null && existing.hasCert()) {
			return ImmutableCertPair.from(existing);
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
		X509.X509CertPair intermediateProto = X509.X509CertPair.newBuilder()
				.setKey(intermediateKey)
				.setCert(intermediateCert)
				.build();

		serviceCaWriter.accept(serviceName, intermediateProto);
		logger.info("Created intermediate CA for service: {}", serviceName);

		return ImmutableCertPair.from(intermediateProto);
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
