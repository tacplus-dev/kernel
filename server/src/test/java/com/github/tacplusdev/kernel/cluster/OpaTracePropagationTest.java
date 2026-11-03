// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.stub.StreamObserver;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The OPA evaluation a request causes carries that request's {@code trace_id}
 * (field 200), so UncleOPA appears in the request's trace (tacplus-dev/looper#51,
 * kernel#38, kernel#39): each handler, on each of its paths that reaches OPA.
 * The fake OPA is a real gRPC server behind the generated clients, recording
 * the {@code trace_id} of every input it receives.
 */
class OpaTracePropagationTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String DELEGATE_NAME = "oauth";
	private static final String TENANT_NAMESPACE = "/tenants/acme";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	/** An issuer no people provider owns: an ordinary tenant login. */
	private static final String TENANT_ISSUER = "https://login.acme.example/oidc";
	private static final String GRANT_ID = "grant-1";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final String LOGIN_TRACE = "trace-login";
	private static final String TRACE = "trace-0123456789abcdef";
	private static final String NONCE =
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Grant> grants = new CopyOnWriteArrayList<>();
	private RecordingOpaServer opa;
	private PrincipalMap principalMap;
	private KeyRotator keyRotator;
	private IdentityServiceImpl identityService;
	private HazelcastInstance hazelcast;

	@BeforeEach
	void setUp() throws Exception {
		opa = new RecordingOpaServer(TENANT_NAMESPACE);
		keyRotator = new KeyRotator(
				3600, 30L * 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		List<Kernel.Delegate> delegates = List.of(Kernel.Delegate.newBuilder()
				.setName(DELEGATE_NAME)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.addAuthBrokerKinds(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)
				.build());
		principalMap = new PrincipalMap(new InMemoryManager());
		identityService = new IdentityServiceImpl(
				3600, 900, 86_400, 30L * 86_400, 90L * 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				() -> grants,
				g -> { },
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				"https://kernel.test/oidc",
				opa.entitlementClient(),
				opa.proxyPolicyClient(),
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty (fail closed)
	}

	@AfterEach
	void tearDown() {
		keyRotator.stop();
		opa.close();
		if (hazelcast != null) {
			hazelcast.shutdown();
		}
	}

	// ---- MintToken exchange ------------------------------------------------

	@Test
	void refreshToAccessExchangeCarriesTheRequestTraceToOpa() throws Exception {
		String refreshToken = loginTokens(false).getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(refreshToken)
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void offlineTokenProjectSwitchCarriesTheRequestTraceToOpa() throws Exception {
		String offlineToken = loginTokens(true).getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(offlineToken)
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void offlineTokenRenewalCarriesTheRequestTraceToOpa() throws Exception {
		String offlineToken = loginTokens(true).getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(offlineToken)
				.setOfflineAccess(true)
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void refreshServiceAudsBatchCarriesTheRequestTraceToOpa() throws Exception {
		String refreshToken = loginTokens(false).getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(refreshToken)
				.addServiceAuds("sentinel")
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	/** The session-credential arm, with a service_auds batch beside its access token. */
	@Test
	void sessionCredentialExchangeCarriesTheRequestTraceToOpa() throws Exception {
		String credential = personLogin(GOOGLE_ISSUER, "alice-google-sub").getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintToken(CALLER, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(credential)
				.setTenantNamespace(TENANT_NAMESPACE)
				.addServiceAuds("sentinel")
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- MintServiceToken (input_token) ------------------------------------

	@Test
	void serviceTokenRefreshExchangeCarriesTheRequestTraceToOpa() throws Exception {
		String refreshToken = loginTokens(false).getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintServiceToken(CALLER, Tokenrequest.MintServiceTokenRequest.newBuilder()
				.setInputToken(refreshToken)
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void serviceTokenOfflineTokenExchangeCarriesTheRequestTraceToOpa() throws Exception {
		String offlineToken = loginTokens(true).getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintServiceToken(CALLER, Tokenrequest.MintServiceTokenRequest.newBuilder()
				.setInputToken(offlineToken)
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void serviceTokenSessionCredentialExchangeCarriesTheRequestTraceToOpa() throws Exception {
		String credential = personLogin(GOOGLE_ISSUER, "alice-google-sub").getRefreshToken().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.mintServiceToken(CALLER, Tokenrequest.MintServiceTokenRequest.newBuilder()
				.setInputToken(credential)
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- MintUserToken -----------------------------------------------------

	@Test
	void tenantIdpLoginCarriesTheRequestTraceToOpa() throws Exception {
		mintUserToken(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("alice@acme.example")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(TENANT_ISSUER, "alice-acme-sub"))
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void peopleLoginCarriesTheRequestTraceToOpa() throws Exception {
		mintUserToken(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(GOOGLE_ISSUER, "alice-google-sub"))
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	@Test
	void deviceLoginCarriesTheRequestTraceToOpa() throws Exception {
		DevicePrincipalTest.DeviceKey key = DevicePrincipalTest.DeviceKey.generate("cred-iphone");
		KernelIdentityGraph graph = new KernelIdentityGraph(principalMap, () -> { }, () -> false);
		String xid = graph.resolveOrCreate("google", "alice-google-sub").person().getXid();
		graph.addDevice(xid, Kernel.PersonalCredential.newBuilder()
				.setCredentialId(key.credentialId)
				.setPublicKey(key.publicJwk)
				.setLabel("iPhone")
				.setCreatedAtMs(System.currentTimeMillis())
				.build());

		mintUserToken(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE)
				.setProofToken(key.proof())
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- MintDelegatedToken ------------------------------------------------

	@Test
	void mintDelegatedTokenCarriesTheRequestTraceToOpa() throws Exception {
		String grantSubject = "spiffe://" + TRUST_DOMAIN + "/system/users/alice";
		grants.add(Kernel.Grant.newBuilder()
				.setId(GRANT_ID)
				.setDelegateName(DELEGATE_NAME)
				.setSubject(grantSubject)
				.setClaims(Struct.newBuilder()
						.putFields("sub", Value.newBuilder().setStringValue(grantSubject).build()))
				.setCreatedAtMs(Instant.now().toEpochMilli())
				.build());

		withBearer(serviceToken(DELEGATE_NAME), () -> identityService.mintDelegatedToken(CALLER,
				Tokenrequest.MintDelegatedTokenRequest.newBuilder()
						.setGrantId(GRANT_ID)
						.setTraceId(TRACE)
						.build()));

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- MintDelegateOfflineToken ------------------------------------------

	@Test
	void mintDelegateOfflineTokenCarriesTheRequestTraceToOpa() throws Exception {
		String accessToken = loginTokens(false).getAccessToken().getBase64();
		opa.entitlementTraceIds.clear();

		withBearer(accessToken, () -> identityService.mintDelegateOfflineToken(CALLER,
				Tokenrequest.MintDelegateOfflineTokenRequest.newBuilder()
						.setDelegateName(DELEGATE_NAME)
						.setTraceId(TRACE)
						.build()));

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- RevokeCredentialProof ---------------------------------------------

	/** Signing out of one provider mints the access token the remaining proof vouches for. */
	@Test
	void revokeCredentialProofCarriesTheRequestTraceToOpa() throws Exception {
		TokenWrapper google = TokenWrapper.parse(
				personLogin(GOOGLE_ISSUER, "alice-google-sub").getRefreshToken().getBase64());
		linkToTheSamePerson(google, APPLE_ISSUER, "alice-apple-sub");
		TokenWrapper apple = TokenWrapper.parse(
				personLogin(APPLE_ISSUER, "alice-apple-sub").getRefreshToken().getBase64());
		Caller bearer = new Caller("{\"sub\":\"" + google.getSubject() + "\",\"namespace\":\""
				+ TENANT_NAMESPACE + "\"}", "test-req");
		String merged = identityService.mergeCredentials(bearer, Kernel.MergeCredentialsRequest.newBuilder()
				.addCredentials(google.getBase64())
				.addCredentials(apple.getBase64())
				.build()).getCredential().getBase64();
		opa.entitlementTraceIds.clear();

		identityService.revokeCredentialProof(bearer, Kernel.RevokeCredentialProofRequest.newBuilder()
				.setCredential(merged)
				.setIdpId("apple")
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- MintExternalToken -------------------------------------------------

	@Test
	void mintExternalTokenCarriesTheRequestTraceToProxyPolicyOpa() throws Exception {
		String accessToken = loginTokens(false).getAccessToken().getBase64();

		identityService.mintExternalToken(CALLER, Tokenrequest.ExternalTokenMintRequest.newBuilder()
				.setUserToken(accessToken)
				.setMetadata("{}")
				.setTraceId(TRACE)
				.build());

		assertEveryCallCarries(TRACE, opa.proxyPolicyTraceIds);
	}

	// ---- BrokerStream CompleteNonce ----------------------------------------

	@Test
	void brokerCompleteNonceCarriesItsTraceToOpa() {
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = brokerStream();

		requests.onNext(registerNonce());
		requests.onNext(completeNonce());

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	/** A CompleteNonce parked before its RegisterNonce is minted later, still under its own trace. */
	@Test
	void parkedBrokerCompleteNonceCarriesItsTraceToOpaWhenMinted() {
		StreamObserver<Kernel.CliTokenBrokerRequest> requests = brokerStream();

		requests.onNext(completeNonce());
		awaitCondition(() -> hazelcast.getMap("cli-token-broker").containsKey("pending:" + NONCE),
				"the completion was never parked");
		requests.onNext(registerNonce());
		awaitCondition(() -> !opa.entitlementTraceIds.isEmpty(), "the parked completion was never minted");

		assertEveryCallCarries(TRACE, opa.entitlementTraceIds);
	}

	// ---- fixture -----------------------------------------------------------

	private static void assertEveryCallCarries(String traceId, List<String> received) {
		assertFalse(received.isEmpty(), "the request made no OPA call");
		assertEquals(Collections.nCopies(received.size(), traceId), received,
				"every OPA call the request causes must carry its trace_id");
	}

	/**
	 * A user's login tokens of the shape the exchange's legacy arm reads: a refresh
	 * token (or an offline token) and an access token, minted as the broker mints
	 * them. A people-tenant login mints a session credential instead, whose arm
	 * already carries the trace.
	 */
	private Tokenrequest.TokenMintResponse loginTokens(boolean offlineAccess) throws Exception {
		return identityService.mintUserTokenInternal(
				"alice-idp-sub", idpClaims(), 0, LOGIN_TRACE, DELEGATE_NAME, offlineAccess, null);
	}

	private static Struct idpClaims() {
		return idpClaims(GOOGLE_ISSUER, "alice-idp-sub");
	}

	private static Struct idpClaims(String issuer, String sub) {
		return Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(sub).build())
				.build();
	}

	/**
	 * A people-provider login through MintUserToken: its long-lived token is a
	 * session credential, with a proof for the tenant the fake OPA routes it to.
	 */
	private Tokenrequest.TokenMintResponse personLogin(String issuer, String sub) throws Exception {
		return mintUserToken(Tokenrequest.MintUserTokenRequest.newBuilder()
				.setSubject("whatever-the-broker-says")
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
				.setClaims(idpClaims(issuer, sub))
				.setTraceId(LOGIN_TRACE)
				.build());
	}

	/** Links a second provider identity to the person {@code credential} names, as Link writes it. */
	private void linkToTheSamePerson(TokenWrapper credential, String issuer, String sub) throws Exception {
		String xid = SessionCredential.xidOf(credential);
		String idpId = PeopleTenant.idpId(PeopleTenant.providerForIssuer(issuer));
		String key = IdentityServiceImpl.identityLinkKey(idpId, sub);
		principalMap.putIdentityLinks(key, Kernel.IdentityLinkRow.newBuilder()
				.setLinkKey(key).setXid(xid).build());
		principalMap.putPeople(xid, principalMap.getPeople(xid).toBuilder()
				.addLinks(Kernel.IdentityLink.newBuilder().setIdpId(idpId).setProviderSubject(sub))
				.build());
	}

	/** MintUserToken as the oauth broker. */
	private Tokenrequest.TokenMintResponse mintUserToken(Tokenrequest.MintUserTokenRequest request)
			throws Exception {
		return withBearer(serviceToken(DELEGATE_NAME), () -> identityService.mintUserToken(CALLER, request));
	}

	/** Runs {@code call} with {@code token} as the request's raw bearer token. */
	private static <T> T withBearer(String token, Call<T> call) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current().withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, token);
		io.grpc.Context previous = ctx.attach();
		try {
			return call.run();
		} finally {
			ctx.detach(previous);
		}
	}

	@FunctionalInterface
	private interface Call<T> {
		T run() throws Exception;
	}

	/** A kernel-signed S2S token for the /system delegate {@code name}. */
	private String serviceToken(String name) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", name);
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		return t.getBase64();
	}

	/** The broker as kernel wires it: minting through the identity service. */
	private StreamObserver<Kernel.CliTokenBrokerRequest> brokerStream() {
		Config config = new Config();
		config.setClusterName("opa-trace-propagation-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		hazelcast = Hazelcast.newHazelcastInstance(config);
		StreamObserver<Kernel.CliTokenBrokerRequest> requests =
				new CliTokenBrokerServiceImpl(identityService, hazelcast)
						.brokerStream(null, new DiscardingObserver());
		requests.onNext(Kernel.CliTokenBrokerRequest.newBuilder()
				.setRegister(Kernel.CliTokenBrokerRegister.newBuilder().setInstanceId("oauth-a"))
				.build());
		return requests;
	}

	private static Kernel.CliTokenBrokerRequest registerNonce() {
		return Kernel.CliTokenBrokerRequest.newBuilder()
				.setRegisterNonce(Kernel.CliTokenBrokerRegisterNonce.newBuilder().setNonce(NONCE))
				.build();
	}

	private static Kernel.CliTokenBrokerRequest completeNonce() {
		return Kernel.CliTokenBrokerRequest.newBuilder()
				.setCompleteNonce(Kernel.CliTokenBrokerCompleteNonce.newBuilder()
						.setNonce(NONCE)
						.setSubject("alice-idp-sub")
						.setClaims(idpClaims())
						.setTraceId(TRACE))
				.build();
	}

	private static void awaitCondition(java.util.function.BooleanSupplier condition, String message) {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
		while (System.nanoTime() < deadline) {
			if (condition.getAsBoolean()) return;
			try {
				Thread.sleep(20);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				fail("interrupted while waiting: " + message);
			}
		}
		fail(message);
	}

	private static final class DiscardingObserver implements StreamObserver<Kernel.CliTokenBrokerResponse> {
		@Override
		public void onNext(Kernel.CliTokenBrokerResponse value) {
		}

		@Override
		public void onError(Throwable t) {
		}

		@Override
		public void onCompleted() {
		}
	}
}
