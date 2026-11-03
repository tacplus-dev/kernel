// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.stub.StreamObserver;
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
 * kernel#38). The fake OPA is a real gRPC server behind the generated clients,
 * recording the {@code trace_id} of every input it receives.
 */
class OpaTracePropagationTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String DELEGATE_NAME = "oauth";
	private static final String TENANT_NAMESPACE = "/tenants/acme";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final String LOGIN_TRACE = "trace-login";
	private static final String TRACE = "trace-0123456789abcdef";
	private static final String NONCE =
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private RecordingOpaServer opa;
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
		List<Kernel.Delegate> delegates = List.of(Kernel.Delegate.newBuilder().setName(DELEGATE_NAME).build());
		identityService = new IdentityServiceImpl(
				3600, 900, 86_400, 30L * 86_400, 90L * 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				List::of,
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
				new PrincipalMap(new InMemoryManager()),
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

	// ---- MintExternalToken -------------------------------------------------

	@Test
	void mintExternalTokenCarriesTheRequestTraceToProxyPolicyOpa() throws Exception {
		String accessToken = loginTokens(false).getAccessToken().getBase64();
		// The external token takes its namespace from the policy's extra_claims
		// alone: none is forwarded from the user token (kernel#40).
		opa.proxyPolicyResult = Proxypolicy.ProxyPolicyEvalResult.newBuilder()
				.setAllow(true)
				.setExtraClaims(Struct.newBuilder()
						.putFields("namespace", Value.newBuilder().setStringValue(TENANT_NAMESPACE).build()))
				.build();

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
		return Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder()
						.setStringValue("https://accounts.google.com").build())
				.putFields("origin_sub", Value.newBuilder()
						.setStringValue("alice-idp-sub").build())
				.build();
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
