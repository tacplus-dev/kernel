// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.vservices.proxypolicy.Proxypolicy;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MintExternalToken end to end (kernel#40): the external token's {@code namespace}
 * is the verified caller token's, copied by the mint and by nothing else. The proxy
 * policy cannot set it, nor {@code tid} (kernel#32): a policy-supplied namespace
 * would let a policy mint into another tenant. The fake OPA is a real gRPC server
 * behind the generated clients.
 */
class MintExternalTokenTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String DELEGATE_NAME = "oauth";
	private static final String TENANT_NAMESPACE = "/tenants/acme";
	private static final Caller CALLER = new Caller("", "test-req");

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private RecordingOpaServer opa;
	private KeyRotator keyRotator;
	private IdentityServiceImpl identityService;

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
				.build());
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
	}

	@Test
	void aValidUserTokenMintsAndItsNamespaceCarriesThrough() throws Exception {
		String accessToken = userAccessToken();
		String userNamespace = TokenWrapper.parse(accessToken).getNamespace();
		assertEquals(TENANT_NAMESPACE, userNamespace);

		Tokenrequest.ExternalTokenMintResponse response = mintExternal(accessToken);

		TokenWrapper external = TokenWrapper.parse(response.getToken().getBase64());
		assertEquals(userNamespace, external.getNamespace());
		assertEquals("external", external.getTokenUse());
	}

	@Test
	void aPolicySettingNamespaceIsRefused() throws Exception {
		assertPolicyClaimRefused("namespace", "/tenants/other");
	}

	/** Even naming the caller's own namespace: the mint copies it, the policy never sets it. */
	@Test
	void aPolicySettingTheCallersOwnNamespaceIsRefused() throws Exception {
		assertPolicyClaimRefused("namespace", TENANT_NAMESPACE);
	}

	@Test
	void aPolicySettingTidIsRefused() throws Exception {
		assertPolicyClaimRefused("tid", "abcdefgh");
	}

	@Test
	void aPolicyAddingOtherClaimsStillMints() throws Exception {
		opa.proxyPolicyResult = Proxypolicy.ProxyPolicyEvalResult.newBuilder()
				.setAllow(true)
				.setExtraClaims(Struct.newBuilder().putFields("team", string("payments")))
				.build();

		TokenWrapper external = TokenWrapper.parse(mintExternal(userAccessToken()).getToken().getBase64());

		assertEquals("payments", external.getProto().getPayloadMap().get("team"));
		assertEquals(TENANT_NAMESPACE, external.getNamespace());
	}

	/**
	 * A caller token that verifies but carries no namespace is refused by the RPC
	 * itself, as an INVALID_ARGUMENT, before the policy is asked: not with an
	 * IllegalStateException from TokenWrapper.sign. TokenWrapper cannot sign such a
	 * token, so it is a hand-assembled EdDSA JWT under a key in the verifying set.
	 */
	@Test
	void aCallerTokenWithoutNamespaceIsRefusedAtTheRpc() throws Exception {
		DevicePrincipalTest.DeviceKey key = DevicePrincipalTest.DeviceKey.generate("no-namespace-key");
		verifyingKeys.add(key.publicJwk);

		ProtoException e = assertThrows(ProtoException.class, () -> mintExternal(key.proof()));

		assertEquals(ProtoException.INVALID_ARGUMENT, e.getCode());
		assertTrue(e.getMessage().contains("namespace"), e.getMessage());
		assertTrue(opa.proxyPolicyTraceIds.isEmpty(), "the policy must not be asked");
	}

	// ---- fixture -----------------------------------------------------------

	private void assertPolicyClaimRefused(String claim, String value) throws Exception {
		String accessToken = userAccessToken();
		opa.proxyPolicyResult = Proxypolicy.ProxyPolicyEvalResult.newBuilder()
				.setAllow(true)
				.setExtraClaims(Struct.newBuilder().putFields(claim, string(value)))
				.build();

		ProtoException e = assertThrows(ProtoException.class, () -> mintExternal(accessToken));

		assertEquals(ProtoException.PERMISSION_DENIED, e.getCode());
		assertTrue(e.getMessage().contains(claim), e.getMessage());
	}

	private Tokenrequest.ExternalTokenMintResponse mintExternal(String userToken) throws Exception {
		return identityService.mintExternalToken(CALLER, Tokenrequest.ExternalTokenMintRequest.newBuilder()
				.setUserToken(userToken)
				.setMetadata("{}")
				.build());
	}

	/** A kernel-signed user access token in {@link #TENANT_NAMESPACE}, minted as the broker mints it. */
	private String userAccessToken() throws Exception {
		Struct claims = Struct.newBuilder()
				.putFields("origin_iss", string("https://accounts.google.com"))
				.putFields("origin_sub", string("alice-idp-sub"))
				.build();
		return identityService.mintUserTokenInternal(
						"alice-idp-sub", claims, 0, "", DELEGATE_NAME, false, null)
				.getAccessToken().getBase64();
	}

	private static Value string(String s) {
		return Value.newBuilder().setStringValue(s).build();
	}
}
