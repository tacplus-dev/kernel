// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.generated.services.Services;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The member-port audience (kernel#30, for tacplus#212): {@code member:<svc>}
 * is minted only for the caller's own service label, in its own tenant, and
 * lives at most five minutes. It cannot collide with a service label, so a
 * gRPC token ({@code aud=<svc>}) is never a member-port token, nor the reverse.
 *
 * <p>Two tenants, acme and beta, each run their own {@code docmanager}; acme's
 * delegate may mint for any service ({@code SERVICE_NAME_ANY}), which must not
 * reach a member-port audience. {@code eventbus} is a /system service.
 */
class MemberPortAudienceTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String SERVICE_NAME = "docmanager";
	private static final String SYSTEM_SERVICE = "eventbus";
	private static final String ACME = "/tenants/acme";
	private static final String BETA = "/tenants/beta";
	private static final String OWN_MEMBER_AUD = "member:" + SERVICE_NAME;
	private static final long MEMBER_TTL_SECONDS = 300;

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new CopyOnWriteArrayList<>();
	private KeyRotator keyRotator;
	private ConfigMap configMap;
	private IdentityServiceImpl svc;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(SERVICE_NAME)
				.setTenantNamespace(ACME)
				.addAuthorizedServices(Services.ServiceName.SERVICE_NAME_ANY)
				.build());
		delegates.add(Kernel.Delegate.newBuilder()
				.setName(SERVICE_NAME)
				.setTenantNamespace(BETA)
				.addAuthorizedServices(Services.ServiceName.SERVICE_NAME_OPA)
				.build());
		delegates.add(Kernel.Delegate.newBuilder().setName(SYSTEM_SERVICE).build());

		configMap = new ConfigMap(new InMemoryManager());
		TenantAdminServiceImpl admin = new TenantAdminServiceImpl(configMap, () -> TRUST_DOMAIN, null);
		for (String ns : List.of(ACME, BETA)) {
			admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ns).build());
		}
		svc = new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				List::of,        // grants
				null,            // grantsWriter
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				null,            // opaEvalClient: no path here calls OPA
				null,            // proxyPolicyOpaClient
				configMap,
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty
	}

	@AfterEach
	void tearDown() {
		keyRotator.stop();
	}

	// ---- own label: minted, short-lived ------------------------------------

	@Test
	void aServiceMintsMemberOfItsOwnLabelForFiveMinutesAtMost() throws Exception {
		String acme = acmeService();
		long now = Instant.now().getEpochSecond();

		TokenWrapper token = mint(serviceAccess(acme, ACME), OWN_MEMBER_AUD, 0);

		assertEquals(OWN_MEMBER_AUD, token.getAudience());
		assertEquals(acme, token.getSubject());
		assertEquals(ACME, token.getNamespace(), "in its own tenant");
		assertEquals(IdentityServiceImpl.SUB_TYPE_SERVICE, token.getSubType());
		assertTrue(token.getExpiration() > now, "live");
		assertTrue(token.getExpiration() <= Instant.now().getEpochSecond() + MEMBER_TTL_SECONDS,
				"exp " + token.getExpiration() + " is more than five minutes away");
	}

	@Test
	void anExplicitExpWithinFiveMinutesIsKeptAndOneBeyondIsRefused() throws Exception {
		String access = serviceAccess(acmeService(), ACME);
		long now = Instant.now().getEpochSecond();

		assertEquals(now + 120, mint(access, OWN_MEMBER_AUD, now + 120).getExpiration());
		assertEquals(ProtoException.INVALID_ARGUMENT,
				codeOf(() -> mint(access, OWN_MEMBER_AUD, now + MEMBER_TTL_SECONDS + 60)));
	}

	@Test
	void eachTenantsServiceMintsItsOwnInItsOwnTenant() throws Exception {
		TokenWrapper beta = mint(serviceAccess(service(BETA), BETA), OWN_MEMBER_AUD, 0);

		assertEquals(OWN_MEMBER_AUD, beta.getAudience());
		assertEquals(BETA, beta.getNamespace());
		assertEquals(service(BETA), beta.getSubject());
	}

	@Test
	void aSystemServiceMintsItsOwnToo() throws Exception {
		String eventbus = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", SYSTEM_SERVICE);

		TokenWrapper token = mint(serviceAccess(eventbus, "/system"), "member:" + SYSTEM_SERVICE, 0);

		assertEquals("member:" + SYSTEM_SERVICE, token.getAudience());
		assertTrue(token.getExpiration() <= Instant.now().getEpochSecond() + MEMBER_TTL_SECONDS);
	}

	@Test
	void aBatchMintsTheOwnMemberAudienceShortLivedBesideThePlainOnes() throws Exception {
		Tokenrequest.TokenMintResponse resp = svc.mintToken(null, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(serviceAccess(acmeService(), ACME))
				.addServiceAuds("opa")
				.addServiceAuds(OWN_MEMBER_AUD)
				.build());
		long now = Instant.now().getEpochSecond();

		TokenWrapper opa = TokenWrapper.from(resp.getServiceTokens(0));
		TokenWrapper member = TokenWrapper.from(resp.getServiceTokens(1));
		assertEquals("opa", opa.getAudience());
		assertTrue(opa.getExpiration() > now + MEMBER_TTL_SECONDS, "a plain audience keeps its lifetime");
		assertEquals(OWN_MEMBER_AUD, member.getAudience());
		assertTrue(member.getExpiration() <= now + MEMBER_TTL_SECONDS);
	}

	// ---- anything else: refused --------------------------------------------

	@Test
	void anotherServicesMemberAudienceIsRefusedEvenForADelegateAuthorizedForAny() throws Exception {
		String access = serviceAccess(acmeService(), ACME);

		assertEquals(ProtoException.PERMISSION_DENIED, codeOf(() -> mint(access, "member:opa", 0)));
		assertEquals(ProtoException.PERMISSION_DENIED, codeOf(() -> mint(access, "member:", 0)));
		assertEquals(ProtoException.PERMISSION_DENIED,
				codeOf(() -> mint(access, "member:" + SERVICE_NAME + "/workloads/pigeon", 0)));
	}

	@Test
	void aMemberAudienceNamingAnotherTenantIsRefused() throws Exception {
		String access = serviceAccess(acmeService(), ACME);

		for (String aud : List.of(
				"member:" + service(BETA),
				"member:" + acmeService(),
				"member:" + BETA + "/" + SERVICE_NAME,
				"member:" + SERVICE_NAME + "@" + BETA)) {
			assertEquals(ProtoException.PERMISSION_DENIED, codeOf(() -> mint(access, aud, 0)), aud);
		}
	}

	@Test
	void aBatchWithAnotherServicesMemberAudienceIsRefused() throws Exception {
		assertEquals(ProtoException.PERMISSION_DENIED, codeOf(() -> svc.mintToken(null,
				Tokenrequest.TokenMintRequest.newBuilder()
						.setInputToken(serviceAccess(acmeService(), ACME))
						.addServiceAuds("opa")
						.addServiceAuds("member:opa")
						.build())));
	}

	@Test
	void aUserNeverMintsAMemberAudience() throws Exception {
		TokenWrapper user = base(Spiffe.userSpiffeId(TRUST_DOMAIN, ACME, "alice"), ACME);
		user.setSubType("user");
		user.setTokenUse("access");
		user.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));

		assertEquals(ProtoException.PERMISSION_DENIED,
				codeOf(() -> mint(user.getBase64(), OWN_MEMBER_AUD, 0)));
		assertEquals(ProtoException.PERMISSION_DENIED,
				codeOf(() -> mint(user.getBase64(), "member:alice", 0)));
	}

	@Test
	void aWorkloadUnderTheServiceDoesNotMintItsMemberAudience() throws Exception {
		String pigeon = Spiffe.workloadSpiffeId(acmeService(), "pigeon");

		assertEquals(ProtoException.PERMISSION_DENIED,
				codeOf(() -> mint(serviceAccess(pigeon, ACME), OWN_MEMBER_AUD, 0)));
	}

	// ---- a plain audience: unchanged ---------------------------------------

	@Test
	void aPlainServiceAudienceIsUnchanged() throws Exception {
		String access = serviceAccess(acmeService(), ACME);
		long now = Instant.now().getEpochSecond();

		TokenWrapper opa = mint(access, "opa", 0);
		assertEquals("opa", opa.getAudience());
		assertTrue(opa.getExpiration() > now + MEMBER_TTL_SECONDS, "not shortened");
		assertEquals(now + 1800, mint(access, "opa", now + 1800).getExpiration());

		// beta's delegate is authorized for opa only, as before.
		String beta = serviceAccess(service(BETA), BETA);
		assertEquals("opa", mint(beta, "opa", 0).getAudience());
		assertEquals(ProtoException.PERMISSION_DENIED, codeOf(() -> mint(beta, "llmproxy", 0)));
	}

	// ---- fixture -----------------------------------------------------------

	private String acmeService() {
		return service(ACME);
	}

	private String service(String tenant) {
		return TenantServiceSubjects.of(configMap, TRUST_DOMAIN, tenant, SERVICE_NAME);
	}

	private TokenWrapper mint(String inputToken, String aud, long exp) throws ProtoException {
		return TokenWrapper.from(svc.mintToken(null, Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(inputToken)
				.setAud(aud)
				.setExp(exp)
				.build()).getAccessToken());
	}

	/** A kernel-signed service access token for kernel's own audience, an hour long. */
	private String serviceAccess(String subject, String namespace) {
		TokenWrapper t = base(subject, namespace);
		t.setSubType(IdentityServiceImpl.SUB_TYPE_SERVICE);
		t.setTokenUse("access");
		t.sign(keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519));
		return t.getBase64();
	}

	private static TokenWrapper base(String subject, String namespace) {
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(subject)
				.setAudience(Kernel.getDescriptor().getPackage())
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(namespace);
		return t;
	}

	@FunctionalInterface
	private interface Call {
		Object call() throws Exception;
	}

	private static int codeOf(Call call) {
		return assertThrows(ProtoException.class, call::call).getCode();
	}
}
