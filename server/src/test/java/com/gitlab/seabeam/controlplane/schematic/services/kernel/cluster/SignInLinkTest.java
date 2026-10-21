// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Mint.CreateSignInLink and the {@code AUTH_BROKER_KIND_EMAIL_LINK} arm of
 * MintUserToken: a link kernel issues, keeps only the hash of, and spends once.
 *
 * <p>The map is a real Hazelcast map, the same kind ClusterServer wires, because
 * the properties under test — atomic single-use and the entry TTL — are the
 * map's, not anything a HashMap stand-in would show.
 */
class SignInLinkTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String DELEGATE_NAME = "oauth";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final String EMAIL = "Pat@SelfHosted.Example";

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private final PrincipalMap principalMap = new PrincipalMap(new InMemoryManager());
	private KeyRotator keyRotator;
	private HazelcastInstance hazelcast;
	private IMap<String, IdentityServiceImpl.SignInLinkEntry> links;

	@AfterEach
	void stopHazelcast() {
		if (hazelcast != null) {
			hazelcast.shutdown();
		}
	}

	/** The service with one {@code oauth} delegate listing exactly {@code kinds}, links wired. */
	private IdentityServiceImpl newService(Tokenrequest.AuthBrokerKind... kinds) {
		IdentityServiceImpl svc = unwiredService(kinds);
		Config config = new Config();
		config.setClusterName("sign-in-link-test-" + UUID.randomUUID());
		config.getNetworkConfig().setPort(0);
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		hazelcast = Hazelcast.newHazelcastInstance(config);
		links = hazelcast.getMap("sign-in-links");
		svc.setSignInLinks(links);
		return svc;
	}

	private IdentityServiceImpl unwiredService(Tokenrequest.AuthBrokerKind... kinds) {
		keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		Kernel.Delegate.Builder delegate = Kernel.Delegate.newBuilder().setName(DELEGATE_NAME);
		for (Tokenrequest.AuthBrokerKind kind : kinds) {
			delegate.addAuthBrokerKinds(kind);
		}
		delegates.add(delegate.build());
		return new IdentityServiceImpl(
				3600, 86_400, 86_400,
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
				new FakeOpaEvalGrpcClient(),
				null,            // proxyPolicyOpaClient
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				"schematic-kernel",
				null);           // webauthnRelyingParty
	}

	/** Runs {@code call} authenticated as the oauth delegate's own S2S token. */
	private <T> T asDelegate(Callable<T> call) throws Exception {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", DELEGATE_NAME);
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, t.getBase64());
		io.grpc.Context previous = ctx.attach();
		try {
			return call.call();
		} finally {
			ctx.detach(previous);
		}
	}

	private String createLink(IdentityServiceImpl svc, String email) throws Exception {
		return asDelegate(() -> svc.createSignInLink(CALLER,
				Kernel.CreateSignInLinkRequest.newBuilder().setEmail(email).build())).getToken();
	}

	private Tokenrequest.TokenMintResponse spend(IdentityServiceImpl svc, String token) throws Exception {
		return asDelegate(() -> svc.mintUserToken(CALLER, Tokenrequest.MintUserTokenRequest.newBuilder()
				.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK)
				.setProofToken(token)
				// Ignored on this arm: kernel names the person from the link.
				.setSubject("someone-else@example.com")
				.build()));
	}

	private static String sha256Hex(String s) throws Exception {
		return HexFormat.of().formatHex(
				MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	void aLinkMintsThePeopleTenantPersonKeyedOnTheAddress() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK);

		String token = createLink(svc, EMAIL);
		assertEquals(43, token.length(), "32 random bytes, base64url without padding");
		Tokenrequest.TokenMintResponse resp = spend(svc, token);

		TokenWrapper refresh = TokenWrapper.parse(resp.getRefreshToken().getBase64());
		TokenWrapper access = TokenWrapper.parse(resp.getAccessToken().getBase64());
		String userId = PeopleTenant.userId(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_MAIL_LINK,
				"pat@selfhosted.example");
		String expectedSubject = Spiffe.userSpiffeId(TRUST_DOMAIN, PeopleTenant.NAMESPACE, userId);
		assertEquals(expectedSubject, refresh.getSubject());
		assertEquals(expectedSubject, access.getSubject());
		assertEquals(PeopleTenant.NAMESPACE, refresh.getNamespace());
		assertEquals(PeopleTenant.NAMESPACE, access.getNamespace());
		assertFalse(refresh.getSubject().contains("@"), "no address in a SPIFFE id: " + refresh.getSubject());

		List<Kernel.Person> people = principalMap.proto().getPeopleList();
		assertEquals(1, people.size());
		assertEquals(Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_MAIL_LINK, people.get(0).getProvider());
		assertEquals("pat@selfhosted.example", people.get(0).getProviderSubject());
		assertEquals(userId, people.get(0).getUserId());

		// The same address in another case, on a second link, is the same person.
		TokenWrapper again = TokenWrapper.parse(
				spend(svc, createLink(svc, "pat@selfhosted.example")).getRefreshToken().getBase64());
		assertEquals(expectedSubject, again.getSubject());
		assertEquals(1, principalMap.proto().getPeopleCount());
	}

	@Test
	void aLinkIsSpentOnce() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK);
		String token = createLink(svc, EMAIL);
		spend(svc, token);

		ProtoException ex = assertThrows(ProtoException.class, () -> spend(svc, token));
		assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode());
		assertTrue(links.isEmpty(), "the spent link is gone from the map");
	}

	@Test
	void anExpiredLinkIsRefusedAndConsumed() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK);
		String token = createLink(svc, EMAIL);
		// Past its expiry but not yet dropped by the TTL sweep: the arm's own
		// expiry check is what refuses it.
		links.put(sha256Hex(token), new IdentityServiceImpl.SignInLinkEntry(
				"pat@selfhosted.example", System.currentTimeMillis() - 1));

		ProtoException ex = assertThrows(ProtoException.class, () -> spend(svc, token));
		assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode());
		assertTrue(links.isEmpty());
		assertEquals(0, principalMap.proto().getPeopleCount(), "an expired link creates no person");
	}

	@Test
	void theMapHoldsOnlyTheHashAndDropsItAfterTheTtl() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK);
		long before = System.currentTimeMillis();
		String token = createLink(svc, EMAIL);

		assertEquals(1, links.size());
		String key = links.keySet().iterator().next();
		assertEquals(sha256Hex(token), key);
		assertFalse(key.contains(token));
		assertEquals(900_000L, links.getEntryView(key).getTtl(), "Hazelcast drops the entry after 15 minutes");
		long expiresAt = links.get(key).expiresAtMs;
		assertTrue(expiresAt >= before + 900_000L && expiresAt <= System.currentTimeMillis() + 900_000L);
	}

	@Test
	void anUnknownOrEmptyTokenIsRefused() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK);
		for (String token : List.of("", "not-a-link-kernel-issued-0000000000000000000")) {
			ProtoException ex = assertThrows(ProtoException.class, () -> spend(svc, token));
			assertEquals(ProtoException.UNAUTHENTICATED, ex.getCode(), "token '" + token + "'");
		}
	}

	@Test
	void onlyAnEmailLinkBrokerMayCreateOrSpendLinks() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP);

		ProtoException create = assertThrows(ProtoException.class, () -> createLink(svc, EMAIL));
		assertEquals(ProtoException.PERMISSION_DENIED, create.getCode());
		assertTrue(links.isEmpty(), "a refused create stores nothing");

		links.put(sha256Hex("planted"), new IdentityServiceImpl.SignInLinkEntry(
				"pat@selfhosted.example", System.currentTimeMillis() + 60_000));
		ProtoException mint = assertThrows(ProtoException.class, () -> spend(svc, "planted"));
		assertEquals(ProtoException.PERMISSION_DENIED, mint.getCode());
		assertNotNull(links.get(sha256Hex("planted")),
				"a refused broker never reaches the map, so the link is not burned");
	}

	@Test
	void anUnwiredKernelRefusesRatherThanMinting() throws Exception {
		IdentityServiceImpl svc = unwiredService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_EMAIL_LINK);
		assertEquals(ProtoException.UNAVAILABLE,
				assertThrows(ProtoException.class, () -> createLink(svc, EMAIL)).getCode());
		assertEquals(ProtoException.UNAVAILABLE,
				assertThrows(ProtoException.class, () -> spend(svc, "anything")).getCode());
	}

	private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		FakeOpaEvalGrpcClient() {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
		}

		/** No namespace: the people arm stamps its own and must not need one. */
		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder().build())
					.build();
		}

		private static final Channel UNUSABLE_CHANNEL = new Channel() {
			@Override
			public <ReqT, RespT> ClientCall<ReqT, RespT> newCall(
					MethodDescriptor<ReqT, RespT> methodDescriptor, CallOptions callOptions) {
				throw new UnsupportedOperationException("fake channel must never be used");
			}

			@Override
			public String authority() {
				throw new UnsupportedOperationException("fake channel must never be used");
			}
		};
	}
}
