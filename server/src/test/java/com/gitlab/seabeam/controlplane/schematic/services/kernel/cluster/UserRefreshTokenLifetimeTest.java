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
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The refresh token a broker's IdP login mints (oauth's callback →
 * MintUserToken, no requested exp) lives for {@code refresh_token_lifetime_seconds}
 * — 24 h by default — not for {@code default_token_expiry_seconds}, which is the
 * 1 h access-token default. A refresh never extends a refresh token (an exchange
 * is capped at the presented token's own exp), so whatever lifetime it is born
 * with is the whole web session.
 */
class UserRefreshTokenLifetimeTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String DELEGATE_NAME = "oauth";
	private static final String TENANT_NAMESPACE = "/tenants/acme";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final long DEFAULT_EXPIRY_SECONDS = 3600;
	private static final long REFRESH_LIFETIME_SECONDS = 86_400;
	/** Tolerance for the second boundary between the test's `now` and the impl's. */
	private static final long SKEW_SECONDS = 5;

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private KeyRotator keyRotator;

	private IdentityServiceImpl newService() {
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
		return new IdentityServiceImpl(
				DEFAULT_EXPIRY_SECONDS, REFRESH_LIFETIME_SECONDS, 30L * 86_400, 90L * 86_400,
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
				new FakeOpaEvalGrpcClient(TENANT_NAMESPACE),
				null,            // proxyPolicyOpaClient
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty (fail closed)
	}

	/** The delegate's own S2S token, which is what authenticates a MintUserToken call. */
	private String delegateToken() {
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
		return t.getBase64();
	}

	/** What oauth's mint_callback_tokens sends: IdP broker kind, no exp. */
	private Tokenrequest.TokenMintResponse mintCallbackTokens(IdentityServiceImpl svc) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken());
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintUserToken(CALLER, Tokenrequest.MintUserTokenRequest.newBuilder()
					.setSubject("alice-idp-sub")
					.setBrokerKind(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP)
					.setClaims(Struct.newBuilder()
							.putFields("origin_iss", Value.newBuilder()
									.setStringValue("https://accounts.google.com").build())
							.build())
					.build());
		} finally {
			ctx.detach(previous);
		}
	}

	@Test
	void callbackRefreshTokenLivesForTheRefreshLifetimeNotTheAccessDefault() throws Exception {
		IdentityServiceImpl svc = newService();
		long now = Instant.now().getEpochSecond();

		Tokenrequest.TokenMintResponse resp = mintCallbackTokens(svc);

		long refreshExp = TokenWrapper.parse(resp.getRefreshToken().getBase64()).getExpiration();
		assertTrue(Math.abs(refreshExp - (now + REFRESH_LIFETIME_SECONDS)) <= SKEW_SECONDS,
				"refresh token exp should be now + " + REFRESH_LIFETIME_SECONDS
						+ "s, was now + " + (refreshExp - now) + "s");
		long accessExp = TokenWrapper.parse(resp.getAccessToken().getBase64()).getExpiration();
		assertTrue(Math.abs(accessExp - (now + DEFAULT_EXPIRY_SECONDS)) <= SKEW_SECONDS,
				"access token exp should stay now + " + DEFAULT_EXPIRY_SECONDS
						+ "s, was now + " + (accessExp - now) + "s");
	}

	/** Returns a canned EntitlementEvalResult; the channel throws if ever used. */
	private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		private final String namespace;

		FakeOpaEvalGrpcClient(String namespace) {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
			this.namespace = namespace;
		}

		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setNamespace(namespace)
					.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder()
							.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
							.build())
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
