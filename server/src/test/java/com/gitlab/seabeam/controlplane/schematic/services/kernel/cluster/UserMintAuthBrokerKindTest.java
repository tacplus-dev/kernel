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
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MintUserToken enforces {@code Delegate.auth_broker_kinds} — which classes of
 * user-authentication proof a delegate is trusted to attest.
 *
 * <p>This replaced the hardcoded {@code auth_services} broker allowlist on
 * the RPC. That literal was the only thing standing between "any
 * registered delegate" and "may assert who a human is"; the RPC now accepts
 * {@code ["*"]}, so the whole boundary lives in the handler and every case
 * below is load-bearing rather than belt-and-braces.
 *
 * <p>The checks are two, deliberately: a delegate must LIST the kind it is
 * presenting, and the kind must be one kernel can actually verify. DEVICE
 * and PERSONAL_LINK are enum values whose proof verification is not
 * written yet, so a delegate configured for one must not mint through the IdP
 * path just because its list is non-empty.
 */
class UserMintAuthBrokerKindTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String DELEGATE_NAME = "oauth";
	private static final String USER_SUBJECT = "alice@example.com";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final String TENANT_NAMESPACE = "/tenants/acme";

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private KeyRotator keyRotator;

	/**
	 * Builds the service with a single {@code oauth} delegate whose
	 * auth_broker_kinds are exactly {@code kinds} — none for the un-migrated
	 * default.
	 */
	private IdentityServiceImpl newService(Tokenrequest.AuthBrokerKind... kinds) {
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
				3600, 900, 86_400, 86_400, 86_400,
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
				KERNEL_AUDIENCE,
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

	/**
	 * An otherwise-valid MintUserToken call: authenticated as the delegate, with
	 * claims the (faked) policy maps to a real tenant. Only broker_kind varies,
	 * so anything refused below is refused by the broker-kind check and not by
	 * some unrelated precondition.
	 */
	private Tokenrequest.TokenMintResponse mintUser(IdentityServiceImpl svc,
			Tokenrequest.AuthBrokerKind brokerKind) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken());
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintUserToken(CALLER, Tokenrequest.MintUserTokenRequest.newBuilder()
					.setSubject(USER_SUBJECT)
					.setBrokerKind(brokerKind)
					.setClaims(Struct.newBuilder()
							.putFields("origin_iss", Value.newBuilder()
									.setStringValue("https://idp.example.com").build())
							.build())
					.build());
		} finally {
			ctx.detach(previous);
		}
	}

	/**
	 * Regression pin: the migrated oauth delegate keeps working exactly as
	 * before. If this ever fails, this task broke IdP login rather than
	 * containing it.
	 */
	@Test
	void delegateDeclaringIdpStillMintsThroughTheIdpPath() throws Exception {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP);

		Tokenrequest.TokenMintResponse resp =
				mintUser(svc, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP);

		assertNotNull(resp.getRefreshToken());
		assertEquals(TENANT_NAMESPACE,
				TokenWrapper.parse(resp.getRefreshToken().getBase64()).getNamespace());
		assertEquals(TENANT_NAMESPACE,
				TokenWrapper.parse(resp.getAccessToken().getBase64()).getNamespace());
	}

	/**
	 * The new default. Every delegate in the fleet has an empty
	 * auth_broker_kinds until its config is migrated, and an empty list means
	 * "not an auth broker" — not "unrestricted".
	 */
	@Test
	void delegateWithNoBrokerKindsIsRefused() {
		IdentityServiceImpl svc = newService();

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mintUser(svc, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("not authorized to broker"),
				"expected the broker-kind check to be the refuser, got: " + ex.getMessage());
	}

	/**
	 * Containment, not mere non-emptiness: a delegate trusted for DEVICE proofs
	 * must not be able to attest an IdP login. Without the {@code contains}
	 * check — if the handler asked only "is the list non-empty" — this passes
	 * and any future device broker silently gains IdP attestation.
	 */
	@Test
	void delegateDeclaringAnotherKindCannotBrokerIdp() {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mintUser(svc, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_IDP));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("not authorized to broker"),
				"expected the broker-kind check to be the refuser, got: " + ex.getMessage());
	}

	/**
	 * The second check, isolated. This delegate DOES list PERSONAL_LINK, so the
	 * containment check passes and only the switch can refuse it. PERSONAL_LINK
	 * requires kernel to verify request.proof_token itself, which is a later Goal
	 * B item and is not written — minting here would issue a user token on a
	 * proof nobody checked.
	 *
	 * <p>This case was DEVICE until device-proof verification landed; DEVICE now
	 * has a real verification arm ({@code DevicePrincipalMintTest}), so the only
	 * kind that still exercises the unimplemented arm is PERSONAL_LINK.
	 */
	@Test
	void kindWithNoVerificationIsRefusedEvenWhenDeclared() {
		IdentityServiceImpl svc = newService(Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_PERSONAL_LINK);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mintUser(svc, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_PERSONAL_LINK));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("not supported"),
				"expected the unimplemented-kind arm to be the refuser, got: " + ex.getMessage());
	}

	/**
	 * The zero value is a real attack surface, not a formality: a caller that
	 * simply omits broker_kind sends UNSPECIFIED, and a delegate misconfigured
	 * with UNSPECIFIED in its list satisfies the containment check. The switch's
	 * default arm is what stops an unnamed proof from taking the IdP path.
	 */
	@Test
	void unspecifiedKindIsRefusedEvenWhenDeclared() {
		IdentityServiceImpl svc = newService(
				Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_UNSPECIFIED);

		ProtoException ex = assertThrows(ProtoException.class,
				() -> mintUser(svc, Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_UNSPECIFIED));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("not supported"),
				"expected the unimplemented-kind arm to be the refuser, got: " + ex.getMessage());
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
