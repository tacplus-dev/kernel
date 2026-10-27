// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.github.tacplusdev.kernel.model.types.generated.entitlements.Entitlements;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
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
 * MintDelegatedToken must fail CLOSED when the entitlements policy names no
 * tenant — the same refusal {@link UserMintNamespaceFailClosedTest} proves for
 * the user-mint path.
 *
 * <p>This path replays the {@link Kernel.Grant}'s recorded claims into OPA
 * fresh, so a policy that names no tenant for the consenting user leaves it with
 * nothing to stamp. Until this refusal it stamped the cluster ROOT instead, so a
 * delegate holding any grant could mint a fleet-wide-root access token out of
 * the same generated-policy silence that affected every login.
 */
class DelegatedMintNamespaceFailClosedTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String DELEGATE_NAME = "oauth";
	private static final String GRANT_ID = "grant-1";
	private static final String GRANT_SUBJECT = "alice@example.com";
	private static final Caller CALLER = new Caller("", "test-req");

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private final List<Kernel.Grant> grants = new CopyOnWriteArrayList<>();
	private KeyRotator keyRotator;

	private IdentityServiceImpl newService(OpaEvalGrpcClient opaEvalClient) {
		keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		delegates.add(Kernel.Delegate.newBuilder().setName(DELEGATE_NAME).build());
		grants.add(Kernel.Grant.newBuilder()
				.setId(GRANT_ID)
				.setDelegateName(DELEGATE_NAME)
				.setSubject(GRANT_SUBJECT)
				.setClaims(Struct.newBuilder()
						.putFields("sub", Value.newBuilder().setStringValue(GRANT_SUBJECT).build())
						.build())
				.setCreatedAtMs(Instant.now().toEpochMilli())
				.build());
		return new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
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
				opaEvalClient,
				null,            // proxyPolicyOpaClient
				null,            // configMap
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty (fail closed)
	}

	/** The delegate's own S2S token, which is what authenticates a MintDelegatedToken call. */
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

	private Tokenrequest.MintDelegatedTokenResponse mintDelegated(IdentityServiceImpl svc) throws Exception {
		io.grpc.Context ctx = io.grpc.Context.current()
				.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, delegateToken());
		io.grpc.Context previous = ctx.attach();
		try {
			return svc.mintDelegatedToken(CALLER,
					Tokenrequest.MintDelegatedTokenRequest.newBuilder().setGrantId(GRANT_ID).build());
		} finally {
			ctx.detach(previous);
		}
	}

	@Test
	void policyThatNamesNoTenantRefusesTheMint() {
		IdentityServiceImpl svc = newService(new FakeOpaEvalGrpcClient(""));

		ProtoException ex = assertThrows(ProtoException.class, () -> mintDelegated(svc));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("no namespace"),
				"expected the namespace check to be the refuser, got: " + ex.getMessage());
	}

	@Test
	void policyThatNamesATenantMintsThere() throws Exception {
		IdentityServiceImpl svc = newService(new FakeOpaEvalGrpcClient("/tenants/acme"));

		Tokenrequest.MintDelegatedTokenResponse resp = mintDelegated(svc);

		assertNotNull(resp.getToken());
		assertEquals("/tenants/acme",
				TokenWrapper.parse(resp.getToken().getBase64()).getNamespace());
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
