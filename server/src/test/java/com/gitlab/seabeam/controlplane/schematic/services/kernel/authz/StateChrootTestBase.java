// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.authz;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster.KeyRotator;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.opa.OpaStateServiceServer;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.stub.MetadataUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

/**
 * Shared harness for the namespace-chroot tests: a real listening gRPC server
 * running the real generated {@link OpaStateServiceServer} behind the real
 * {@link SecurityAuthenticator#callerInterceptor()}, exactly as
 * {@code BackendServers.getGrpcServices()} wires it in production.
 *
 * <p>{@code opa.OpaState} is the fixture because it is the one state root that
 * carries both shapes the chroot has to handle under a single policy
 * ({@code rw: opa}): a collection ({@code tenant_entitlements_policies}, all
 * eleven key RPCs plus Watch) and singletons ({@code entitlements_policy},
 * {@code proxy_policy}).
 */
abstract class StateChrootTestBase {

	static final String TRUST_DOMAIN = "test.schematic.io";
	private static final Metadata.Key<String> AUTHORIZATION =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	SecurityAuthenticator authenticator;
	OpaStateServiceServer stateServer;
	private Server server;
	ManagedChannel channel;

	@BeforeEach
	void setUpHarness() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		authenticator = new SecurityAuthenticator();
		authenticator.setKeyProvider(() -> JwkOuterClass.Jwks.newBuilder().addAllKeys(verifyingKeys).build());
		stateServer = new OpaStateServiceServer(new InMemoryManager(), authenticator);
	}

	/**
	 * Starts the gRPC server. Subclasses call this once per test so a test can
	 * choose its own interceptor stack; the default stack is
	 * {@link #startServer()}.
	 */
	void startServer(ServerServiceDefinition definition) throws Exception {
		server = ServerBuilder.forPort(0).addService(definition).build().start();
		channel = ManagedChannelBuilder.forAddress("localhost", server.getPort()).usePlaintext().build();
	}

	/** The production wiring: the state server behind the caller interceptor. */
	void startServer() throws Exception {
		startServer(ServerInterceptors.interceptForward(
				stateServer.bindService(), authenticator.callerInterceptor()));
	}

	@AfterEach
	void tearDownHarness() throws Exception {
		if (channel != null) {
			channel.shutdownNow();
		}
		if (server != null) {
			server.shutdownNow();
			server.awaitTermination(5, TimeUnit.SECONDS);
		}
		stateServer.close();
		keyRotator.stop();
	}

	/** Attaches {@code token} as the bearer credential of a stub. */
	static ClientInterceptor bearer(String token) {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + token);
		return MetadataUtils.newAttachHeadersInterceptor(headers);
	}

	/**
	 * Mints a valid, kernel-signed S2S token whose subject is {@code subject}.
	 * The namespace claim is derived from the subject exactly as
	 * {@code IdentityServiceImpl.mintRefreshToken} derives it for a real mint,
	 * so the fixture cannot be more permissive than a real token.
	 */
	String tokenFor(String subject, String serviceName) {
		return tokenFor(subject, serviceName, null);
	}

	/**
	 * {@link #tokenFor(String, String)} plus the {@code instance_id} claim a real
	 * service token carries, which instance-keyed writes (ServiceHealth) require.
	 * A null {@code instanceId} leaves the claim out.
	 */
	String tokenFor(String subject, String serviceName, String instanceId) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setServiceName(serviceName);
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		if (instanceId != null) {
			t.setInstanceId(instanceId);
		}
		t.sign(signingKey);
		return t.getBase64();
	}

	/**
	 * Mints a valid, kernel-signed non-service token: a {@code user} token as
	 * {@code IdentityServiceImpl.doMintUserToken} mints one, or any other
	 * {@code sub_type} the enum carries ({@code pipeline}). {@code namespace} is
	 * the claim {@code requireNamespaceFromOpa} stamps — the tenant OPA mapped the
	 * caller's IdP to. None of these tokens carries a service path, by
	 * construction.
	 *
	 * <p>There is deliberately no way to mint one with NO namespace claim:
	 * {@code TokenWrapper.sign} refuses to sign a token without one.
	 */
	String principalTokenFor(String subType, String subject, String namespace) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType(subType);
		// principal and token_use as IdentityServiceImpl's refresh->access exchange
		// stamps them: that access token is the one that actually calls kernel APIs.
		t.setPrincipal(subject);
		t.setTokenUse("access");
		t.setNamespace(namespace);
		t.sign(signingKey);
		return t.getBase64();
	}
}
