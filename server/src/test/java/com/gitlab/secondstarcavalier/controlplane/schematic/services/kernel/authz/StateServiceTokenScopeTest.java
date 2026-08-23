// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.KeyRotator;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.IdentityStateServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.IdentityStateServiceServer;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F2 — the kernel state plane checked neither the token's audience nor its class.
 *
 * <p>Same harness as {@link StateServiceAuthorizationTest}: real gRPC calls against
 * the real generated {@link IdentityStateServiceServer} behind the real
 * {@link SecurityAuthenticator#callerInterceptor()}. Every token here is signed by
 * kernel's own rotator and names {@code kernel} as its subject, so nothing but the
 * {@code aud} claim and the {@code token_use} class separates accept from reject.
 */
class StateServiceTokenScopeTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final Metadata.Key<String> AUTHORIZATION =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	private IdentityStateServiceServer stateServer;
	private Server server;
	private ManagedChannel channel;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		SecurityAuthenticator authenticator = new SecurityAuthenticator();
		authenticator.setKeyProvider(() -> JwkOuterClass.Jwks.newBuilder().addAllKeys(verifyingKeys).build());

		stateServer = new IdentityStateServiceServer(new InMemoryManager(), authenticator);

		server = ServerBuilder.forPort(0)
				.addService(ServerInterceptors.interceptForward(
						stateServer.bindService(), authenticator.callerInterceptor()))
				.build()
				.start();
		channel = ManagedChannelBuilder.forAddress("localhost", server.getPort())
				.usePlaintext()
				.build();
	}

	@AfterEach
	void tearDown() throws Exception {
		channel.shutdownNow();
		server.shutdownNow();
		server.awaitTermination(5, TimeUnit.SECONDS);
		stateServer.close();
		keyRotator.stop();
	}

	/**
	 * Mints a valid, kernel-signed token for the kernel service itself — the caller
	 * that holds rw on kernel.Identity — with the given audience and token_use.
	 */
	private String kernelToken(String audience, String tokenUse) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", "kernel"))
				.setAudience(audience)
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setServiceName("kernel");
		if (tokenUse != null) {
			t.setTokenUse(tokenUse);
		}
		t.sign(signingKey);
		return t.getBase64();
	}

	private IdentityStateServiceGrpc.IdentityStateServiceBlockingStub stubWith(String token) {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + token);
		return IdentityStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));
	}

	private int sizeVerifyingKeys(String token) {
		return stubWith(token).sizeVerifyingKeys(
				Kernel.VerifyingKeysSizeRequest.newBuilder().build()).getSize();
	}

	private StatusRuntimeException rejected(String token) {
		return assertThrows(StatusRuntimeException.class, () -> sizeVerifyingKeys(token));
	}

	@Test
	void tokenMintedForAnotherServiceIsRejected() {
		// The F2 attack: echo mints a token for its own audience and presents it to
		// kernel's state plane. Signature, subject and class are all valid.
		StatusRuntimeException e = rejected(kernelToken("echo", "service"));

		assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains("audience \"echo\""),
				"description should name the rejected audience, got: " + e.getStatus().getDescription());
	}

	@Test
	void tokenMintedForKernelIsAccepted() {
		assertEquals(0, sizeVerifyingKeys(kernelToken("kernel", "service")));
	}

	@Test
	void bootstrapLocalityAndExternalTokensAreRejected() {
		for (String tokenUse : List.of("bootstrap", "locality", "external", "refresh")) {
			StatusRuntimeException e = rejected(kernelToken("kernel", tokenUse));
			assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode(), tokenUse);
			assertTrue(e.getStatus().getDescription().contains(tokenUse + " tokens cannot be used"),
					"description should name the rejected class, got: " + e.getStatus().getDescription());
		}
	}

	@Test
	void accessAndServiceClassTokensAreAccepted() {
		for (String tokenUse : List.of("access", "service")) {
			assertEquals(0, sizeVerifyingKeys(kernelToken("kernel", tokenUse)), tokenUse);
		}
	}
}
