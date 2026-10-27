// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.authz;

import com.github.tacplusdev.kernel.cluster.KeyRotator;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.services.kernel.IdentityStateServiceGrpc;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.tacplusbackend.SecurityAuthenticator;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.IdentityStateServiceServer;
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
 * F1 — run-time authorization on the kernel state RPC plane.
 *
 * <p>Drives real gRPC calls against the real generated {@link IdentityStateServiceServer}
 * behind the real {@link SecurityAuthenticator#callerInterceptor()}, exactly as
 * {@code BackendServers.getGrpcServices()} wires it in production, and asserts the
 * generated policy for {@code kernel.Identity} (rw: kernel; ro: kernel, letsencrypt,
 * oauth) is enforced in both directions.
 *
 * <p>{@code PutVerifyingKeys} is the RPC F1 names: it injects a JWK into the cluster's
 * verifying-key set, so an unauthorized caller reaching it can forge tokens for any
 * principal.
 */
class StateServiceAuthorizationTest {

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

		// A real listening gRPC server on an ephemeral port, with the same
		// interceptForward(bindService(), callerInterceptor()) wiring
		// BackendServers.getGrpcServices() uses in production.
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

	/** A blocking stub that presents a kernel-signed service token for {@code service}. */
	private IdentityStateServiceGrpc.IdentityStateServiceBlockingStub stubFor(String service) {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + serviceToken(service));
		return IdentityStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));
	}

	/** Mints a valid, kernel-signed S2S token for {@code service}. */
	private String serviceToken(String service) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", service);
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setServiceName(service);
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		return t.getBase64();
	}

	private int verifyingKeysSizeAsKernel() {
		return stubFor("kernel").sizeVerifyingKeys(
				Kernel.VerifyingKeysSizeRequest.newBuilder().build()).getSize();
	}

	private Kernel.VerifyingKeysPutRequest putRequest(String kid) {
		return Kernel.VerifyingKeysPutRequest.newBuilder()
				.setKey(kid)
				// A real, ingress-valid JWK: the rotator's own published verifying key
				// under a different kid — exactly the shape F1's forged injection takes.
				.setValue(verifyingKeys.get(0).toBuilder().setKid(kid).build())
				.build();
	}

	@Test
	void serviceOutsidePolicyIsDeniedWriteOnTheTrustRoot() {
		// sentinel holds a valid kernel-signed token and declares no state_import of
		// kernel.Identity, so it is in neither the rw nor the ro set.
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> stubFor("sentinel").putVerifyingKeys(putRequest("forged-kid")));

		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains("kernel.Identity.verifying_keys"),
				"description should name the graph and boundary, got: " + e.getStatus().getDescription());
		// And the write did not land — read the size back as kernel, which may.
		assertEquals(0, verifyingKeysSizeAsKernel());
	}

	@Test
	void serviceInPolicyIsAllowedWriteOnTheTrustRoot() {
		// kernel holds rw on kernel.Identity.
		stubFor("kernel").putVerifyingKeys(putRequest("kernel-kid"));

		assertEquals(1, verifyingKeysSizeAsKernel());
	}

	@Test
	void readOnlyImporterMayReadButNotWrite() {
		// oauth declares (spec.state_imports) of kernel.Identity → ro, not rw.
		Kernel.VerifyingKeysValueResponse resp = stubFor("oauth").getVerifyingKeys(
				Kernel.VerifyingKeysGetRequest.newBuilder().setKey("absent").build());
		assertEquals(false, resp.getFound());

		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> stubFor("oauth").putVerifyingKeys(putRequest("oauth-kid")));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
	}
}
