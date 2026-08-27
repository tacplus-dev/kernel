// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.MintGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.OpaEvalGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F17 — a child workload's refresh is checked against the locality its parent
 * registered in {@code WorkloadState.localities}.
 *
 * <p>Same harness as {@link WorkloadRevocationTest}: real gRPC calls against the real
 * generated {@link Mint} wrapper over {@link IdentityServiceImpl}, behind the same
 * {@link Authorizer#headerCaptureInterceptor()} + raw-Bearer-forwarding interceptor pair
 * {@code ClusterServer} installs in production. Nothing on the path under test is
 * mocked — the tokens are really signed by a real {@link KeyRotator} key and really
 * verified.
 *
 * <p>Asserts both directions: a child presenting the registered locality token
 * refreshes, and a child presenting a missing or wrong one is rejected on the wire.
 * The last test pins the deliberate limit of this fix — see F17's report.
 */
class WorkloadLocalityTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String PARENT_SERVICE = "sentinel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String LOCALITY = "locality-token-abc123";
	private static final Metadata.Key<String> AUTHORIZATION =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	private WorkloadMap workloadMap;
	private Authorizer authorizer;
	private Server server;
	private ManagedChannel channel;
	private Server opaServer;
	private ManagedChannel opaChannel;
	private String parentSpiffe;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		workloadMap = new WorkloadMap(new InMemoryManager());
		parentSpiffe = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", PARENT_SERVICE);

		// refresh -> access resolves entitlements through uncleopa. Stand up a real
		// permissive EvalEntitlement server behind a real generated client so the
		// accepted path is observed succeeding end to end, not merely "failing for a
		// different reason".
		opaServer = ServerBuilder.forPort(0).addService(new OpaEvalGrpc.OpaEvalImplBase() {
			@Override
			public void evalEntitlement(Userentitlements.EntitlementEvalInput request,
					io.grpc.stub.StreamObserver<Userentitlements.EntitlementEvalResult> obs) {
				obs.onNext(Userentitlements.EntitlementEvalResult.getDefaultInstance());
				obs.onCompleted();
			}
		}).build().start();
		opaChannel = ManagedChannelBuilder.forAddress("localhost", opaServer.getPort())
				.usePlaintext()
				.build();
		OpaEvalGrpcClient opaClient = new OpaEvalGrpcClient(opaChannel, () -> "test-token");

		IdentityServiceImpl identityService = new IdentityServiceImpl(
				3600, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				List::of,        // delegates
				List::of,        // grants
				null,            // serviceEntitlements
				null,            // signingCa (no cert minting on these paths)
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				opaClient,
				null,            // proxyPolicyOpaClient
				null,            // configMap
				workloadMap,
				null,            // persistState (no disk snapshot in-test)
				null,            // kubernetesTokenVerifier
				null);           // kubernetesTokenAudience

		authorizer = new Authorizer(new LocalJwkSource(() -> verifyingKeys));
		Mint.registerMethodAuth(authorizer);

		server = ServerBuilder.forPort(0)
				.addService(ServerInterceptors.interceptForward(
						new Mint(identityService, authorizer),
						Authorizer.headerCaptureInterceptor(),
						rawAuthInterceptor()))
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
		opaChannel.shutdownNow();
		opaServer.shutdownNow();
		opaServer.awaitTermination(5, TimeUnit.SECONDS);
		authorizer.close();
		keyRotator.stop();
	}

	/** Mirrors ClusterServer's rpcInterceptor: forwards the raw Bearer token. */
	private static ServerInterceptor rawAuthInterceptor() {
		return new ServerInterceptor() {
			@Override
			public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
					ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
				Context ctx = Context.current();
				String authHeader = headers.get(AUTHORIZATION);
				if (authHeader != null && authHeader.startsWith("Bearer ")) {
					ctx = ctx.withValue(ClusterServer.RAW_AUTH_TOKEN_KEY, authHeader.substring(7));
				}
				return Contexts.interceptCall(ctx, call, headers, next);
			}
		};
	}

	// ---- Wire helpers ------------------------------------------------------

	/** Anonymous stub — MintToken self-authenticates via the request body. */
	private MintGrpc.MintBlockingStub stub() {
		return MintGrpc.newBlockingStub(channel);
	}

	/** Stub presenting the parent service's kernel-signed S2S token. */
	private MintGrpc.MintBlockingStub parentStub() {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + parentServiceToken());
		return MintGrpc.newBlockingStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));
	}

	private String parentServiceToken() {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(parentSpiffe)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setTokenUse("service");
		t.setServiceName(PARENT_SERVICE);
		t.sign(signingKey);
		return t.getBase64();
	}

	/** MintWorkload → MintToken(bootstrap): a live child workload with a refresh token. */
	private Tokenrequest.TokenMintResponse bringUpWorkload(String name) {
		Tokenrequest.WorkloadMintResponse minted = parentStub().mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder().setWorkloadName(name).build());
		String bootstrap = TokenWrapper.from(minted.getBootstrapToken()).getBase64();
		return stub().mintToken(
				Tokenrequest.TokenMintRequest.newBuilder().setInputToken(bootstrap).build());
	}

	/** Exchanges a refresh token for a fresh access token, presenting {@code locality}. */
	private Tokenrequest.TokenMintResponse refresh(Tokenrequest.TokenMintResponse pair, String locality) {
		return stub().mintToken(Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(TokenWrapper.from(pair.getRefreshToken()).getBase64())
				.setLocalityToken(locality)
				.build());
	}

	/** What a parent does today only in this test: registers its current locality token. */
	private void registerParentLocality(String localityToken) throws Exception {
		workloadMap.putLocalities(parentSpiffe, Kernel.WorkloadLocality.newBuilder()
				.setSpiffeId(parentSpiffe)
				.setLocalityToken(localityToken)
				.setUpdatedAtMs(Instant.now().toEpochMilli())
				.build());
	}

	// ---- Tests -------------------------------------------------------------

	@Test
	void childPresentingTheRegisteredLocalityTokenRefreshes() throws Exception {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		registerParentLocality(LOCALITY);

		Tokenrequest.TokenMintResponse refreshed = refresh(child, LOCALITY);
		assertNotNull(refreshed.getAccessToken());
		assertFalse(refreshed.getAccessToken().getBase64().isEmpty());
	}

	@Test
	void childOmittingTheLocalityTokenIsRejected() throws Exception {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		registerParentLocality(LOCALITY);

		StatusRuntimeException e =
				assertThrows(StatusRuntimeException.class, () -> refresh(child, ""));
		assertEquals(Status.Code.INVALID_ARGUMENT, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains("locality_token"),
				"description should name the missing proof, got: " + e.getStatus().getDescription());
	}

	@Test
	void childPresentingAForeignLocalityTokenIsRejected() throws Exception {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		registerParentLocality(LOCALITY);

		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> refresh(child, "locality-token-from-somewhere-else"));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains(parentSpiffe),
				"description should name the parent whose locality was expected, got: "
						+ e.getStatus().getDescription());
	}

	@Test
	void rotatingTheParentsLocalityInvalidatesTheOldToken() throws Exception {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		registerParentLocality(LOCALITY);
		assertNotNull(refresh(child, LOCALITY).getAccessToken());

		// The parent rotates its locality token; the child has not picked up the new
		// one, so it can no longer prove reachability.
		registerParentLocality("locality-token-rotated");

		StatusRuntimeException e =
				assertThrows(StatusRuntimeException.class, () -> refresh(child, LOCALITY));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());

		// ... and the rotated value is accepted.
		assertNotNull(refresh(child, "locality-token-rotated").getAccessToken());
	}

	/**
	 * Pins the deliberate limit of the F17 fix: nothing in the fleet registers a
	 * locality yet, and until something does, a child refresh with no locality token
	 * is still accepted. Demanding one unconditionally would reject every workload
	 * refresh that exists rather than tighten anything — see the F17 report.
	 */
	@Test
	void withNoRegisteredParentLocalityRefreshStillSucceeds() {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		assertNotNull(refresh(child, "").getAccessToken());
	}
}
