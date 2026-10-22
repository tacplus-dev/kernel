// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.MintGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.OpaEvalGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.WorkloadMap;
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
 * F8 — {@code RevokeWorkload} records the revocation and the mint/refresh path
 * enforces it.
 *
 * <p>Drives real gRPC calls against the real generated {@link Mint} wrapper over
 * {@link IdentityServiceImpl}, behind the same {@link Authorizer#headerCaptureInterceptor()} +
 * raw-Bearer-forwarding interceptor pair {@code ClusterServer} installs in
 * production, and asserts both directions: the revoked workload's refresh is
 * rejected, an unrevoked sibling's refresh still succeeds.
 */
class WorkloadRevocationTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String PARENT_SERVICE = "sentinel";
	private static final String ISSUER = "https://kernel.test/oidc";
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
		// unrevoked path can be observed succeeding end to end, not merely
		// "failing for a different reason".
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
				3600, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				List::of,        // delegates
				List::of,        // grants
				null,            // grantsWriter (no grant revocation on these paths)
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
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot (no disk snapshot in-test)
				null,            // kubernetesTokenVerifier
				null,            // kubernetesTokenAudience
				null);           // webauthnRelyingParty (fail closed)

		authorizer = new Authorizer(new LocalJwkSource(() -> verifyingKeys));
		Mint.registerMethodAuth(authorizer);

		// A real listening gRPC server carrying the production interceptor pair:
		// Authorizer.headerCaptureInterceptor() populates AUTH_HEADER_CTX_KEY for the generated
		// wrapper's checkAuth, and rawAuthInterceptor() forwards the raw Bearer the
		// way ClusterServer's rpcInterceptor does so MintWorkload/RevokeWorkload can
		// validate the caller themselves.
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
		t.setNamespace(Spiffe.namespaceFromSpiffe(parentSpiffe));
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

	/** Exchanges a refresh token for a fresh access token — the F8 refresh path. */
	private Tokenrequest.TokenMintResponse refresh(Tokenrequest.TokenMintResponse pair) {
		return stub().mintToken(Tokenrequest.TokenMintRequest.newBuilder()
				.setInputToken(TokenWrapper.from(pair.getRefreshToken()).getBase64())
				.build());
	}

	private String workloadSpiffe(String name) {
		return Spiffe.workloadSpiffeId(parentSpiffe, name);
	}

	private void revoke(String spiffeId) {
		parentStub().revokeWorkload(
				Kernel.WorkloadRevokeRequest.newBuilder().setSpiffeId(spiffeId).build());
	}

	// ---- Tests -------------------------------------------------------------

	@Test
	void revocationIsRecordedAndBlocksTheRevokedWorkloadsRefresh() {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		Tokenrequest.TokenMintResponse sibling = bringUpWorkload("sibling");

		// Both refresh fine before the revocation.
		assertNotNull(refresh(child).getAccessToken());
		assertNotNull(refresh(sibling).getAccessToken());

		revoke(workloadSpiffe("child"));

		// The revocation landed in WorkloadState.revocations, attributed to the caller.
		Kernel.WorkloadRevocation recorded = workloadMap.getRevocations(workloadSpiffe("child"));
		assertEquals(workloadSpiffe("child"), recorded.getSpiffeId());
		assertEquals(parentSpiffe, recorded.getRevokedBy());
		assertTrue(recorded.getRevokedAtMs() > 0);

		// Direction 1: the SAME workload's next refresh is rejected on the wire.
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class, () -> refresh(child));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains(workloadSpiffe("child")),
				"description should name the revoked identity, got: " + e.getStatus().getDescription());

		// Direction 2: the unrevoked sibling is untouched.
		assertNotNull(refresh(sibling).getAccessToken());
		assertFalse(refresh(sibling).getAccessToken().getBase64().isEmpty());
	}

	@Test
	void revokedIdentityCannotBeReMinted() {
		bringUpWorkload("child");
		revoke(workloadSpiffe("child"));

		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> parentStub().mintWorkload(
						Tokenrequest.WorkloadMintRequest.newBuilder().setWorkloadName("child").build()));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());

		// A different name under the same parent still mints.
		assertNotNull(parentStub().mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder().setWorkloadName("other").build())
				.getBootstrapToken());
	}

	@Test
	void revokingAnAncestorRevokesItsDescendants() throws Exception {
		Tokenrequest.TokenMintResponse child = bringUpWorkload("child");
		assertNotNull(refresh(child).getAccessToken());

		// RevokeWorkload only accepts strict descendants of the caller, so a
		// revocation ON the parent identity is recorded directly — the proto
		// contract says a descendant's refresh must then be denied too.
		workloadMap.putRevocations(parentSpiffe, Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(parentSpiffe)
				.setRevokedBy(parentSpiffe)
				.setRevokedAtMs(Instant.now().toEpochMilli())
				.build());

		StatusRuntimeException e = assertThrows(StatusRuntimeException.class, () -> refresh(child));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains(parentSpiffe),
				"description should name the ancestor carrying the revocation, got: "
						+ e.getStatus().getDescription());
	}

}
