// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.grpcserver.Authorizer;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.servers.services.kernel.Mint;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.servers.sys.minter.Minter;
import com.github.tacplusdev.kernel.model.types.sys.minter.MinterGrpc;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.services.kernel.MintGrpc;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.OpaEvalGrpc;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
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
 * A workload broker (the coop) mints pigeons rooted under the dog that asked
 * for them — WorkloadMintRequest.parent_spiffe_id — so a pigeon is its dog's
 * tenant's by construction; and it may revoke them, though they are not its
 * descendants. A service that is not a broker can do neither.
 */
class WorkloadBrokerTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String PARENT_SERVICE = "coop";
	/** The dog a pigeon is minted for: another service, in a tenant. */
	private static final String DOG_SPIFFE = "spiffe://" + TRUST_DOMAIN + "/tenants/acme/services/tenantecho";
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
				3600, 900, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> List.of(
						Kernel.Delegate.newBuilder().setName("coop").setWorkloadBroker(true).build(),
						Kernel.Delegate.newBuilder().setName("plain").build()),
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
				.addService(ServerInterceptors.interceptForward(
						new Minter(identityService, authorizer),
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

	/** The sys minting contract (MintToken, MintX509Cert, ...), hosted by kernel. */
	private MinterGrpc.MinterBlockingStub minterStub() {
		return MinterGrpc.newBlockingStub(channel);
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
		return minterStub().mintToken(
				Tokenrequest.TokenMintRequest.newBuilder().setInputToken(bootstrap).build());
	}

	/** Exchanges a refresh token for a fresh access token — the F8 refresh path. */
	private Tokenrequest.TokenMintResponse refresh(Tokenrequest.TokenMintResponse pair) {
		return minterStub().mintToken(Tokenrequest.TokenMintRequest.newBuilder()
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

	private MintGrpc.MintBlockingStub stubAs(String spiffe, String serviceName) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(spiffe)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setTokenUse("service");
		t.setServiceName(serviceName);
		t.setNamespace(Spiffe.namespaceFromSpiffe(spiffe));
		t.sign(signingKey);
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + t.getBase64());
		return MintGrpc.newBlockingStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));
	}

	@Test
	void aBrokerMintsUnderTheServiceItNames() {
		Tokenrequest.WorkloadMintResponse minted = parentStub().mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder()
						.setWorkloadName("pigeon-01run").setTerminal(true).setParentSpiffeId(DOG_SPIFFE).build());
		TokenWrapper bootstrap = TokenWrapper.from(minted.getBootstrapToken());
		assertEquals(DOG_SPIFFE + "/workloads/pigeon-01run", bootstrap.getSubject());
		assertEquals(DOG_SPIFFE, bootstrap.getCustomField("parent_sub"));
		assertEquals("/tenants/acme", bootstrap.getNamespace());

		// The bootstrap token is live: it exchanges for the pigeon's refresh + access pair.
		Tokenrequest.TokenMintResponse pair = minterStub().mintToken(
				Tokenrequest.TokenMintRequest.newBuilder().setInputToken(bootstrap.getBase64()).build());
		assertEquals(DOG_SPIFFE + "/workloads/pigeon-01run", TokenWrapper.from(pair.getAccessToken()).getSubject());
	}

	@Test
	void aBrokerRevokesWhatItMintedUnderAnother() {
		parentStub().mintWorkload(Tokenrequest.WorkloadMintRequest.newBuilder()
				.setWorkloadName("pigeon-02run").setTerminal(true).setParentSpiffeId(DOG_SPIFFE).build());
		parentStub().revokeWorkload(Kernel.WorkloadRevokeRequest.newBuilder()
				.setSpiffeId(DOG_SPIFFE + "/workloads/pigeon-02run").build());
		StatusRuntimeException denied = assertThrows(StatusRuntimeException.class, () -> parentStub().mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder()
						.setWorkloadName("pigeon-02run").setTerminal(true).setParentSpiffeId(DOG_SPIFFE).build()));
		assertEquals(Status.Code.PERMISSION_DENIED, denied.getStatus().getCode());
		// Even a broker revokes only workloads, never a service itself.
		StatusRuntimeException notAWorkload = assertThrows(StatusRuntimeException.class, () -> parentStub().revokeWorkload(
				Kernel.WorkloadRevokeRequest.newBuilder().setSpiffeId(DOG_SPIFFE).build()));
		assertEquals(Status.Code.PERMISSION_DENIED, notAWorkload.getStatus().getCode());
	}

	@Test
	void aServiceThatIsNoBrokerMintsOnlyUnderItself() {
		String plain = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", "plain");
		StatusRuntimeException denied = assertThrows(StatusRuntimeException.class, () -> stubAs(plain, "plain").mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder()
						.setWorkloadName("pigeon-03run").setParentSpiffeId(DOG_SPIFFE).build()));
		assertEquals(Status.Code.PERMISSION_DENIED, denied.getStatus().getCode());
		assertTrue(denied.getStatus().getDescription().contains("not a workload broker"), denied.getStatus().getDescription());

		// Without naming a parent it still mints under itself, as before.
		Tokenrequest.WorkloadMintResponse own = stubAs(plain, "plain").mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder().setWorkloadName("child").build());
		assertEquals(plain + "/workloads/child", TokenWrapper.from(own.getBootstrapToken()).getSubject());

		// And a broker may not name a workload as the parent, only a service.
		StatusRuntimeException bad = assertThrows(StatusRuntimeException.class, () -> parentStub().mintWorkload(
				Tokenrequest.WorkloadMintRequest.newBuilder()
						.setWorkloadName("x").setParentSpiffeId(DOG_SPIFFE + "/workloads/pigeon-01run").build()));
		assertEquals(Status.Code.INVALID_ARGUMENT, bad.getStatus().getCode());
	}
}
