// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.chassis.x509.ImmutableCertChain;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tlscert.Tlscert;
import com.github.tacplusdev.kernel.model.types.sys.tlscert.TlsCertServiceGrpc;
import com.github.tacplusdev.kernel.model.types.sys.x509.X509;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
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
import io.grpc.stub.StreamObserver;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ManageCert enforces workload revocation on every cert issuance, not just on
 * the first one.
 *
 * <p>The stream is long-lived and renews at half-life, so a workload revoked
 * after its stream is up used to keep renewing its mTLS cert indefinitely and
 * stay a trusted mesh peer — while every kernel-signed token exchange had
 * already stopped serving it ({@link WorkloadRevocationTest}). Drives the real
 * bidi RPC against the real {@link TlsCertServiceImpl} behind the same raw-Bearer
 * forwarding interceptor {@code ClusterServer} installs.
 */
class TlsCertRevocationTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String PARENT_SERVICE = "sentinel";
	private static final String WORKLOAD_NAME = "worker";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final Metadata.Key<String> AUTHORIZATION =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final Map<String, X509.X509CertChain> serviceCas = new ConcurrentHashMap<>();

	private KeyRotator keyRotator;
	private WorkloadMap workloadMap;
	private ConfigMap configMap;
	private TlsCertServiceImpl tlsCertService;
	private Server server;
	private ManagedChannel channel;
	private String workloadSpiffe;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		workloadMap = new WorkloadMap(new InMemoryManager());
		configMap = new ConfigMap(new InMemoryManager());
		workloadSpiffe = Spiffe.workloadSpiffeId(
				Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", PARENT_SERVICE), WORKLOAD_NAME);

		tlsCertService = new TlsCertServiceImpl(
				86_400,
				signingCa("signing-ca"),
				serviceCas::get,
				serviceCas::put,
				() -> TRUST_DOMAIN,
				() -> verifyingKeys,
				workloadMap,
				configMap);

		server = ServerBuilder.forPort(0)
				.addService(ServerInterceptors.interceptForward(tlsCertService, rawAuthInterceptor()))
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
		tlsCertService.stop();
		keyRotator.stop();
	}

	/**
	 * The bug: a workload revoked while its ManageCert stream is open renews its
	 * cert as if nothing happened. The renewal CSR must be refused instead.
	 */
	@Test
	void revokedWorkloadCannotRenewItsCert() throws Exception {
		Recorder recorder = new Recorder();
		StreamObserver<Tlscert.TlsCertClientMsg> client = openStream(recorder);

		client.onNext(init());
		client.onNext(csr());
		assertNotNull(recorder.awaitCert(), "first issuance should succeed for a live workload");

		// The workload is revoked mid-stream, the way RevokeWorkload records it.
		workloadMap.putRevocations(workloadSpiffe, Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(workloadSpiffe)
				.setRevokedBy(Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", PARENT_SERVICE))
				.setRevokedAtMs(Instant.now().toEpochMilli())
				.build());

		// Renewal: the service generates a new keypair and sends another CSR.
		recorder.reset();
		client.onNext(csr());

		StatusRuntimeException e = recorder.awaitError();
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains(workloadSpiffe),
				"description should name the revoked identity, got: " + e.getStatus().getDescription());
		assertEquals(0, recorder.certCount(),
				"a revoked workload must not be handed a renewed cert");
	}

	/** Revoking an ancestor stops its descendants' renewals too, per the proto contract. */
	@Test
	void revokedAncestorBlocksDescendantCertRenewal() throws Exception {
		Recorder recorder = new Recorder();
		StreamObserver<Tlscert.TlsCertClientMsg> client = openStream(recorder);

		client.onNext(init());
		client.onNext(csr());
		assertNotNull(recorder.awaitCert());

		String parentSpiffe = Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", PARENT_SERVICE);
		workloadMap.putRevocations(parentSpiffe, Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(parentSpiffe)
				.setRevokedBy(parentSpiffe)
				.setRevokedAtMs(Instant.now().toEpochMilli())
				.build());

		recorder.reset();
		client.onNext(csr());

		StatusRuntimeException e = recorder.awaitError();
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains(parentSpiffe),
				"description should name the ancestor carrying the revocation, got: "
						+ e.getStatus().getDescription());
	}

	/** The other direction: an unrevoked workload keeps renewing. */
	@Test
	void unrevokedWorkloadStillRenews() throws Exception {
		Recorder recorder = new Recorder();
		StreamObserver<Tlscert.TlsCertClientMsg> client = openStream(recorder);

		client.onNext(init());
		client.onNext(csr());
		assertNotNull(recorder.awaitCert());

		// An unrelated workload's revocation must not touch this one.
		String other = Spiffe.workloadSpiffeId(
				Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", PARENT_SERVICE), "other");
		workloadMap.putRevocations(other, Kernel.WorkloadRevocation.newBuilder()
				.setSpiffeId(other)
				.setRevokedBy(other)
				.setRevokedAtMs(Instant.now().toEpochMilli())
				.build());

		recorder.reset();
		client.onNext(csr());
		assertNotNull(recorder.awaitCert(), "renewal for a live workload must still be served");
	}

	/**
	 * A tenant deleted while one of its services holds the stream stops that
	 * service's renewals too (kernel#19): a deleted tenant mints nothing.
	 */
	@Test
	void aDeletedTenantsServiceCannotRenewItsCert() throws Exception {
		String acme = "/tenants/acme";
		TenantAdminServiceImpl admin = new TenantAdminServiceImpl(configMap, () -> TRUST_DOMAIN, () -> { });
		admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(acme).build());
		workloadSpiffe = Spiffe.namespaceSpiffeId(TRUST_DOMAIN, acme) + "/" + Spiffe.SERVICES_SEGMENT + "/docmanager";
		Recorder recorder = new Recorder();
		StreamObserver<Tlscert.TlsCertClientMsg> client = openStream(recorder);

		client.onNext(init());
		client.onNext(csr());
		assertNotNull(recorder.awaitCert(), "a live tenant's service is issued its cert");

		admin.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder().setTenantNamespace(acme).build());
		recorder.reset();
		client.onNext(csr());

		StatusRuntimeException e = recorder.awaitError();
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains("tenant " + acme + " was deleted"),
				"description should name the deleted tenant, got: " + e.getStatus().getDescription());
		assertEquals(0, recorder.certCount());
	}

	// ---- Wire helpers ------------------------------------------------------

	private StreamObserver<Tlscert.TlsCertClientMsg> openStream(Recorder recorder) {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + workloadToken());
		return TlsCertServiceGrpc.newStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
				.manageCert(recorder);
	}

	/** A kernel-signed token for the workload, the credential ManageCert accepts. */
	private String workloadToken() {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(workloadSpiffe)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setTokenUse("service");
		t.setServiceName(WORKLOAD_NAME);
		t.setNamespace(Spiffe.namespaceFromSpiffe(workloadSpiffe));
		t.sign(signingKey);
		return t.getBase64();
	}

	private Tlscert.TlsCertClientMsg init() {
		return Tlscert.TlsCertClientMsg.newBuilder()
				.setInit(Tlscert.TlsCertInit.newBuilder()
						.setServiceName(SpiffeIds.serviceName(workloadSpiffe))
						.setInstanceId(WORKLOAD_NAME + "-0")
						.build())
				.build();
	}

	private Tlscert.TlsCertClientMsg csr() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair keyPair = generator.generateKeyPair();
		return Tlscert.TlsCertClientMsg.newBuilder()
				.setCsr(Tlscert.TlsCertCsr.newBuilder()
						.setPublicKey(KeyOuterClass.PublicKey.newBuilder()
								.setId(WORKLOAD_NAME + "-tls")
								.setBase64(Base64.getUrlEncoder().withoutPadding()
										.encodeToString(keyPair.getPublic().getEncoded()))
								.build())
						.build())
				.build();
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

	/** Collects what the server sends back on the stream. */
	private static final class Recorder implements StreamObserver<Tlscert.TlsCertServerMsg> {
		private final AtomicReference<CountDownLatch> settled = new AtomicReference<>(new CountDownLatch(1));
		private final AtomicReference<Tlscert.TlsCertDelivery> cert = new AtomicReference<>();
		private final AtomicReference<StatusRuntimeException> error = new AtomicReference<>();
		private final java.util.concurrent.atomic.AtomicInteger certs =
				new java.util.concurrent.atomic.AtomicInteger();

		@Override
		public void onNext(Tlscert.TlsCertServerMsg msg) {
			if (msg.getMsgCase() == Tlscert.TlsCertServerMsg.MsgCase.CERT) {
				certs.incrementAndGet();
				cert.set(msg.getCert());
				settled.get().countDown();
			} else if (msg.getMsgCase() == Tlscert.TlsCertServerMsg.MsgCase.ERROR) {
				error.set(new StatusRuntimeException(
						Status.INTERNAL.withDescription(msg.getError())));
				settled.get().countDown();
			}
		}

		@Override
		public void onError(Throwable t) {
			error.set((StatusRuntimeException) t);
			settled.get().countDown();
		}

		@Override
		public void onCompleted() {
			settled.get().countDown();
		}

		void reset() {
			cert.set(null);
			error.set(null);
			certs.set(0);
			settled.set(new CountDownLatch(1));
		}

		int certCount() {
			return certs.get();
		}

		Tlscert.TlsCertDelivery awaitCert() throws Exception {
			await();
			if (error.get() != null) {
				throw new AssertionError("expected a cert, got error: " + error.get().getStatus());
			}
			return cert.get();
		}

		StatusRuntimeException awaitError() throws Exception {
			await();
			StatusRuntimeException e = error.get();
			if (e == null) {
				throw new AssertionError("expected the stream to be refused, but it was not");
			}
			return e;
		}

		private void await() throws Exception {
			assertTrue(settled.get().await(10, TimeUnit.SECONDS), "server never responded");
		}
	}

	// ---- CA fixture --------------------------------------------------------

	private static ImmutableCertChain signingCa(String name) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair keyPair = generator.generateKeyPair();
		String pem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes())
						.encodeToString(keyPair.getPrivate().getEncoded())
				+ "\n-----END PRIVATE KEY-----\n";
		ImmutableKey key = ImmutableKey.from(KeyOuterClass.Key.newBuilder()
				.setId(name)
				.setBase64(Base64.getUrlEncoder().withoutPadding().encodeToString(pem.getBytes()))
				.build());
		X509.X509Cert cert = ImmutableCertChain.forSelfSigning(key).selfSign(
				name,
				Instant.now().plusSeconds(86_400).getEpochSecond(),
				X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN,
				List.of());
		return ImmutableCertChain.from(X509.X509CertChain.newBuilder()
				.setId(name)
				.setKey(key.getProto())
				.addChain(cert)
				.build());
	}
}
