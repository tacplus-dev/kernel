// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.x509.ImmutableCertChain;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.host.HostOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.x509.X509;
import io.grpc.ManagedChannel;
import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthCheckResponse.ServingStatus;
import io.grpc.health.v1.HealthGrpc;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ConnectException;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The kubelet's readiness probe asks grpc.health.v1 on the plaintext 8444
 * listener, which is bound before any kernel init so startup probes can
 * connect. ClusterServer used to mark that health SERVING partway through
 * construction, ahead of the boot-time map work and of
 * {@code grpcServer.start()}: when that work hung on dev, :5000 never opened
 * while the pod stayed Ready. Readiness must report SERVING only once :5000
 * accepts.
 */
class KernelReadinessGatedOnListenerTest {

	@TempDir
	Path disk;

	private ClusterServer server;
	private ManagedChannel probe;

	@AfterEach
	void tearDown() throws Exception {
		if (probe != null) {
			probe.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
		if (server != null) {
			server.shutdown();
		}
	}

	@Test
	void healthProbeReportsNotServingUntilTheGrpcListenerHasStarted() throws Exception {
		int grpcPort = HazelcastTestMembers.freePort();
		int healthPort = HazelcastTestMembers.freePort();
		server = new ClusterServer(config(grpcPort, healthPort));
		probe = NettyChannelBuilder.forAddress("127.0.0.1", healthPort).usePlaintext().build();

		// Construction is done, the boot-time map work included, but :5000 is not
		// listening yet: readiness must not pass.
		assertThrows(ConnectException.class, () -> new Socket("127.0.0.1", grpcPort).close());
		assertEquals(ServingStatus.NOT_SERVING, health(),
				"8444 must report NOT_SERVING while :5000 is not listening");

		server.start();

		new Socket("127.0.0.1", grpcPort).close();
		assertEquals(ServingStatus.SERVING, health(),
				"8444 must report SERVING once :5000 has started");
	}

	private ServingStatus health() {
		return HealthGrpc.newBlockingStub(probe).withDeadlineAfter(5, TimeUnit.SECONDS)
				.check(HealthCheckRequest.getDefaultInstance()).getStatus();
	}

	private Kernel.Config config(int grpcPort, int healthPort) throws Exception {
		X509.X509CertChain chain = selfSignedChain("kernel-readiness-test");
		return Kernel.Config.newBuilder()
				.setClusterName("kernel-readiness-test-" + UUID.randomUUID())
				.setListener(host(grpcPort))
				.addMembers(host(0))
				.setHazelcastListener(host(HazelcastTestMembers.freePort()))
				.setRatisListener(host(HazelcastTestMembers.freePort()))
				.setHealthProbePort(healthPort)
				.setDiskDir(disk.resolve("kernel").toString())
				.setConfigOverridePath(disk.resolve("override.json").toString())
				.setTls(chain)
				.setSigningCa(chain)
				.build();
	}

	private static HostOuterClass.Host host(int port) {
		return HostOuterClass.Host.newBuilder().setHost("127.0.0.1").setPort(port).build();
	}

	private static X509.X509CertChain selfSignedChain(String name) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair keyPair = generator.generateKeyPair();
		String pem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
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
		return X509.X509CertChain.newBuilder()
				.setId(name)
				.setKey(key.getProto())
				.addChain(cert)
				.build();
	}
}
