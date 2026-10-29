// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.Bootstrap;
import com.github.tacplusdev.kernel.model.types.services.kernel.Helpers;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.host.HostOuterClass;
import com.hazelcast.config.Config;
import com.hazelcast.config.SSLConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.instance.BuildInfoProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What kernel's Hazelcast member traffic actually is (kernel#24). Open-source
 * Hazelcast has no member TLS: an enabled SSLConfig is refused at start unless
 * the internal {@code hazelcast.internal.override.enterprise} flag reports the
 * jar as Enterprise, and then the open-source channel pipeline (which has no TLS
 * handler) carries the traffic in plain text with the TLS config ignored.
 * Kernel set that flag, from SeaBeam, and no longer does. Its members speak
 * plain Hazelcast, which this test pins so that no TLS config can come back
 * that silently does nothing.
 */
class KernelMemberTransportTest {

	private static final String OVERRIDE_ENTERPRISE = "hazelcast.internal.override.enterprise";

	private final List<HazelcastInstance> members = new ArrayList<>();
	private final List<AutoCloseable> closeables = new ArrayList<>();

	@AfterEach
	void tearDown() throws Exception {
		for (HazelcastInstance member : members) {
			member.getLifecycleService().terminate();
		}
		for (AutoCloseable closeable : closeables) {
			closeable.close();
		}
		System.clearProperty(OVERRIDE_ENTERPRISE);
	}

	@Test
	void bootstrapLeavesHazelcastAnOpenSourceBuild() {
		System.clearProperty(OVERRIDE_ENTERPRISE);

		// Bootstrap.run reads its config after its first statements; a missing
		// config file stops it there, before any server starts.
		assertThrows(IOException.class,
				() -> Bootstrap.run(new String[] { "--config", "/nonexistent/kernel-24.yaml" }));

		assertNull(System.getProperty(OVERRIDE_ENTERPRISE),
				"kernel must not set Hazelcast's internal Enterprise override");
		assertFalse(BuildInfoProvider.getBuildInfo().isEnterprise(),
				"the open-source Hazelcast jar must report itself as open source");
	}

	@Test
	void kernelConfiguresNoMemberTls() throws Exception {
		Config config = memberConfig("kernel-transport-" + UUID.randomUUID(), HazelcastTestMembers.freePort());

		SSLConfig ssl = config.getNetworkConfig().getSSLConfig();
		assertTrue(ssl == null || !ssl.isEnabled(), "kernel must not configure a member TLS it cannot have");
		assertFalse(config.getAdvancedNetworkConfig().isEnabled());
	}

	@Test
	void memberTlsIsRefusedOnOpenSourceHazelcast() throws Exception {
		Config config = memberConfig("kernel-transport-" + UUID.randomUUID(), HazelcastTestMembers.freePort());
		config.getNetworkConfig().setSSLConfig(new SSLConfig().setEnabled(true));

		IllegalStateException refused = assertThrows(IllegalStateException.class,
				() -> members.add(Hazelcast.newHazelcastInstance(config)));
		assertEquals("SSL/TLS requires Hazelcast Enterprise Edition", refused.getMessage());
	}

	@Test
	void kernelMembersTalkPlainHazelcast() throws Exception {
		String cluster = "kernel-transport-" + UUID.randomUUID();
		int firstPort = HazelcastTestMembers.freePort();
		HazelcastInstance first = Hazelcast.newHazelcastInstance(memberConfig(cluster, firstPort));
		members.add(first);

		// The second member joins the first through a proxy that records what it sends.
		RecordingProxy proxy = new RecordingProxy(firstPort);
		closeables.add(proxy);
		Config second = memberConfig(cluster, HazelcastTestMembers.freePort());
		second.getNetworkConfig().getJoin().getTcpIpConfig().setMembers(List.of("127.0.0.1:" + proxy.port()));
		members.add(Hazelcast.newHazelcastInstance(second));

		assertEquals(2, first.getCluster().getMembers().size(), "the members must form one cluster");

		byte[] sent = proxy.firstConnectionBytes();
		assertTrue(sent.length > 3, "the joining member must have sent through the proxy");
		// A TLS connection opens with a handshake record (0x16); a plain Hazelcast
		// member connection opens with its protocol header, "HZC".
		assertEquals("HZC", new String(sent, 0, 3, StandardCharsets.US_ASCII),
				"member traffic must be plain Hazelcast, not TLS");
		assertTrue(new String(sent, StandardCharsets.ISO_8859_1).contains(cluster),
				"the join request, cluster name included, travels in clear text");
	}

	/** Kernel's own member config, as ClusterServer builds it, for a member on {@code port}. */
	private static Config memberConfig(String cluster, int port) {
		Kernel.Config cfg = Helpers.configDefaults(Kernel.Config.newBuilder()
				.setClusterName(cluster)
				.setHazelcastListener(HostOuterClass.Host.newBuilder().setHost("127.0.0.1").setPort(port))
				.addMembers(HostOuterClass.Host.newBuilder().setHost("127.0.0.1"))
				.build()).build();
		Config config = ClusterServer.hazelcastConfig(cfg, "node-" + port);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		return config;
	}

	/** Forwards loopback connections to {@code target} and records what the first one sends. */
	private static final class RecordingProxy implements AutoCloseable {
		private final ServerSocket listener = new ServerSocket(0);
		private final ByteArrayOutputStream first = new ByteArrayOutputStream();
		private final List<Socket> sockets = new ArrayList<>();
		private final Thread acceptor;

		RecordingProxy(int target) throws IOException {
			acceptor = new Thread(() -> {
				boolean recording = true;
				while (!listener.isClosed()) {
					try {
						Socket in = listener.accept();
						Socket out = new Socket("127.0.0.1", target);
						synchronized (sockets) {
							sockets.add(in);
							sockets.add(out);
						}
						pump(in.getInputStream(), out.getOutputStream(), recording ? first : null);
						pump(out.getInputStream(), in.getOutputStream(), null);
						recording = false;
					} catch (IOException e) {
						return;
					}
				}
			}, "recording-proxy");
			acceptor.setDaemon(true);
			acceptor.start();
		}

		int port() {
			return listener.getLocalPort();
		}

		byte[] firstConnectionBytes() {
			synchronized (first) {
				return first.toByteArray();
			}
		}

		private void pump(InputStream from, OutputStream to, ByteArrayOutputStream record) {
			Thread pump = new Thread(() -> {
				byte[] buffer = new byte[8192];
				try {
					for (int n; (n = from.read(buffer)) != -1;) {
						if (record != null) {
							synchronized (record) {
								record.write(buffer, 0, n);
							}
						}
						to.write(buffer, 0, n);
						to.flush();
					}
				} catch (IOException e) {
					// the connection closed
				}
			}, "recording-proxy-pump");
			pump.setDaemon(true);
			pump.start();
		}

		@Override
		public void close() throws IOException {
			listener.close();
			synchronized (sockets) {
				for (Socket socket : sockets) {
					socket.close();
				}
			}
		}
	}
}
