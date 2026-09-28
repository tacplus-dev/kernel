// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.hazelcast;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCert;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Helpers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.Manager;
import com.hazelcast.config.Config;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.SSLConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.core.HazelcastInstance;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.hazelcast.Hazelcast;

/**
 * Factory for creating a configured Hazelcast instance from a
 * {@link Kernel.Config}. Extracted from the former monolithic
 * StateDbServer so the gRPC server code (now in {@code libs/statedb}) stays
 * backend-agnostic.
 */
public class HazelcastFactory {

	private static final Logger logger = LoggerFactory.getLogger(HazelcastFactory.class);

	/**
	 * Creates a {@link Manager} backed by Hazelcast, configured from the given
	 * config.
	 */
	public static Manager createManager(Kernel.Config config) {
		HazelcastInstance hz = create(config);
		return new HazelcastManager(hz);
	}

	/**
	 * Creates and starts a Hazelcast instance from the given config.
	 */
	static HazelcastInstance create(Kernel.Config statedbConfig) {
		Kernel.Config cfg = Helpers.configDefaults(statedbConfig).build();

		Config hzConfig = new Config();
		hzConfig.setClusterName(Objects.requireNonNull(cfg.getClusterName()));

		// Partition count
		hzConfig.setProperty(
				"hazelcast.partition.count", Objects.requireNonNull(String.valueOf(cfg.getPartitionCount())));

		// Network: TCP-IP discovery
		NetworkConfig networkConfig = hzConfig.getNetworkConfig();
		JoinConfig joinConfig = networkConfig.getJoin();
		joinConfig.getMulticastConfig().setEnabled(false);

		TcpIpConfig tcpIpConfig = joinConfig.getTcpIpConfig();
		tcpIpConfig.setEnabled(true);
		int hzPort = cfg.getHazelcastListener().getPort();
		for (var member : cfg.getMembersList()) {
			tcpIpConfig.addMember(member.getHost() + ":" + hzPort);
		}
		networkConfig.setPort(hzPort);
		networkConfig.setPortAutoIncrement(false);

		// Network timeouts
		if (cfg.hasNetwork()) {
			Hazelcast.NetworkConfig net = com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.hazelcast.Helpers
					.networkConfigDefaults(cfg.getNetwork()).build();
			tcpIpConfig.setConnectionTimeoutSeconds((int) net.getConnectTimeoutSeconds());
			hzConfig.setProperty(
					"hazelcast.heartbeat.interval.seconds",
					Objects.requireNonNull(String.valueOf(net.getHeartbeatIntervalSeconds())));
			hzConfig.setProperty(
					"hazelcast.max.no.heartbeat.seconds",
					Objects.requireNonNull(String.valueOf(net.getHeartbeatTimeoutSeconds())));
		}

		// mTLS using X509CertChain and cluster_ca
		if (cfg.hasTls()) {
			try {
				ImmutableCertChain tlsChain = ImmutableCertChain.from(cfg.getTls());

				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(null, null);
				keyStore.setKeyEntry("node", tlsChain.getEffectiveKey(), new char[0], new Certificate[] {
						tlsChain.leaf().getX509Certificate()
				});

				KeyStore trustStore = KeyStore.getInstance("PKCS12");
				trustStore.load(null, null);
				for (int i = 0; i < cfg.getClusterCaCount(); i++) {
					ImmutableCert ca = ImmutableCert.from(cfg.getClusterCa(i));
					trustStore.setCertificateEntry("ca-" + i, ca.getX509Certificate());
				}

				Path keyStorePath = Files.createTempFile("hz-keystore-", ".p12");
				try (var fos = new FileOutputStream(keyStorePath.toFile())) {
					keyStore.store(fos, new char[0]);
				}
				Path trustStorePath = Files.createTempFile("hz-truststore-", ".p12");
				try (var fos = new FileOutputStream(trustStorePath.toFile())) {
					trustStore.store(fos, new char[0]);
				}

				hzConfig.setProperty("hazelcast.socket.connect.timeout.seconds", "5");
				SSLConfig sslConfig = new SSLConfig();
				sslConfig.setEnabled(true);
				sslConfig.setProperty("protocol", "TLSv1.3");
				sslConfig.setProperty("mutualAuthentication", "REQUIRED");
				sslConfig.setProperty("keyStore", keyStorePath.toString());
				sslConfig.setProperty("keyStorePassword", "");
				sslConfig.setProperty("keyStoreType", "PKCS12");
				sslConfig.setProperty("trustStore", trustStorePath.toString());
				sslConfig.setProperty("trustStorePassword", "");
				sslConfig.setProperty("trustStoreType", "PKCS12");
				networkConfig.setSSLConfig(sslConfig);
			} catch (Exception e) {
				throw new RuntimeException("Failed to configure Hazelcast mTLS", e);
			}
		}

		// Data replication: ensure data exists on MIN_DATA_COPIES nodes.
		// backupCount = min(MIN_DATA_COPIES - 1, nodeCount - 1) so a 3+ node
		// cluster keeps 3 copies, while smaller clusters degrade gracefully.
		int nodeCount = cfg.getNodeCount() > 0 ? cfg.getNodeCount() : cfg.getMembersCount();
		int backupCount = Math.min((int) Helpers.MIN_DATA_COPIES - 1, Math.max(nodeCount - 1, 0));
		hzConfig.getMapConfig("default").setBackupCount(backupCount);
		logger.info("Hazelcast backup count set to {} (target {} copies, {} nodes)",
				backupCount, Helpers.MIN_DATA_COPIES, nodeCount);

		SerializerRegistry.register(hzConfig);

		return com.hazelcast.core.Hazelcast.newHazelcastInstance(hzConfig);
	}
}
