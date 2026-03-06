// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.hazelcast;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCert;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Helpers;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Manager;
import com.hazelcast.config.Config;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.SSLConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.config.cp.CPSubsystemConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;

/**
 * Factory for creating a configured Hazelcast instance from a
 * {@link Kernel.BootstrapConfig}. Extracted from the former monolithic
 * StateDbServer so the gRPC server code (now in {@code libs/statedb}) stays
 * backend-agnostic.
 */
public class HazelcastFactory {

	private static final Logger logger = LoggerFactory.getLogger(HazelcastFactory.class);

	/**
	 * Creates a {@link Manager} backed by Hazelcast, configured from the given
	 * config.
	 */
	public static Manager createManager(Kernel.BootstrapConfig config) {
		HazelcastInstance hz = create(config);
		return new HazelcastManager(hz);
	}

	/**
	 * Creates and starts a Hazelcast instance from the given config.
	 */
	static HazelcastInstance create(Kernel.BootstrapConfig statedbConfig) {
		Kernel.BootstrapConfig cfg = Helpers.bootstrapConfigDefaults(statedbConfig).build();

		Config hzConfig = new Config();
		hzConfig.setClusterName(Objects.requireNonNull(cfg.getClusterName()));

		// Partition count
		hzConfig.setProperty(
				"hazelcast.partition.count",
				Objects.requireNonNull(String.valueOf(cfg.getPartitionCount())));

		// Network: TCP-IP discovery
		NetworkConfig networkConfig = hzConfig.getNetworkConfig();
		JoinConfig joinConfig = networkConfig.getJoin();
		joinConfig.getMulticastConfig().setEnabled(false);

		TcpIpConfig tcpIpConfig = joinConfig.getTcpIpConfig();
		tcpIpConfig.setEnabled(true);
		for (var member : cfg.getMembersList()) {
			tcpIpConfig.addMember(member.getHost() + ":" + (member.getPort() + 1));
		}

		// Hazelcast port = listener (gRPC) port + 1
		int hzPort = cfg.getListener().getPort() + 1;
		networkConfig.setPort(hzPort);
		networkConfig.setPortAutoIncrement(false);

		// Network timeouts
		if (cfg.hasNetwork()) {
			Kernel.NetworkConfig net = Helpers.networkConfigDefaults(cfg.getNetwork()).build();
			tcpIpConfig.setConnectionTimeoutSeconds((int) net.getConnectTimeoutSeconds());
			hzConfig.setProperty(
					"hazelcast.heartbeat.interval.seconds",
					Objects.requireNonNull(String.valueOf(net.getHeartbeatIntervalSeconds())));
			hzConfig.setProperty(
					"hazelcast.max.no.heartbeat.seconds",
					Objects.requireNonNull(String.valueOf(net.getHeartbeatTimeoutSeconds())));
		}

		// mTLS using X509CertPair and loader_ca
		if (cfg.hasTls()) {
			try {
				ImmutableCertPair tlsPair = ImmutableCertPair.from(cfg.getTls());

				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(null, null);
				keyStore.setKeyEntry("node", tlsPair.getKey().getPrivateKey(),
						new char[0], new Certificate[] { tlsPair.getCert().getX509Certificate() });

				KeyStore trustStore = KeyStore.getInstance("PKCS12");
				trustStore.load(null, null);
				for (int i = 0; i < cfg.getLoaderCaCount(); i++) {
					ImmutableCert ca = ImmutableCert.from(cfg.getLoaderCa(i));
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

		// CP Subsystem (needed for FencedLock / ATOMIC boundaries)
		if (cfg.hasCpSubsystem() && cfg.getCpSubsystem().getEnabled()) {
			Kernel.CPSubsystemConfig cpCfg = Helpers.cPSubsystemConfigDefaults(cfg.getCpSubsystem()).build();

			CPSubsystemConfig hzCp = hzConfig.getCPSubsystemConfig();
			hzCp.setCPMemberCount(cpCfg.getCpMemberCount());
			hzCp.setSessionTimeToLiveSeconds((int) cpCfg.getSessionTimeoutSeconds());
			hzCp.setSessionHeartbeatIntervalSeconds((int) cpCfg.getSessionHeartbeatIntervalSeconds());
			hzCp.setMissingCPMemberAutoRemovalSeconds((int) cpCfg.getMissingCpMemberAutoRemovalSeconds());

			logger.info("CP subsystem enabled, cp_member_count={}", cpCfg.getCpMemberCount());
		}

		SerializerRegistry.register(hzConfig);

		return Hazelcast.newHazelcastInstance(hzConfig);
	}

}
