// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.types.sys.grpcconfig.Grpcconfig;
import com.github.tacplusdev.kernel.model.types.sys.grpcconfig.Helpers;
import com.github.tacplusdev.kernel.model.types.sys.host.HostOuterClass;
import com.github.tacplusdev.kernel.tacplusbackend.sys.grpcconfig.ServiceConfigStateMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code ClusterServer} seeds ServiceConfigState on every kernel start with
 * Kernel.Config's {@code spiffe_trust_domain} and {@code location_path}. Every
 * service's generated ServiceManager fetches that Config at start and merges it
 * under its boot config, so a service whose boot config carries no trust domain
 * builds its SPIFFE identity under the kernel's.
 *
 * <p>The seed used to be a Config holding only those two fields. putConfig
 * validates the whole Config and {@code listen_address} is required, so it was
 * refused on every boot ("Failed to seed ServiceConfigState: field
 * listenAddress is required") and the root stayed empty. The seed now merges
 * the two fields into what the root holds and defaults the rest, the same
 * defaults every reader applies to what it fetches.
 */
class ServiceConfigSeedTest {

	private ServiceConfigStateMap map;
	private final ListAppender<ILoggingEvent> log = new ListAppender<>();
	private ch.qos.logback.classic.Logger logger;

	@BeforeEach
	void setUp() {
		map = new ServiceConfigStateMap(new InMemoryManager());
		logger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(ClusterServer.class);
		log.start();
		logger.addAppender(log);
	}

	@AfterEach
	void tearDown() {
		logger.detachAppender(log);
	}

	/** Cold boot: the trust domain and location path land, and nothing is warned. */
	@Test
	void bootSeedLandsWithoutAWarning() {
		ClusterServer.seedServiceConfig(map, "seatrials.tacplus.dev", "gcp/us-central1");

		Grpcconfig.Config seeded = map.getConfig();
		assertEquals("seatrials.tacplus.dev", seeded.getSpiffeTrustDomain());
		assertEquals("gcp/us-central1", seeded.getLocationPath());
		assertEquals(List.of(), warnings());
	}

	/** What a service does with it: a boot config without a trust domain takes the kernel's. */
	@Test
	void aServiceWithoutATrustDomainBuildsUnderTheKernels() {
		ClusterServer.seedServiceConfig(map, "seatrials.tacplus.dev", "gcp/us-central1");

		Grpcconfig.Config runtime = Helpers.configDefaults(map.getConfig()).build();
		Grpcconfig.Config service = Helpers.mergeConfig(Grpcconfig.Config.getDefaultInstance(), runtime).build();

		assertEquals("seatrials.tacplus.dev", service.getSpiffeTrustDomain());
		assertEquals("gcp/us-central1", service.getLocationPath());
	}

	/**
	 * Restart: the kernel's two fields are replaced (a changed Kernel.Config takes
	 * effect), anything else the root holds is kept.
	 */
	@Test
	void reseedReplacesTheTwoFieldsAndKeepsTheRest() throws Exception {
		HostOuterClass.Host endpoint = HostOuterClass.Host.newBuilder().setHost("kernel-0.kernel.svc.cluster.local").setPort(8443).build();
		ClusterServer.seedServiceConfig(map, "old.tacplus.dev", "gcp/us-east1");
		map.putConfig(map.getConfig().toBuilder().addEndpoints(endpoint).build());

		ClusterServer.seedServiceConfig(map, "seatrials.tacplus.dev", "");

		Grpcconfig.Config seeded = map.getConfig();
		assertEquals("seatrials.tacplus.dev", seeded.getSpiffeTrustDomain());
		assertEquals("", seeded.getLocationPath());
		assertEquals(List.of(endpoint), seeded.getEndpointsList());
		assertEquals(List.of(), warnings());
	}

	private List<String> warnings() {
		return log.list.stream()
				.filter(e -> e.getLevel().isGreaterOrEqual(Level.WARN))
				.map(ILoggingEvent::getFormattedMessage)
				.toList();
	}
}
