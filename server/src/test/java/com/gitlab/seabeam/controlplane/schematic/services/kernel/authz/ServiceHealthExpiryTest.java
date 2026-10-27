// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.authz;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.graphs.hazelcast.HazelcastManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.servicehealth.ServiceHealthStateServiceGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.healthreport.Healthreport;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SerializerRegistry;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.sys.servicehealth.ServiceHealthMap;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.sys.servicehealth.ServiceHealthStateServiceServer;
import com.hazelcast.config.Config;
import com.hazelcast.core.EntryView;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.ServerInterceptors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * A service instance's {@code ServiceHealth} entry lives only as long as
 * the instance keeps reporting. A pod that is killed without a clean shutdown
 * never deletes its entry, so the write itself has to carry an expiry; without
 * one every restart added an instance that nothing ever removed, and the
 * gateway's routing table grew without bound.
 *
 * <p>Runs the real generated {@link ServiceHealthStateServiceServer} on a real
 * Hazelcast member, behind the real caller interceptor, and reads the TTL
 * Hazelcast holds for the entry.
 */
class ServiceHealthExpiryTest extends StateChrootTestBase {

	private static final String INSTANCES_MAP =
			ServiceHealthMap.class.getName() + ":sys.servicehealth.ServiceHealth.Instances";

	private HazelcastInstance hz;
	private ServiceHealthStateServiceServer healthServer;

	@BeforeEach
	void startHealthServer() throws Exception {
		Config config = new Config();
		config.setClusterName("health-expiry-" + UUID.randomUUID());
		config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
		config.getNetworkConfig().getJoin().getAutoDetectionConfig().setEnabled(false);
		SerializerRegistry.register(config);
		hz = Hazelcast.newHazelcastInstance(config);
		healthServer = new ServiceHealthStateServiceServer(new HazelcastManager(hz), authenticator);
		startServer(ServerInterceptors.interceptForward(
				healthServer.bindService(), authenticator.callerInterceptor()));
	}

	@AfterEach
	void stopHealthServer() {
		healthServer.close();
		hz.shutdown();
	}

	@Test
	void everyReportArmsAThirtySecondExpiry() {
		ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub eventbus =
				ServiceHealthStateServiceGrpc.newBlockingStub(channel).withInterceptors(bearer(
						tokenFor(SpiffeIds.build(TRUST_DOMAIN, "eventbus"), "eventbus", "eb-7f9c")));

		eventbus.setInstances(Healthreport.ServiceInstanceHealth.newBuilder()
				.setStatus(Healthreport.InstanceStatus.INSTANCE_STATUS_HEALTHY)
				.build());

		EntryView<String, Healthreport.ServiceInstanceHealth> entry =
				hz.<String, Healthreport.ServiceInstanceHealth>getMap(INSTANCES_MAP).getEntryView("eventbus@eb-7f9c");
		assertNotNull(entry, "the report must be stored");
		assertEquals(TimeUnit.SECONDS.toMillis(30), entry.getTtl(),
				"an instance that stops reporting must expire three missed 10s reports later");
	}
}
