// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.authz;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.ServiceHealthStateServiceGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.healthreport.Healthreport;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.trace.Trace;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ServiceHealthStateServiceServer;
import io.grpc.ServerInterceptors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Service discovery is fleet-wide. A tenant-owned service
 * ({@code /tenants/<t>/services/<name>}) finds the /system services it calls —
 * eventbus, blobstore — through {@code kernel.ServiceHealth}, the same as a
 * /system service does. The key-prefix chroot used to hide those instances from
 * it, and the chassis failed with "No healthy instance found for service
 * eventbus".
 *
 * <p>A tenant caller reads the /system instances plus its own tenant's, and never
 * another tenant's. Every assertion goes through real gRPC against the real
 * generated {@link ServiceHealthStateServiceServer} behind the real caller
 * interceptor, with each instance published by its own identity.
 */
class FleetWideDiscoveryTest extends StateChrootTestBase {

	private ServiceHealthStateServiceServer healthServer;

	private ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub eventbus;
	private ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub blobstore;
	private ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub tenantX;
	private ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub tenantY;

	@BeforeEach
	void startHealthServer() throws Exception {
		healthServer = new ServiceHealthStateServiceServer(new InMemoryManager(), authenticator);
		startServer(ServerInterceptors.interceptForward(
				healthServer.bindService(), authenticator.callerInterceptor()));
		eventbus = stubFor(SpiffeIds.build(TRUST_DOMAIN, "eventbus"), "eventbus", "eb-1");
		blobstore = stubFor(SpiffeIds.build(TRUST_DOMAIN, "blobstore"), "blobstore", "bs-1");
		tenantX = stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/x", "docmanager"), "docmanager", "dm-x");
		tenantY = stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/y", "docmanager"), "docmanager", "dm-y");

		for (ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub s
				: new ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub[] {
						eventbus, blobstore, tenantX, tenantY}) {
			publishHealthy(s);
		}
	}

	@AfterEach
	void closeHealthServer() {
		healthServer.close();
	}

	private ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub stubFor(
			String subject, String serviceName, String instanceId) {
		return ServiceHealthStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(subject, serviceName, instanceId)));
	}

	private static void publishHealthy(ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub stub) {
		stub.setInstances(Healthreport.ServiceInstanceHealth.newBuilder()
				.setStatus(Healthreport.InstanceStatus.INSTANCE_STATUS_HEALTHY)
				.build());
	}

	private static Set<String> getAll(ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub stub) {
		return stub.getAllInstances(Kernel.InstancesGetAllRequest.getDefaultInstance()).getEntriesMap().keySet();
	}

	private static Kernel.InstancesValueResponse get(
			ServiceHealthStateServiceGrpc.ServiceHealthStateServiceBlockingStub stub, String key) {
		return stub.getInstances(Kernel.InstancesGetRequest.newBuilder().setKey(key).build());
	}

	@Test
	void tenantGetAllSeesSystemInstancesAndItsOwnButNeverAnotherTenants() {
		assertEquals(Set.of("eventbus@eb-1", "blobstore@bs-1", "docmanager@dm-x"), getAll(tenantX));
		assertEquals(Set.of("eventbus@eb-1", "blobstore@bs-1", "docmanager@dm-y"), getAll(tenantY));

		// The payload is what the chassis matches on: service_id, untouched.
		Kernel.InstancesEntriesResponse all = tenantX.getAllInstances(Kernel.InstancesGetAllRequest.getDefaultInstance());
		assertEquals("eventbus", all.getEntriesMap().get("eventbus@eb-1").getServiceId());
		assertEquals("blobstore", all.getEntriesMap().get("blobstore@bs-1").getServiceId());
		assertEquals("dm-x", all.getEntriesMap().get("docmanager@dm-x").getInstanceId());
	}

	@Test
	void tenantWatchStreamsSystemInstancesAndItsOwnButNeverAnotherTenants() {
		// The deadline turns a stream that never delivers into a failure, not a hang.
		Iterator<Kernel.InstancesEntriesResponse> xStream = tenantX.withDeadlineAfter(10, TimeUnit.SECONDS)
				.watchInstances(Trace.TraceRequest.getDefaultInstance());

		assertEquals(Set.of("eventbus@eb-1", "blobstore@bs-1", "docmanager@dm-x"),
				xStream.next().getEntriesMap().keySet());

		// Another tenant's new instance must not wake x's stream; the next thing x
		// sees is the new /system instance, still without y's.
		publishHealthy(stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/y", "docmanager"), "docmanager", "dm-y2"));
		publishHealthy(stubFor(SpiffeIds.build(TRUST_DOMAIN, "eventbus"), "eventbus", "eb-2"));

		assertEquals(Set.of("eventbus@eb-1", "eventbus@eb-2", "blobstore@bs-1", "docmanager@dm-x"),
				xStream.next().getEntriesMap().keySet());
	}

	@Test
	void tenantKeyedReadsResolveSystemInstancesButNotAnotherTenants() {
		assertTrue(get(tenantX, "eventbus@eb-1").getFound());
		assertTrue(get(tenantX, "docmanager@dm-x").getFound());
		assertFalse(get(tenantX, "docmanager@dm-y").getFound());
		// Naming y's storage key does not escape the chroot either.
		assertFalse(get(tenantX, "/tenants/y/docmanager@dm-y").getFound());

		assertTrue(tenantX.containsKeyInstances(
				Kernel.InstancesGetRequest.newBuilder().setKey("blobstore@bs-1").build()).getFound());
		assertEquals(Set.of("eventbus@eb-1", "blobstore@bs-1", "docmanager@dm-x"), Set.copyOf(
				tenantX.keySetInstances(Kernel.InstancesKeysRequest.getDefaultInstance()).getKeysList()));
		assertEquals(3, tenantX.sizeInstances(Kernel.InstancesSizeRequest.getDefaultInstance()).getSize());
	}

	@Test
	void tenantWritesStayChrootedAndSystemReadsAreUnchanged() {
		// /system is the root scope: it sees every entry, tenants' under their
		// storage keys, exactly as before. That the tenants' entries show up here
		// prefixed also shows their writes were chrooted, not published fleet-wide.
		assertEquals(Set.of("eventbus@eb-1", "blobstore@bs-1",
				"/tenants/x/docmanager@dm-x", "/tenants/y/docmanager@dm-y"), getAll(eventbus));
	}
}
