// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.authz;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster.SpiffeIds;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Helpers;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.ServiceConfigStateServiceGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.trace.Trace;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.sys.grpcconfig.ServiceConfigStateStateServiceServer;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Iterator;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@code grpcconfig.ServiceConfigState} is the one cluster-wide runtime config
 * that every service's generated ServiceManager reads at boot (GetConfig): SPIFFE
 * trust domain, endpoints, TLS trust, logging. Kernel is its only writer. The
 * key-prefix chroot used to hand a tenant-owned caller the empty default instead,
 * because it read {@code /tenants/<t>/SINGLETON}, a key nobody writes.
 *
 * <p>A tenant caller reads the /system value, over Get and Watch alike.
 */
class FleetWideRuntimeConfigTest extends StateChrootTestBase {

	private ServiceConfigStateStateServiceServer configServer;

	private ServiceConfigStateServiceGrpc.ServiceConfigStateServiceBlockingStub kernel;
	private ServiceConfigStateServiceGrpc.ServiceConfigStateServiceBlockingStub tenantX;
	private ServiceConfigStateServiceGrpc.ServiceConfigStateServiceBlockingStub tenantY;

	@BeforeEach
	void startConfigServer() throws Exception {
		configServer = new ServiceConfigStateStateServiceServer(new InMemoryManager(), authenticator);
		startServer(ServerInterceptors.interceptForward(
				configServer.bindService(), authenticator.callerInterceptor()));
		kernel = stubFor(SpiffeIds.build(TRUST_DOMAIN, "kernel"), "kernel");
		tenantX = stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/x", "docmanager"), "docmanager");
		tenantY = stubFor(SpiffeIds.build(TRUST_DOMAIN, "/tenants/y", "docmanager"), "docmanager");
	}

	@AfterEach
	void closeConfigServer() {
		configServer.close();
	}

	private ServiceConfigStateServiceGrpc.ServiceConfigStateServiceBlockingStub stubFor(
			String subject, String serviceName) {
		return ServiceConfigStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(subject, serviceName)));
	}

	private static Grpcconfig.Config config(String trustDomain) {
		return Helpers.configDefaults(Grpcconfig.Config.newBuilder()
				.setSpiffeTrustDomain(trustDomain).build()).build();
	}

	@Test
	void tenantGetConfigReadsTheSystemConfig() {
		kernel.setConfig(config("fleet.example"));

		assertEquals("fleet.example",
				tenantX.getConfig(Trace.TraceRequest.getDefaultInstance()).getSpiffeTrustDomain());
		assertEquals("fleet.example",
				tenantY.getConfig(Trace.TraceRequest.getDefaultInstance()).getSpiffeTrustDomain());
	}

	@Test
	void tenantWatchConfigStreamsTheSystemConfig() {
		kernel.setConfig(config("fleet.example"));

		// The deadline turns a stream that never delivers into a failure, not a hang.
		Iterator<Grpcconfig.Config> xStream = tenantX.withDeadlineAfter(10, TimeUnit.SECONDS)
				.watchConfig(Trace.TraceRequest.getDefaultInstance());
		assertEquals("fleet.example", xStream.next().getSpiffeTrustDomain());

		kernel.setConfig(config("fleet2.example"));
		assertEquals("fleet2.example", xStream.next().getSpiffeTrustDomain());
	}

	@Test
	void aTenantCannotWriteTheConfigEveryoneReads() {
		// Only kernel writes it, so no tenant can plant a value that another tenant
		// (or itself) would read in place of the system one.
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> tenantY.setConfig(config("evil.example")));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
	}
}
