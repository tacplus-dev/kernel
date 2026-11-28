// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.authz;

import com.github.tacplusdev.kernel.cluster.SpiffeIds;
import com.github.tacplusdev.kernel.cluster.TenantBootstrapSeeds;
import com.github.tacplusdev.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.github.tacplusdev.kernel.model.types.services.kernel.ConfigStateServiceGrpc;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.services.stratum.Stratum;
import com.github.tacplusdev.kernel.model.types.sys.trace.Trace;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigStateServiceServer;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A tenant's own Stratum reads its seed members (kernel#34) from
 * {@code ConfigState.tenant_configs} through the real generated
 * {@link ConfigStateServiceServer}, as the instance kernel mints for it: subject
 * {@code spiffe://<td>/tenants/<tid>/services/stratum}, namespace claim
 * {@code /tenants/<name>}. The slices are written by the boot seed of the
 * deployment's bootstrap tenants, and each Stratum gets its own tenant's entry
 * only, keyed {@code /tenants/<name>}, projected to the {@code stratum} slice.
 */
class StratumTenantSliceReadTest extends StateChrootTestBase {

	private static final String ACME = "/tenants/acme";
	private static final String BETA = "/tenants/beta";
	private static final String ACME_TID = "q1w2e3r4";
	private static final String BETA_TID = "z9x8c7v6";

	private static final Stratum.StratumTenantConfig ACME_SEEDS = Stratum.StratumTenantConfig.newBuilder()
			.addSeedMembers("stratum-0.stratum.tac-dev-q1w2e3r4.svc.cluster.local:5001")
			.build();
	private static final Stratum.StratumTenantConfig BETA_SEEDS = Stratum.StratumTenantConfig.newBuilder()
			.addSeedMembers("stratum-0.stratum.tac-dev-z9x8c7v6.svc.cluster.local:5001")
			.build();

	private InMemoryManager manager;
	private ConfigStateServiceServer configServer;

	@BeforeEach
	void startConfigServer() throws Exception {
		manager = new InMemoryManager();
		ConfigMap configMap = new ConfigMap(manager);
		configServer = new ConfigStateServiceServer(manager, authenticator);
		startServer(ServerInterceptors.interceptForward(
				configServer.bindService(), authenticator.callerInterceptor()));
		TenantBootstrapSeeds.seed(configMap, List.of(
				Kernel.BootstrapTenant.newBuilder().setName("acme").setTid(ACME_TID).addAllStratumSeedMembers(ACME_SEEDS.getSeedMembersList()).build(),
				Kernel.BootstrapTenant.newBuilder().setName("beta").setTid(BETA_TID).addAllStratumSeedMembers(BETA_SEEDS.getSeedMembersList()).build()));
	}

	@AfterEach
	void closeConfigServer() {
		configServer.close();
	}

	/** The tenant's Stratum instance as kernel mints it: rooted at its tid, acting in its namespace. */
	private ConfigStateServiceGrpc.ConfigStateServiceBlockingStub stratumOf(String tid, String namespace) {
		String subject = SpiffeIds.build(TRUST_DOMAIN, SpiffeIds.tenantRoot(tid), "stratum");
		return ConfigStateServiceGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(tokenFor(subject, namespace, "stratum", null)));
	}

	private static Kernel.TenantConfigEntry projected(String ns, Stratum.StratumTenantConfig seeds) {
		return Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(ns)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder().setStratum(seeds))
				.build();
	}

	@Test
	void eachTenantsStratumReadsOnlyItsOwnSeeds() {
		assertEquals(Map.of(ACME, projected(ACME, ACME_SEEDS)), stratumOf(ACME_TID, ACME)
				.getAllTenantConfigs(Kernel.TenantConfigsGetAllRequest.getDefaultInstance()).getEntriesMap());
		assertEquals(Map.of(BETA, projected(BETA, BETA_SEEDS)), stratumOf(BETA_TID, BETA)
				.getAllTenantConfigs(Kernel.TenantConfigsGetAllRequest.getDefaultInstance()).getEntriesMap());
	}

	@Test
	void theWatchDeliversOnlyItsOwnSeeds() {
		Kernel.TenantConfigsEntriesResponse snapshot = stratumOf(ACME_TID, ACME)
				.withDeadlineAfter(10, TimeUnit.SECONDS)
				.watchTenantConfigs(Trace.TraceRequest.getDefaultInstance())
				.next();
		assertEquals(Map.of(ACME, projected(ACME, ACME_SEEDS)), snapshot.getEntriesMap());
	}

	@Test
	void anotherTenantsEntryIsDenied() {
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class, () -> stratumOf(ACME_TID, ACME)
				.getTenantConfigs(Kernel.TenantConfigsGetRequest.newBuilder().setKey(BETA).build()));
		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
	}
}
