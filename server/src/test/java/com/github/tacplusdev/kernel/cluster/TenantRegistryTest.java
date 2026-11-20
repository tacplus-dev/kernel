// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.types.generated.services.Services;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The tenant registry (kernel#69): an entry the operator wrote makes its tenant
 * exist under the entry's tid and derives its workloads' delegates, so a
 * tenant's workload mints its identity before kernel holds any of the tenant's
 * settings. An entry applies only at a higher version, and its tid and name are
 * immutable.
 */
class TenantRegistryTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final Caller CALLER = new Caller("", "test-req");
	private static final String TID = "acmetid1";
	private static final String NS = "/tenants/acme";
	private static final String K8S_NS = "tac-dev-" + TID;
	private static final String SA = "docmanager-acme";

	private final ConfigMap configMap = new ConfigMap(new InMemoryManager());
	private final AtomicInteger snapshots = new AtomicInteger();
	private final TenantRegistry registry = new TenantRegistry(configMap, snapshots::incrementAndGet);
	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private static Kernel.TenantRegistryEntry entry(String tid, String name, long version) {
		return Kernel.TenantRegistryEntry.newBuilder()
				.setTid(tid)
				.setName(name)
				.setKubernetesNamespace("tac-dev-" + tid)
				.addServices(Kernel.TenantRegistryService.newBuilder()
						.setName("docmanager")
						.setKubernetesServiceAccount("docmanager-" + name)
						.addAuthorizedServices(Services.ServiceName.SERVICE_NAME_OPA))
				.setVersion(version)
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.build();
	}

	private IdentityServiceImpl newService(List<Kernel.Delegate> configured, String k8sNamespace, String sa) {
		KeyRotator keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		return new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> registry.withDelegatesOf(configured),
				List::of,        // grants
				null,            // grantsWriter
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				"https://kernel.test/oidc",
				null,            // opaEvalClient
				null,            // proxyPolicyOpaClient
				configMap,
				new WorkloadMap(new InMemoryManager()),
				new PrincipalMap(new InMemoryManager()),
				null,            // writeIdentitySnapshot
				FakeKubernetesTokenVerifier.returning(
						FakeKubernetesTokenVerifier.identity(k8sNamespace, sa, List.of(KERNEL_AUDIENCE))),
				KERNEL_AUDIENCE,
				null);           // webauthnRelyingParty
	}

	/** Mints a service token for the workload running as {@code sa} in {@code k8sNamespace}. */
	private TokenWrapper mint(String k8sNamespace, String sa) throws Exception {
		Tokenrequest.TokenMintResponse resp = newService(List.of(), k8sNamespace, sa).mintServiceToken(CALLER,
				Tokenrequest.MintServiceTokenRequest.newBuilder().setKubernetesToken(fakeJwt()).build());
		return TokenWrapper.parse(resp.getAccessToken().getBase64());
	}

	private int mintRefusal(String k8sNamespace, String sa) {
		return assertThrows(ProtoException.class, () -> mint(k8sNamespace, sa)).getCode();
	}

	private static String tenantSpiffe(String tid, String service) {
		return Spiffe.namespaceSpiffeId(TRUST_DOMAIN, "/tenants/" + tid) + "/" + Spiffe.SERVICES_SEGMENT + "/" + service;
	}

	/** A structurally well-formed (3-segment) but otherwise meaningless JWT. */
	private static String fakeJwt() {
		return "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0"
				+ ".eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YmVkcm9jazpvYXV0aC1zYSJ9"
				+ ".c2lnbmF0dXJl";
	}

	// ---- An entry makes its tenant and its identities ------------------------

	@Test
	void aRegisteredTenantsWorkloadMintsItsIdentityBeforeTheTenantHasAnySettings() throws Exception {
		assertEquals(TenantRegistry.Outcome.APPLIED, registry.apply(entry(TID, "acme", 1)));

		Kernel.Tenant tenant = configMap.getTenants(NS);
		assertEquals("acme", tenant.getName());
		assertEquals(TID, tenant.getTid(), "the entry's tid is taken as given");
		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE, tenant.getStatus());
		assertTrue(configMap.getTenantConfigs(NS).getTenantName().isEmpty(), "the tenant has no settings");

		TokenWrapper token = mint(K8S_NS, SA);
		assertEquals(tenantSpiffe(TID, "docmanager"), token.getSubject());
		assertEquals(1, snapshots.get(), "the applied entry is written to the disk snapshot");
	}

	@Test
	void theDerivedDelegateIsTheTrustTheEntryNames() throws Exception {
		registry.apply(entry(TID, "acme", 1));

		assertEquals(List.of(Kernel.Delegate.newBuilder()
				.setName("docmanager")
				.setTenantNamespace(NS)
				.addKubernetesServiceAccounts(Kernel.KubernetesServiceAccountMatcher.newBuilder()
						.setKubernetesNamespace(K8S_NS)
						.setKubernetesServiceAccount(SA))
				.addAuthorizedServices(Services.ServiceName.SERVICE_NAME_OPA)
				.build()), registry.delegates());
	}

	@Test
	void aServiceTheEntryDoesNotNameMintsNothing() throws Exception {
		assertEquals(TenantRegistry.Outcome.APPLIED, registry.apply(entry(TID, "acme", 1)));

		assertEquals(ProtoException.PERMISSION_DENIED, mintRefusal(K8S_NS, "other-acme"));
		assertEquals(ProtoException.PERMISSION_DENIED, mintRefusal("tac-dev-elsewhere", SA));
	}

	@Test
	void aConfiguredDelegateMatchesBeforeADerivedOne() throws Exception {
		registry.apply(entry(TID, "acme", 1));
		List<Kernel.Delegate> configured = List.of(Kernel.Delegate.newBuilder()
				.setName("legacy")
				.addKubernetesServiceAccounts(Kernel.KubernetesServiceAccountMatcher.newBuilder()
						.setKubernetesNamespace(K8S_NS)
						.setKubernetesServiceAccount(SA))
				.build());

		List<Kernel.Delegate> all = registry.withDelegatesOf(configured);
		assertEquals(2, all.size());
		assertEquals("legacy", all.get(0).getName());
		assertEquals("docmanager", all.get(1).getName());
	}

	// ---- Versions ------------------------------------------------------------

	@Test
	void aLowerOrEqualVersionIsIgnored() throws Exception {
		registry.apply(entry(TID, "acme", 5));
		Kernel.TenantRegistryEntry suspended = entry(TID, "acme", 5).toBuilder()
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED).build();

		assertEquals(TenantRegistry.Outcome.STALE, registry.apply(suspended));
		assertEquals(TenantRegistry.Outcome.STALE, registry.apply(suspended.toBuilder().setVersion(4).build()));

		assertEquals(Kernel.TenantStatus.TENANT_STATUS_ACTIVE, configMap.getTenants(NS).getStatus());
		assertEquals(5, registry.entries().get(0).getVersion());
		assertEquals(1, registry.delegates().size());
		assertEquals(1, snapshots.get(), "nothing changed, nothing was written");
	}

	@Test
	void aHigherVersionReplacesTheTrust() throws Exception {
		registry.apply(entry(TID, "acme", 1));
		registry.apply(entry(TID, "acme", 2).toBuilder()
				.addServices(Kernel.TenantRegistryService.newBuilder()
						.setName("wiki")
						.setKubernetesServiceAccount("wiki-acme"))
				.build());

		assertEquals(tenantSpiffe(TID, "wiki"), mint(K8S_NS, "wiki-acme").getSubject());
		assertEquals(2, registry.delegates().size());
	}

	// ---- Immutability --------------------------------------------------------

	@Test
	void anEntryNamingATenantKernelHoldsUnderAnotherTidIsRefused() throws Exception {
		registry.apply(entry(TID, "acme", 1));

		ProtoException e = assertThrows(ProtoException.class, () -> registry.apply(entry("othertid", "acme", 1)));
		assertEquals(ProtoException.FAILED_PRECONDITION, e.getCode());
		assertEquals(TID, configMap.getTenants(NS).getTid());
	}

	@Test
	void anEntryThatRenamesItsTidIsRefused() throws Exception {
		registry.apply(entry(TID, "acme", 1));

		ProtoException e = assertThrows(ProtoException.class, () -> registry.apply(entry(TID, "globex", 2)));
		assertEquals(ProtoException.FAILED_PRECONDITION, e.getCode());
		assertTrue(configMap.getTenants("/tenants/globex").getName().isEmpty(), "no tenant was made");
		assertEquals("acme", registry.entries().get(0).getName());
	}

	@Test
	void aBootstrapTenantKeepsItsTidWhenTheRegistryListsIt() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(Kernel.BootstrapTenant.newBuilder().setName("acme").setTid(TID).build()));

		assertEquals(TenantRegistry.Outcome.APPLIED, registry.apply(entry(TID, "acme", 1)));
		assertEquals(TID, configMap.getTenants(NS).getTid());
	}

	@Test
	void malformedEntriesAreRefused() {
		for (Kernel.TenantRegistryEntry bad : List.of(
				entry("", "acme", 1),
				entry("00000009", "acme", 1),
				entry(TID, "people", 1),
				entry(TID, "acme", 1).toBuilder().setKubernetesNamespace("").build(),
				entry(TID, "acme", 1).toBuilder().setServices(0,
						Kernel.TenantRegistryService.newBuilder().setName("a/b").setKubernetesServiceAccount("x")).build(),
				entry(TID, "acme", 1).toBuilder().setServices(0,
						Kernel.TenantRegistryService.newBuilder().setName("docmanager")).build())) {
			assertThrows(ProtoException.class, () -> registry.apply(bad), bad.toString());
		}
		assertTrue(registry.entries().isEmpty());
		assertTrue(registry.delegates().isEmpty());
	}

	// ---- Status and removal --------------------------------------------------

	@Test
	void aSuspendedTenantsWorkloadsMintNothing() throws Exception {
		registry.apply(entry(TID, "acme", 1));
		registry.apply(entry(TID, "acme", 2).toBuilder()
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED).build());

		assertEquals(Kernel.TenantStatus.TENANT_STATUS_SUSPENDED, configMap.getTenants(NS).getStatus());
		assertTrue(registry.delegates().isEmpty());
		assertEquals(ProtoException.PERMISSION_DENIED, mintRefusal(K8S_NS, SA));
	}

	@Test
	void aTenantThatLeavesTheRegistryMintsNothing() throws Exception {
		registry.apply(entry(TID, "acme", 1));

		assertTrue(registry.remove(TID));
		assertTrue(registry.delegates().isEmpty());
		assertEquals(ProtoException.PERMISSION_DENIED, mintRefusal(K8S_NS, SA));
		assertEquals(TID, configMap.getTenants(NS).getTid(), "the tenant's record is TenantAdmin's to delete");
	}

	@Test
	void restoredEntriesServeAtOnce() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(Kernel.BootstrapTenant.newBuilder().setName("acme").setTid(TID).build()));

		registry.restore(List.of(entry(TID, "acme", 3)));

		assertEquals(tenantSpiffe(TID, "docmanager"), mint(K8S_NS, SA).getSubject());
		assertEquals(TenantRegistry.Outcome.STALE, registry.apply(entry(TID, "acme", 3)),
				"the restored version is the one held");
		assertEquals(0, snapshots.get());
	}

	// ---- The operator, the registry's writer ---------------------------------

	@Test
	void theOperatorMintsItsSystemIdentity() throws Exception {
		List<Kernel.Delegate> configured = List.of(Kernel.Delegate.newBuilder()
				.setName("operator")
				.addKubernetesServiceAccounts(Kernel.KubernetesServiceAccountMatcher.newBuilder()
						.setKubernetesNamespace("tac-dev")
						.setKubernetesServiceAccount("operator"))
				.build());
		Tokenrequest.TokenMintResponse resp = newService(configured, "tac-dev", "operator").mintServiceToken(CALLER,
				Tokenrequest.MintServiceTokenRequest.newBuilder().setKubernetesToken(fakeJwt()).build());

		assertEquals(Spiffe.serviceSpiffeId(TRUST_DOMAIN, "", "operator"),
				TokenWrapper.parse(resp.getAccessToken().getBase64()).getSubject());
	}

	// ---- TenantAdmin ---------------------------------------------------------

	@Test
	void createTenantRefusesATopLevelTenant() throws Exception {
		TenantAdminServiceImpl admin = new TenantAdminServiceImpl(configMap, () -> TRUST_DOMAIN, () -> { });

		ProtoException e = assertThrows(ProtoException.class, () -> admin.createTenant(CALLER,
				Kernel.CreateTenantRequest.newBuilder().setTenantNamespace("/tenants/globex").build()));
		assertEquals(ProtoException.FAILED_PRECONDITION, e.getCode());
		assertTrue(configMap.getTenants("/tenants/globex").getName().isEmpty());

		registry.apply(entry(TID, "acme", 1));
		Kernel.Tenant sub = admin.createTenant(CALLER,
				Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(NS + "/sub").build());
		assertEquals("sub", sub.getName(), "a registered tenant's sub-tenants are TenantAdmin's");
	}
}
