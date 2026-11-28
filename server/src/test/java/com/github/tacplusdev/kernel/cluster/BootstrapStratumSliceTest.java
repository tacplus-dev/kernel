// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.types.common.credentials.Credentials;
import com.github.tacplusdev.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.services.oauth.Oauth;
import com.github.tacplusdev.kernel.model.types.services.stratum.Stratum;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Each bootstrap tenant's Stratum slice (kernel#34): {@code BootstrapTenant.stratum_seed_members},
 * the seed members the operator derives from the tenant's Stratum StatefulSet, is
 * written into that tenant's {@code TenantConfig.stratum} at every boot, replacing
 * what is stored. Nothing else writes it: SetTenantConfig keeps the stored slice.
 */
class BootstrapStratumSliceTest {

	private static final String ACME = "/tenants/acme";
	private static final String BETA = "/tenants/beta";

	private ConfigMap configMap;
	private TenantAdminServiceImpl admin;

	@BeforeEach
	void setUp() {
		configMap = new ConfigMap(new InMemoryManager());
		admin = new TenantAdminServiceImpl(configMap, () -> "test.schematic.io", () -> { });
	}

	private static Stratum.StratumTenantConfig seeds(String... members) {
		return Stratum.StratumTenantConfig.newBuilder().addAllSeedMembers(List.of(members)).build();
	}

	private static String member(int i, String namespace) {
		return "stratum-" + i + ".stratum." + namespace + ".svc.cluster.local:5001";
	}

	private static Kernel.BootstrapTenant bootstrap(String name, String tid, Stratum.StratumTenantConfig stratum) {
		return Kernel.BootstrapTenant.newBuilder().setName(name).setTid(tid).addAllStratumSeedMembers(stratum.getSeedMembersList()).build();
	}

	/** A real Ed25519 public JWK, as a cred_pair carries one. */
	private static JwkOuterClass.Jwk adminKey() {
		List<JwkOuterClass.Jwk> published = new ArrayList<>();
		KeyRotator keys = new KeyRotator(3600, 86_400, published::add, kid -> { }, () -> published, null);
		keys.start();
		try {
			return keys.getActiveJwk(KeyRotator.SigAlg.ED25519);
		} finally {
			keys.stop();
		}
	}

	private Stratum.StratumTenantConfig stored(String ns) {
		return configMap.getTenantConfigs(ns).getConfig().getStratum();
	}

	@Test
	void eachTenantGetsOnlyItsOwnSeedMembers() throws Exception {
		Stratum.StratumTenantConfig acme = seeds(member(0, "tac-dev-q1w2e3r4"));
		Stratum.StratumTenantConfig beta = seeds(member(0, "tac-dev-z9x8c7v6"), member(1, "tac-dev-z9x8c7v6"));

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("acme", "q1w2e3r4", acme), bootstrap("beta", "z9x8c7v6", beta)));

		assertEquals(acme, stored(ACME));
		assertEquals(beta, stored(BETA));
		assertEquals(ACME, configMap.getTenantConfigs(ACME).getTenantName(), "the entry is keyed as kernel keys it");
		assertEquals(BETA, configMap.getTenantConfigs(BETA).getTenantName());
	}

	@Test
	void theBootstrapValueReplacesTheStoredSliceOnEveryBoot() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("acme", "q1w2e3r4", seeds("old-0:5001", "old-1:5001"))));

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("acme", "q1w2e3r4", seeds("new-0:5001"))));
		assertEquals(seeds("new-0:5001"), stored(ACME));

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("acme", "q1w2e3r4", Stratum.StratumTenantConfig.getDefaultInstance())));
		assertFalse(configMap.getTenantConfigs(ACME).getConfig().hasStratum(), "no seed members clears it");
	}

	@Test
	void theRestOfTheTenantsConfigIsKept() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4", seeds("a:5001"))));
		Oauth.OAuthTenantConfig oauth = Oauth.OAuthTenantConfig.newBuilder()
				.addProviders(Oauth.OAuthProvider.newBuilder()
						.setIssuerUrl("https://idp.example.com")
						.setClientId("client-acme")
						.setClientSecret("secret-acme"))
				.build();
		Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ACME);
		configMap.putTenantConfigs(ACME, entry.toBuilder()
				.setConfig(entry.getConfig().toBuilder().setOauth(oauth))
				.build());

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4", seeds("b:5001"))));

		assertEquals(seeds("b:5001"), stored(ACME));
		assertEquals(oauth, configMap.getTenantConfigs(ACME).getConfig().getOauth());
	}

	@Test
	void aTenantTheBootstrapDoesNotListIsLeftAlone() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("acme", "q1w2e3r4", seeds("a:5001")), bootstrap("beta", "z9x8c7v6", seeds("b:5001"))));

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4", seeds("a:5001"))));

		assertEquals(seeds("b:5001"), stored(BETA));
	}

	@Test
	void anEmptySliceWritesNoEntryForATenantWithoutOne() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("acme", "q1w2e3r4", Stratum.StratumTenantConfig.getDefaultInstance())));

		assertTrue(configMap.getTenantConfigs(ACME).getTenantName().isEmpty());
	}

	@Test
	void thePeopleTenantTakesItsSliceOnly() throws Exception {
		PeopleTenant.seed(configMap, List.of());
		Kernel.Tenant record = configMap.getTenants(PeopleTenant.NAMESPACE);
		TenantConfigOuterClass.TenantConfig before = configMap.getTenantConfigs(PeopleTenant.NAMESPACE).getConfig();

		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("people", "", seeds(member(0, "tac-dev-00000001")))));
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(
				bootstrap("people", TenantIds.PEOPLE, seeds(member(0, "tac-dev-00000001"), member(1, "tac-dev-00000001")))));

		assertEquals(record, configMap.getTenants(PeopleTenant.NAMESPACE), "its record is PeopleTenant's alone");
		TenantConfigOuterClass.TenantConfig after = configMap.getTenantConfigs(PeopleTenant.NAMESPACE).getConfig();
		assertEquals(seeds(member(0, "tac-dev-00000001"), member(1, "tac-dev-00000001")), after.getStratum());
		assertEquals(before.getOauth(), after.getOauth());
	}

	@Test
	void thePeopleTenantRefusesAnyOtherTid() throws Exception {
		PeopleTenant.seed(configMap, List.of());

		assertThrows(ProtoException.class, () -> TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(bootstrap("people", "q1w2e3r4", seeds("p:5001")))));
		assertFalse(configMap.getTenantConfigs(PeopleTenant.NAMESPACE).getConfig().hasStratum());
	}

	@Test
	void theRestoreTenantIsStillRefused() throws Exception {
		RestoreTenant.seed(configMap);

		assertThrows(ProtoException.class, () -> TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(bootstrap("restore", "", seeds("r:5001")))));
		assertFalse(configMap.getTenantConfigs(RestoreTenant.NAMESPACE).getConfig().hasStratum());
	}

	@Test
	void aRefusedTenantGetsNoSlice() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4", seeds("a:5001"))));

		assertThrows(ProtoException.class, () -> TenantAdminServiceImpl.seedBootstrapTenants(configMap,
				List.of(bootstrap("acme", "a1s2d3f4", seeds("other:5001")))));
		assertEquals(seeds("a:5001"), stored(ACME), "an entry whose tid is refused writes nothing");
	}

	@Test
	void setTenantConfigKeepsTheStoredSlice() throws Exception {
		TenantAdminServiceImpl.seedBootstrapTenants(configMap, List.of(bootstrap("acme", "q1w2e3r4", seeds("a:5001"))));
		configMap.putTenants(ACME, configMap.getTenants(ACME).toBuilder()
				.setConstraints(Kernel.Constraints.newBuilder()
						.setEntitlementsCeiling(TenantAdminServiceImpl.buildFullEntitlements()))
				.build());
		Credentials.KernelTenantConfig kernel = Credentials.KernelTenantConfig.newBuilder()
				.addCredPairs(Credentials.CredPair.newBuilder()
						.setId("cp-admin")
						.setTenantName(ACME)
						.setPublicKey(adminKey())
						.setEntitlements(TenantAdminServiceImpl.buildFullEntitlements())
						.addNamespaces("*"))
				.build();

		admin.updateTenantConfig(null, Kernel.SetTenantConfigRequest.newBuilder()
				.setTenantNamespace(ACME)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder()
						.setKernel(kernel)
						.setStratum(seeds("other:5001")))
				.build());
		assertEquals(seeds("a:5001"), stored(ACME), "a config naming another slice must not write it");
		assertEquals(kernel.getCredPairsList(), configMap.getTenantConfigs(ACME).getConfig().getKernel().getCredPairsList());

		admin.updateTenantConfig(null, Kernel.SetTenantConfigRequest.newBuilder()
				.setTenantNamespace(ACME)
				.setConfig(TenantConfigOuterClass.TenantConfig.newBuilder().setKernel(kernel))
				.build());
		assertEquals(seeds("a:5001"), stored(ACME), "a config without the slice must not clear it");
	}
}
