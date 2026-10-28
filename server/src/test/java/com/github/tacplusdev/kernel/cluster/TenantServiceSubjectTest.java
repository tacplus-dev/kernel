// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * A tenant-owned service identity carries its tenant's tid (kernel#23):
 * {@code spiffe://<td>/tenants/<tid>/services/<svc>}. It still acts in its
 * tenant's name, {@code /tenants/<name>}, which kernel resolves from the tid,
 * so the namespace claim, delegate keys and grants stay name-based.
 */
class TenantServiceSubjectTest {

	private static final String TD = "test.schematic.io";
	private static final String ACME = "/tenants/acme";
	private static final String ACME_PROD = "/tenants/acme/prod";

	private ConfigMap configMap;
	private TenantAdminServiceImpl admin;

	@BeforeEach
	void setUp() throws Exception {
		configMap = new ConfigMap(new InMemoryManager());
		PeopleTenant.seed(configMap, List.of());
		admin = new TenantAdminServiceImpl(configMap, () -> TD, () -> { });
		create(ACME);
	}

	private Kernel.Tenant create(String ns) throws ProtoException {
		return admin.createTenant(null, Kernel.CreateTenantRequest.newBuilder().setTenantNamespace(ns).build());
	}

	private String tid(String ns) throws ProtoException {
		return configMap.getTenants(ns).getTid();
	}

	private static String service(String tid, String name) {
		return SpiffeIds.build(TD, SpiffeIds.tenantRoot(tid), name);
	}

	@Test
	void aTidSubjectActsInItsTenantsName() throws Exception {
		String subject = service(tid(ACME), "docmanager");

		assertEquals("spiffe://" + TD + "/tenants/" + tid(ACME) + "/services/docmanager", subject);
		assertEquals(ACME, TenantIds.namespaceOfSubject(configMap, subject));
		assertEquals("docmanager", SpiffeIds.serviceName(subject));
	}

	@Test
	void aWorkloadUnderATidSubjectActsInItsTenantsName() throws Exception {
		String child = Spiffe.workloadSpiffeId(service(tid(ACME), "docmanager"), "pigeon");

		assertEquals(ACME, TenantIds.namespaceOfSubject(configMap, child));
	}

	/** A sub-tenant has a tid of its own, so its instances hang flat from it. */
	@Test
	void aSubTenantsInstanceIsRootedAtItsOwnTid() throws Exception {
		create(ACME_PROD);
		String subject = service(tid(ACME_PROD), "docmanager");

		assertEquals(ACME_PROD, TenantIds.namespaceOfSubject(configMap, subject));
		assertEquals(4, Spiffe.parseSpiffeId(subject).pathSegments.size(), subject);
	}

	/** The reserved, all-digit tids are legal in the grammar and resolve too. */
	@Test
	void aReservedTidSubjectResolves() throws Exception {
		String subject = service(TenantIds.PEOPLE, "scotty");

		assertEquals(Spiffe.SubjectKind.SERVICE, Spiffe.parseSpiffeId(subject).subjectKind);
		assertEquals(PeopleTenant.NAMESPACE, TenantIds.namespaceOfSubject(configMap, subject));
	}

	@Test
	void systemAndUserSubjectsKeepTheNamespaceTheirPathSpells() throws Exception {
		assertEquals("/system", TenantIds.namespaceOfSubject(configMap, SpiffeIds.build(TD, "eventbus")));
		String tenantUser = Spiffe.namespaceSpiffeId(TD, ACME) + "/users/alice";
		assertEquals(ACME, TenantIds.namespaceOfSubject(configMap, tenantUser));
	}

	@Test
	void aTombstonedTidNamesNoLiveTenant() throws Exception {
		String subject = service(tid(ACME), "docmanager");
		admin.deleteTenant(null, Kernel.DeleteTenantRequest.newBuilder().setTenantNamespace(ACME).build());

		assertNull(TenantIds.namespaceOfSubject(configMap, subject));
		// The sweep that clears a deleted tenant's state still finds it.
		assertEquals(ACME, TenantIds.mintedNamespaceOfSubject(configMap, subject));

		// A tenant created again under the same name is another tid: the old
		// identity does not reach it.
		create(ACME);
		assertNull(TenantIds.namespaceOfSubject(configMap, subject));
	}

	@Test
	void aSubjectSpelledByTheTenantsNameNamesNoLiveTenant() throws Exception {
		String nameForm = SpiffeIds.build(TD, ACME, "docmanager");

		assertNull(TenantIds.namespaceOfSubject(configMap, nameForm));
		assertNull(TenantIds.namespaceOfSubject(configMap, service("q1w2e3r4", "docmanager")),
				"a tid nobody was issued");
		assertNull(TenantIds.namespaceOfSubject(null, service(tid(ACME), "docmanager")),
				"no tenant records, no tenant");
		assertEquals(ACME, TenantIds.mintedNamespaceOfSubject(configMap, nameForm));
	}

	@Test
	void theIdentityNamesTheTidOnly() throws Exception {
		String subject = service(tid(ACME), "docmanager");

		assertFalse(subject.contains("/acme/"), subject);
	}
}
