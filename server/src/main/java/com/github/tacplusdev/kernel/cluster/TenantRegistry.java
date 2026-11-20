// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The tenant registry as kernel holds it (kernel#69): the top-level tenants the
 * operator approved, one {@link Kernel.TenantRegistryEntry} per tid, read from
 * the system tenant's Stratum ({@link TenantRegistryWatch}) and kept in the
 * disk snapshot ({@code KernelDiskState.tenant_registry}).
 *
 * <p>Applying an entry makes its tenant exist, {@code /tenants/<name>} under the
 * entry's tid, taken as given, exactly as the boot seed of
 * {@code Config.tenants} does; and it derives one delegate per service of the
 * entry's trust, so the tenant's workloads mint their identity before kernel
 * has any of the tenant's settings. An entry is applied only at a higher
 * version than the one held; its tid and its name are immutable.
 */
final class TenantRegistry {

	private static final Logger logger = LoggerFactory.getLogger(TenantRegistry.class);

	private static final String TENANTS_PREFIX = "/" + Spiffe.TENANTS_SEGMENT + "/";

	/** What {@link #apply} did with an entry. */
	enum Outcome {
		/** The entry is held now, and its tenant is as it says. */
		APPLIED,
		/** A version at or above the entry's is held: nothing changed. */
		STALE
	}

	private final ConfigMap configMap;
	private final Runnable writeSnapshot;
	/** The held entries by tid; guarded by this. */
	private final Map<String, Kernel.TenantRegistryEntry> entries = new TreeMap<>();
	/** The delegates the held entries derive, rebuilt on every change. */
	private volatile List<Kernel.Delegate> delegates = List.of();

	/**
	 * @param configMap     kernel ConfigState accessor, where the tenants live
	 * @param writeSnapshot writes the disk snapshot after a change
	 */
	TenantRegistry(ConfigMap configMap, Runnable writeSnapshot) {
		this.configMap = configMap;
		this.writeSnapshot = writeSnapshot;
	}

	/**
	 * Takes the entries of the disk snapshot as held, without applying them: their
	 * tenants are in the same snapshot. Kernel serves them at once, before its
	 * Watch of the registry connects.
	 */
	synchronized void restore(Collection<Kernel.TenantRegistryEntry> restored) {
		for (Kernel.TenantRegistryEntry entry : restored) {
			entries.put(entry.getTid(), entry);
		}
		rebuild();
		if (!restored.isEmpty()) {
			logger.info("Restored {} tenant registry entries from the disk snapshot", restored.size());
		}
	}

	/**
	 * Applies one entry of the registry.
	 *
	 * @return {@link Outcome#STALE} when a version at or above the entry's is held
	 * @throws ProtoException INVALID_ARGUMENT for a malformed entry,
	 *         FAILED_PRECONDITION for one that would change a tenant's tid or name
	 */
	synchronized Outcome apply(Kernel.TenantRegistryEntry entry) throws ProtoException {
		validate(entry);
		Kernel.TenantRegistryEntry held = entries.get(entry.getTid());
		if (held != null && entry.getVersion() <= held.getVersion()) {
			return Outcome.STALE;
		}
		if (held != null && !held.getName().equals(entry.getName())) {
			throw new ProtoException(ProtoException.FAILED_PRECONDITION,
					"tid " + entry.getTid() + " is tenant " + TENANTS_PREFIX + held.getName()
							+ ", not " + TENANTS_PREFIX + entry.getName() + ": a tenant's tid and name are immutable");
		}
		String ns = TENANTS_PREFIX + entry.getName();
		TenantAdminServiceImpl.seedBootstrapTenant(configMap, ns, Kernel.BootstrapTenant.newBuilder()
				.setName(entry.getName())
				.setTid(entry.getTid())
				.build());
		Kernel.TenantStatus status = statusOf(entry);
		Kernel.Tenant tenant = configMap.getTenants(ns);
		if (tenant.getStatus() != status) {
			configMap.putTenants(ns, tenant.toBuilder()
					.setStatus(status)
					.setUpdatedAt(Timestamp.newBuilder().setSeconds(Instant.now().getEpochSecond()))
					.build());
		}
		entries.put(entry.getTid(), entry);
		rebuild();
		writeSnapshot.run();
		logger.info("Tenant registry: {} (tid {}) at version {}, {}, {} service(s)",
				ns, entry.getTid(), entry.getVersion(), status, entry.getServicesCount());
		return Outcome.APPLIED;
	}

	/**
	 * Drops the entry for {@code tid}: the registry no longer lists the tenant,
	 * so its derived delegates go and its workloads mint nothing. The tenant's
	 * record is left; deleting a tenant and its state is TenantAdmin.DeleteTenant's.
	 *
	 * @return whether an entry was held
	 */
	synchronized boolean remove(String tid) {
		Kernel.TenantRegistryEntry held = entries.remove(tid);
		if (held == null) {
			return false;
		}
		rebuild();
		writeSnapshot.run();
		logger.warn("Tenant registry: {} (tid {}) left the registry: it derives no delegates",
				TENANTS_PREFIX + held.getName(), tid);
		return true;
	}

	/** Drops every held entry whose tid is not in {@code listed}: the registry's snapshot is all there is. */
	synchronized void retainOnly(Set<String> listed) {
		for (String tid : new ArrayList<>(entries.keySet())) {
			if (!listed.contains(tid)) {
				remove(tid);
			}
		}
	}

	/** The held entries, by tid, for the disk snapshot. */
	synchronized List<Kernel.TenantRegistryEntry> entries() {
		return List.copyOf(entries.values());
	}

	/**
	 * The delegates the held entries derive: one per service of each active
	 * entry, rooted at its tenant, matching the one Kubernetes service account
	 * the entry names in the tenant's Kubernetes namespace.
	 */
	List<Kernel.Delegate> delegates() {
		return delegates;
	}

	/** {@code configured} (Config.delegates), then the registry's: a configured delegate matches first. */
	List<Kernel.Delegate> withDelegatesOf(List<Kernel.Delegate> configured) {
		List<Kernel.Delegate> derived = delegates;
		if (derived.isEmpty()) {
			return configured;
		}
		List<Kernel.Delegate> all = new ArrayList<>(configured.size() + derived.size());
		all.addAll(configured);
		all.addAll(derived);
		return all;
	}

	private void rebuild() {
		List<Kernel.Delegate> derived = new ArrayList<>();
		for (Kernel.TenantRegistryEntry entry : entries.values()) {
			if (statusOf(entry) != Kernel.TenantStatus.TENANT_STATUS_ACTIVE) {
				continue;
			}
			for (Kernel.TenantRegistryService service : entry.getServicesList()) {
				derived.add(Kernel.Delegate.newBuilder()
						.setName(service.getName())
						.setTenantNamespace(TENANTS_PREFIX + entry.getName())
						.addKubernetesServiceAccounts(Kernel.KubernetesServiceAccountMatcher.newBuilder()
								.setKubernetesNamespace(entry.getKubernetesNamespace())
								.setKubernetesServiceAccount(service.getKubernetesServiceAccount()))
						.addAllAuthorizedServices(service.getAuthorizedServicesList())
						.build());
			}
		}
		delegates = List.copyOf(derived);
	}

	private static Kernel.TenantStatus statusOf(Kernel.TenantRegistryEntry entry) {
		return entry.getStatus() == Kernel.TenantStatus.TENANT_STATUS_SUSPENDED
				? Kernel.TenantStatus.TENANT_STATUS_SUSPENDED
				: Kernel.TenantStatus.TENANT_STATUS_ACTIVE;
	}

	/** The checks the boot seed does not make: the tid is required here, and the trust. */
	private static void validate(Kernel.TenantRegistryEntry entry) throws ProtoException {
		if (!TenantIds.isWellFormed(entry.getTid()) || TenantIds.isReserved(entry.getTid())) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"tid \"" + entry.getTid() + "\" must be 8 of [0-9a-z] and not all digits");
		}
		if (entry.getKubernetesNamespace().isEmpty()) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"tenant " + entry.getTid() + " names no kubernetes_namespace");
		}
		for (Kernel.TenantRegistryService service : entry.getServicesList()) {
			if (service.getName().isEmpty() || service.getName().indexOf('/') >= 0) {
				throw new ProtoException(ProtoException.INVALID_ARGUMENT,
						"tenant " + entry.getTid() + ": a service name must be one bare segment, not \""
								+ service.getName() + "\"");
			}
			if (service.getKubernetesServiceAccount().isEmpty()) {
				throw new ProtoException(ProtoException.INVALID_ARGUMENT,
						"tenant " + entry.getTid() + ": service " + service.getName()
								+ " names no kubernetes_service_account");
			}
		}
	}
}
