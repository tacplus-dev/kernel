// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;

import java.security.SecureRandom;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tenant ids. Every tenant carries a {@code tid}: exactly 8 characters of
 * {@code [0-9a-z]}, minted once, immutable, never reused. It names the tenant's
 * Kubernetes namespace ({@code tac-<deployment>-<tid>}), which cannot be
 * renamed, so the tenant's name is not usable there.
 *
 * <ul>
 *   <li><b>Unique:</b> a tid is claimed by inserting its {@code TenantIdRow}
 *       into {@code ConfigState.tenant_ids} if absent. Whoever inserts it holds
 *       it; nobody else can.</li>
 *   <li><b>Never reused:</b> the row is never deleted. Deleting a tenant
 *       tombstones its row, so the insert of that tid fails forever after.</li>
 *   <li><b>Reserved:</b> every all-digit tid is the platform's, so a human
 *       recognises one at a glance. {@code people} is {@value #PEOPLE} and
 *       {@code restore} is {@value #RESTORE} in every deployment. A minted tid
 *       starts with a letter, so it can never fall in that range.</li>
 * </ul>
 */
final class TenantIds {

	private static final Logger logger = LoggerFactory.getLogger(TenantIds.class);

	/** The reserved {@code people} tenant's tid (see {@link PeopleTenant}). */
	static final String PEOPLE = "00000001";

	/** The reserved {@code restore} tenant's tid (see {@link RestoreTenant}). */
	static final String RESTORE = "00000002";

	/** Every tenant namespace lies under it. */
	private static final String TENANTS_PREFIX = "/tenants/";

	private static final int LENGTH = 8;
	private static final Pattern WELL_FORMED = Pattern.compile("^[0-9a-z]{8}$");
	private static final Pattern RESERVED = Pattern.compile("^[0-9]{8}$");
	private static final String LETTERS = "abcdefghijklmnopqrstuvwxyz";
	private static final String ALPHABET = "0123456789" + LETTERS;
	private static final SecureRandom RANDOM = new SecureRandom();

	private TenantIds() {
	}

	/** Exactly 8 of {@code [0-9a-z]}. */
	static boolean isWellFormed(String tid) {
		return tid != null && WELL_FORMED.matcher(tid).matches();
	}

	/** All digits: the platform's range. */
	static boolean isReserved(String tid) {
		return tid != null && RESERVED.matcher(tid).matches();
	}

	/**
	 * A fresh random tid: a letter, then 7 of {@code [0-9a-z]} (about 41 bits),
	 * so never all digits.
	 */
	static String newTid() {
		StringBuilder b = new StringBuilder(LENGTH);
		b.append(LETTERS.charAt(RANDOM.nextInt(LETTERS.length())));
		for (int i = 1; i < LENGTH; i++) {
			b.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
		}
		return b.toString();
	}

	/** Mints a fresh tid for {@code namespace} and claims it. */
	static String mint(ConfigMap configMap, String namespace) throws ProtoException {
		return mint(configMap, namespace, TenantIds::newTid);
	}

	/**
	 * Claims the first candidate nobody holds, live or tombstoned, for
	 * {@code namespace}. A collision is not an error, just another draw.
	 */
	static String mint(ConfigMap configMap, String namespace, Supplier<String> candidates)
			throws ProtoException {
		while (true) {
			String tid = candidates.get();
			Kernel.TenantIdRow row = row(tid, namespace);
			if (configMap.putIfAbsentTenantIds(tid, row) == row) {
				logger.info("Minted tid {} for {}", tid, namespace);
				return tid;
			}
		}
	}

	/**
	 * Claims a GIVEN tid for {@code namespace}: a reserved tenant's fixed one, or
	 * one the deployment's bootstrap config carries. Claiming the tid a live
	 * {@code namespace} already holds is a no-op, so a seed can run at every
	 * boot; a tid held by another tenant, or tombstoned, is refused.
	 */
	static void claim(ConfigMap configMap, String tid, String namespace) throws ProtoException {
		if (!isWellFormed(tid)) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"tid \"" + tid + "\" is not 8 of [0-9a-z]");
		}
		Kernel.TenantIdRow row = row(tid, namespace);
		Kernel.TenantIdRow held = configMap.putIfAbsentTenantIds(tid, row);
		if (held == row) {
			logger.info("Claimed tid {} for {}", tid, namespace);
			return;
		}
		if (held.getTombstonedAtMs() != 0) {
			throw new ProtoException(ProtoException.ALREADY_EXISTS,
					"tid " + tid + " belonged to a deleted tenant and is never reused");
		}
		if (!held.getTenantNamespace().equals(namespace)) {
			throw new ProtoException(ProtoException.ALREADY_EXISTS,
					"tid " + tid + " already belongs to " + held.getTenantNamespace());
		}
	}

	/** Tombstones {@code tid}: its tenant is gone, and the tid stays taken. */
	static void tombstone(ConfigMap configMap, String tid) throws ProtoException {
		Kernel.TenantIdRow held = configMap.getTenantIds(tid);
		if (held.getTid().isEmpty() || held.getTombstonedAtMs() != 0) {
			return;
		}
		configMap.putTenantIds(tid, held.toBuilder()
				.setTombstonedAtMs(System.currentTimeMillis())
				.build());
		logger.info("Tombstoned tid {} of {}", tid, held.getTenantNamespace());
	}

	/**
	 * The deleted tenant {@code namespace} lies in, or null when it lies in none
	 * (kernel#19). A tenant is deleted when its tid is tombstoned and no live
	 * tenant record holds its namespace: a tenant created again under the same
	 * name is a new, live tenant, and the loser of a backfill race (a tombstoned
	 * tid beside a live record) is no deletion at all.
	 *
	 * <p>{@code namespace} is a token's: a tenant, a project, or one nested below
	 * them, so every {@code /tenants/...} prefix of it is checked. A prefix with
	 * a live tenant or project record is live and costs one keyed read; only
	 * when some prefix has neither (a deleted tenant, or one a deployment names
	 * in its delegates without a kernel record) are the tid rows read.
	 */
	static String deletedTenantOf(ConfigMap configMap, String namespace) throws ProtoException {
		if (configMap == null || namespace == null || !namespace.startsWith(TENANTS_PREFIX)) {
			return null;
		}
		java.util.Set<String> unrecorded = new java.util.HashSet<>();
		for (int end = namespace.indexOf('/', TENANTS_PREFIX.length()); ;
				end = namespace.indexOf('/', end + 1)) {
			String prefix = end < 0 ? namespace : namespace.substring(0, end);
			if (configMap.getTenants(prefix).getName().isEmpty()
					&& configMap.getProjectConfigs(prefix).getProjectNamespace().isEmpty()) {
				unrecorded.add(prefix);
			}
			if (end < 0) {
				break;
			}
		}
		if (unrecorded.isEmpty()) {
			return null;
		}
		for (Kernel.TenantIdRow row : configMap.proto().getTenantIdsList()) {
			if (row.getTombstonedAtMs() != 0 && unrecorded.contains(row.getTenantNamespace())) {
				return row.getTenantNamespace();
			}
		}
		return null;
	}

	/**
	 * The authorization namespace of a subject, or null when it names no live
	 * tenant (kernel#23). A tenant-owned service or workload subject is rooted
	 * at its tenant's tid, {@code spiffe://<td>/tenants/<tid>/services/<svc>},
	 * and its namespace is the tenant's name, {@code /tenants/<name>}, read from
	 * the tid's {@code TenantIdRow}: the namespace claim, the delegate key and
	 * the grants stay on the name, as every user token's do. A tid that is not
	 * issued, or is tombstoned, names no live tenant. Every other subject, a
	 * {@code /system} service or a user, keeps the namespace its path spells.
	 *
	 * @throws IllegalArgumentException when {@code subject} is not a SPIFFE ID the grammar accepts
	 */
	static String namespaceOfSubject(ConfigMap configMap, String subject) throws ProtoException {
		Kernel.TenantIdRow row = tidRowOf(configMap, subject);
		if (row == null) {
			return Spiffe.namespaceFromSpiffe(subject);
		}
		return row.getTid().isEmpty() || row.getTombstonedAtMs() != 0 ? null : row.getTenantNamespace();
	}

	/**
	 * The tenant namespace a tenant-owned service subject was minted for, live
	 * or deleted, for the sweep that removes a deleted tenant's state: the tid's
	 * row outlives the tenant. A subject whose tenant segment is no issued tid
	 * (one minted before kernel#23, by name) keeps the namespace its path spells.
	 *
	 * @throws IllegalArgumentException when {@code subject} is not a SPIFFE ID the grammar accepts
	 */
	static String mintedNamespaceOfSubject(ConfigMap configMap, String subject) throws ProtoException {
		Kernel.TenantIdRow row = tidRowOf(configMap, subject);
		return row == null || row.getTid().isEmpty()
				? Spiffe.namespaceFromSpiffe(subject) : row.getTenantNamespace();
	}

	/**
	 * The {@code TenantIdRow} a tenant-owned service or workload subject's tid
	 * keys (empty when no such tid was issued), or null when the subject is not
	 * one: a {@code /system} service, or a user. A tenant segment that is not a
	 * well-formed tid, or a path nested below it, keys an empty row.
	 */
	private static Kernel.TenantIdRow tidRowOf(ConfigMap configMap, String subject) throws ProtoException {
		Spiffe.ParsedSpiffeId parsed = Spiffe.parseSpiffeId(subject);
		String namespace = Spiffe.normalizeNamespace(parsed.namespace);
		if (!namespace.startsWith(TENANTS_PREFIX)
				|| (parsed.subjectKind != Spiffe.SubjectKind.SERVICE
						&& parsed.subjectKind != Spiffe.SubjectKind.WORKLOAD)) {
			return null;
		}
		String tid = namespace.substring(TENANTS_PREFIX.length());
		if (!isWellFormed(tid) || configMap == null) {
			return Kernel.TenantIdRow.getDefaultInstance();
		}
		return configMap.getTenantIds(tid);
	}

	/** True when {@code namespace} is {@code tenantNamespace} or lies below it. */
	static boolean isWithin(String namespace, String tenantNamespace) {
		return namespace != null
				&& (namespace.equals(tenantNamespace) || namespace.startsWith(tenantNamespace + "/"));
	}

	/**
	 * Gives every tenant record that has no tid one: the records a kernel wrote
	 * before tids existed. Runs at boot, after the snapshot is restored and the
	 * seeds ran. The record is written with a compare-and-set, so of two kernels
	 * booting at once one wins and the loser's tid is tombstoned, never handed
	 * out.
	 */
	static void backfill(ConfigMap configMap) throws ProtoException {
		Kernel.ConfigState state = configMap.proto();
		for (String namespace : ClusterServer.tenantNamespaces(
				state.getTenantConfigsList(), state.getProjectConfigsList())) {
			Kernel.Tenant tenant = configMap.getTenants(namespace);
			if (tenant.getName().isEmpty() || !tenant.getTid().isEmpty()) {
				continue;
			}
			String tid = mint(configMap, namespace);
			if (!configMap.replaceTenants(namespace, tenant, tenant.toBuilder().setTid(tid).build())) {
				tombstone(configMap, tid);
			}
		}
	}

	private static Kernel.TenantIdRow row(String tid, String namespace) {
		return Kernel.TenantIdRow.newBuilder()
				.setTid(tid)
				.setTenantNamespace(namespace)
				.setCreatedAtMs(System.currentTimeMillis())
				.build();
	}
}
