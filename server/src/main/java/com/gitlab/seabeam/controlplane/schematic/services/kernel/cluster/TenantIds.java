// Copyright (c) 2026 Seabeam LLC. All rights reserved.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;

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
