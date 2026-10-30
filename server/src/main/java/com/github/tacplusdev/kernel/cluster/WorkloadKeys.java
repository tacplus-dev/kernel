// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.jwk.ImmutableJwk;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.types.common.credentials.Credentials;
import com.github.tacplusdev.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Workload keys (kernel#28): key-pair credentials for a tenant's own workloads
 * that cannot federate, held in the tenant's {@code KernelTenantConfig.workload_keys}.
 * Only the public half is held. A workload signs an assertion with the private
 * half and {@code MintClientToken} exchanges it for an ordinary short-lived
 * service access token for the key's subject; see {@code credentials.WorkloadKey}.
 *
 * <p>What a key may do now is computed, never stored: revoked, then expired
 * (the tenant's optional maximum lifetime), then disabled (unused for longer
 * than the tenant's inactivity window), else active. A disabled key stays
 * disabled because only a mint records use, and a disabled key mints nothing.
 */
final class WorkloadKeys {

	/** The inactivity window a tenant gets when it sets none: 90 days. */
	static final long DEFAULT_INACTIVE_AFTER_SECONDS = 90L * 86_400;

	/**
	 * How stale {@code last_used_at} may be before a mint writes it again. A mint
	 * rewrites the tenant's config, so recording every one would put a config
	 * write on the token path; against a 90-day window an hour is exact enough.
	 */
	static final long LAST_USED_RESOLUTION_SECONDS = 3600;

	/** Longest an assertion may live, from its {@code iat} to its {@code exp}. */
	static final long MAX_ASSERTION_LIFETIME_SECONDS = 300;

	/** The id prefix: a workload key's kid reads as one. */
	private static final String ID_PREFIX = "wk-";

	private static final String ID_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
	private static final SecureRandom RANDOM = new SecureRandom();

	private WorkloadKeys() {
	}

	/** A workload key and the tenant whose config holds it. */
	record Owned(String tenantNamespace, Credentials.WorkloadKey key, Credentials.WorkloadKeyPolicy policy) {
		Kernel.WorkloadKeyState state(long nowSeconds) {
			return WorkloadKeys.state(key, policy, nowSeconds);
		}
	}

	/** A fresh id: the prefix and 26 base32 characters (130 random bits). */
	static String newId() {
		StringBuilder b = new StringBuilder(ID_PREFIX);
		for (int i = 0; i < 26; i++) {
			b.append(ID_ALPHABET.charAt(RANDOM.nextInt(ID_ALPHABET.length())));
		}
		return b.toString();
	}

	/** The effective inactivity window of {@code policy}. */
	static long inactiveAfterSeconds(Credentials.WorkloadKeyPolicy policy) {
		long configured = policy.getInactiveAfterSeconds();
		return configured > 0 ? configured : DEFAULT_INACTIVE_AFTER_SECONDS;
	}

	/**
	 * The epoch second {@code key} stops minting at by its maximum lifetime, or
	 * {@link Long#MAX_VALUE} when the tenant sets none.
	 */
	static long expiresAt(Credentials.WorkloadKey key, Credentials.WorkloadKeyPolicy policy) {
		long max = policy.getMaxLifetimeSeconds();
		return max > 0 ? key.getCreatedAt().getSeconds() + max : Long.MAX_VALUE;
	}

	/** What {@code key} may do at {@code nowSeconds} under its tenant's {@code policy}. */
	static Kernel.WorkloadKeyState state(Credentials.WorkloadKey key, Credentials.WorkloadKeyPolicy policy,
			long nowSeconds) {
		if (key.hasRevokedAt()) {
			return Kernel.WorkloadKeyState.WORKLOAD_KEY_STATE_REVOKED;
		}
		if (nowSeconds >= expiresAt(key, policy)) {
			return Kernel.WorkloadKeyState.WORKLOAD_KEY_STATE_EXPIRED;
		}
		long lastUsed = key.hasLastUsedAt() ? key.getLastUsedAt().getSeconds() : key.getCreatedAt().getSeconds();
		if (nowSeconds - lastUsed > inactiveAfterSeconds(policy)) {
			return Kernel.WorkloadKeyState.WORKLOAD_KEY_STATE_DISABLED;
		}
		return Kernel.WorkloadKeyState.WORKLOAD_KEY_STATE_ACTIVE;
	}

	/**
	 * Every workload key with {@code id}, in whichever tenant holds it. Kernel
	 * assigns the ids, so more than one is a fault the caller refuses rather
	 * than resolves by iteration order (as {@code MintClientToken} does for a
	 * cred_pair id).
	 */
	static List<Owned> findById(ConfigMap configMap, String id) throws ProtoException {
		List<Owned> found = new ArrayList<>();
		for (Kernel.TenantConfigEntry e : configMap.proto().getTenantConfigsList()) {
			Credentials.KernelTenantConfig kernel = e.getConfig().getKernel();
			for (Credentials.WorkloadKey key : kernel.getWorkloadKeysList()) {
				if (id.equals(key.getId())) {
					found.add(new Owned(e.getTenantName(), key, kernel.getWorkloadKeyPolicy()));
				}
			}
		}
		return found;
	}

	/**
	 * Refuses a public key that is not Ed25519 or EC P-256, or does not load.
	 * The {@code alg}, when set, must be the one the curve signs with.
	 */
	static void requireSupportedPublicKey(JwkOuterClass.Jwk jwk) throws ProtoException {
		boolean ed25519 = jwk.getKty() == KeyOuterClass.KeyType.KEY_TYPE_OKP && "Ed25519".equals(jwk.getCrv())
				&& (jwk.getAlg().isEmpty() || "EdDSA".equals(jwk.getAlg()));
		boolean es256 = jwk.getKty() == KeyOuterClass.KeyType.KEY_TYPE_EC && "P-256".equals(jwk.getCrv())
				&& (jwk.getAlg().isEmpty() || "ES256".equals(jwk.getAlg()));
		if (!ed25519 && !es256) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"a workload key is Ed25519 (OKP) or ES256 (EC P-256)");
		}
		try {
			ImmutableJwk.from(jwk);
		} catch (Exception e) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT, "public_key does not load: " + e.getMessage());
		}
	}

	/**
	 * The public key as kernel stores it: the registrant's key material, with
	 * the kid kernel assigned ({@code id}), created now unless the registrant
	 * dated it, and signature use.
	 */
	static JwkOuterClass.Jwk storedPublicKey(JwkOuterClass.Jwk jwk, String id, long nowSeconds) {
		JwkOuterClass.Jwk.Builder b = jwk.toBuilder().setKid(id).setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG);
		if (jwk.getCreated() == 0) {
			b.setCreated(nowSeconds);
		}
		return b.build();
	}

	/** True when {@code a} and {@code b} are the same public key, whatever their kid or labels. */
	static boolean samePublicKey(JwkOuterClass.Jwk a, JwkOuterClass.Jwk b) {
		return a.getKty() == b.getKty() && a.getCrv().equals(b.getCrv())
				&& a.getX().equals(b.getX()) && a.getY().equals(b.getY());
	}

	/**
	 * Refuses a subject that is not a SPIFFE service or workload ID in
	 * {@code trustDomain} rooted at {@code tenantNamespace}'s own live tid.
	 */
	static void requireSubjectOfTenant(ConfigMap configMap, String trustDomain, String tenantNamespace,
			String subject) throws ProtoException {
		Spiffe.ParsedSpiffeId parsed;
		try {
			parsed = Spiffe.parseSpiffeId(subject);
		} catch (IllegalArgumentException e) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT, "subject is not a SPIFFE ID: " + e.getMessage());
		}
		if (parsed.subjectKind != Spiffe.SubjectKind.SERVICE && parsed.subjectKind != Spiffe.SubjectKind.WORKLOAD) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"subject must be a service or workload identity, not " + parsed.subjectKind);
		}
		if (trustDomain != null && !trustDomain.isEmpty()
				&& !Spiffe.normalizeTrustDomain(trustDomain).equals(parsed.trustDomain)) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT,
					"subject is not in trust domain " + trustDomain);
		}
		// A tenant-owned subject is rooted at the tid, and the tid's row names the
		// tenant it acts for: anything else (a /system service, another tenant's
		// tid, a tombstoned one, a name in place of the tid) is not this tenant's.
		String namespace;
		try {
			namespace = TenantIds.namespaceOfSubject(configMap, subject);
		} catch (IllegalArgumentException e) {
			throw new ProtoException(ProtoException.INVALID_ARGUMENT, "subject is not a SPIFFE ID: " + e.getMessage());
		}
		if (namespace == null || !namespace.equals(tenantNamespace)
				|| !Spiffe.normalizeNamespace(parsed.namespace).startsWith("/tenants/")) {
			throw new ProtoException(ProtoException.PERMISSION_DENIED,
					"subject " + subject + " is not an identity of " + tenantNamespace
							+ " (spiffe://<td>/tenants/<its tid>/services/<name>)");
		}
	}

	/**
	 * Records that {@code id}, held by {@code tenantNamespace}, minted at
	 * {@code nowSeconds}, unless it was recorded within the last
	 * {@link #LAST_USED_RESOLUTION_SECONDS}. Returns whether it wrote.
	 *
	 * <p>The write replaces the tenant's whole config entry, as every config
	 * write does, so a mint racing an UpdateTenantConfig on another node can
	 * lose one of the two; at most an hour of {@code last_used_at} is lost that
	 * way, and UpdateTenantConfig keeps the stored keys anyway.
	 */
	static boolean recordUse(ConfigMap configMap, String tenantNamespace, String id, long nowSeconds)
			throws ProtoException {
		Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(tenantNamespace);
		Credentials.KernelTenantConfig kernel = entry.getConfig().getKernel();
		for (int i = 0; i < kernel.getWorkloadKeysCount(); i++) {
			Credentials.WorkloadKey key = kernel.getWorkloadKeys(i);
			if (!id.equals(key.getId())) {
				continue;
			}
			if (key.hasLastUsedAt()
					&& nowSeconds - key.getLastUsedAt().getSeconds() < LAST_USED_RESOLUTION_SECONDS) {
				return false;
			}
			Credentials.WorkloadKey used = key.toBuilder()
					.setLastUsedAt(Timestamp.newBuilder().setSeconds(nowSeconds))
					.build();
			putKernelConfig(configMap, entry, kernel.toBuilder().setWorkloadKeys(i, used).build());
			return true;
		}
		return false;
	}

	/** Writes {@code kernel} as the kernel slice of {@code entry}'s tenant config. */
	static void putKernelConfig(ConfigMap configMap, Kernel.TenantConfigEntry entry,
			Credentials.KernelTenantConfig kernel) throws ProtoException {
		TenantConfigOuterClass.TenantConfig config = entry.getConfig().toBuilder().setKernel(kernel).build();
		configMap.putTenantConfigs(entry.getTenantName(), entry.toBuilder().setConfig(config).build());
	}
}
