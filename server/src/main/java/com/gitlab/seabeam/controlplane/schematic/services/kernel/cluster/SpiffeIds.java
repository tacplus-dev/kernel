// Copyright (c) 2026 Seabeam LLC. All rights reserved.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;

/**
 * Thin kernel-side adapter over the generated {@link Spiffe} helper.
 *
 * <p>SPIFFE identity construction and the authorization namespace grammar are
 * owned by tacplus (the generated {@code libs/spiffe} helper). This class keeps
 * the kernel server on a small, stable surface and centralizes two kernel
 * conventions:
 *
 * <ul>
 *   <li>Kernel-minted token subjects are location-agnostic service identities:
 *       {@code spiffe://<td>/system/services/<svc>} for a shared platform
 *       service, {@code spiffe://<td>/tenants/<tenant>/services/<svc>} for a
 *       tenant-owned instance.</li>
 *   <li>The authorization-tree root is {@code "/"}, at-or-above every
 *       {@code /system...} and {@code /tenants...} namespace.</li>
 * </ul>
 */
public final class SpiffeIds {

	/** The namespace every shared platform service identity is rooted at. */
	public static final String SYSTEM_NAMESPACE = "/" + Spiffe.SYSTEM_SEGMENT;

	private SpiffeIds() {
	}

	/**
	 * Builds the canonical location-agnostic service SPIFFE URI for a
	 * kernel-minted token subject rooted at {@code /system}.
	 */
	public static String build(String trustDomain, String serviceName) {
		return build(trustDomain, "", serviceName);
	}

	/**
	 * Builds a kernel-minted service subject rooted at {@code namespace}: an
	 * empty namespace is the shared {@code /system} root, a tenant-owned
	 * service instance passes its canonical {@code /tenants/<tenant>}. The
	 * service name is the same location-agnostic service path either way, so
	 * {@code auth_services} patterns match a tenant instance exactly as they
	 * match the shared one.
	 */
	public static String build(String trustDomain, String namespace, String serviceName) {
		if (namespace == null || namespace.isEmpty()) {
			return Spiffe.serviceSpiffeId(trustDomain, "", serviceName);
		}
		return Spiffe.namespaceSpiffeId(trustDomain, namespace)
				+ "/" + Spiffe.SERVICES_SEGMENT + "/" + Spiffe.normalizeSegment(serviceName);
	}

	/**
	 * A person's identity: {@code spiffe://<td>/users/<xid>}. Rooted at the
	 * tree's root, not at any tenant — the XID names no tenant, cluster or IdP,
	 * so the same human is the same subject in every tenant's access token. The
	 * tenant is the token's {@code namespace} claim, never part of the subject.
	 */
	public static String userSubject(String trustDomain, String xid) {
		return Spiffe.userSpiffeId(trustDomain, namespaceRoot(), xid);
	}

	/** Returns true if the value is a SPIFFE URI. */
	public static boolean isSpiffeUri(String value) {
		return value != null && value.startsWith(Spiffe.SCHEME + "://");
	}

	/** Normalized authorization namespace of a SPIFFE URI, for example /system. */
	public static String namespaceFromSpiffe(String spiffeId) {
		return Spiffe.namespaceFromSpiffe(spiffeId);
	}

	/**
	 * The authorization-tree root namespace. A token at the root is at-or-above
	 * any tenant/project/system namespace for level-or-below checks.
	 */
	public static String namespaceRoot() {
		return "/";
	}

	/**
	 * Location-agnostic service path of a service SPIFFE URI, with any system
	 * location segments stripped.
	 */
	public static String serviceName(String spiffeId) {
		return Spiffe.servicePathFromSpiffe(spiffeId);
	}
}
