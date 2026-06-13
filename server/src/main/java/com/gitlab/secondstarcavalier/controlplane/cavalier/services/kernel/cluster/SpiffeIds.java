// Copyright (c) 2024 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.libs.spiffe.Spiffe;

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
 *       {@code spiffe://<td>/system/services/<svc>}.</li>
 *   <li>The authorization-tree root is {@code "/"}, at-or-above every
 *       {@code /system...} and {@code /tenants...} namespace.</li>
 * </ul>
 */
public final class SpiffeIds {

	private SpiffeIds() {
	}

	/**
	 * Builds the canonical location-agnostic service SPIFFE URI for a
	 * kernel-minted token subject.
	 */
	public static String build(String trustDomain, String serviceName) {
		return Spiffe.serviceSpiffeId(trustDomain, "", serviceName);
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
