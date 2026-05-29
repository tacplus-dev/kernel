// Copyright (c) 2024 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

/**
 * Canonical SPIFFE-ID construction and validation for kernel-issued
 * certificates and tokens.
 *
 * <p>The SPIFFE identity for a workload in this cluster is built from the
 * cluster's trust-domain prefix and the workload's service name:
 *
 * <pre>spiffe://${trust_domain}/${service_name}</pre>
 *
 * <p>The SPIFFE URI is <b>service-scoped</b>, not per-instance — all replicas
 * of a service share the same SPIFFE identity. Instance disambiguation lives
 * in DNS SANs and cert serial numbers, not in the SPIFFE URI.
 *
 * <p>This identity flows through the system unchanged:
 * <ul>
 *   <li>Kernel mints service tokens with {@code sub} = SPIFFE URI.</li>
 *   <li>Auth interceptor sets {@code callerSubject} = {@code sub} = SPIFFE URI.</li>
 *   <li>Cert minting (both X509Mint and TlsCertService.ManageCert) uses the
 *       SAME SPIFFE URI as the cert's URI SAN — no reconstruction.</li>
 * </ul>
 *
 * <p>Cross-cluster identity is preserved because the trust domain encodes the
 * cluster (e.g. {@code spiffe://local/dev} today, {@code spiffe://prod.us-east-1}
 * later) — service names are unique within a cluster, SPIFFE URIs are unique
 * across clusters.
 *
 * <p>All SPIFFE-URI construction in kernel must go through this class. No
 * ad-hoc string concatenation.
 */
public final class SpiffeIds {

	private static final String SCHEME_PREFIX = "spiffe://";

	// The namespace claim is a leading-slash absolute path (e.g. "/local/dev"),
	// so the SPIFFE URI is formed by prefixing "spiffe:/" (one slash). The result
	// is the same canonical two-slash URI: "spiffe:/" + "/local/dev" = "spiffe://local/dev".
	private static final String NS_SCHEME_PREFIX = "spiffe:/";

	private SpiffeIds() {
	}

	/**
	 * Builds the canonical SPIFFE URI for a service in the given trust domain.
	 *
	 * @param trustDomain cluster trust-domain prefix, no leading slash (e.g. {@code "local/dev"})
	 * @param serviceName bare service name (e.g. {@code "oauth"})
	 * @return canonical SPIFFE URI string (e.g. {@code "spiffe://local/dev/oauth"})
	 */
	public static String build(String trustDomain, String serviceName) {
		if (trustDomain == null || trustDomain.isEmpty()) {
			throw new IllegalArgumentException("trust domain must not be empty");
		}
		if (serviceName == null || serviceName.isEmpty()) {
			throw new IllegalArgumentException("service name must not be empty");
		}
		// Defensive: callers should not pass a value that already has scheme.
		if (serviceName.contains("://")) {
			throw new IllegalArgumentException(
					"service name must not contain a URI scheme: " + serviceName);
		}
		return SCHEME_PREFIX + trustDomain + "/" + serviceName;
	}

	/**
	 * Returns true if the value is a well-formed SPIFFE URI.
	 */
	public static boolean isSpiffeUri(String value) {
		return value != null && value.startsWith(SCHEME_PREFIX) && value.length() > SCHEME_PREFIX.length();
	}

	/**
	 * Extracts the namespace (leading-slash absolute path) from a canonical
	 * SPIFFE URI. e.g. {@code "spiffe://local/dev/oauth"} → {@code "/local/dev/oauth"}.
	 *
	 * <p>Only the {@code "spiffe:/"} scheme prefix (one slash) is stripped, so the
	 * leading slash of the path is retained — yielding the canonical namespace claim
	 * format used for level-or-below checks. Returns empty string if the input is not
	 * a SPIFFE URI.
	 */
	public static String namespaceFromSpiffe(String spiffeId) {
		if (!isSpiffeUri(spiffeId)) {
			return "";
		}
		return spiffeId.substring(NS_SCHEME_PREFIX.length());
	}

	/**
	 * Returns the canonical namespace (leading-slash absolute path) for the cluster
	 * root, given the SPIFFE trust-domain prefix. e.g. {@code "local/dev"} → {@code "/local/dev"}.
	 *
	 * <p>This is the authorization-tree position of the cluster root — the namespace
	 * claim a token receives when it is not scoped to a specific sub-tenant.
	 */
	public static String namespaceRoot(String trustDomain) {
		if (trustDomain == null || trustDomain.isEmpty()) {
			return "";
		}
		return trustDomain.startsWith("/") ? trustDomain : "/" + trustDomain;
	}

	/**
	 * Extracts the bare service name (last path segment) from a SPIFFE URI.
	 *
	 * @param spiffeId canonical SPIFFE URI
	 * @return bare service name
	 * @throws IllegalArgumentException if the input is not a SPIFFE URI or has no path segment
	 */
	public static String serviceName(String spiffeId) {
		if (!isSpiffeUri(spiffeId)) {
			throw new IllegalArgumentException("not a SPIFFE URI: " + spiffeId);
		}
		int lastSlash = spiffeId.lastIndexOf('/');
		if (lastSlash <= SCHEME_PREFIX.length() - 2 || lastSlash == spiffeId.length() - 1) {
			throw new IllegalArgumentException("SPIFFE URI has no service segment: " + spiffeId);
		}
		return spiffeId.substring(lastSlash + 1);
	}
}
