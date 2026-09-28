package com.gitlab.seabeam.controlplane.codegen;

import com.gitlab.seabeam.controlplane.codegen.model.AccessPolicy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Access policies for state roots declared in tacplus's own infra protos.
 *
 * <p>tacplus computes a policy for every {@code (spec.service_state)} message it
 * finds, but {@code ComputeSecurityPolicies} skips any file for which
 * {@code IsInfraProto} is true (tacplus {@code pkg/internal/proto/libs_protos.go}).
 * A state root declared in {@code sys/} therefore never appears in
 * codegen-config.json's {@code securityPolicies}, no matter how it is annotated —
 * it is a structural property of where the message lives, not a missing
 * annotation. Kernel still generates a backend state server for such a root, and
 * that server needs a policy like any other, so the policy is declared here.
 *
 * <p>These entries are merged into the policy list before generation, so they
 * reach both the graph key each generated server carries and the
 * {@code GRAPH_POLICIES} map the generated SecurityAuthenticator enforces against.
 * Declaring one here is the narrow alternative to the old fallback, which emitted
 * {@code NO_POLICY_GRAPH} and left every RPC on the root unauthenticated.
 */
final class InfraStatePolicies {

	/**
	 * {@code grpcconfig.ServiceConfigState} — the single cluster-wide runtime
	 * config (endpoints, TLS trust, logging, SPIFFE trust domain) that every
	 * service reads.
	 *
	 * <p>rw is kernel alone: kernel seeds and maintains the config
	 * (ClusterServer's {@code getServiceConfigStateMap().putConfig}) and is the
	 * only writer anywhere in the platform. ro is {@code *} because the config is
	 * a singleton every service must read to boot — each service's ServiceManager
	 * subscribes through the generated grpcconfig state client. This is the shape
	 * {@code kernel.KernelDiskState} already uses (rw kernel, ro {@code *}).
	 */
	private static final AccessPolicy SERVICE_CONFIG_STATE = new AccessPolicy(
			"ServiceConfigState", "grpcconfig",
			List.of("service:kernel"), List.of("*"), List.of(),
			Map.of(), false, false);

	private static final List<AccessPolicy> POLICIES = List.of(SERVICE_CONFIG_STATE);

	private InfraStatePolicies() {
	}

	/**
	 * Returns {@code computed} plus every infra-proto policy it does not already
	 * carry. A computed policy always wins: if tacplus ever starts emitting one of
	 * these, the declaration here goes quietly unused rather than overriding it.
	 */
	static List<AccessPolicy> merge(List<AccessPolicy> computed) {
		List<AccessPolicy> merged = new ArrayList<>(computed);
		for (AccessPolicy infra : POLICIES) {
			boolean present = computed.stream()
					.anyMatch(p -> infra.graphKey().equals(p.graphKey()));
			if (!present) {
				merged.add(infra);
			}
		}
		return List.copyOf(merged);
	}
}
