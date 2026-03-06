package com.gitlab.secondstarcavalier.controlplane.codegen.model;

import java.util.List;

/**
 * Represents a single access policy for a backend state root.
 * Computed from proto annotations at build time by tacplus.
 *
 * @param name        the state root name (e.g., "ClusterState")
 * @param rw          subjects with read-write access
 * @param ro          subjects with read-only access
 * @param exec        subjects with execution access (unused in namespace model)
 * @param disableAuth true if this backend skips authentication
 * @param internal    true if this backend is private to its namespace (no cross-namespace access)
 */
public record AccessPolicy(String name, List<String> rw, List<String> ro, List<String> exec,
                            boolean disableAuth, boolean internal) {

    /** Compatibility constructor for 4-arg callers. */
    public AccessPolicy(String name, List<String> rw, List<String> ro, List<String> exec) {
        this(name, rw, ro, exec, false, false);
    }
}
