package com.gitlab.secondstarcavalier.controlplane.codegen.model;

import java.util.List;
import java.util.Map;

/**
 * Represents a single access policy for a backend state root.
 * Computed from proto annotations at build time by tacplus.
 *
 * @param name           the state root name (e.g., "ClusterState")
 * @param pkg            the owning proto package (e.g., "kernel"); may be empty
 *                       for policies parsed from backenddb.yaml
 * @param rw             subjects with read-write access
 * @param ro             subjects with read-only access
 * @param exec           subjects with execution access (unused in namespace model)
 * @param boundaryGrants boundary field name → callers granted that boundary,
 *                       from (spec.boundary_callers) on queue/topic/command fields
 * @param disableAuth    true if this backend skips authentication
 * @param internal       true if this backend is private to its namespace (no cross-namespace access)
 */
public record AccessPolicy(String name, String pkg, List<String> rw, List<String> ro, List<String> exec,
                            Map<String, List<String>> boundaryGrants,
                            boolean disableAuth, boolean internal) {

    /** Compatibility constructor for 4-arg callers. */
    public AccessPolicy(String name, List<String> rw, List<String> ro, List<String> exec) {
        this(name, "", rw, ro, exec, Map.of(), false, false);
    }

    /**
     * The key generated servers use to look their policy up at run time:
     * "&lt;proto package&gt;.&lt;state root name&gt;", e.g. "kernel.Identity".
     */
    public String graphKey() {
        return pkg == null || pkg.isEmpty() ? name : pkg + "." + name;
    }
}
