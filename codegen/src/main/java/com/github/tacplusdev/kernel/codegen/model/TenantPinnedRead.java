package com.github.tacplusdev.kernel.codegen.model;

import java.util.Map;

/**
 * A tenant-pinned read of one collection of a state root, from
 * codegen-config.json {@code securityPolicies[].tenantPinnedReads} (tacplus #130).
 *
 * <p>Each caller in {@code slices} that is not in the policy's rw/ro may call the
 * collection's read RPCs only, and is served according to its namespace: every
 * tenant's entry from {@code /system[/...]}, only the entry keyed {@code <t>} from
 * exactly {@code /tenants/<t>}, nothing from anywhere else. Every entry it is
 * served is projected to {@code keyField} plus, inside {@code configField}, its
 * own slice field.
 *
 * @param boundary    the collection field of the state root, e.g. "tenant_configs"
 * @param keyField    the entry's (spec.indexed) key field, e.g. "tenant_name"
 * @param configField the entry's per_service_config field, e.g. "config"
 * @param slices      pinned caller (bare service path, matched like a
 *                    boundaryGrants caller) → the config field it may see
 */
public record TenantPinnedRead(String boundary, String keyField, String configField, Map<String, String> slices) {
}
