// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.collection.CollectionRuntime;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.grants.Grants;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TenantAdminServiceImpl is kernel's single tenant/project control plane
 * (the {@code TenantAdmin} C2S service). It implements all nine
 * RPCs over the uniform namespace tree (ROOT "/" + tenants + projects).
 *
 * <p>Tenants/projects live in the kernel {@link ConfigMap} keyed by their full
 * namespace path (e.g. {@code "/acme"}, {@code "/acme/sub"}, {@code "/acme/prod"}).
 * The flat-map-keyed-by-full-path representation IS the tree: a parent's
 * immediate children are exactly the keys with {@code parentNs + "/"} as prefix
 * and no further {@code '/'}.
 *
 * <p>The generated C2S authorizer already enforces the level-or-below rule on
 * each method's {@code target_namespace_field} (caller must be at-or-above the
 * target), so the handler TRUSTS the inbound namespace strings and does not
 * re-derive or re-check the caller's namespace for authorization. The
 * {@link Caller} is consulted only for the SetTenantConfig self-lockout guard.
 *
 * <p>After every mutating RPC the handler invokes {@code persistHook} so the
 * kernel writes a fresh disk snapshot (see {@link KernelPersistence}).
 */
public class TenantAdminServiceImpl implements TenantAdmin.TenantAdminHandler {
    private static final Logger logger = LoggerFactory.getLogger(TenantAdminServiceImpl.class);

    private final ConfigMap configMap;
    private final Supplier<String> trustDomainReader;
    private final Runnable persistHook;

    /**
     * @param configMap          kernel ConfigState accessor (tenants / tenant_configs / project_configs)
     * @param trustDomainReader  SPIFFE trust domain supplier (authorization root namespace is "/")
     * @param persistHook        invoked after every mutating RPC so the kernel persists a new disk snapshot
     */
    public TenantAdminServiceImpl(
            ConfigMap configMap,
            Supplier<String> trustDomainReader,
            Runnable persistHook) {
        this.configMap = configMap;
        this.trustDomainReader = trustDomainReader;
        this.persistHook = persistHook != null ? persistHook : () -> {};
        logger.info("TenantAdminServiceImpl initialised");
    }

    // ========================================================================
    // Tenant lifecycle
    // ========================================================================

    @Override
    public Kernel.Tenant createTenant(Caller caller, Kernel.CreateTenantRequest request)
            throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        if (!ns.startsWith("/")) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "tenant_namespace must be an absolute path (leading '/')");
        }
        if (!configMap.getTenants(ns).getName().isEmpty()) {
            throw new ProtoException(ProtoException.ALREADY_EXISTS, "tenant already exists at " + ns);
        }
        String leaf = leafOf(ns);
        if (leaf.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "tenant_namespace must have a leaf segment");
        }

        // Validate the new tenant's ceiling against the parent's ceiling. The
        // parent is the namespace one level up; ROOT (no tenant record above)
        // has an unbounded ceiling.
        Kernel.Constraints constraints = request.hasConstraints()
                ? request.getConstraints() : Kernel.Constraints.getDefaultInstance();
        Entitlements.TokenEntitlements parentCeiling = parentCeiling(ns);
        if (parentCeiling != null
                && !entitlementsSubsetOf(constraints.getEntitlementsCeiling(), parentCeiling)) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "constraints.entitlements_ceiling exceeds the parent tenant's ceiling");
        }

        Timestamp now = nowTs();
        Kernel.Tenant tenant = Kernel.Tenant.newBuilder()
                .setName(leaf)
                .setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
                .setConstraints(constraints)
                .setCreatedAt(now)
                .setUpdatedAt(now)
                .build();
        configMap.putTenants(ns, tenant);

        // Auto-create an empty "/{tenant}/default" project (existence only). No
        // config or key material is produced — bootstrap cred_pairs via
        // SetTenantConfig.
        putEmptyProject(ns + "/default");

        persistHook.run();
        logger.info("CreateTenant ns={} leaf={}", ns, leaf);
        return tenant;
    }

    @Override
    public Kernel.DeleteTenantResponse deleteTenant(Caller caller, Kernel.DeleteTenantRequest request)
            throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        if (configMap.getTenants(ns).getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        // Remove the tenant + its tenant_config + child project_configs.
        configMap.deleteTenants(ns);
        configMap.deleteTenantConfigs(ns);
        for (String projectNs : childProjectKeys(ns)) {
            configMap.deleteProjectConfigs(projectNs);
        }
        persistHook.run();
        logger.info("DeleteTenant ns={}", ns);
        return Kernel.DeleteTenantResponse.getDefaultInstance();
    }

    @Override
    public CollectionRuntime.Page<Kernel.Tenant> listTenants(
            Caller caller, Kernel.ListTenantsRequest request, CollectionRuntime.PageParams page)
            throws ProtoException {
        String parentNs = require(request.getParentNamespace(), "parent_namespace");
        Kernel.ConfigState state = configMap.proto();
        // tenants are keyed by full namespace path, but proto() loses the map
        // keys. Recover candidate immediate-child tenant namespaces from the
        // keyed sibling collections: tenant_configs (configured tenants) and
        // project_configs (every tenant has an auto-created "/{tenant}/default"
        // project at creation, so a brand-new tenant with no config yet is still
        // discoverable). Verify each candidate against the tenants map.
        java.util.Set<String> candidates = new java.util.LinkedHashSet<>();
        for (Kernel.TenantConfigEntry e : state.getTenantConfigsList()) {
            String key = e.getTenantName();
            if (isImmediateChild(key, parentNs)) {
                candidates.add(key);
            }
        }
        String prefix = parentNs.endsWith("/") ? parentNs : parentNs + "/";
        for (Kernel.ProjectConfigEntry e : state.getProjectConfigsList()) {
            String pk = e.getProjectNamespace();
            if (pk.startsWith(prefix)) {
                String rest = pk.substring(prefix.length());
                int slash = rest.indexOf('/');
                // A project key is "/parent/<tenant>/<project>"; its first
                // segment under parentNs is an immediate child tenant.
                if (slash > 0) {
                    candidates.add(prefix + rest.substring(0, slash));
                }
            }
        }
        List<Kernel.Tenant> tenants = new ArrayList<>();
        for (String key : candidates) {
            Kernel.Tenant t = configMap.getTenants(key);
            if (!t.getName().isEmpty()) {
                tenants.add(t);
            }
        }
        tenants.sort(java.util.Comparator.comparing(Kernel.Tenant::getName));
        return pageByStringKey(tenants, page, Kernel.Tenant::getName);
    }

    // ========================================================================
    // Tenant config (atomic whole-config replace)
    // ========================================================================

    @Override
    public TenantConfigOuterClass.TenantConfig getTenantConfig(
            Caller caller, Kernel.GetTenantConfigRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        Kernel.TenantConfigEntry entry = configMap.getTenantConfigs(ns);
        if (entry.getTenantName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant config at " + ns);
        }
        return entry.getConfig();
    }

    @Override
    public TenantConfigOuterClass.TenantConfig updateTenantConfig(
            Caller caller, Kernel.SetTenantConfigRequest request) throws ProtoException {
        String ns = require(request.getTenantNamespace(), "tenant_namespace");
        if (!request.hasConfig()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "config is required");
        }
        Kernel.Tenant tenant = configMap.getTenants(ns);
        if (tenant.getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        TenantConfigOuterClass.TenantConfig newConfig = request.getConfig();
        List<Credentials.CredPair> credPairs = newConfig.getKernel().getCredPairsList();

        Entitlements.TokenEntitlements ceiling = tenant.getConstraints().getEntitlementsCeiling();

        // Invariant 1: every cred_pair's entitlements ⊆ the tenant's ceiling.
        for (Credentials.CredPair cp : credPairs) {
            if (!entitlementsSubsetOf(cp.getEntitlements(), ceiling)) {
                throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                        "cred_pair '" + cp.getId() + "' entitlements exceed the tenant's ceiling");
            }
        }

        // Invariant 2 (min-admin-credential): the resulting config must contain
        // >=1 cred_pair entitled to administer this tenant (i.e. holding a
        // TenantAdmin-capable entitlement).
        boolean hasAdmin = false;
        for (Credentials.CredPair cp : credPairs) {
            if (isTenantAdminCapable(cp.getEntitlements())) {
                hasAdmin = true;
                break;
            }
        }
        if (!hasAdmin) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "config must contain at least one cred_pair entitled to administer the tenant");
        }

        // Invariant 3 (self-lockout guard): if the caller is acting on its OWN
        // tenant, the new config must still contain the authenticating
        // cred_pair, so a lockout requires a deliberate two-step rotation.
        String callerCredPairId = callerCredPairId(caller, ns);
        if (callerCredPairId != null) {
            boolean stillPresent = false;
            for (Credentials.CredPair cp : credPairs) {
                if (cp.getId().equals(callerCredPairId)) {
                    stillPresent = true;
                    break;
                }
            }
            if (!stillPresent) {
                throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                        "config must retain the authenticating cred_pair '" + callerCredPairId
                                + "' (self-lockout guard); rotate in two steps");
            }
        }

        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(ns)
                .setConfig(newConfig)
                .build();
        configMap.putTenantConfigs(ns, entry);
        persistHook.run();
        logger.info("SetTenantConfig ns={} cred_pairs={}", ns, credPairs.size());
        return newConfig;
    }

    // ========================================================================
    // Project config (existence only)
    // ========================================================================

    @Override
    public Kernel.ProjectConfig getProjectConfig(
            Caller caller, Kernel.GetProjectConfigRequest request) throws ProtoException {
        String ns = require(request.getProjectNamespace(), "project_namespace");
        Kernel.ProjectConfigEntry entry = configMap.getProjectConfigs(ns);
        if (entry.getProjectNamespace().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no project at " + ns);
        }
        return entry.getConfig();
    }

    @Override
    public Kernel.ProjectConfig updateProjectConfig(
            Caller caller, Kernel.SetProjectConfigRequest request) throws ProtoException {
        String ns = require(request.getProjectNamespace(), "project_namespace");
        if (!request.hasConfig()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "config is required");
        }
        Kernel.ProjectConfigEntry entry = Kernel.ProjectConfigEntry.newBuilder()
                .setProjectNamespace(ns)
                .setConfig(request.getConfig())
                .build();
        configMap.putProjectConfigs(ns, entry);
        persistHook.run();
        logger.info("SetProjectConfig ns={}", ns);
        return request.getConfig();
    }

    @Override
    public CollectionRuntime.Page<Kernel.ProjectNamespace> listProjects(
            Caller caller, Kernel.ListProjectsRequest request, CollectionRuntime.PageParams page)
            throws ProtoException {
        String tenantNs = require(request.getTenantNamespace(), "tenant_namespace");
        List<Kernel.ProjectNamespace> projects = new ArrayList<>();
        for (Kernel.ProjectConfigEntry e : configMap.proto().getProjectConfigsList()) {
            if (isImmediateChild(e.getProjectNamespace(), tenantNs)) {
                projects.add(Kernel.ProjectNamespace.newBuilder()
                        .setProjectNamespace(e.getProjectNamespace())
                        .build());
            }
        }
        projects.sort(java.util.Comparator.comparing(Kernel.ProjectNamespace::getProjectNamespace));
        return pageByStringKey(projects, page, Kernel.ProjectNamespace::getProjectNamespace);
    }

    @Override
    public Kernel.DeleteProjectResponse deleteProject(
            Caller caller, Kernel.DeleteProjectRequest request) throws ProtoException {
        String ns = require(request.getProjectNamespace(), "project_namespace");
        if (configMap.getProjectConfigs(ns).getProjectNamespace().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no project at " + ns);
        }
        configMap.deleteProjectConfigs(ns);
        persistHook.run();
        logger.info("DeleteProject ns={}", ns);
        return Kernel.DeleteProjectResponse.getDefaultInstance();
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /** Stores an empty ProjectConfig at the given full project namespace. */
    private void putEmptyProject(String projectNs) throws ProtoException {
        configMap.putProjectConfigs(projectNs, Kernel.ProjectConfigEntry.newBuilder()
                .setProjectNamespace(projectNs)
                .setConfig(Kernel.ProjectConfig.getDefaultInstance())
                .build());
    }

    /** Leaf segment of a full namespace path ("/acme/sub" -> "sub"). */
    private static String leafOf(String ns) {
        int slash = ns.lastIndexOf('/');
        return slash < 0 ? ns : ns.substring(slash + 1);
    }

    /**
     * Returns the parent tenant's entitlements ceiling, or {@code null} when the
     * parent is ROOT (unbounded ceiling — no validation needed).
     */
    private Entitlements.TokenEntitlements parentCeiling(String ns) {
        int slash = ns.lastIndexOf('/');
        if (slash <= 0) {
            // Parent is the root "/" — unbounded ceiling.
            return null;
        }
        String parentNs = ns.substring(0, slash);
        Kernel.Tenant parent = configMap.getTenants(parentNs);
        if (parent.getName().isEmpty()) {
            // No tenant record above (e.g. parent is the cluster-root namespace).
            // Treat as unbounded.
            return null;
        }
        return parent.getConstraints().getEntitlementsCeiling();
    }

    /** Returns true if {@code key} is an immediate child of {@code parentNs}. */
    private static boolean isImmediateChild(String key, String parentNs) {
        String prefix = parentNs.endsWith("/") ? parentNs : parentNs + "/";
        if (!key.startsWith(prefix)) {
            return false;
        }
        String rest = key.substring(prefix.length());
        return !rest.isEmpty() && rest.indexOf('/') < 0;
    }

    /** Full project-namespace keys at or below {@code tenantNs}. */
    private List<String> childProjectKeys(String tenantNs) throws ProtoException {
        List<String> out = new ArrayList<>();
        String prefix = tenantNs + "/";
        for (Kernel.ProjectConfigEntry e : configMap.proto().getProjectConfigsList()) {
            String k = e.getProjectNamespace();
            if (k.equals(tenantNs) || k.startsWith(prefix)) {
                out.add(k);
            }
        }
        return out;
    }

    private static <T> CollectionRuntime.Page<T> pageByStringKey(
            List<T> orderedItems, CollectionRuntime.PageParams page, java.util.function.Function<T, String> keyFn)
            throws ProtoException {
        String after = pageCursorKey(page);
        long limit = page == null ? 0 : page.limit;
        if (limit <= 0) {
            return new CollectionRuntime.Page<>(java.util.Collections.emptyList(), null, orderedItems.size());
        }

        List<T> items = new ArrayList<>();
        CollectionRuntime.Cursor nextAfter = null;
        for (T item : orderedItems) {
            String key = keyFn.apply(item);
            if (after != null && key.compareTo(after) <= 0) {
                continue;
            }
            if (items.size() >= limit) {
                nextAfter = cursorFor(keyFn.apply(items.get(items.size() - 1)));
                break;
            }
            items.add(item);
        }
        return new CollectionRuntime.Page<>(items, nextAfter, orderedItems.size());
    }

    private static String pageCursorKey(CollectionRuntime.PageParams page) throws ProtoException {
        if (page == null || page.after == null) {
            return null;
        }
        if (page.after.keys == null || page.after.keys.size() != 1) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "page_token cursor does not match the collection order");
        }
        return page.after.keys.get(0);
    }

    private static CollectionRuntime.Cursor cursorFor(String key) {
        return new CollectionRuntime.Cursor(java.util.Collections.singletonList(key));
    }

    /**
     * Subset check for native flat grant tokens. Wildcards are expanded through
     * the generated Grants catalog before comparison. A null/empty ceiling means
     * "no grants" (only an empty candidate is a subset). An unbounded ceiling
     * (ROOT) is handled by the caller passing {@code null} and skipping the check.
     */
    static boolean entitlementsSubsetOf(
            Entitlements.TokenEntitlements candidate, Entitlements.TokenEntitlements ceiling) {
        if (candidate == null) {
            return true;
        }
        if (ceiling == null) {
            ceiling = Entitlements.TokenEntitlements.getDefaultInstance();
        }
        return Grants.containsAll(candidate.getGrantsList(), ceiling.getGrantsList());
    }

    /**
     * Returns true if these entitlements grant any kernel TenantAdmin RPC.
     * Wildcards are expanded through the generated Grants catalog first, so
     * KERNEL_ANY / KERNEL_PAGE_ANY / KERNEL_READ_ANY work as intended.
     */
    static boolean isTenantAdminCapable(Entitlements.TokenEntitlements entitlements) {
        if (entitlements == null) {
            return false;
        }
        for (String token : Grants.normalize(entitlements.getGrantsList())) {
            var grantInfo = Grants.lookup(token);
            if (grantInfo.isPresent()
                    && "kernel".equals(grantInfo.get().pkg)
                    && "TenantAdmin".equals(grantInfo.get().service)) {
                return true;
            }
        }
        return false;
    }

    /**
     * If the caller's cred_pair belongs to {@code tenantNs}, returns its
     * cred_pair id; otherwise null (caller is an ancestor acting from above).
     *
     * <p>The caller's verified token payload carries the cred_pair SPIFFE
     * subject {@code spiffe://<prefix>/<tenant>/users/cred-pair:<id>}; the
     * namespace component equals {@code tenantNs} when acting on its own tenant.
     * We parse the verified JSON payload for {@code namespace}/{@code sub}.
     */
    private String callerCredPairId(Caller caller, String tenantNs) {
        if (caller == null) {
            return null;
        }
        String payload = caller.getTokenPayload();
        if (payload == null || payload.isEmpty()) {
            return null;
        }
        String sub = jsonStringField(payload, "sub");
        if (sub == null || !sub.startsWith("spiffe://")) {
            return null;
        }
        String callerNs = SpiffeIds.namespaceFromSpiffe(sub);
        // Only the tenant's own cred_pair (namespace == tenantNs) triggers the
        // self-lockout guard; ancestors acting from above are exempt.
        if (!tenantNs.equals(callerNs)) {
            // The cred_pair subject embeds "/users/cred-pair:<id>"; its tenant
            // namespace is the portion before "/users/". Compare that too.
            int usersIdx = callerNs.indexOf("/users/");
            if (usersIdx < 0 || !tenantNs.equals(callerNs.substring(0, usersIdx))) {
                return null;
            }
        }
        int marker = sub.indexOf("cred-pair:");
        if (marker < 0) {
            return null;
        }
        String id = sub.substring(marker + "cred-pair:".length());
        int slash = id.indexOf('/');
        if (slash >= 0) {
            id = id.substring(0, slash);
        }
        return id.isEmpty() ? null : id;
    }

    /** Minimal extractor for a top-level JSON string field from a token payload. */
    private static String jsonStringField(String json, String field) {
        String needle = "\"" + field + "\"";
        int k = json.indexOf(needle);
        if (k < 0) {
            return null;
        }
        int colon = json.indexOf(':', k + needle.length());
        if (colon < 0) {
            return null;
        }
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) {
            return null;
        }
        int q2 = json.indexOf('"', q1 + 1);
        if (q2 < 0) {
            return null;
        }
        return json.substring(q1 + 1, q2);
    }

    /**
     * Builds a "full entitlements" {@link Entitlements.TokenEntitlements} using
     * every package-level ANY wildcard from the generated grant catalog.
     */
    static Entitlements.TokenEntitlements buildFullEntitlements() {
        Entitlements.TokenEntitlements.Builder builder = Entitlements.TokenEntitlements.newBuilder();
        for (String token : Grants.tokens()) {
            var grantInfo = Grants.lookup(token);
            if (grantInfo.isPresent() && "ANY".equals(grantInfo.get().capability)) {
                builder.addGrants(token);
            }
        }
        return builder.build();
    }

    /**
     * Seeds the root-admin cred_pairs (from {@code kernel.Config.root_cred_pairs})
     * into the root namespace's {@code TenantConfig}, so the standard
     * {@code MintClientToken} resolution path can authenticate them.
     *
     * <p>Each input {@link Credentials.CredPair} (whose {@code public_key} is
     * ALREADY a {@code jwk.Jwk} — no PEM conversion) is re-emitted owned by the
     * root namespace, holding full entitlements (every service's {@code _RPCS_ANY})
     * and {@code namespaces=["*"]}. The minted token therefore carries
     * {@code namespace=}root, which is at-or-above any tenant/project for the
     * generated level-or-below check (TenantAdmin). Idempotent: re-running
     * overwrites the root entry. No-op when the list is empty.
     */
    static void seedRootCredPairs(
            ConfigMap configMap,
            List<Credentials.CredPair> rootCredPairs,
            String rootNamespace) throws ProtoException {
        if (rootCredPairs == null || rootCredPairs.isEmpty()) {
            return;
        }
        Entitlements.TokenEntitlements fullEntitlements = buildFullEntitlements();
        Timestamp now = nowTs();
        Credentials.KernelTenantConfig.Builder kernelCfg = Credentials.KernelTenantConfig.newBuilder();
        for (Credentials.CredPair in : rootCredPairs) {
            Credentials.CredPair.Builder cp = Credentials.CredPair.newBuilder()
                    .setId(in.getId())
                    .setTenantName(rootNamespace)
                    .setPublicKey(in.getPublicKey())
                    .setEntitlements(fullEntitlements)
                    .addNamespaces("*")
                    .setCreatedAt(now);
            if (!in.getDescription().isEmpty()) {
                cp.setDescription(in.getDescription());
            }
            kernelCfg.addCredPairs(cp.build());
        }
        TenantConfigOuterClass.TenantConfig cfg = TenantConfigOuterClass.TenantConfig.newBuilder()
                .setKernel(kernelCfg.build())
                .build();
        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(rootNamespace)
                .setConfig(cfg)
                .build();
        configMap.putTenantConfigs(rootNamespace, entry);
        logger.info("Seeded {} root cred_pair(s) into root namespace {}",
                rootCredPairs.size(), rootNamespace);
    }

    private static Timestamp nowTs() {
        Instant n = Instant.now();
        return Timestamp.newBuilder().setSeconds(n.getEpochSecond()).setNanos(n.getNano()).build();
    }

    private static String require(String v, String name) throws ProtoException {
        if (v == null || v.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, name + " is required");
        }
        return v;
    }
}
