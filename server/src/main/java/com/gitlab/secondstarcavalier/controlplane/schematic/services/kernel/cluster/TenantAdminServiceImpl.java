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
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.spec.Spec;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
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
 * namespace path. Tenants are canonically rooted at {@code /tenants}
 * (e.g. {@code "/tenants/acme"}, {@code "/tenants/acme/sub"},
 * {@code "/tenants/acme/prod"}).
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
 * kernel writes a fresh disk snapshot (see {@link IdentitySnapshot}).
 */
public class TenantAdminServiceImpl implements TenantAdmin.TenantAdminHandler {
    private static final Logger logger = LoggerFactory.getLogger(TenantAdminServiceImpl.class);

    /** Canonical root of the tenant subtree; every tenant namespace lives under it. */
    private static final String TENANTS_ROOT = "/tenants";
    private static final String TENANTS_PREFIX = TENANTS_ROOT + "/";

    /**
     * Page size applied when the caller asks for none. A caller that omits
     * {@code page.limit} sends 0, which is the ordinary "just give me the default
     * page" wiring — it must not read back as "give me nothing, but here is the
     * real total", which is a page the caller cannot act on and cannot resume
     * from.
     *
     * <p>These two match the generated wrapper's own
     * {@code CollectionRuntime.effectivePageSize(page_size, 100, 10000)}, which
     * defaults and clamps every limit that arrives over gRPC. They are the same
     * rule applied where the paging actually happens, so a handler reached any
     * other way (in-process, tests) pages the same as one reached over the wire.
     */
    private static final int DEFAULT_PAGE_LIMIT = 100;

    /** Ceiling on a page limit; matches the generated wrapper's ceiling. */
    private static final int MAX_PAGE_LIMIT = 10000;

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
        if (!ns.startsWith(TENANTS_PREFIX)) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "tenant_namespace must be under \"" + TENANTS_PREFIX + "\"");
        }
        rejectReserved(ns);
        if (!configMap.getTenants(ns).getName().isEmpty()) {
            throw new ProtoException(ProtoException.ALREADY_EXISTS, "tenant already exists at " + ns);
        }
        String leaf = leafOf(ns);
        if (leaf.isEmpty()) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT, "tenant_namespace must have a leaf segment");
        }

        // Validate the new tenant's ceiling against the parent's ceiling. The
        // parent is the namespace one level up and must already exist (only
        // TENANTS_ROOT, the parent of a top-level tenant, is unbounded).
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
        rejectReserved(ns);
        if (configMap.getTenants(ns).getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + ns);
        }
        // Refuse to orphan a subtree. Deleting only this level left every nested
        // tenant's record and tenant_config in place, so its cred_pairs kept
        // minting tokens under a parent that no longer exists — and no ceiling
        // above them could ever be tightened again. DeleteTenantRequest carries
        // no cascade flag, so the caller must delete the subtree leaf-first.
        List<String> nested = descendantTenantKeys(ns);
        if (!nested.isEmpty()) {
            throw new ProtoException(ProtoException.FAILED_PRECONDITION,
                    "tenant at " + ns + " still has nested tenants: " + String.join(", ", nested));
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
        rejectReserved(ns);
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
        requireActiveParentTenant(ns);
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
     * parent is {@link #TENANTS_ROOT} (unbounded ceiling — no validation needed).
     *
     * <p>Every other parent MUST already hold a tenant record: a tenant is only
     * ever created one level below an existing tenant, so a namespace whose
     * immediate parent segment does not exist is rejected rather than treated as
     * unbounded. Treating it as unbounded let a tenant admin skip a level
     * ({@code /tenants/acme/ghost/evil} with no {@code /tenants/acme/ghost}) and
     * escape its own ceiling entirely.
     *
     * <p>Because every existing tenant was itself validated against its parent
     * at creation, the immediate parent's ceiling is already a subset of every
     * ceiling above it — so it IS the tightest ceiling on the ancestor chain and
     * no walk is needed.
     */
    private Entitlements.TokenEntitlements parentCeiling(String ns) throws ProtoException {
        String parentNs = ns.substring(0, ns.lastIndexOf('/'));
        if (TENANTS_ROOT.equals(parentNs)) {
            // Parent is the tenants root — a top-level tenant, unbounded ceiling.
            return null;
        }
        Kernel.Tenant parent = configMap.getTenants(parentNs);
        if (parent.getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND,
                    "no parent tenant at " + parentNs);
        }
        return parent.getConstraints().getEntitlementsCeiling();
    }

    /**
     * Requires the tenant that owns {@code projectNs} to exist and be ACTIVE.
     *
     * <p>The tenant path got this check at {@code 636378e}; the project path
     * never did, so a project config row could be written under a namespace with
     * no tenant record at all. That orphan is returned by ListProjects (which
     * filters on {@link #isImmediateChild}, not on tenant existence) and survives
     * DeleteTenant, which refuses on nested tenants but says nothing about
     * nested projects. A SUSPENDED tenant is refused for the same reason a
     * missing one is: neither is a tenant new config should be attached to.
     */
    private void requireActiveParentTenant(String projectNs) throws ProtoException {
        int slash = projectNs.lastIndexOf('/');
        if (slash <= 0) {
            throw new ProtoException(ProtoException.INVALID_ARGUMENT,
                    "project_namespace must be a project under a tenant namespace");
        }
        String tenantNs = projectNs.substring(0, slash);
        Kernel.Tenant tenant = configMap.getTenants(tenantNs);
        if (tenant.getName().isEmpty()) {
            throw new ProtoException(ProtoException.NOT_FOUND, "no tenant at " + tenantNs);
        }
        if (tenant.getStatus() != Kernel.TenantStatus.TENANT_STATUS_ACTIVE) {
            throw new ProtoException(ProtoException.NOT_FOUND,
                    "tenant at " + tenantNs + " is not active");
        }
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

    /**
     * Full namespaces of live tenants strictly below {@code tenantNs}, sorted.
     *
     * <p>The tenants map's keys are not recoverable from {@code proto()}, so —
     * exactly as ListTenants does — candidates come from the keyed sibling
     * collections and are then verified against the tenants map: tenant_configs
     * keys (configured tenants) and the owning namespace of every project key
     * (every tenant gets an auto-created "/{tenant}/default" project at
     * creation, so a tenant with no config yet is still discoverable).
     */
    private List<String> descendantTenantKeys(String tenantNs) throws ProtoException {
        String prefix = tenantNs + "/";
        java.util.Set<String> candidates = new java.util.LinkedHashSet<>();
        Kernel.ConfigState state = configMap.proto();
        for (Kernel.TenantConfigEntry e : state.getTenantConfigsList()) {
            if (e.getTenantName().startsWith(prefix)) {
                candidates.add(e.getTenantName());
            }
        }
        for (Kernel.ProjectConfigEntry e : state.getProjectConfigsList()) {
            String pk = e.getProjectNamespace();
            if (pk.startsWith(prefix)) {
                String owner = pk.substring(0, pk.lastIndexOf('/'));
                if (!owner.equals(tenantNs)) {
                    candidates.add(owner);
                }
            }
        }
        List<String> out = new ArrayList<>();
        for (String key : candidates) {
            if (!configMap.getTenants(key).getName().isEmpty()) {
                out.add(key);
            }
        }
        java.util.Collections.sort(out);
        return out;
    }

    private static <T> CollectionRuntime.Page<T> pageByStringKey(
            List<T> orderedItems, CollectionRuntime.PageParams page, java.util.function.Function<T, String> keyFn)
            throws ProtoException {
        String after = pageCursorKey(page);
        long requested = page == null ? 0 : page.limit;
        long limit = requested <= 0 ? DEFAULT_PAGE_LIMIT : Math.min(requested, MAX_PAGE_LIMIT);

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
     * Subset check across EVERY authority-bearing field of TokenEntitlements —
     * {@code grants}, {@code data_grants} and {@code principal_scope}. Checking
     * only {@code grants} left the other two unbounded: a tenant could hand a
     * sub-tenant (or a cred_pair) data grants it does not hold itself, or widen
     * {@code principal_scope} to ANY, escaping the ceiling on the two dimensions
     * the ceiling never compared.
     *
     * <p>A null/empty ceiling means "nothing granted" (only an equally empty
     * candidate is a subset). An unbounded ceiling (the tenants ROOT) is handled
     * by the caller passing {@code null} and skipping the check.
     */
    static boolean entitlementsSubsetOf(
            Entitlements.TokenEntitlements candidate, Entitlements.TokenEntitlements ceiling) {
        if (candidate == null) {
            return true;
        }
        if (ceiling == null) {
            ceiling = Entitlements.TokenEntitlements.getDefaultInstance();
        }
        // grants: wildcards are expanded through the generated Grants catalog
        // before comparison.
        if (!Grants.containsAll(candidate.getGrantsList(), ceiling.getGrantsList())) {
            return false;
        }
        // data_grants have no wildcard catalog entries — Grants.normalize would
        // silently DROP any token it doesn't recognise — so compare the flat
        // lists directly rather than normalizing.
        if (!new java.util.HashSet<>(ceiling.getDataGrantsList())
                .containsAll(candidate.getDataGrantsList())) {
            return false;
        }
        // principal_scope is a single widening dial rather than a set: the
        // candidate may not out-rank the ceiling.
        return principalScopeRank(candidate.getPrincipalScope())
                <= principalScopeRank(ceiling.getPrincipalScope());
    }

    /**
     * Parses a principal_scope value (an enum VALUE NAME, e.g.
     * "PRINCIPAL_SCOPE_ANY") into its ordinal rank. Absent/empty/unrecognized
     * values are treated as SELF_ONLY, the enum's own documented default for
     * "says nothing about principal scope", so both sides fail closed.
     */
    private static int principalScopeRank(String value) {
        if (value != null && !value.isEmpty()) {
            try {
                Spec.PrincipalScope parsed = Spec.PrincipalScope.valueOf(value);
                if (parsed.getNumber() > 0) {
                    return parsed.getNumber();
                }
            } catch (IllegalArgumentException ignored) {
                // Unrecognized value — fall through to the SELF_ONLY default.
            }
        }
        return Spec.PrincipalScope.PRINCIPAL_SCOPE_SELF_ONLY.getNumber();
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
     * <p>The caller's verified token payload carries the cred_pair id in its
     * {@code sub} claim. Two subject shapes reach this handler: the cred_pair
     * tokens {@code MintClientToken} issues, whose subject is a bare
     * {@code cred-pair:<id>} and whose tree position is the {@code namespace}
     * claim; and the SPIFFE-URI form {@code
     * spiffe://<prefix>/<tenant>/users/cred-pair:<id>}, which carries the tree
     * position in its path. We read {@code namespace}/{@code sub} off the
     * verified JSON payload, parsed properly: this guard decides whether a
     * lockout is refused, so a claim VALUE that itself carries JSON (the shape
     * {@code buildClaimsStruct} in {@code IdentityServiceImpl} produces) must not
     * be able to pass itself off as the top-level subject.
     */
    private String callerCredPairId(Caller caller, String tenantNs) {
        if (caller == null) {
            return null;
        }
        String payload = caller.getTokenPayload();
        if (payload == null || payload.isEmpty()) {
            return null;
        }
        JsonObject claims;
        try {
            JsonElement parsed = JsonParser.parseString(payload);
            if (!parsed.isJsonObject()) {
                return null;
            }
            claims = parsed.getAsJsonObject();
        } catch (JsonParseException e) {
            logger.warn("SetTenantConfig self-lockout guard: token payload is not parseable JSON");
            return null;
        }
        String sub = stringClaim(claims, "sub");
        if (sub == null) {
            return null;
        }
        String callerNs = sub.startsWith("spiffe://")
                ? SpiffeIds.namespaceFromSpiffe(sub)
                : stringClaim(claims, "namespace");
        if (callerNs == null) {
            return null;
        }
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

    /** Top-level string claim, or null when absent or not a JSON string. */
    private static String stringClaim(JsonObject claims, String name) {
        JsonElement value = claims.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            return null;
        }
        return value.getAsString();
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
     * generated level-or-below check (TenantAdmin). No-op when the list is empty.
     *
     * <p>Kernel runs this on every start, after the disk snapshot has been
     * rehydrated, so the seed MERGES into the root entry rather than replacing
     * it: a bootstrap cred_pair is upserted by id (the bundle stays authoritative
     * for the ids it declares, so rotating a root key there still takes effect,
     * and an already-seeded id keeps its original {@code created_at}), while
     * every other cred_pair and every other field of the root
     * {@link TenantConfigOuterClass.TenantConfig} is left untouched. A blind
     * replace here discarded whatever the running cluster held for the root
     * namespace on each restart. The per-service config roots solve the same
     * class of problem differently — the bundle simply overwrites them on every
     * start — which never covered this path.
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
        TenantConfigOuterClass.TenantConfig.Builder cfg =
                configMap.getTenantConfigs(rootNamespace).getConfig().toBuilder();
        Credentials.KernelTenantConfig.Builder kernelCfg = cfg.getKernelBuilder();
        for (Credentials.CredPair in : rootCredPairs) {
            int at = indexOfCredPair(kernelCfg.getCredPairsList(), in.getId());
            Credentials.CredPair.Builder cp = Credentials.CredPair.newBuilder()
                    .setId(in.getId())
                    .setTenantName(rootNamespace)
                    .setPublicKey(in.getPublicKey())
                    .setEntitlements(fullEntitlements)
                    .addNamespaces("*")
                    .setCreatedAt(at < 0 ? now : kernelCfg.getCredPairs(at).getCreatedAt());
            if (!in.getDescription().isEmpty()) {
                cp.setDescription(in.getDescription());
            }
            if (at < 0) {
                kernelCfg.addCredPairs(cp.build());
            } else {
                kernelCfg.setCredPairs(at, cp.build());
            }
        }
        Kernel.TenantConfigEntry entry = Kernel.TenantConfigEntry.newBuilder()
                .setTenantName(rootNamespace)
                .setConfig(cfg.build())
                .build();
        configMap.putTenantConfigs(rootNamespace, entry);
        logger.info("Seeded {} root cred_pair(s) into root namespace {} ({} cred_pair(s) total)",
                rootCredPairs.size(), rootNamespace, kernelCfg.getCredPairsCount());
    }

    /**
     * Refuses any write to a RESERVED tenant namespace.
     *
     * <p>{@code /tenants/people} is the one reserved name (see {@link
     * PeopleTenant}). Kernel creates it at boot and owns its fixed IdP set, so
     * there is nothing here for an admin to create, reconfigure or delete — and
     * this tenant deliberately has no admin, so the refusal is what makes that
     * true rather than merely intended. A root-entitled caller passes the
     * generated level-or-below check like any other namespace, which is exactly
     * why the check cannot live in the authorizer.
     */
    private static void rejectReserved(String ns) throws ProtoException {
        if (PeopleTenant.NAMESPACE.equals(ns)) {
            throw new ProtoException(ProtoException.PERMISSION_DENIED,
                    PeopleTenant.NAMESPACE + " is a reserved tenant and is not administrable");
        }
    }

    /** Index of the cred_pair with {@code id} in {@code credPairs}, or -1. */
    private static int indexOfCredPair(List<Credentials.CredPair> credPairs, String id) {
        for (int i = 0; i < credPairs.size(); i++) {
            if (credPairs.get(i).getId().equals(id)) {
                return i;
            }
        }
        return -1;
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
