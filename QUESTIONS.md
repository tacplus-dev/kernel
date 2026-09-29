# Open questions — fleet-wide discovery fix (2026-09-29)

Each question lists the default taken, so work proceeded without waiting.

1. **What marks a state root as fleet-wide?**
   Default taken: its access policy grants the wildcard subject (`*` in rw or ro).
   Today that is exactly `kernel.ServiceHealth` (rw `*`) and
   `grpcconfig.ServiceConfigState` (ro `*`, from `InfraStatePolicies`). A policy
   that grants every service is already the statement "every namespace reads
   this", so no new annotation or hard-coded list was added. The alternative is
   an explicit `(spec.service_state)` flag in platform/proto, which is outside the
   kernel directory and would need a tacplus change. Say if you want that instead.

2. **Which stored keys count as /system entries a tenant may read?**
   Default taken: stored keys that contain no `/`. Every confined prefix ends in
   `/`, so no tenant can write one, which means "never another tenant's" holds by
   construction. A /system writer's key that does contain `/` stays hidden from
   tenants (fail closed). The ServiceHealth composite key (`svc@instance`) and the
   singleton key (`SINGLETON`) never contain `/`.

3. **Same-name collision: tenant's own entry vs. the /system entry.**
   Default taken: the caller's own entry shadows the /system entry of the same
   name in every read (Get, ContainsKey, GetAll, KeySet, Size, Watch, and singleton
   Get/Watch). For ServiceHealth this cannot happen in practice (instance ids
   differ). Tenants cannot write ServiceConfigState at all (rw is kernel only).

4. **Writes on fleet-wide roots.**
   Default taken: unchanged, and still chrooted. A tenant's `SetInstances` lands
   under `/tenants/<t>/`. Fleet-wide applies to reads only.

5. **Not changed, noted: /system callers still see every tenant's instances.**
   The root scope owns every key, so a /system caller's GetAllInstances returns
   `/tenants/<t>/svc@i` entries alongside the system ones. The chassis filters
   by the payload's `service_id`, so a /system service that targets a
   tenant-owned service name would get every tenant's instances. This behavior
   predates this fix and was left alone. Does it need its own item?
