# Kernel honors `(spec.persistence)` for every boundary, not just its own

Slice owner: schematic looper (kernel), 2026-09-23.
Authority: `looper/schematic/decisions/kernel-state-persistence-honored-2026-09-23.md`,
items 1, 2, 4, 5, 6. Item 3 (tacplus fails generation when a target cannot honor
the flag, and the `spec.proto` / `docs/API.md` wording) is tacplus's own work and
is NOT here.

---

## Why the gap existed

Kernel state was originally durable-capable, through a redo log plus periodic
full dumps. Durability then moved out to each service handling its own. Then it
moved back to kernel — and only kernel's own half came back, as the single
atomic `KernelDiskState` snapshot `KernelPersistence` writes. The generic half
never returned. `PersistenceProvider` survived that round trip as an interface
shaped like the deleted redo log, wired everywhere but implemented by
`PersistenceProvider.disabled()`, which `ClusterServer` described as "a no-op map
tracker for cluster stats only".

`(spec.persistence) = true` kept promising durability the whole time. The
codegen read it (`BoundaryAnalyzer` → `SharedBoundary.setPersistent`), threaded
it to `Manager.getConvergentMap(name, persistent)`, and the flag reached a
registration call that registered the map for statistics and did nothing else.
Every flagged boundary outside kernel's own — the Let's Encrypt cert and ACME
account, `llmsettings`, `mailbox`, and all of scotty's product state — lived in
Hazelcast memory alone. It survived a single pod restart through partition
backups, and was lost the moment all three kernels went down together, which a
node-pool rotation does routinely.

The flag's second drop was quieter and just as fatal: the generated
`<Backend>StateServiceServer` — the path every CROSS-SERVICE write takes — called
`getConvergentMap(name)` without the flag at all. Even a working provider would
have persisted only writes made through kernel's in-process `<Backend>Map`.

## What it does now

`BoundaryPersistence` is the durable store for every flagged boundary, from any
service's proto. `KernelPersistence` is unchanged and still owns kernel's own
whole-state snapshot; the two share the volume, the atomic write helper and the
fail-closed rules.

- **One file per boundary**, `<data>/_root/boundaries/<map name>.snapshot`. Not
  one blob: the flagged set includes collections whose declared maxima run to
  the millions, and a blob would rewrite the whole fleet's state per write.
- **Self-describing payload**: a stream of length-delimited `PersistenceEntry`
  records, each value in an `Any`. A boundary whose value type changed under an
  older file is a startup failure, not a mis-parse. (`PersistenceDump` was not
  reused: its `entries` field declares `assert_max_size = 65536`, two orders of
  magnitude below the boundaries it would have to hold.)
- **Written on change, synchronously, by the node serving the write.**
  `PersistentMap` wraps the boundary's `IMap` and rewrites the file inside the
  mutation, letting the exception out — the RPC fails rather than acking data
  that exists only in memory. Every other node keeps its own copy current from
  the boundary's Hazelcast entry listener, coalesced by one background writer,
  so each node holds a complete set and a cold start is safe whichever pod
  forms the cluster first.
- **Restore is cold-start only.** `ClusterServer.isColdStart` reads the live
  Hazelcast member count once, before any boundary is touched. One member means
  this pod is forming the cluster and may load its files; more than one means it
  joined peers that hold the cluster's current state and it must never replay
  its own. Rehydration additionally writes put-if-absent, so even a mistaken
  call cannot overwrite a live entry. The two guards are deliberately redundant:
  a stale snapshot landing on live state is the one way this feature destroys
  data silently.
- **Kernel's own snapshot got the same gate.** `KernelPersistence.load()` was
  replayed on every boot, including a rejoin; a rejoining pod would un-revoke
  workloads and grants the cluster had revoked while it was down.

The value type now reaches the manager
(`getConvergentMap(name, persistent, defaultInstance)`) because rehydration
happens before any value has been seen and cannot infer it from the map. Both
generators emit the flag and the type, so the two generated classes that share
one Hazelcast map agree about it.

## What it does not do

`PersistenceEntry`'s home message `AdminPersistenceStatus` still names two of
its fields `redo_log_size_bytes` and `last_dump_time_ms`. They now carry the
on-disk snapshot size and the last snapshot time. Renaming them is a change to
`platform/proto` and to every consumer of the admin surface, and was not made
here.

Snapshot-on-write is O(boundary) per write. That is fine for kernel's own
state, the config singletons and the cert, and it does not scale to the
app collections at their declared maxima — see the sizing section of the
delivery report. The binding constraint is write latency, not disk.
