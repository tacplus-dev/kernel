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

- **One redo log per boundary**, `<data>/_root/boundaries/<map name>.log`. Not
  one blob: the flagged set includes collections whose declared maxima run to
  the millions, and a blob would rewrite the whole fleet's state per write.
- **Self-describing payload**: each record carries a `PersistenceEntry` whose
  value is in an `Any`. A boundary whose value type changed under an older log
  is a startup failure, not a mis-parse. (`PersistenceDump` was not reused: its
  `entries` field declares `assert_max_size = 65536`, two orders of magnitude
  below the boundaries it would have to hold.)
- **Appended on change, synchronously, by the node serving the write.**
  `PersistentMap` wraps the boundary's `IMap` and appends ONE record for the
  one key the mutation touched, letting the exception out — the RPC fails
  rather than acking data that exists only in memory. Every other node keeps
  its own log current from the boundary's Hazelcast entry listener, coalesced
  by one background writer, so each node holds a complete set and a cold start
  is safe whichever pod forms the cluster first.
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

`PersistenceEntry`'s home message `AdminPersistenceStatus` names two of its
fields `redo_log_size_bytes` and `last_dump_time_ms`. As of the amendment
below those names are literally right again — the first is the boundary logs'
on-disk size, the second the last record written. No proto change was needed.

---

# Amendment, 2026-09-23: redo log, and a full copy on join

Authority: Jody's review of `0597813`, looper inbox 2026-09-23 12:35 MDT
("kernel persistence: switch to the redo-log pattern; snapshot everything on
join"). Two corrections, both before the cold-restart verification. Nothing
above is reverted — this is the same feature with its write path and its
rolling-restart behavior corrected.

## 1. Redo log and periodic checkpoint, not a rewrite per mutation

The first implementation rewrote the ENTIRE boundary file inside every
mutation: iterate the whole live map, serialize every entry, atomic rename. It
is correct, and it is O(rows) per write. The same section above says the flagged
set holds collections declared in the millions — which is exactly the reason a
single all-boundaries blob was rejected, and the per-boundary file reproduced
the same defect one scale down. Writing row 1,000,000 of `weather.observations`
cost a million serializations; the delivery report sized the PVC from a
10MB-per-file write-latency CEILING, i.e. from the point at which the write
path stops working, which is an admission that the shape was wrong rather than
a sizing.

The fix is the shape kernel had before durability moved out and back (see "Why
the gap existed"), and the shape stratum uses today
(`stratum/checkpoint/DailyCheckpoint.java`: append, dump, truncate, in that
order): an append-only redo log, coalesced by a periodic checkpoint.

**It is not a new log.** The tacplus chassis already generates one — UC2
`RedoLog` in `model/chassis/diskstore` — with exactly the operations needed:
`append` (one newline-framed record, fsync'd, throwing), `roll` (redirect
appends to a temp log, rebuild the file from a caller-supplied current state,
fold the temp back in, commit by one atomic rename) and `restore` (read, dedup
latest-per-key, replay, recovering a leftover temp or half-promoted file from a
crash mid-roll). `BoundaryPersistence` opens one per boundary. Writing a second
redo log beside the platform's own would have been the mistake, not the work.

Each record's payload is still a `PersistenceEntry` — the platform's own
persistence record, value in an `Any` — base64'd into the log envelope's JSON
payload slot, so the type-change-is-a-startup-failure rule above is unchanged.

### Why the checkpoint trigger is size-based

A boundary is checkpointed when its log has grown past **4MiB** AND past
**twice** the size the last checkpoint left behind. Both halves matter:

- **Doubling, not a fixed size or a clock.** Under doubling each row is
  rewritten once per doubling of the log, so total rewriting is proportional to
  writes received — amortized O(1) per write, which is the property the whole
  correction is about. A fixed threshold degrades to O(rows/threshold) rewrites
  per write for a large boundary; a wall-clock trigger cannot serve boundaries
  whose write rates differ by orders of magnitude with one number, and the
  flagged set spans a single TLS cert and a 10,000,000-row observation table.
- **The 4MiB floor**, because rolling a 12KB log costs more in fsyncs than the
  bytes it saves, and most flagged boundaries — the cert, the config
  singletons, `llmsettings` — never pass it at all and so are never rolled.
- **It rides the existing flusher.** The 250ms coalescing writer that already
  drains remote members' changes checks the sizes on the same tick. No second
  timer, no new thread.

It also bounds disk: a boundary's log never exceeds twice its live state plus
one checkpoint's worth of concurrent writes, which is what makes the PVC
sizeable from live state rather than from a latency ceiling.

### What a checkpoint costs

`RedoLog.roll` takes the current state as a list the caller builds, and
redirects appends only for its own duration — so the list must be built and
handed over as one step, or a write landing during the build is lost when the
old log is archived. `BoundaryPersistence` holds a per-boundary
`ReadWriteLock`: appends take the read lock and run concurrently, a checkpoint
takes the write lock. Writes to THAT boundary therefore block for the duration
of its checkpoint. This is a deliberate trade, and it is the honest cost of
reusing the chassis log rather than hand-rolling a lock-free capture: a
multi-second stall once per doubling, against O(rows) on every single write
before.

## 2. A pod that joined a live cluster writes its own full copy

`ClusterServer` only wrote to disk on a true cold start, and only through
subsequent mutations after that. A pod that boots INTO a live cluster takes its
state from peers by Hazelcast replication and **writes none of it to its own
volume**. So after a rolling restart, a row that is never written again exists
on no pod's disk — and the first real simultaneous cold restart, which is what
this whole feature exists for, loses exactly the quiet rows.

After a join, `ClusterServer.snapshotJoinedStateInBackground` waits for this
member's partitions to be safe and then calls `BoundaryPersistence.checkpointAll`,
which writes every boundary's complete current contents to this pod's own log.

- **It waits for partition safety** because rows arrive here by migration, and
  migration fires no entry events. A copy taken before the member is safe would
  omit whatever had not migrated, and nothing later would notice.
- **It is background and nothing waits on it.** Cluster join and readiness must
  not depend on serializing every boundary, and until this pod goes down the
  live cluster is still the source of truth.
- **One log line per boundary with its row count**, so a rolling deploy can be
  verified to have left every pod holding a full copy of every boundary rather
  than only the ones that happened to serve recent writes.

## What it measures

`scottypersonal.chat_events` is the largest declared-max flagged boundary in the
fleet: `assert_max_size = 10,000,000`, 223.6GB at the 22,360 bytes/row the
original sizing used. Measured on an M-series laptop, APFS, at that row size —
one mutation's on-disk cost, old shape against new:

```
      rows      file MB    rewrite p50    rewrite p95     append p50     append p95
      1000           21        56.95ms        60.87ms        2.954ms        3.258ms
      5000          107       186.02ms       275.03ms        4.071ms        4.841ms
     20000          429      1602.02ms      1900.91ms        3.847ms        4.989ms
```

The rewrite column is the OLD write path — serialize every live row and commit
the file — and it is linear in the boundary, ~3.7ms per MB. The append column
is the new one, and it is **flat**: a write to a boundary holding 429MB costs
the same ~4ms as a write to one holding 21MB, because the record written is the
same size either way.

Extrapolating the measured linear rewrite to the declared maximum: 1602ms ×
(10,000,000 / 20,000) = **~801 seconds per write** at 223.6GB. The append stays
at ~4ms. That is the whole correction — the old shape did not have a bad
constant at the declared maximum, it did not function there at all, and the
PVC sizing derived from a 10MB-per-file "write-latency ceiling" was really the
point past which writes stop completing.

Two honest caveats the numbers carry:

- **The log is ~1.33× the equivalent snapshot on disk**, because the chassis
  log frames records as JSON and the protobuf payload is base64 inside it
  (20,000 rows: 429MB as a snapshot, 600MB as an unrolled log). The checkpoint
  is what keeps that from compounding — a boundary's log is bounded at twice
  its checkpoint, so the steady-state ceiling is ~2.7× live state rather than
  unbounded.
- **`work.tasks`**, the boundary named in the correction, declares 1,000,000 —
  a tenth of `chat_events`. Its old-shape write extrapolates to ~80s and its
  new-shape write is the same ~4ms.

## Torn tails

Append-only introduces a failure the atomic-rename shape could not have: a
crash between an append's write and its fsync leaves an unterminated final
line. That record's RPC threw, so no caller was ever told it was durable, and
dropping it loses nothing. `BoundaryPersistence.recoverTornTail` truncates it
before the log is opened, and logs a warning. Every other damage stays fatal —
a malformed line with a newline after it is real corruption and refuses the
boot, which is the fail-closed rule this store shares with kernel's own
snapshot.
