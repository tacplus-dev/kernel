// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.diskstore.DiskStoreException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.diskstore.Snapshot;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.diskstore.stores.DiskStores;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IdentitySnapshot wraps the tacplus-generated diskstore UC1 helpers for
 * kernel's OWN whole-state snapshot ({@code KernelDiskState}) — signing keys,
 * the public verifying set, the cluster CA + per-service intermediate CAs, the
 * tenant/project tree, workload revocations, standing delegation grants, and
 * the registered personal principals — written as one atomic object on the
 * kernel's local volume. Ephemeral, rebuilt-at-runtime state (cluster
 * membership, service health, localities, FQDN, trusted CAs from Config) is
 * deliberately NOT snapshotted.
 *
 * <p>This is the ONLY thing kernel writes to disk. Kernel does no durability
 * for service state and holds no user data: every other boundary is in-memory
 * coordination, rebuilt from config seeding and from peers on every start, and
 * durable data belongs in stratum records.
 *
 * <p>{@link #load()} is called once at boot to rehydrate Hazelcast-backed state;
 * {@link #save()} is invoked after every state mutation that must survive a
 * restart — via the {@link KeyRotator} {@code onKeysChanged} hook and after each
 * mutating TenantAdmin write. {@code save()} is {@code synchronized} so the two
 * call sites never corrupt the snapshot by racing.
 *
 * <p>Neither method swallows a failure. A write that does not land throws, so
 * the mutating RPC that triggered it fails instead of acking a revocation or a
 * registration that only exists in memory; a snapshot that exists but cannot be
 * read throws, so the kernel refuses to boot instead of coming up as a cold
 * start with every revocation and grant silently dropped.
 */
public final class IdentitySnapshot {

    private static final Logger logger = LoggerFactory.getLogger(IdentitySnapshot.class);

    /** UC1 diskstore namespace for the singleton kernel snapshot. */
    private static final String NS = "/";

    private final Path base;
    private final KeyRotator keyRotator;
    private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader;
    private final Supplier<Kernel.Ca> caReader;
    private final Supplier<Kernel.ConfigState> configStateReader;
    private final Supplier<List<Kernel.WorkloadRevocation>> revocationsReader;
    private final Supplier<List<Kernel.Grant>> grantsReader;
    private final Supplier<Kernel.PrincipalState> principalStateReader;

    /**
     * @param diskDir              the kernel disk directory (Config.disk_dir — kernel's
     *                             one on-disk artifact is this snapshot); the diskstore base path
     * @param keyRotator           source of the active signing-key records
     * @param verifyingKeysReader  current public verifying keys (Identity.verifying_keys)
     * @param caReader             current Ca state (ca_certs + service_cas)
     * @param configStateReader    current ConfigState (tenants + tenant_configs + project_configs)
     * @param revocationsReader    current workload revocations (WorkloadState.revocations)
     * @param grantsReader         current standing delegation grants
     * @param principalStateReader current PrincipalState: the registered personal
     *                             principals and the `people` tenant's user rows
     */
    public IdentitySnapshot(
            String diskDir,
            KeyRotator keyRotator,
            Supplier<List<JwkOuterClass.Jwk>> verifyingKeysReader,
            Supplier<Kernel.Ca> caReader,
            Supplier<Kernel.ConfigState> configStateReader,
            Supplier<List<Kernel.WorkloadRevocation>> revocationsReader,
            Supplier<List<Kernel.Grant>> grantsReader,
            Supplier<Kernel.PrincipalState> principalStateReader) {
        this.base = Paths.get(
                (diskDir != null && !diskDir.isEmpty()) ? diskDir : "/var/lib/kernel");
        this.keyRotator = keyRotator;
        this.verifyingKeysReader = verifyingKeysReader;
        this.caReader = caReader;
        this.configStateReader = configStateReader;
        this.revocationsReader = revocationsReader;
        this.grantsReader = grantsReader;
        this.principalStateReader = principalStateReader;
    }

    /**
     * Loads the kernel identity snapshot from disk, or {@code null} if none exists yet
     * (first boot).
     *
     * <p>Only a genuinely absent snapshot is a cold start: {@code
     * DiskStores.loadKernelDiskState} returns {@code null} when neither the
     * active file nor its {@code .bak.1} archive exists, and throws for
     * everything else (unreadable, truncated, unparseable, failing validation).
     * A present-but-unusable snapshot is an unrecoverable startup condition and
     * propagates, so the kernel refuses to boot rather than rehydrating nothing
     * and un-revoking every workload revocation and standing grant it held.
     *
     * @throws DiskStoreException if a snapshot exists but cannot be read
     */
    public Kernel.KernelDiskState load() {
        Kernel.KernelDiskState state;
        try {
            state = DiskStores.loadKernelDiskState(base, NS);
        } catch (RuntimeException e) {
            logger.error("Kernel disk snapshot at {} exists but could not be read — refusing to "
                    + "start as a cold start: {}", base, e.getMessage(), e);
            throw e;
        }
        if (state == null) {
            logger.info("No kernel disk snapshot at {} — cold start", base);
            return null;
        }
        logger.info(
                "Loaded kernel disk snapshot from {}: signing_keys={}, verifying_keys={}, "
                        + "ca_certs={}, service_cas={}, tenants={}, tenant_configs={}, "
                        + "project_configs={}, revocations={}, grants={}, "
                        + "personal_principals={}, people={}",
                base,
                state.getSigningKeysCount(),
                state.getVerifyingKeysCount(),
                state.getCaCertsCount(),
                state.getServiceCasCount(),
                state.getTenantsCount(),
                state.getTenantConfigsCount(),
                state.getProjectConfigsCount(),
                state.getWorkloadRevocationsCount(),
                state.getGrantsCount(),
                state.getPersonalPrincipalsCount(),
                state.getPeopleCount());
        return state;
    }

    /**
     * Builds the current {@code KernelDiskState} from live state and writes it
     * atomically. Synchronized so the KeyRotator hook and TenantAdmin writes do
     * not race.
     *
     * <p>Throws on any failure to build or write the snapshot. Callers invoke
     * this on the mutating-RPC path (RevokeWorkload, RevokeGrant,
     * CreatePersonalPrincipal, TenantAdmin writes), where the exception becomes
     * a non-OK status: a caller must never be told its write is durable when
     * the snapshot it depends on did not land.
     *
     * @throws DiskStoreException if the snapshot could not be built or written
     */
    public synchronized void save() {
        try {
            Kernel.KernelDiskState.Builder b = Kernel.KernelDiskState.newBuilder();

            if (keyRotator != null) {
                b.addAllSigningKeys(keyRotator.getSigningKeyRecords());
            }
            if (verifyingKeysReader != null) {
                b.addAllVerifyingKeys(verifyingKeysReader.get());
            }
            if (caReader != null) {
                Kernel.Ca ca = caReader.get();
                b.addAllCaCerts(ca.getCaCertsList());
                b.addAllServiceCas(ca.getServiceCasList());
            }
            if (configStateReader != null) {
                Kernel.ConfigState cfg = configStateReader.get();
                b.addAllTenants(cfg.getTenantsList());
                b.addAllTenantConfigs(cfg.getTenantConfigsList());
                b.addAllProjectConfigs(cfg.getProjectConfigsList());
            }
            if (revocationsReader != null) {
                b.addAllWorkloadRevocations(revocationsReader.get());
            }
            if (grantsReader != null) {
                b.addAllGrants(grantsReader.get());
            }
            if (principalStateReader != null) {
                Kernel.PrincipalState principals = principalStateReader.get();
                b.addAllPersonalPrincipals(principals.getPersonalPrincipalsList());
                b.addAllPeople(principals.getPeopleList());
                b.addAllIdentityLinks(principals.getIdentityLinksList());
                b.addAllTenantUserLinks(principals.getTenantUserLinksList());
            }

            DiskStores.saveKernelDiskState(base, NS, b.build(), Snapshot.Opts.defaults());
            logger.debug("Wrote kernel identity snapshot to {}", base);
        } catch (RuntimeException e) {
            logger.error("Failed to write kernel identity snapshot to {}: {}", base, e.getMessage(), e);
            throw e;
        }
    }
}
