// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplusbackend.SecurityAuthenticator;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.entitlementview.EntitlementProfileViewServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.entitlementview.Entitlementview;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.generated.entitlements.Entitlements;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.trace.Trace;
import io.grpc.Status;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * EntitlementProfileViewServer implements the EntitlementProfileViewService.
 *
 * <p>Publishes entitlement profiles from kernel Config so that each service's
 * authorizer can resolve profile names to per-service RPCs at request time.
 * Watch RPCs use polling-based change detection (500ms), same pattern as
 * JwkVerifyingKeysViewServer.
 */
public class EntitlementProfileViewServer
        extends EntitlementProfileViewServiceGrpc.EntitlementProfileViewServiceImplBase
        implements Closeable {

    private static final Logger logger = LoggerFactory.getLogger(EntitlementProfileViewServer.class);

    private final ScheduledExecutorService scheduler =
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "EntitlementProfileViewWatcher");
            t.setDaemon(true);
            return t;
        });

    private final SecurityAuthenticator authenticator;
    private final Supplier<List<Entitlements.TokenEntitlements>> profilesSupplier;
    private final List<WatcherEntry> watchers = new CopyOnWriteArrayList<>();

    public EntitlementProfileViewServer(
            SecurityAuthenticator authenticator,
            Supplier<List<Entitlements.TokenEntitlements>> profilesSupplier) {
        this.authenticator = authenticator;
        this.profilesSupplier = profilesSupplier;
        scheduler.scheduleAtFixedRate(this::pollAll, 500, 500, TimeUnit.MILLISECONDS);
    }

    @Override
    public void watch(Trace.TraceRequest request,
            StreamObserver<Entitlementview.EntitlementProfileViewResponse> observer) {
        try {
            authenticator.checkAccess("*", "entitlement_profile_view",
                    SecurityAuthenticator.OperationType.READ);
        } catch (Exception e) {
            observer.onError(Status.PERMISSION_DENIED
                .withDescription("access denied to EntitlementProfileView")
                .asRuntimeException());
            return;
        }

        Entitlementview.EntitlementProfileViewResponse snapshot = buildResponse();
        if (snapshot.getProfilesCount() > 0) {
            observer.onNext(snapshot);
        }

        WatcherEntry entry = new WatcherEntry(observer, snapshot);
        watchers.add(entry);

        if (observer instanceof ServerCallStreamObserver) {
            ((ServerCallStreamObserver<Entitlementview.EntitlementProfileViewResponse>) observer)
                .setOnCancelHandler(() -> watchers.remove(entry));
        }
    }

    private void pollAll() {
        if (watchers.isEmpty()) {
            return;
        }
        Entitlementview.EntitlementProfileViewResponse current = buildResponse();
        for (WatcherEntry entry : watchers) {
            try {
                Entitlementview.EntitlementProfileViewResponse lastSent = entry.lastSent.get();
                if (!current.equals(lastSent)) {
                    entry.observer.onNext(current);
                    entry.lastSent.set(current);
                }
            } catch (Exception e) {
                logger.debug("Removing failed watcher: {}", e.getMessage());
                watchers.remove(entry);
            }
        }
    }

    private Entitlementview.EntitlementProfileViewResponse buildResponse() {
        var builder = Entitlementview.EntitlementProfileViewResponse.newBuilder();
        try {
            List<Entitlements.TokenEntitlements> profiles = profilesSupplier.get();
            for (Entitlements.TokenEntitlements profile : profiles) {
                builder.putProfiles(profile.getId(), profile);
            }
        } catch (Exception e) {
            logger.warn("Failed to read entitlement profiles: {}", e.getMessage());
        }
        return builder.build();
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        for (WatcherEntry entry : watchers) {
            try {
                entry.observer.onCompleted();
            } catch (Exception ignored) {
            }
        }
        watchers.clear();
    }

    private static class WatcherEntry {
        final StreamObserver<Entitlementview.EntitlementProfileViewResponse> observer;
        final AtomicReference<Entitlementview.EntitlementProfileViewResponse> lastSent;

        WatcherEntry(StreamObserver<Entitlementview.EntitlementProfileViewResponse> observer,
                     Entitlementview.EntitlementProfileViewResponse initial) {
            this.observer = observer;
            this.lastSent = new AtomicReference<>(initial);
        }
    }
}
