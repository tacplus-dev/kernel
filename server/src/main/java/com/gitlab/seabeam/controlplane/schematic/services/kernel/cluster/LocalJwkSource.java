// Copyright (c) 2026 Seabeam LLC. All rights reserved.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Local key source for the kernel's own {@link Authorizer}.
 *
 * <p>The kernel is the JWKS authority: it can't watch its own
 * JwkVerifyingKeysViewService over a channel (the generated RemoteJwkSource path
 * every consumer uses), so it feeds the Authorizer directly from its in-process
 * key state — the same supplier that backs SecurityAuthenticator and the JWK view.
 *
 * <p>Keys are pushed once at start and re-pushed on a short interval so the
 * Authorizer's cache picks up signing-key rotations. The interval alone left the
 * Authorizer up to {@link #REFRESH_SECONDS} behind a rotation, rejecting tokens
 * signed with a key this very node had just published as "unknown signing key"
 * — an UNAUTHENTICATED the caller cannot retry usefully. {@link #refreshNow()}
 * closes that window: the kernel calls it on its own key-change hook, so a local
 * rotation reaches the Authorizer synchronously and the interval is only the
 * backstop for keys another node published.
 *
 * <p>There is deliberately no refresh-on-miss path here. The generated
 * Authorizer resolves a kid straight out of its cache and gives a JwkSource no
 * callback on a miss, and the blocking retry for keys still propagating between
 * kernels lives exclusively on that path (see {@code
 * IdentityServiceImpl.isPlausibleKid}), not on every verify.
 */
final class LocalJwkSource implements Authorizer.JwkSource {
    private static final Logger logger = LoggerFactory.getLogger(LocalJwkSource.class);
    private static final long REFRESH_SECONDS = 10;

    private final Supplier<List<JwkOuterClass.Jwk>> keysSupplier;
    private final ScheduledExecutorService poller =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "local-jwk-source");
                t.setDaemon(true);
                return t;
            });
    private volatile Authorizer.JwkSink sink;

    LocalJwkSource(Supplier<List<JwkOuterClass.Jwk>> keysSupplier) {
        this.keysSupplier = keysSupplier;
    }

    @Override
    public void start(Authorizer.JwkSink sink) {
        this.sink = sink;
        push();
        poller.scheduleAtFixedRate(this::push, REFRESH_SECONDS, REFRESH_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * Pushes the current key set to the Authorizer immediately. Safe to call from
     * any thread and before {@link #start}, where it is a no-op — the start push
     * publishes the keys instead.
     */
    void refreshNow() {
        push();
    }

    /**
     * Reads the live key state and replaces the Authorizer's cache with it.
     *
     * <p>Synchronized so the poller thread and a rotation-hook caller cannot
     * interleave reads and updates and leave the cache holding the older of two
     * concurrent key sets. Both the read and the update are in-process and
     * cheap, so serializing them costs nothing worth guarding against.
     */
    private synchronized void push() {
        Authorizer.JwkSink target = sink;
        if (target == null) {
            return;
        }
        try {
            Map<String, JwkOuterClass.Jwk> byKid = new HashMap<>();
            for (JwkOuterClass.Jwk jwk : keysSupplier.get()) {
                if (!jwk.getKid().isEmpty()) {
                    byKid.put(jwk.getKid(), jwk);
                }
            }
            target.update(byKid);
        } catch (Exception e) {
            logger.warn("LocalJwkSource refresh failed: {}", e.getMessage());
        }
    }

    @Override
    public void stop() {
        poller.shutdownNow();
    }
}
