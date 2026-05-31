// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.grpcserver.Authorizer;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;

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
 * Authorizer's cache picks up signing-key rotations.
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

    LocalJwkSource(Supplier<List<JwkOuterClass.Jwk>> keysSupplier) {
        this.keysSupplier = keysSupplier;
    }

    @Override
    public void start(Authorizer.JwkSink sink) {
        Runnable push = () -> {
            try {
                Map<String, JwkOuterClass.Jwk> byKid = new HashMap<>();
                for (JwkOuterClass.Jwk jwk : keysSupplier.get()) {
                    if (!jwk.getKid().isEmpty()) {
                        byKid.put(jwk.getKid(), jwk);
                    }
                }
                sink.update(byKid);
            } catch (Exception e) {
                logger.warn("LocalJwkSource refresh failed: {}", e.getMessage());
            }
        };
        push.run();
        poller.scheduleAtFixedRate(push, REFRESH_SECONDS, REFRESH_SECONDS, TimeUnit.SECONDS);
    }

    @Override
    public void stop() {
        poller.shutdownNow();
    }
}
