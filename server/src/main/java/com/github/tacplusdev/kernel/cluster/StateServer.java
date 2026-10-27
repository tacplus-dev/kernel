// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import io.grpc.stub.StreamObserver;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.github.tacplusdev.kernel.model.types.sys.grpcconfig.Grpcconfig.LogMessage;
import com.github.tacplusdev.kernel.model.types.sys.logger.Logger.Level;

/**
 * Manages gRPC Log stream observers and pushes {@link LogMessage} entries
 * (e.g. rate-limit warnings, quorum status changes).
 *
 * <p>Streams are keyed by a per-stream registration token, not by peer address:
 * a peer address identifies a pod, not a stream, so two streams from the same
 * pod — or a reconnect landing before the old stream's cancel does — used to
 * overwrite each other's entry, and the late cancel then unregistered the live
 * stream. The peer is carried alongside each registration so {@link
 * #sendToPeer} still addresses every stream a peer holds.
 */
public final class StateServer {

    private static final Logger logger = LoggerFactory.getLogger(StateServer.class);

    /** One open Log stream: the peer that opened it and the observer to write to. */
    private record Registration(String peer, StreamObserver<LogMessage> observer) {}

    private final ConcurrentHashMap<String, Registration> logObservers = new ConcurrentHashMap<>();

    /**
     * Registers a Log stream and returns its token. The caller must pass that
     * token — not the peer address — to {@link #removeLogObserver} when the
     * stream ends, so it cannot unregister a different stream.
     */
    public String addLogObserver(String peer, StreamObserver<LogMessage> observer) {
        String token = UUID.randomUUID().toString();
        logObservers.put(token, new Registration(peer, observer));
        logger.info("Log stream opened: peer={} (total={})", peer, logObservers.size());
        return token;
    }

    public void removeLogObserver(String token) {
        Registration removed = logObservers.remove(token);
        if (removed == null) {
            return;
        }
        logger.info("Log stream closed: peer={} (total={})", removed.peer(), logObservers.size());
    }

    public void sendToPeer(String peer, Level level, String message) {
        LogMessage msg = LogMessage.newBuilder().setLevel(level).setMessage(message).build();
        for (var entry : logObservers.entrySet()) {
            if (!entry.getValue().peer().equals(peer)) {
                continue;
            }
            send(entry.getKey(), entry.getValue(), msg);
        }
    }

    public void broadcast(Level level, String message) {
        LogMessage msg = LogMessage.newBuilder().setLevel(level).setMessage(message).build();
        for (var entry : logObservers.entrySet()) {
            send(entry.getKey(), entry.getValue(), msg);
        }
    }

    private void send(String token, Registration reg, LogMessage msg) {
        try {
            reg.observer().onNext(msg);
        } catch (Exception e) {
            logger.debug("Failed to send log message to peer {}", reg.peer(), e);
            logObservers.remove(token);
        }
    }

    public void warnPeer(String peer, String message) {
        sendToPeer(peer, Level.LEVEL_WARN, message);
    }

    public void info(String message) {
        broadcast(Level.LEVEL_INFO, message);
    }

    public void warn(String message) {
        broadcast(Level.LEVEL_WARN, message);
    }

    public void error(String message) {
        broadcast(Level.LEVEL_ERROR, message);
    }
}
