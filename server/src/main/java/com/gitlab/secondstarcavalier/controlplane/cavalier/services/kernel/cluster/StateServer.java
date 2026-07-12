// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import io.grpc.stub.StreamObserver;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.grpcconfig.Grpcconfig.LogMessage;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.logger.Logger.Level;

/**
 * Manages gRPC Log stream observers. Tracks connected client streams keyed by peer address
 * and pushes {@link LogMessage} entries (e.g. rate-limit warnings, quorum status changes).
 */
public final class StateServer {

    private static final Logger logger = LoggerFactory.getLogger(StateServer.class);

    private final ConcurrentHashMap<String, StreamObserver<LogMessage>> logObservers =
            new ConcurrentHashMap<>();

    public void addLogObserver(String peer, StreamObserver<LogMessage> observer) {
        logObservers.put(peer, observer);
        logger.info("Log stream opened: peer={} (total={})", peer, logObservers.size());
    }

    public void removeLogObserver(String peer) {
        logObservers.remove(peer);
        logger.info("Log stream closed: peer={} (total={})", peer, logObservers.size());
    }

    public void sendToPeer(String peer, Level level, String message) {
        StreamObserver<LogMessage> observer = logObservers.get(peer);
        if (observer == null) {
            return;
        }
        LogMessage msg = LogMessage.newBuilder().setLevel(level).setMessage(message).build();
        try {
            observer.onNext(msg);
        } catch (Exception e) {
            logger.debug("Failed to send log message to peer {}", peer, e);
            logObservers.remove(peer);
        }
    }

    public void broadcast(Level level, String message) {
        LogMessage msg = LogMessage.newBuilder().setLevel(level).setMessage(message).build();
        for (var entry : logObservers.entrySet()) {
            try {
                entry.getValue().onNext(msg);
            } catch (Exception e) {
                logger.debug("Failed to send log message to peer {}", entry.getKey(), e);
                logObservers.remove(entry.getKey());
            }
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
