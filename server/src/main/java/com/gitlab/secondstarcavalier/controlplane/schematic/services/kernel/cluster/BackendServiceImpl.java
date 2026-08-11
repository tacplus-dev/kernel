// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import static com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster.PeerContext.PEER_KEY;

// StateServer is in this package
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.host.HostOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.ClusterServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.ClusterInfo;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.ClusterMember;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.ClusterState;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.LogMessage;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.MemberStatus;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.grpcconfig.Grpcconfig.PingResponse;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * gRPC implementation of BackendService (renamed from MessagingService).
 * Implements Log, Ping, and Subscribe RPCs.
 *
 * <ul>
 *   <li><b>Log</b>: registers the client's stream observer with {@link BackendServer}
 *       for server-pushed log messages (rate-limit warnings).</li>
 *   <li><b>Ping</b>: returns the member identity (endpoint, status, org, region, zone, cluster).</li>
 *   <li><b>Subscribe</b>: streams {@link ClusterState} updates whenever membership or priorities change.</li>
 * </ul>
 */
public class BackendServiceImpl extends ClusterServiceGrpc.ClusterServiceImplBase {

    private static final Logger logger = LoggerFactory.getLogger(BackendServiceImpl.class);

    /** How often the JWKS is re-read to notice a rotation. */
    private static final int JWKS_POLL_SECONDS = 10;

    private final StateServer stateServer;
    private final int grpcPort;
    private final HazelcastInstance hazelcast;
    private final String clusterName;

    /** Verifying keys, same supplier the authenticator's key provider uses. */
    private final Supplier<List<JwkOuterClass.Jwk>> verifyingKeys;

    private final Set<StreamObserver<JwkOuterClass.Jwks>> jwksObservers = new CopyOnWriteArraySet<>();
    private final ScheduledExecutorService jwksPoller =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "watch-jwks-poller");
                t.setDaemon(true);
                return t;
            });

    /** Last set pushed, so a poll that finds no change pushes nothing. */
    private volatile JwkOuterClass.Jwks lastPublishedJwks;

    public BackendServiceImpl(
            StateServer stateServer,
            int grpcPort,
            HazelcastInstance hazelcast,
            String clusterName,
            Supplier<List<JwkOuterClass.Jwk>> verifyingKeys) {
        this.stateServer = stateServer;
        this.grpcPort = grpcPort;
        this.hazelcast = hazelcast;
        this.clusterName = clusterName;
        this.verifyingKeys = verifyingKeys;
        this.lastPublishedJwks = currentJwks();
        jwksPoller.scheduleWithFixedDelay(
                this::publishJwksIfChanged, JWKS_POLL_SECONDS, JWKS_POLL_SECONDS, TimeUnit.SECONDS);
    }

    @Override
    public void log(com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.trace.Trace.TraceRequest request, StreamObserver<LogMessage> responseObserver) {
        String peer = PEER_KEY.get();
        if (peer == null) {
            peer = "unknown";
        }

        stateServer.addLogObserver(peer, responseObserver);

        // Register cancellation handler to clean up when client disconnects
        final String peerKey = peer;
        if (responseObserver instanceof ServerCallStreamObserver) {
            ((ServerCallStreamObserver<LogMessage>) responseObserver).setOnCancelHandler(() -> {
                stateServer.removeLogObserver(peerKey);
            });
        }
    }

    @Override
    public void ping(com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.trace.Trace.TraceRequest request, StreamObserver<PingResponse> responseObserver) {
        PingResponse response = PingResponse.newBuilder()
                .setStatus(MemberStatus.MEMBER_STATUS_READY)
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void subscribe(com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.trace.Trace.TraceRequest request, StreamObserver<ClusterState> responseObserver) {
        String peer = PEER_KEY.get();
        if (peer == null) {
            peer = "unknown";
        }
        logger.info("Subscribe stream opened: peer={}", peer);

        // Send initial cluster state
        ClusterState initialState = buildClusterState();
        responseObserver.onNext(initialState);

        // Register cancellation handler
        final String peerKey = peer;
        if (responseObserver instanceof ServerCallStreamObserver) {
            ((ServerCallStreamObserver<ClusterState>) responseObserver).setOnCancelHandler(() -> {
                logger.info("Subscribe stream closed: peer={}", peerKey);
            });
        }

        // The stream stays open — ClusterState updates will be pushed by the
        // membership listener in ClusterServer when members join/leave.
    }

    /**
     * Streams the JWKS used for token verification.
     *
     * Every generated ServiceManager opens this stream on startup to keep its
     * local JWKS cache fresh. It was never implemented here — BackendServiceImpl
     * overrode log, ping and subscribe only — so gRPC answered UNIMPLEMENTED and
     * the whole fleet reconnected to a method that does not exist, forever.
     *
     * The current set is sent immediately: a client that gets one frame has a
     * usable cache even if the stream later drops, and the first delivered frame
     * is also what tells the client's reconnect backoff that the stream is real.
     * After that, frames are sent only when the key set actually CHANGES, so a
     * fleet of idle subscribers costs one comparison every
     * {@value #JWKS_POLL_SECONDS} seconds and no traffic at all.
     *
     * Polling rather than hooking KeyRotator is deliberate: keys also arrive from
     * other members through the replicated identity map, so rotation is not the
     * only way the set changes, and a poll over the same supplier the
     * authenticator uses cannot disagree with it.
     */
    @Override
    public void watchJwks(
            com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.trace.Trace.TraceRequest request,
            StreamObserver<JwkOuterClass.Jwks> responseObserver) {
        String peer = PEER_KEY.get();
        if (peer == null) {
            peer = "unknown";
        }

        JwkOuterClass.Jwks current = currentJwks();
        try {
            responseObserver.onNext(current);
        } catch (RuntimeException e) {
            logger.warn("WatchJwks initial send failed: peer={} error={}", peer, e.getMessage());
            return;
        }
        logger.info("WatchJwks stream opened: peer={} keys={}", peer, current.getKeysCount());

        jwksObservers.add(responseObserver);

        final String peerKey = peer;
        if (responseObserver instanceof ServerCallStreamObserver) {
            ((ServerCallStreamObserver<JwkOuterClass.Jwks>) responseObserver).setOnCancelHandler(() -> {
                jwksObservers.remove(responseObserver);
                logger.info("WatchJwks stream closed: peer={}", peerKey);
            });
        }
    }

    private JwkOuterClass.Jwks currentJwks() {
        return JwkOuterClass.Jwks.newBuilder().addAllKeys(verifyingKeys.get()).build();
    }

    /**
     * Pushes the JWKS to every open observer, but only when it differs from what
     * was last published. A dead observer is dropped rather than allowed to fail
     * the whole broadcast.
     */
    private void publishJwksIfChanged() {
        try {
            JwkOuterClass.Jwks current = currentJwks();
            if (current.equals(lastPublishedJwks)) {
                return;
            }
            lastPublishedJwks = current;
            if (jwksObservers.isEmpty()) {
                return;
            }
            logger.info("JWKS changed — pushing to {} subscriber(s), keys={}",
                    jwksObservers.size(), current.getKeysCount());
            for (StreamObserver<JwkOuterClass.Jwks> observer : jwksObservers) {
                try {
                    observer.onNext(current);
                } catch (RuntimeException e) {
                    jwksObservers.remove(observer);
                    logger.warn("Dropping WatchJwks subscriber after send failure: {}", e.getMessage());
                }
            }
        } catch (RuntimeException e) {
            // Never let a poll failure kill the scheduled task; the next tick retries.
            logger.warn("JWKS poll failed: {}", e.getMessage());
        }
    }

    /**
     * Builds the current cluster state from the Hazelcast cluster.
     */
    private ClusterState buildClusterState() {
        var cluster = hazelcast.getCluster();
        var clusterInfo = ClusterInfo.newBuilder().setClusterName(clusterName);

        for (var member : cluster.getMembers()) {
            var address = member.getAddress();
            clusterInfo.addMembers(ClusterMember.newBuilder()
                    .setEndpoint(HostOuterClass.Host.newBuilder()
                            .setHost(address.getHost())
                            .setPort(grpcPort)
                            .build())
                    .setStatus(MemberStatus.MEMBER_STATUS_READY)
                    .setPriority(member.localMember() ? 10 : 5)
                    .build());
        }

        return ClusterState.newBuilder().addClusters(clusterInfo.build()).build();
    }
}
