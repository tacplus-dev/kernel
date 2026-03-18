// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import static com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster.PeerContext.PEER_KEY;

// StateServer is in this package
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.host.HostOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.ClusterServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig.ClusterInfo;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig.ClusterMember;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig.ClusterState;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig.LogMessage;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig.MemberStatus;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.grpcconfig.Grpcconfig.PingResponse;
import com.hazelcast.core.HazelcastInstance;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
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

    private final StateServer stateServer;
    private final int grpcPort;
    private final HazelcastInstance hazelcast;
    private final String clusterName;

    public BackendServiceImpl(
            StateServer stateServer, int grpcPort, HazelcastInstance hazelcast, String clusterName) {
        this.stateServer = stateServer;
        this.grpcPort = grpcPort;
        this.hazelcast = hazelcast;
        this.clusterName = clusterName;
    }

    @Override
    public void log(com.google.protobuf.Empty request, StreamObserver<LogMessage> responseObserver) {
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
    public void ping(com.google.protobuf.Empty request, StreamObserver<PingResponse> responseObserver) {
        PingResponse response = PingResponse.newBuilder()
                .setStatus(MemberStatus.MEMBER_STATUS_READY)
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }

    @Override
    public void subscribe(com.google.protobuf.Empty request, StreamObserver<ClusterState> responseObserver) {
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
