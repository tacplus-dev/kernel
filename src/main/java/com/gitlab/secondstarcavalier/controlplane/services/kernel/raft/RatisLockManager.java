// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.raft;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCert;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.host.HostOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.proto.interfaces.java.graphs.Lock;

import org.apache.ratis.client.RaftClient;
import org.apache.ratis.conf.Parameters;
import org.apache.ratis.conf.RaftProperties;
import org.apache.ratis.grpc.GrpcConfigKeys;
import org.apache.ratis.grpc.GrpcFactory;
import org.apache.ratis.grpc.GrpcTlsConfig;
import org.apache.ratis.protocol.*;
import org.apache.ratis.server.RaftServer;
import org.apache.ratis.server.RaftServerConfigKeys;
import org.apache.ratis.thirdparty.com.google.protobuf.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Manages a Ratis (Raft consensus) cluster for distributed fenced locks.
 *
 * <p>Each kernel node runs a Ratis peer. The Raft group provides linearizable
 * lock operations via {@link LockStateMachine}. mTLS is configured using the
 * same TLS cert pair and trusted CAs from the BootstrapConfig.
 */
public class RatisLockManager {

    private static final Logger logger = LoggerFactory.getLogger(RatisLockManager.class);
    private static final RaftGroupId LOCK_GROUP_ID =
            RaftGroupId.valueOf(UUID.fromString("00000000-0000-0000-0000-000000000001"));

    private final RaftServer server;
    private final RaftClient client;
    private final String ownerId;

    /**
     * Creates a RatisLockManager.
     *
     * @param selfHost   this node's hostname (must match one of the member hosts)
     * @param raftPort   the raft port (same for all nodes)
     * @param members    all cluster members (host used for peer addresses)
     * @param storageDir directory for Raft log storage
     * @param tls        TLS cert pair for mTLS (may be null to disable TLS)
     * @param trustedCas trusted CA certs for mTLS (may be empty)
     */
    public RatisLockManager(
            String selfHost,
            int raftPort,
            List<HostOuterClass.Host> members,
            File storageDir,
            X509.X509CertPair tls,
            List<X509.X509Cert> trustedCas)
            throws IOException {

        this.ownerId = selfHost + ":" + raftPort;

        // Build peer list — all nodes use the same raft port
        List<RaftPeer> peers = new ArrayList<>();
        RaftPeerId selfPeerId = null;
        for (int i = 0; i < members.size(); i++) {
            String host = members.get(i).getHost();
            RaftPeerId peerId = RaftPeerId.valueOf("peer-" + i);
            peers.add(RaftPeer.newBuilder()
                    .setId(peerId)
                    .setAddress(host + ":" + raftPort)
                    .build());
            if (host.equals(selfHost)) {
                selfPeerId = peerId;
            }
        }

        if (selfPeerId == null) {
            throw new IllegalArgumentException(
                    "Self host " + selfHost + " not found in member list: "
                    + members.stream().map(HostOuterClass.Host::getHost)
                            .collect(java.util.stream.Collectors.joining(", ")));
        }

        RaftGroup group = RaftGroup.valueOf(LOCK_GROUP_ID, peers);
        RaftProperties properties = new RaftProperties();
        // Clean stale Ratis data from previous runs — lock state is ephemeral
        // and doesn't need to survive restarts (Hazelcast redo log handles persistence).
        if (storageDir.exists()) {
            logger.info("Cleaning stale Ratis data at {}", storageDir);
            deleteRecursive(storageDir);
        }
        RaftServerConfigKeys.setStorageDir(properties, List.of(storageDir));
        GrpcConfigKeys.Server.setPort(properties, raftPort);

        // Configure mTLS
        Parameters parameters = new Parameters();
        if (tls != null) {
            try {
                ImmutableCertPair certPair = ImmutableCertPair.from(tls);

                // Build trusted CA cert list
                List<java.security.cert.X509Certificate> caCerts = new ArrayList<>();
                for (X509.X509Cert ca : trustedCas) {
                    ImmutableCert immCa = ImmutableCert.from(ca);
                    caCerts.add(immCa.getX509Certificate());
                }

                GrpcTlsConfig tlsConfig = new GrpcTlsConfig(
                        certPair.getKey().getPrivateKey(),
                        certPair.getCert().getX509Certificate(),
                        caCerts,
                        true); // mutual TLS
                GrpcConfigKeys.TLS.setConf(parameters, tlsConfig);

                logger.info("Ratis mTLS configured with {} trusted CA(s)", trustedCas.size());
            } catch (Exception e) {
                logger.warn("Failed to configure Ratis mTLS, proceeding without TLS", e);
            }
        }

        this.server = RaftServer.newBuilder()
                .setServerId(selfPeerId)
                .setGroup(group)
                .setStateMachine(new LockStateMachine())
                .setProperties(properties)
                .setParameters(parameters)
                .build();

        this.client = RaftClient.newBuilder()
                .setRaftGroup(group)
                .setProperties(properties)
                .setClientRpc(new GrpcFactory(parameters).newRaftClientRpc(ClientId.randomId(), properties))
                .build();

        logger.info("RatisLockManager created: self={}:{}, peers={}", selfHost, raftPort, peers.size());
    }

    /** Starts the Raft server. */
    public void start() throws IOException {
        server.start();
        logger.info("Ratis server started");
    }

    /**
     * Blocks until the Raft group has elected a leader.
     * Times out after 30 seconds.
     */
    public void waitForLeader() throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                RaftClientReply reply = client.io().send(
                        Message.valueOf(ByteString.copyFromUtf8("QUERY:__ping__")));
                if (reply.isSuccess()) {
                    logger.info("Raft leader elected, cluster ready");
                    return;
                }
            } catch (IOException e) {
                // Leader not yet elected, retry
            }
            Thread.sleep(200);
        }
        throw new IOException("Raft leader election timed out after 30 seconds");
    }

    /** Stops the Raft server and client. */
    public void close() {
        try {
            client.close();
        } catch (IOException e) {
            logger.warn("Error closing Ratis client", e);
        }
        try {
            server.close();
        } catch (IOException e) {
            logger.warn("Error closing Ratis server", e);
        }
        logger.info("Ratis server stopped");
    }

    /** Returns the owner ID for this node (used in lock ownership tracking). */
    public String getOwnerId() {
        return ownerId;
    }

    /**
     * Attempts to acquire a named lock.
     *
     * @return fence token (>= 0) on success, or -1 if the lock is held by another owner
     */
    public long acquire(String lockName) {
        try {
            String command = "ACQUIRE:" + lockName + ":" + ownerId;
            RaftClientReply reply = client.io().send(
                    Message.valueOf(ByteString.copyFromUtf8(command)));
            String response = reply.getMessage().getContent().toStringUtf8();
            if (response.startsWith("OK:")) {
                return Long.parseLong(response.substring(3));
            }
            return -1;
        } catch (IOException e) {
            logger.warn("Lock acquire failed for {}: {}", lockName, e.getMessage());
            return -1;
        }
    }

    /** Releases a named lock. */
    public void release(String lockName) {
        try {
            String command = "RELEASE:" + lockName + ":" + ownerId;
            client.io().send(Message.valueOf(ByteString.copyFromUtf8(command)));
        } catch (IOException e) {
            logger.warn("Lock release failed for {}: {}", lockName, e.getMessage());
        }
    }

    /** Queries the state of a named lock. Returns the raw state string. */
    public String query(String lockName) {
        try {
            String command = "QUERY:" + lockName;
            RaftClientReply reply = client.io().send(
                    Message.valueOf(ByteString.copyFromUtf8(command)));
            return reply.getMessage().getContent().toStringUtf8();
        } catch (IOException e) {
            logger.warn("Lock query failed for {}: {}", lockName, e.getMessage());
            return null;
        }
    }

    /** Creates a Lock backed by this Raft cluster. */
    public Lock getLock(String name) {
        return new RatisLock(this, name);
    }

    private static void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }
}
