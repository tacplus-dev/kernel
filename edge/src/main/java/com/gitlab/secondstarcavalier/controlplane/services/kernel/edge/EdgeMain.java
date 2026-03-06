// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.edge;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.Bootstrap;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;

/**
 * Entry point for a kernel edge node. Edge nodes join as Hazelcast lite
 * members (no data partitions), skip Raft and persistence, and serve all
 * gRPC for microservices (backend state RPCs, TokenExchanger, JwkView).
 * They are scalable 0-N and do not affect quorum.
 */
public class EdgeMain {

    public static void main(String[] args) throws Exception {
        Bootstrap.run(args, Kernel.NodeMode.NODE_MODE_EDGE);
    }
}
