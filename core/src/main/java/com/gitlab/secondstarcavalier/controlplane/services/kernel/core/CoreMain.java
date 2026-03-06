// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.core;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.Bootstrap;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.Kernel;

/**
 * Entry point for a kernel core node. Core nodes own data partitions,
 * write persistence, participate in Raft consensus, and count toward
 * quorum. They do NOT accept gRPC from microservices.
 */
public class CoreMain {

    public static void main(String[] args) throws Exception {
        Bootstrap.run(args, Kernel.NodeMode.NODE_MODE_CORE);
    }
}
