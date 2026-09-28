// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import io.grpc.Context;

/**
 * Shared gRPC context key for peer address identification.
 * Used by the server interceptor to store the peer address,
 * and by generated backend service servers to filter topic messages
 * so the originator does not receive its own publications.
 */
public final class PeerContext {
    /** Context key carrying the remote peer address for the current RPC. */
    public static final Context.Key<String> PEER_KEY = Context.key("peer-address");

    private PeerContext() {}
}
