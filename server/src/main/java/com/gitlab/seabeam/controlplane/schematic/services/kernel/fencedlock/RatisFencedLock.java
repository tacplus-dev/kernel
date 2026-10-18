// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.fencedlock;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.ratis.RaftConfigKeys;
import org.apache.ratis.client.RaftClient;
import org.apache.ratis.conf.RaftProperties;
import org.apache.ratis.grpc.GrpcConfigKeys;
import org.apache.ratis.protocol.Message;
import org.apache.ratis.protocol.RaftClientReply;
import org.apache.ratis.protocol.RaftGroup;
import org.apache.ratis.protocol.RaftGroupId;
import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.retry.RetryPolicies;
import org.apache.ratis.rpc.SupportedRpcType;
import org.apache.ratis.server.RaftServer;
import org.apache.ratis.server.RaftServerConfigKeys;
import org.apache.ratis.server.storage.RaftStorage;
import org.apache.ratis.thirdparty.com.google.protobuf.ByteString;
import org.apache.ratis.util.NetUtils;
import org.apache.ratis.util.TimeDuration;

/**
 * RatisFencedLock is kernel's embedded Apache Ratis peer: one Raft server
 * running {@link FencedLockStateMachine}, plus a client that submits lock
 * operations to whichever peer is currently leader.
 *
 * <p>Kernel is the only service in the fleet that runs this. Every other
 * service that needs a lock calls kernel's FencedLock s2s surface, which lands
 * here (decisions/kernel-convergent-only-plus-fenced-lock-2026-08-31.md).
 *
 * <p>Both operations go through the Raft log rather than being answered locally:
 * a lock decision read from a stale follower is not a lock decision. The client
 * follows leader changes on its own, so callers see an ordinary blocking call.
 */
public final class RatisFencedLock implements AutoCloseable {

	/**
	 * The lock group's id is fixed and derived from the name, not random: every
	 * kernel instance must join the SAME Raft group, and a group id generated per
	 * process would give each instance its own single-member group — which looks
	 * healthy and grants every contender the lock.
	 */
	public static final RaftGroupId GROUP_ID =
			RaftGroupId.valueOf(UUID.nameUUIDFromBytes("kernel.FencedLock".getBytes(java.nio.charset.StandardCharsets.UTF_8)));

	private static final int RETRY_ATTEMPTS = 20;
	private static final long RETRY_SLEEP_MS = 250;

	/**
	 * Log entries between automatic snapshots. Low, because the state being
	 * snapshotted is one small map: the cost of taking one is negligible next to
	 * replaying every lock operation the cluster has ever performed at startup.
	 */
	private static final long SNAPSHOT_TRIGGER_ENTRIES = 1000;

	private final RaftServer server;
	private final RaftClient client;

	private RatisFencedLock(RaftServer server, RaftClient client) {
		this.server = server;
		this.client = client;
	}

	/** peer builds the RaftPeer for one kernel instance at host:port. */
	public static RaftPeer peer(String id, String host, int port) {
		return RaftPeer.newBuilder().setId(id).setAddress(host + ":" + port).build();
	}

	/**
	 * start brings up this instance's Raft server and returns a handle that can
	 * serve Acquire/Release.
	 *
	 * @param selfId     this instance's peer id; must be one of the group's peers
	 * @param group      the full peer set, identical on every instance
	 * @param storageDir directory for this instance's Raft log
	 */
	public static RatisFencedLock start(RaftPeerId selfId, RaftGroup group, File storageDir) throws IOException {
		final RaftPeer self = group.getPeer(selfId);
		if (self == null) {
			throw new IOException("peer " + selfId + " is not a member of the FencedLock group " + group.getGroupId());
		}

		final RaftProperties properties = new RaftProperties();
		RaftConfigKeys.Rpc.setType(properties, SupportedRpcType.GRPC);
		RaftServerConfigKeys.setStorageDir(properties, List.of(storageDir));
		GrpcConfigKeys.Server.setPort(properties, NetUtils.createSocketAddr(self.getAddress()).getPort());

		// Snapshot on a schedule and purge the log behind it. Ratis will not purge
		// a log it has no snapshot for, so leaving these at their defaults means
		// the segment log grows for the life of the cluster and every restart
		// replays it from index 0 — startup time rising with total lock traffic on
		// the service that gates cluster leadership. FencedLockStateMachine
		// implements the snapshot these keys trigger.
		RaftServerConfigKeys.Snapshot.setAutoTriggerEnabled(properties, true);
		RaftServerConfigKeys.Snapshot.setAutoTriggerThreshold(properties, SNAPSHOT_TRIGGER_ENTRIES);
		RaftServerConfigKeys.Log.setPurgeUptoSnapshotIndex(properties, true);

		// RECOVER when this peer already has a log, FORMAT only on first start.
		// Ratis defaults to FORMAT and refuses to start over an existing
		// directory; taking the default would mean a kernel restart either fails
		// outright or, worse, discards the log the fencing tokens are numbered
		// from and starts handing out indexes a live holder still carries.
		final RaftStorage.StartupOption startupOption = hasExistingLog(storageDir, group.getGroupId())
				? RaftStorage.StartupOption.RECOVER
				: RaftStorage.StartupOption.FORMAT;

		final RaftServer server = RaftServer.newBuilder()
				.setServerId(selfId)
				.setGroup(group)
				.setProperties(properties)
				.setOption(startupOption)
				.setStateMachine(new FencedLockStateMachine())
				.build();
		server.start();

		// A bounded retry, not the default single attempt: a leader election or a
		// leader step-down is routine, and a lock call that fails outright because
		// it happened to land mid-election would push that retry onto every caller
		// in the fleet. Bounded rather than forever so a genuinely down group
		// surfaces as UNAVAILABLE instead of hanging the caller's RPC.
		final RaftClient client = RaftClient.newBuilder()
				.setRaftGroup(group)
				.setProperties(properties)
				.setRetryPolicy(RetryPolicies.retryUpToMaximumCountWithFixedSleep(
						RETRY_ATTEMPTS, TimeDuration.valueOf(RETRY_SLEEP_MS, TimeUnit.MILLISECONDS)))
				.build();

		return new RatisFencedLock(server, client);
	}

	/** hasExistingLog reports whether this peer has already formatted storage for the group. */
	private static boolean hasExistingLog(File storageDir, RaftGroupId groupId) {
		return new File(storageDir, groupId.getUuid().toString()).isDirectory();
	}

	/**
	 * acquire submits an Acquire through Raft and returns the replicated answer.
	 *
	 * @param holderId the caller identity kernel verified for this RPC; it, not
	 *                 the request's {@code holder_id} field, is what gets
	 *                 recorded as the holder
	 */
	public Kernel.FencedLockAcquireResponse acquire(String holderId, Kernel.FencedLockAcquireRequest request)
			throws IOException {
		final byte[] reply = send(FencedLockOp.encodeAcquire(holderId, request));
		try {
			return Kernel.FencedLockAcquireResponse.parseFrom(reply);
		} catch (com.google.protobuf.InvalidProtocolBufferException e) {
			throw new IOException("FencedLock state machine returned an undecodable acquire reply", e);
		}
	}

	/**
	 * release submits a Release through Raft and returns the replicated answer.
	 *
	 * @param holderId the caller identity kernel verified for this RPC; the state
	 *                 machine releases only if it matches the recorded holder
	 */
	public Kernel.FencedLockReleaseResponse release(String holderId, Kernel.FencedLockReleaseRequest request)
			throws IOException {
		final byte[] reply = send(FencedLockOp.encodeRelease(holderId, request));
		try {
			return Kernel.FencedLockReleaseResponse.parseFrom(reply);
		} catch (com.google.protobuf.InvalidProtocolBufferException e) {
			throw new IOException("FencedLock state machine returned an undecodable release reply", e);
		}
	}

	private byte[] send(byte[] op) throws IOException {
		final RaftClientReply reply = client.io().send(Message.valueOf(ByteString.copyFrom(op)));
		if (!reply.isSuccess()) {
			throw new IOException("FencedLock Raft operation failed: " + reply.getException(), reply.getException());
		}
		return reply.getMessage().getContent().toByteArray();
	}

	@Override
	public void close() throws IOException {
		try {
			client.close();
		} finally {
			server.close();
		}
	}
}
