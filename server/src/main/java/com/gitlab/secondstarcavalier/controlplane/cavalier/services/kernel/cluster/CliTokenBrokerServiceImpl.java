// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.common.tokenrequest.Tokenrequest;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * CliTokenBroker mediates CLI auth nonce matching between oauth instances.
 *
 * Nonce registry uses Hazelcast IMap (distributed across all kernel nodes).
 * Instance streams are local (gRPC streams can't cross nodes).
 * Cross-node delivery: minting node writes "delivery:<nonce>" to IMap,
 * entry listener on the node holding the stream picks it up.
 */
public class CliTokenBrokerServiceImpl implements
		com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker.CliTokenBrokerHandler {

	private static final Logger logger = LoggerFactory.getLogger(CliTokenBrokerServiceImpl.class);
	private static final long NONCE_TTL_SECONDS = 300;
	private static final String DELIVERY_PREFIX = "delivery:";

	// Local: instance_id → gRPC stream (streams can't cross nodes)
	private final ConcurrentHashMap<String, StreamObserver<Kernel.CliTokenBrokerResponse>> instanceStreams =
			new ConcurrentHashMap<>();

	// Local: nonce → instance_id (so we know which local stream to deliver to)
	private final ConcurrentHashMap<String, String> localNonceOwners = new ConcurrentHashMap<>();

	// Distributed: nonce → NonceEntry (instance_id + timestamp)
	private final IMap<String, NonceEntry> nonceMap;
	private final IdentityServiceImpl identityService;

	public static class NonceEntry implements Serializable {
		private static final long serialVersionUID = 1L;
		public final String instanceId;
		public final String refreshToken; // only set for delivery entries
		public final long createdAt;

		public NonceEntry(String instanceId) {
			this(instanceId, null);
		}

		public NonceEntry(String instanceId, String refreshToken) {
			this.instanceId = instanceId;
			this.refreshToken = refreshToken;
			this.createdAt = System.currentTimeMillis() / 1000;
		}

		public boolean isExpired() {
			return (System.currentTimeMillis() / 1000) - createdAt > NONCE_TTL_SECONDS;
		}
	}

	// Kernel is the cluster trust root and the sole token authority. On
	// CompleteNonce the broker mints the user's token via the in-process Mint
	// handler (identityService) using the broker-attested subject+claims, then
	// delivers it to the waiting oauth instance.
	public CliTokenBrokerServiceImpl(IdentityServiceImpl identityService, HazelcastInstance hazelcast) {
		this.identityService = identityService;
		this.nonceMap = hazelcast.getMap("cli-token-broker");

		// Listen for cross-node token deliveries.
		// When "delivery:<nonce>" appears, check if the target stream is local.
		nonceMap.addEntryListener(
				(com.hazelcast.map.listener.EntryAddedListener<String, NonceEntry>) event -> {
					String key = event.getKey();
					if (!key.startsWith(DELIVERY_PREFIX)) return;
					String nonce = key.substring(DELIVERY_PREFIX.length());

					// Is the stream for this nonce on this node?
					String localInstanceId = localNonceOwners.remove(nonce);
					if (localInstanceId == null) return; // not ours

					NonceEntry delivery = nonceMap.remove(key);
					if (delivery == null || delivery.refreshToken == null) return;

					StreamObserver<Kernel.CliTokenBrokerResponse> stream =
							instanceStreams.get(localInstanceId);
					if (stream != null) {
						stream.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
								.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
										.setNonce(nonce)
										.setRefreshToken(delivery.refreshToken)
										.build())
								.build());
						logger.info("CliTokenBroker: cross-node token delivered for nonce {} → instance {}",
								nonce.substring(0, 8), localInstanceId);
					}
				}, true);
	}

	@Override
	public StreamObserver<Kernel.CliTokenBrokerRequest> brokerStream(
			com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.libs.servicemanager.Caller caller,
			StreamObserver<Kernel.CliTokenBrokerResponse> responseObserver) {

		return new StreamObserver<>() {
			private String instanceId;

			@Override
			public void onNext(Kernel.CliTokenBrokerRequest request) {
				switch (request.getMsgCase()) {
					case REGISTER -> {
						instanceId = request.getRegister().getInstanceId();
						instanceStreams.put(instanceId, responseObserver);
						logger.info("CliTokenBroker: oauth instance registered: {}", instanceId);
						// Flush gRPC response headers so the client's stream-open await completes.
						// In gRPC-Java, bidi response headers are deferred until the first onNext().
						responseObserver.onNext(Kernel.CliTokenBrokerResponse.getDefaultInstance());
					}
					case REGISTER_NONCE -> {
						if (instanceId == null) { logger.warn("RegisterNonce before Register"); return; }
						String nonce = request.getRegisterNonce().getNonce();
						nonceMap.put(nonce, new NonceEntry(instanceId), NONCE_TTL_SECONDS, TimeUnit.SECONDS);
						localNonceOwners.put(nonce, instanceId);
						logger.info("CliTokenBroker: nonce registered: {} → instance {}", nonce.substring(0, 8), instanceId);

						// Buffered delivery: if CompleteNonce already minted a token while the
						// owning oauth instance was disconnected (or before any instance
						// registered), the refresh_token sits in nonceMap keyed by
						// DELIVERY_PREFIX + nonce. Replay it now that we have a stream.
						NonceEntry pending = nonceMap.remove(DELIVERY_PREFIX + nonce);
						if (pending != null && pending.refreshToken != null && !pending.isExpired()) {
							responseObserver.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
									.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
											.setNonce(nonce)
											.setRefreshToken(pending.refreshToken)
											.build())
									.build());
							localNonceOwners.remove(nonce);
							logger.info("CliTokenBroker: buffered token replayed for nonce {} → instance {}",
									nonce.substring(0, 8), instanceId);
						}
					}
					case COMPLETE_NONCE -> handleCompleteNonce(request.getCompleteNonce());
					default -> logger.warn("Unknown message type: {}", request.getMsgCase());
				}
			}

			private void handleCompleteNonce(Kernel.CliTokenBrokerCompleteNonce complete) {
				String nonce = complete.getNonce();

				// Retry — IMap replication may lag slightly across nodes
				NonceEntry entry = null;
				for (int attempt = 0; attempt < 10; attempt++) {
					entry = nonceMap.remove(nonce);
					if (entry != null) break;
					try { Thread.sleep(500); } catch (InterruptedException e) {
						Thread.currentThread().interrupt(); return;
					}
				}

				if (entry == null || entry.isExpired()) {
					logger.warn("CliTokenBroker: CompleteNonce — nonce not found or expired: {}", nonce.substring(0, 8));
					return;
				}

				// Kernel mints the user's token from the broker-attested subject +
				// claims (azp = oauth, the authorized broker), then delivers it.
				String refreshToken;
				try {
					Tokenrequest.TokenMintResponse mintResponse = identityService.mintUserTokenInternal(
							complete.getSubject(),
							complete.hasClaims() ? complete.getClaims() : null,
							0, "", "oauth", false);
					refreshToken = mintResponse.getRefreshToken().getBase64();
				} catch (IdentityServiceImpl.StatusException e) {
					logger.error("CliTokenBroker: mint failed for nonce {}", nonce.substring(0, 8), e);
					return;
				}

				// Deliver the oauth-minted token to the owning oauth instance.
				// Local fast path if that instance's stream is on this node;
				// otherwise hand off cross-node via the DELIVERY_PREFIX entry
				// (the entry listener on the owning node replays it).
				StreamObserver<Kernel.CliTokenBrokerResponse> localStream =
						instanceStreams.get(entry.instanceId);
				if (localStream != null) {
					localNonceOwners.remove(nonce);
					localStream.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
							.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
									.setNonce(nonce)
									.setRefreshToken(refreshToken)
									.build())
							.build());
					logger.info("CliTokenBroker: token delivered for nonce {} → instance {}",
							nonce.substring(0, 8), entry.instanceId);
				} else {
					nonceMap.put(DELIVERY_PREFIX + nonce,
							new NonceEntry(entry.instanceId, refreshToken),
							NONCE_TTL_SECONDS, TimeUnit.SECONDS);
					logger.info("CliTokenBroker: token queued for cross-node delivery for nonce {} → instance {}",
							nonce.substring(0, 8), entry.instanceId);
				}
			}

			@Override
			public void onError(Throwable t) {
				if (instanceId != null) {
					instanceStreams.remove(instanceId);
					logger.info("CliTokenBroker: oauth instance disconnected: {}", instanceId);
				}
			}

			@Override
			public void onCompleted() {
				if (instanceId != null) {
					instanceStreams.remove(instanceId);
					logger.info("CliTokenBroker: oauth instance stream closed: {}", instanceId);
				}
				responseObserver.onCompleted();
			}
		};
	}
}
