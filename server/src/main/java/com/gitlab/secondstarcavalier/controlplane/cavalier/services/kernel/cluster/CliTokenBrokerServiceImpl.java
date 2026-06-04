// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
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
		com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker.CliTokenBrokerHandler {

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

	// Token SIGNING/minting moved out of the kernel into the mint service, so
	// this broker no longer takes a signing service — it only matches nonces and
	// delivers the token that mint produces (TODO(mint-wire) in handleCompleteNonce).
	public CliTokenBrokerServiceImpl(HazelcastInstance hazelcast) {
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
			com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.servicemanager.Caller caller,
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

				// TODO(mint-wire): user-token minting has moved out of the kernel
				// into the `mint` service (the authoritative token_minter). The
				// kernel no longer signs JWTs (KeyRotator deleted,
				// IdentityServiceImpl minting removed). To complete CLI login this
				// broker must obtain the user's refresh token from the mint service
				// S2S — passing the verified subject + IdP claims that the oauth
				// instance attested in CompleteNonce — instead of minting locally.
				// Until that kernel→mint S2S call is wired, the nonce is matched but
				// no token can be delivered; the CLI will time out and retry.
				//
				// Once kernel→mint S2S is wired, mint returns a refresh token for
				// the verified subject/claims; deliver it to the owning oauth
				// instance — locally via instanceStreams.get(entry.instanceId), or
				// cross-node by writing NonceEntry(entry.instanceId, refreshToken)
				// to nonceMap under DELIVERY_PREFIX + nonce (the entry listener on
				// the owning node replays it). See the entry listener above.
				logger.warn("CliTokenBroker: token minting moved to mint service and is not yet wired "
						+ "(TODO(mint-wire)); cannot deliver token for nonce {} (subject={})",
						nonce.substring(0, 8), complete.getSubject());
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
