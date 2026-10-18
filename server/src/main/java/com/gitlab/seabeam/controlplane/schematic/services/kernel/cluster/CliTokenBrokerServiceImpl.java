// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.google.protobuf.InvalidProtocolBufferException;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * CliTokenBroker mediates CLI auth nonce matching between oauth instances.
 *
 * Nonce registry uses Hazelcast IMap (distributed across all kernel nodes).
 * Instance streams are local (gRPC streams can't cross nodes).
 * Cross-node delivery: minting node writes "delivery:<nonce>" to IMap,
 * entry listener on the node holding the stream picks it up.
 *
 * <p><b>A token is never minted before there is somewhere to put it.</b> A
 * refresh token for a real user cannot be un-issued, so the broker reserves the
 * delivery slot first and mints into it: buffering can legitimately be refused
 * (cap lock busy, buffer full, slot taken), and a mint that happened first would
 * leave a valid token nobody delivers, nobody revokes, and nothing expires until
 * its own lifetime runs out. For the same reason a CompleteNonce that arrives
 * before any RegisterNonce parks the REQUEST under "pending:&lt;nonce&gt;" rather
 * than minting: {@code offline_access} is stated by the registration and is
 * baked into the token at mint time, so minting early would hand the user a
 * token of the wrong kind.
 */
public class CliTokenBrokerServiceImpl implements
		com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.CliTokenBroker.CliTokenBrokerHandler {

	private static final Logger logger = LoggerFactory.getLogger(CliTokenBrokerServiceImpl.class);
	private static final long NONCE_TTL_SECONDS = 300;
	private static final long NONCE_REGISTRATION_WAIT_MILLIS = 5000;
	private static final int MAX_BUFFERED_DELIVERIES = 1024;
	private static final String DELIVERY_PREFIX = "delivery:";
	private static final String CONSUMED_PREFIX = "consumed:";
	/** A CompleteNonce parked until a RegisterNonce says whether offline access was asked for. */
	private static final String PENDING_PREFIX = "pending:";
	/** A delivery slot claimed before minting, so a minted token always has a slot. */
	private static final String RESERVE_PREFIX = "reserve:";
	private static final String DELIVERY_CAP_LOCK = "delivery-cap-lock";

	/**
	 * Shortest nonce the broker will handle. The nonce is client-generated and
	 * travels through the browser, so it is the only thing standing between a
	 * pending login and whoever guesses it — a three-character nonce is not a
	 * credential worth brokering. Deliberately well below the 128 bits a real
	 * client generates, so this rejects abuse rather than short-but-honest
	 * encodings.
	 */
	private static final int MIN_NONCE_LENGTH = 16;

	// Local: instance_id → gRPC stream (streams can't cross nodes)
	private final ConcurrentHashMap<String, StreamObserver<Kernel.CliTokenBrokerResponse>> instanceStreams =
			new ConcurrentHashMap<>();

	// Local: nonce → instance_id (so we know which local stream to deliver to)
	private final ConcurrentHashMap<String, String> localNonceOwners = new ConcurrentHashMap<>();

	// Local: nonce → CompleteNonce parked until its registration replicates here
	private final ConcurrentHashMap<String, CompletableFuture<NonceEntry>> pendingCompletions =
			new ConcurrentHashMap<>();

	// Distributed: nonce → NonceEntry (instance_id + timestamp)
	private final IMap<String, NonceEntry> nonceMap;
	private final TokenMinter tokenMinter;

	@FunctionalInterface
	interface TokenMinter {
		String mint(Kernel.CliTokenBrokerCompleteNonce complete, String nonce, boolean offlineAccess);
	}

	/**
	 * First 8 characters of a nonce, for logs. Length-checked because the nonce is
	 * client-supplied: a bare {@code substring(0, 8)} throws on a short one, and
	 * these log sites sit on the gRPC handling thread and inside a mint-failure
	 * catch, where the throw would replace a handled error with one that kills the
	 * broker stream.
	 */
	private static String shortNonce(String nonce) {
		return nonce == null ? "" : nonce.substring(0, Math.min(8, nonce.length()));
	}

	/** A nonce below {@link #MIN_NONCE_LENGTH} is refused outright. */
	private static boolean isNonceAcceptable(String nonce) {
		return nonce != null && nonce.length() >= MIN_NONCE_LENGTH;
	}

	public static class NonceEntry implements Serializable {
		private static final long serialVersionUID = 1L;
		public final String instanceId;
		public final String refreshToken; // only set for delivery entries
		public final boolean offlineAccess; // only meaningful for nonce registrations
		// Wire-encoded CliTokenBrokerCompleteNonce; only set for PENDING_PREFIX entries.
		public final byte[] pendingComplete;
		public final long createdAt;

		public NonceEntry(String instanceId) {
			this(instanceId, null, false);
		}

		public NonceEntry(String instanceId, String refreshToken) {
			this(instanceId, refreshToken, false);
		}

		public NonceEntry(String instanceId, boolean offlineAccess) {
			this(instanceId, null, offlineAccess);
		}

		public NonceEntry(String instanceId, String refreshToken, boolean offlineAccess) {
			this(instanceId, refreshToken, offlineAccess, System.currentTimeMillis() / 1000);
		}

		NonceEntry(String instanceId, String refreshToken, long createdAt) {
			this(instanceId, refreshToken, false, createdAt);
		}

		NonceEntry(String instanceId, String refreshToken, boolean offlineAccess, long createdAt) {
			this(instanceId, refreshToken, offlineAccess, null, createdAt);
		}

		private NonceEntry(String instanceId, String refreshToken, boolean offlineAccess,
				byte[] pendingComplete, long createdAt) {
			this.instanceId = instanceId;
			this.refreshToken = refreshToken;
			this.offlineAccess = offlineAccess;
			this.pendingComplete = pendingComplete;
			this.createdAt = createdAt;
		}

		/** A CompleteNonce parked until its registration arrives; nothing has been minted. */
		static NonceEntry pendingCompletion(Kernel.CliTokenBrokerCompleteNonce complete) {
			return new NonceEntry("", null, false, complete.toByteArray(),
					System.currentTimeMillis() / 1000);
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
		this((complete, nonce, offlineAccess) -> {
			try {
				Tokenrequest.TokenMintResponse mintResponse = identityService.mintUserTokenInternal(
						complete.getSubject(),
						complete.hasClaims() ? complete.getClaims() : null,
						0, "", "oauth", offlineAccess, null);
				return mintResponse.getRefreshToken().getBase64();
			} catch (IdentityServiceImpl.StatusException e) {
				logger.error("CliTokenBroker: mint failed for nonce {}", shortNonce(nonce), e);
				return null;
			}
		}, hazelcast);
	}

	CliTokenBrokerServiceImpl(TokenMinter tokenMinter, HazelcastInstance hazelcast) {
		this.tokenMinter = tokenMinter;
		this.nonceMap = hazelcast.getMap("cli-token-broker");

		// Listen for cross-node token deliveries.
		// When "delivery:<nonce>" appears, check if the target stream is local.
		nonceMap.addEntryListener(
				(com.hazelcast.map.listener.EntryAddedListener<String, NonceEntry>) event -> {
					String key = event.getKey();
					if (!key.startsWith(DELIVERY_PREFIX)) {
						// A nonce registration landing here may be what a parked
						// CompleteNonce is waiting for. The broker's own bookkeeping
						// key spaces are not registrations and must not be taken for one.
						if (!key.startsWith(CONSUMED_PREFIX)
								&& !key.startsWith(PENDING_PREFIX)
								&& !key.startsWith(RESERVE_PREFIX)) {
							resumePendingCompletion(key);
						}
						return;
					}
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
								shortNonce(nonce), localInstanceId);
					}
				}, true);
	}

	// Hands a nonce's registration to the CompleteNonce parked on it, if any.
	// Claiming the entry with remove() keeps the "first completer wins" semantics
	// the synchronous path has.
	private void resumePendingCompletion(String nonce) {
		CompletableFuture<NonceEntry> pending = pendingCompletions.get(nonce);
		if (pending == null) return;
		NonceEntry registered = nonceMap.remove(nonce);
		if (registered != null) pending.complete(registered);
	}

	@Override
	public StreamObserver<Kernel.CliTokenBrokerRequest> brokerStream(
			com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Caller caller,
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
						if (!isNonceAcceptable(nonce)) {
							logger.warn("CliTokenBroker: RegisterNonce rejected — nonce below {} characters",
									MIN_NONCE_LENGTH);
							return;
						}

						// Buffered delivery: a token minted while the owning oauth instance
						// was disconnected sits in nonceMap keyed by DELIVERY_PREFIX + nonce.
						// Replay it now that we have a stream.
						NonceEntry buffered = nonceMap.remove(DELIVERY_PREFIX + nonce);
						if (buffered != null) {
							if (buffered.refreshToken != null && !buffered.isExpired()) {
								responseObserver.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
										.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
												.setNonce(nonce)
												.setRefreshToken(buffered.refreshToken)
												.build())
										.build());
								markNonceConsumed(nonce);
								logger.info("CliTokenBroker: buffered token replayed for nonce {} → instance {}",
										shortNonce(nonce), instanceId);
							} else {
								logger.warn("CliTokenBroker: buffered token expired for nonce {}", shortNonce(nonce));
							}
							return;
						}

						// Buffered completion: CompleteNonce arrived before any oauth
						// instance had registered this nonce, so nothing was minted —
						// offline_access is stated by the REGISTRATION and is baked into the
						// token at mint time. The registration is what was missing; mint
						// against it now rather than replaying a token of the wrong kind.
						NonceEntry parked = nonceMap.remove(PENDING_PREFIX + nonce);
						if (parked != null) {
							mintParkedCompletion(parked, nonce,
									request.getRegisterNonce().getOfflineAccess());
							return;
						}

						if (isNonceConsumed(nonce)) {
							logger.warn("CliTokenBroker: RegisterNonce rejected for consumed nonce {}", shortNonce(nonce));
							return;
						}

						// First registration wins. The nonce is generated by the CLI and
						// reaches oauth over an unauthenticated session, so a second
						// RegisterNonce for a live nonce is a claim on somebody else's
						// pending login: an unconditional put would move the delivery
						// target to the second registrant's oauth instance and hand it
						// the victim's token. putIfAbsent keeps the original owner.
						NonceEntry registration =
								new NonceEntry(instanceId, request.getRegisterNonce().getOfflineAccess());
						NonceEntry existing =
								nonceMap.putIfAbsent(nonce, registration, NONCE_TTL_SECONDS, TimeUnit.SECONDS);
						if (existing != null) {
							if (!existing.isExpired()) {
								logger.warn("CliTokenBroker: RegisterNonce rejected for nonce {} — already registered to instance {}",
										shortNonce(nonce), existing.instanceId);
								return;
							}
							// An expired registration is nobody's live login. Replace it
							// rather than let it block the nonce until its TTL lapses —
							// across nodes the two can disagree by the clock skew.
							nonceMap.put(nonce, registration, NONCE_TTL_SECONDS, TimeUnit.SECONDS);
						}
						localNonceOwners.put(nonce, instanceId);
						logger.info("CliTokenBroker: nonce registered: {} → instance {}", shortNonce(nonce), instanceId);
					}
					case COMPLETE_NONCE -> handleCompleteNonce(request.getCompleteNonce());
					default -> logger.warn("Unknown message type: {}", request.getMsgCase());
				}
			}

			private void handleCompleteNonce(Kernel.CliTokenBrokerCompleteNonce complete) {
				String nonce = complete.getNonce();
				if (!isNonceAcceptable(nonce)) {
					logger.warn("CliTokenBroker: CompleteNonce rejected — nonce below {} characters",
							MIN_NONCE_LENGTH);
					return;
				}

				if (isNonceConsumed(nonce)) {
					logger.warn("CliTokenBroker: CompleteNonce rejected for consumed nonce {}", shortNonce(nonce));
					return;
				}

				NonceEntry entry = nonceMap.remove(nonce);
				if (entry != null) {
					completeWithRegistration(complete, nonce, entry);
					return;
				}

				// IMap replication may lag across nodes, so this nonce's registration
				// may not be visible here yet. Park the completion and let the entry
				// listener resume it the moment the registration lands; if it never
				// does, orTimeout resumes it with no registration (the buffering path).
				// Either way the gRPC handling thread is released immediately.
				CompletableFuture<NonceEntry> registration = new CompletableFuture<>();
				pendingCompletions.put(nonce, registration);
				registration
						.orTimeout(NONCE_REGISTRATION_WAIT_MILLIS, TimeUnit.MILLISECONDS)
						.whenComplete((registered, failure) -> {
							pendingCompletions.remove(nonce, registration);
							completeWithRegistration(complete, nonce, registered);
						});
				// The registration may have landed between the remove() above and the
				// park, in which case the listener already missed it.
				resumePendingCompletion(nonce);
			}

			private void completeWithRegistration(
					Kernel.CliTokenBrokerCompleteNonce complete, String nonce, NonceEntry entry) {
				if (entry == null) {
					// No registration has been seen, so nothing has said whether the CLI
					// asked for offline access — and that is decided at mint time, not
					// afterwards. Park the REQUEST; RegisterNonce mints it. Minting here
					// would hand the user a non-offline token it could never upgrade, and
					// would leave a signed token stranded if the buffering below refused.
					if (bufferUnderCap(PENDING_PREFIX + nonce, nonce, NonceEntry.pendingCompletion(complete))) {
						logger.info("CliTokenBroker: completion parked before nonce registration for nonce {}",
								shortNonce(nonce));
					}
					return;
				}
				if (entry.isExpired()) {
					logger.warn("CliTokenBroker: CompleteNonce — nonce expired: {}", shortNonce(nonce));
					return;
				}

				// Deliver the oauth-minted token to the owning oauth instance.
				// Local fast path if that instance's stream is on this node;
				// otherwise hand off cross-node via the DELIVERY_PREFIX entry
				// (the entry listener on the owning node replays it).
				StreamObserver<Kernel.CliTokenBrokerResponse> localStream =
						instanceStreams.get(entry.instanceId);
				if (localStream != null) {
					// Kernel mints the user's token from the broker-attested subject +
					// claims (azp = oauth, the authorized broker), then delivers it.
					String refreshToken = mintRefreshToken(complete, nonce, entry.offlineAccess);
					if (refreshToken == null) {
						restoreRegistration(nonce, entry);
						return;
					}
					localNonceOwners.remove(nonce);
					localStream.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
							.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
									.setNonce(nonce)
									.setRefreshToken(refreshToken)
									.build())
							.build());
					markNonceConsumed(nonce);
					logger.info("CliTokenBroker: token delivered for nonce {} → instance {}",
							shortNonce(nonce), entry.instanceId);
				} else {
					// Claim the delivery slot BEFORE minting. Buffering can legitimately
					// be refused, and a token minted first would then be signed, valid,
					// never delivered, never revoked, and live until its own expiry.
					String reserveKey = RESERVE_PREFIX + nonce;
					if (!bufferUnderCap(reserveKey, nonce, new NonceEntry(entry.instanceId))) {
						restoreRegistration(nonce, entry);
						return;
					}
					String refreshToken = mintRefreshToken(complete, nonce, entry.offlineAccess);
					if (refreshToken == null) {
						nonceMap.remove(reserveKey);
						restoreRegistration(nonce, entry);
						return;
					}
					// The reservation guarantees this delivery key is ours alone.
					nonceMap.put(DELIVERY_PREFIX + nonce, new NonceEntry(entry.instanceId, refreshToken),
							NONCE_TTL_SECONDS, TimeUnit.SECONDS);
					nonceMap.remove(reserveKey);
					markNonceConsumed(nonce);
					logger.info("CliTokenBroker: token queued for cross-node delivery for nonce {} → instance {}",
							shortNonce(nonce), entry.instanceId);
				}
			}

			/**
			 * Mints a parked CompleteNonce now that a registration has stated
			 * offline_access, and delivers it on the registering stream.
			 */
			private void mintParkedCompletion(NonceEntry parked, String nonce, boolean offlineAccess) {
				if (parked.pendingComplete == null || parked.isExpired()) {
					logger.warn("CliTokenBroker: parked completion expired for nonce {}", shortNonce(nonce));
					return;
				}
				Kernel.CliTokenBrokerCompleteNonce complete;
				try {
					complete = Kernel.CliTokenBrokerCompleteNonce.parseFrom(parked.pendingComplete);
				} catch (InvalidProtocolBufferException e) {
					logger.error("CliTokenBroker: parked completion for nonce {} is undecodable",
							shortNonce(nonce), e);
					return;
				}
				String refreshToken = mintRefreshToken(complete, nonce, offlineAccess);
				if (refreshToken == null) {
					// Nothing was delivered, so the completion must stay claimable: the
					// CLI is still waiting and oauth will register the nonce again.
					nonceMap.putIfAbsent(PENDING_PREFIX + nonce, parked, NONCE_TTL_SECONDS, TimeUnit.SECONDS);
					return;
				}
				responseObserver.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
						.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
								.setNonce(nonce)
								.setRefreshToken(refreshToken)
								.build())
						.build());
				markNonceConsumed(nonce);
				logger.info("CliTokenBroker: parked completion minted and delivered for nonce {} → instance {}",
						shortNonce(nonce), instanceId);
			}

			/**
			 * Puts a registration back after a mint failed. handleCompleteNonce claims
			 * the registration with remove(); without this the waiting oauth instance
			 * is left with no entry to retry against.
			 */
			private void restoreRegistration(String nonce, NonceEntry entry) {
				nonceMap.putIfAbsent(nonce, entry, NONCE_TTL_SECONDS, TimeUnit.SECONDS);
			}

			/**
			 * Takes a slot in the bounded buffer for {@code nonce} and stores
			 * {@code entry} under {@code key}. Refuses — leaving the buffer untouched —
			 * when the cap lock is busy, the cap is reached, or this nonce already has
			 * a buffered entry of any kind.
			 */
			private boolean bufferUnderCap(String key, String nonce, NonceEntry entry) {
				boolean locked = false;
				try {
					locked = nonceMap.tryLock(DELIVERY_CAP_LOCK, 2, TimeUnit.SECONDS, 5, TimeUnit.SECONDS);
					if (!locked) {
						logger.warn("CliTokenBroker: refusing to buffer for nonce {} — delivery buffer lock busy",
								shortNonce(nonce));
						return false;
					}

					if (nonceMap.containsKey(DELIVERY_PREFIX + nonce)
							|| nonceMap.containsKey(PENDING_PREFIX + nonce)
							|| nonceMap.containsKey(RESERVE_PREFIX + nonce)) {
						logger.warn("CliTokenBroker: refusing to replace the existing buffered entry for nonce {}",
								shortNonce(nonce));
						return false;
					}

					if (bufferedEntryCount() >= MAX_BUFFERED_DELIVERIES) {
						logger.warn("CliTokenBroker: refusing to buffer for nonce {} — delivery buffer full ({})",
								shortNonce(nonce), MAX_BUFFERED_DELIVERIES);
						return false;
					}

					nonceMap.put(key, entry, NONCE_TTL_SECONDS, TimeUnit.SECONDS);
					return true;
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					logger.warn("CliTokenBroker: interrupted while buffering for nonce {}", shortNonce(nonce));
					return false;
				} finally {
					if (locked) {
						nonceMap.unlock(DELIVERY_CAP_LOCK);
					}
				}
			}

			/** Live entries occupying the buffer: minted deliveries, parked completions and reservations. */
			private int bufferedEntryCount() {
				int count = 0;
				for (String key : nonceMap.keySet()) {
					if (!key.startsWith(DELIVERY_PREFIX)
							&& !key.startsWith(PENDING_PREFIX)
							&& !key.startsWith(RESERVE_PREFIX)) {
						continue;
					}
					NonceEntry entry = nonceMap.get(key);
					if (entry == null) continue;
					if (entry.isExpired()) {
						nonceMap.remove(key);
						continue;
					}
					count++;
				}
				return count;
			}

			private boolean isNonceConsumed(String nonce) {
				NonceEntry entry = nonceMap.get(CONSUMED_PREFIX + nonce);
				return entry != null && !entry.isExpired();
			}

			private void markNonceConsumed(String nonce) {
				nonceMap.put(CONSUMED_PREFIX + nonce, new NonceEntry(""), NONCE_TTL_SECONDS, TimeUnit.SECONDS);
				nonceMap.remove(nonce);
				localNonceOwners.remove(nonce);
			}

			private String mintRefreshToken(Kernel.CliTokenBrokerCompleteNonce complete, String nonce, boolean offlineAccess) {
				return tokenMinter.mint(complete, nonce, offlineAccess);
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
