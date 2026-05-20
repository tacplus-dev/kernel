// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.common.tokenrequest.Tokenrequest;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.services.kernel.Kernel;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * CliTokenBroker mediates CLI auth nonce matching between oauth instances.
 *
 * Each oauth instance opens a BrokerStream bidi on startup. Protocol:
 *   1. OAuth sends Register (instance_id) — identifies this stream
 *   2. CLI auth starts: OAuth sends RegisterNonce (nonce)
 *   3. Browser completes auth: OAuth sends CompleteNonce (nonce, subject, claims)
 *   4. Kernel matches, mints token, sends TokenDelivery to the registering instance
 *
 * Nonce registry is in-memory. Kernel restarts clear it (CLI retries).
 */
public class CliTokenBrokerServiceImpl {

	private static final Logger logger = LoggerFactory.getLogger(CliTokenBrokerServiceImpl.class);
	private static final long NONCE_TTL_SECONDS = 300; // 5 minutes

	private final IdentityServiceImpl identityService;

	// instance_id → stream for sending responses back to specific oauth instances
	private final ConcurrentHashMap<String, StreamObserver<Kernel.CliTokenBrokerResponse>> instanceStreams =
			new ConcurrentHashMap<>();

	// nonce → instance_id for routing completed tokens
	private final ConcurrentHashMap<String, NonceEntry> nonceRegistry =
			new ConcurrentHashMap<>();

	private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread t = new Thread(r, "cli-token-broker-cleanup");
		t.setDaemon(true);
		return t;
	});

	private static class NonceEntry {
		final String instanceId;
		final long createdAt;

		NonceEntry(String instanceId) {
			this.instanceId = instanceId;
			this.createdAt = System.currentTimeMillis() / 1000;
		}

		boolean isExpired() {
			return (System.currentTimeMillis() / 1000) - createdAt > NONCE_TTL_SECONDS;
		}
	}

	public CliTokenBrokerServiceImpl(IdentityServiceImpl identityService) {
		this.identityService = identityService;

		// Periodic cleanup of expired nonces
		scheduler.scheduleAtFixedRate(() -> {
			nonceRegistry.entrySet().removeIf(e -> {
				if (e.getValue().isExpired()) {
					logger.debug("Expired nonce: {}", e.getKey().substring(0, 8));
					return true;
				}
				return false;
			});
		}, 60, 60, TimeUnit.SECONDS);
	}

	/**
	 * BrokerStream bidi handler. Called by each oauth instance on startup.
	 * Returns a StreamObserver that receives client messages.
	 */
	public StreamObserver<Kernel.CliTokenBrokerRequest> brokerStream(
			StreamObserver<Kernel.CliTokenBrokerResponse> responseObserver) {

		return new StreamObserver<>() {
			private String instanceId;

			@Override
			public void onNext(Kernel.CliTokenBrokerRequest request) {
				switch (request.getMsgCase()) {
					case REGISTER -> handleRegister(request.getRegister(), responseObserver);
					case REGISTER_NONCE -> handleRegisterNonce(request.getRegisterNonce());
					case COMPLETE_NONCE -> handleCompleteNonce(request.getCompleteNonce());
					default -> logger.warn("Unknown message type: {}", request.getMsgCase());
				}
			}

			private void handleRegister(Kernel.CliTokenBrokerRegister reg,
					StreamObserver<Kernel.CliTokenBrokerResponse> observer) {
				instanceId = reg.getInstanceId();
				instanceStreams.put(instanceId, observer);
				logger.info("CliTokenBroker: oauth instance registered: {}", instanceId);
			}

			private void handleRegisterNonce(Kernel.CliTokenBrokerRegisterNonce reg) {
				if (instanceId == null) {
					logger.warn("RegisterNonce before Register — ignoring");
					return;
				}
				String nonce = reg.getNonce();
				nonceRegistry.put(nonce, new NonceEntry(instanceId));
				logger.info("CliTokenBroker: nonce registered: {} → instance {}",
						nonce.substring(0, 8), instanceId);
			}

			private void handleCompleteNonce(Kernel.CliTokenBrokerCompleteNonce complete) {
				String nonce = complete.getNonce();
				NonceEntry entry = nonceRegistry.remove(nonce);

				if (entry == null) {
					logger.warn("CliTokenBroker: CompleteNonce for unknown nonce: {}",
							nonce.substring(0, 8));
					// Send error back to the completing instance (if registered)
					if (instanceId != null) {
						StreamObserver<Kernel.CliTokenBrokerResponse> stream = instanceStreams.get(instanceId);
						if (stream != null) {
							try {
								stream.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
										.setError(Kernel.CliTokenBrokerError.newBuilder()
												.setNonce(nonce)
												.setMessage("unknown or expired nonce")
												.build())
										.build());
							} catch (Exception e) {
								logger.debug("Failed to send error to completing instance", e);
							}
						}
					}
					return;
				}

				if (entry.isExpired()) {
					logger.warn("CliTokenBroker: CompleteNonce for expired nonce: {}",
							nonce.substring(0, 8));
					return;
				}

				// Mint the token
				try {
					Tokenrequest.TokenMintResponse mintResponse = identityService.mintUserTokenInternal(
							complete.getSubject(),
							complete.hasClaims() ? complete.getClaims() : null,
							0, // default expiry
							complete.getTraceId(),
							"oauth" // delegate name
					);

					String refreshToken = mintResponse.getRefreshToken().getBase64();

					// Deliver to the registering oauth instance
					StreamObserver<Kernel.CliTokenBrokerResponse> targetStream =
							instanceStreams.get(entry.instanceId);
					if (targetStream != null) {
						targetStream.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
								.setTokenDelivery(Kernel.CliTokenBrokerTokenDelivery.newBuilder()
										.setNonce(nonce)
										.setRefreshToken(refreshToken)
										.build())
								.build());
						logger.info("CliTokenBroker: token delivered for nonce {} → instance {}",
								nonce.substring(0, 8), entry.instanceId);
					} else {
						logger.warn("CliTokenBroker: target instance {} disconnected for nonce {}",
								entry.instanceId, nonce.substring(0, 8));
					}

				} catch (IdentityServiceImpl.StatusException e) {
					logger.error("CliTokenBroker: failed to mint token for nonce {}",
							nonce.substring(0, 8), e);
					// Try to send error to the registering instance
					StreamObserver<Kernel.CliTokenBrokerResponse> targetStream =
							instanceStreams.get(entry.instanceId);
					if (targetStream != null) {
						try {
							targetStream.onNext(Kernel.CliTokenBrokerResponse.newBuilder()
									.setError(Kernel.CliTokenBrokerError.newBuilder()
											.setNonce(nonce)
											.setMessage("token minting failed: " + e.getMessage())
											.build())
									.build());
						} catch (Exception ex) {
							logger.debug("Failed to send error to registering instance", ex);
						}
					}
				}
			}

			@Override
			public void onError(Throwable t) {
				if (instanceId != null) {
					instanceStreams.remove(instanceId);
					// Clean up nonces registered by this instance
					nonceRegistry.entrySet().removeIf(e -> e.getValue().instanceId.equals(instanceId));
					logger.info("CliTokenBroker: oauth instance disconnected: {}", instanceId);
				}
			}

			@Override
			public void onCompleted() {
				if (instanceId != null) {
					instanceStreams.remove(instanceId);
					nonceRegistry.entrySet().removeIf(e -> e.getValue().instanceId.equals(instanceId));
					logger.info("CliTokenBroker: oauth instance stream closed: {}", instanceId);
				}
				responseObserver.onCompleted();
			}
		};
	}
}
