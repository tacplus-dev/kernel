// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

// StateServer is in this package
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.SecurityAuthenticator;
import io.grpc.ForwardingServerCall;
import io.grpc.ForwardingServerCallListener;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerMethodDefinition;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * gRPC interceptor that detects and rate-limits polling of unary read RPCs.
 *
 * <p>
 * Methods are auto-classified into four categories by introspecting registered
 * services:
 * <ul>
 * <li><b>EXEMPT</b> — state-map write RPCs (Set, Put, Remove, etc.) and
 * streaming RPCs: never limited
 * <li><b>CREDENTIAL</b> — credential-issuing RPCs (Mint*): limited at
 * {@code unaryRate}. These are writes, so the verb table would otherwise
 * exempt them, but they are exactly the endpoints an attacker hammers to
 * brute-force a cred_pair or bulk-mint tokens, so they are bounded per caller.
 * <li><b>HAS_STREAMING</b> — unary reads with a Watch/Subscribe counterpart:
 * limited at {@code pollingRate}, or at {@code unaryRate} when the caller
 * authenticated with a service/workload identity (an internal service has no
 * keyed read for a state map, so the pollable read is its only option)
 * <li><b>NO_STREAMING</b> — unary reads without a streaming counterpart:
 * limited at {@code unaryRate}
 * </ul>
 *
 * <p>
 * Rate limiting uses a per-(peer, method) token bucket. Rejected calls receive
 * {@link Status#RESOURCE_EXHAUSTED} with a descriptive message.
 */
public class RateLimitInterceptor implements ServerInterceptor {

	private static final Logger logger = LoggerFactory.getLogger(RateLimitInterceptor.class);

	enum Category {
		EXEMPT,
		CREDENTIAL,
		HAS_STREAMING,
		NO_STREAMING
	}

	private static final Set<String> WRITE_PREFIXES = Set.of("Set", "Put", "PutIfAbsent", "Remove", "Delete", "Clear",
			"Offer", "Publish");

	// Sorted longest-first so "GetAll" matches before "Get"
	private static final List<String> READ_PREFIXES = List.of("ContainsKey", "GetAll", "KeySet", "Peek", "Size", "Get");

	// Credential-issuing verb. Checked before WRITE_PREFIXES so a minting RPC
	// cannot be swept into the write exemption.
	private static final String CREDENTIAL_PREFIX = "Mint";

	private final double pollingRate;
	private final double unaryRate;
	private final ConcurrentHashMap<String, Category> methodCategories;
	private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, Boolean> warnedKeys = new ConcurrentHashMap<>();
	private final ScheduledExecutorService cleaner;
	private final StateServer stateServer;

	private final AtomicLong totalRpcs = new AtomicLong();
	private final AtomicLong rateLimitedCount = new AtomicLong();
	private final ConcurrentHashMap<String, AtomicLong> perMethodCounts = new ConcurrentHashMap<>();
	private final AtomicInteger activeConnections = new AtomicInteger();
	private final AtomicInteger activeRpcs = new AtomicInteger();
	private final AtomicInteger activeStreams = new AtomicInteger();

	/**
	 * @param pollingRate   max req/s per peer per method for RPCs with streaming
	 *                      alternatives (0 = no limit)
	 * @param unaryRate     max req/s per peer per method for RPCs without streaming
	 *                      alternatives (0 = no limit)
	 * @param services      the registered gRPC services to introspect for method
	 *                      classification
	 * @param backendServer optional backend server for sending rate-limit warnings
	 *                      to clients (nullable)
	 */
	public RateLimitInterceptor(
			double pollingRate, double unaryRate, List<ServerServiceDefinition> services, StateServer stateServer) {
		this.pollingRate = pollingRate;
		this.unaryRate = unaryRate;
		this.stateServer = stateServer;
		this.methodCategories = classifyMethods(services);
		this.cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
			Thread t = new Thread(r, "RateLimitCleaner");
			t.setDaemon(true);
			return t;
		});
		cleaner.scheduleAtFixedRate(this::cleanupStale, 60, 60, TimeUnit.SECONDS);

		if (logger.isInfoEnabled()) {
			Map<Category, Integer> counts = new EnumMap<>(Category.class);
			for (Category c : Category.values())
				counts.put(c, 0);
			methodCategories.values().forEach(c -> counts.merge(c, 1, (old, incr) -> old + incr));
			logger.info(
					"RateLimitInterceptor initialized: pollingRate={}/s, unaryRate={}/s, "
							+ "methods: {} exempt, {} credential-issuing, {} with streaming alt, "
							+ "{} without streaming alt",
					pollingRate,
					unaryRate,
					counts.get(Category.EXEMPT),
					counts.get(Category.CREDENTIAL),
					counts.get(Category.HAS_STREAMING),
					counts.get(Category.NO_STREAMING));
		}
	}

	@Override
	public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
			ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {

		String fullMethodName = call.getMethodDescriptor().getFullMethodName();
		totalRpcs.incrementAndGet();
		perMethodCounts.computeIfAbsent(fullMethodName, k -> new AtomicLong()).incrementAndGet();

		Category cat = methodCategories.get(fullMethodName);

		boolean isStreaming = call.getMethodDescriptor().getType() == MethodDescriptor.MethodType.SERVER_STREAMING;

		if (cat == null || cat == Category.EXEMPT) {
			return trackActiveCall(call, headers, next, isStreaming);
		}

		// An internal service reading one row out of a kernel state map has no
		// keyed alternative — tacplus generates only GetAll*/Put*/Delete* for a
		// state map — so it must call the pollable read. Hold those calls to the
		// bounded unaryRate instead of the anti-polling pollingRate. End-user /
		// CLI callers leave the service path empty and stay on pollingRate.
		boolean serviceStateRead = cat == Category.HAS_STREAMING && callerIsService();
		double rate = (cat == Category.HAS_STREAMING && !serviceStateRead) ? pollingRate : unaryRate;
		if (rate <= 0) {
			return trackActiveCall(call, headers, next, isStreaming);
		}

		var remote = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
		String peer = remote != null ? remote.toString() : "unknown";
		// Separate buckets per rate class so one peer speaking with both a service
		// and a user token cannot lend either rate to the other.
		String bucketKey = peer + "|" + fullMethodName + (serviceStateRead ? "|service" : "");

		TokenBucket bucket = buckets.computeIfAbsent(bucketKey, k -> new TokenBucket(rate));

		if (!bucket.tryConsume()) {
			rateLimitedCount.incrementAndGet();
			String warnKey = bucketKey;
			if (warnedKeys.putIfAbsent(warnKey, Boolean.TRUE) == null) {
				String warnMsg;
				if (cat == Category.CREDENTIAL) {
					warnMsg = "Exceeded the credential-issuance rate limit on " + fullMethodName;
					logger.warn("Peer {} exceeded the credential-issuance rate limit on {}", peer, fullMethodName);
				} else if (cat == Category.HAS_STREAMING) {
					warnMsg = "Polling " + fullMethodName + " — use the streaming Watch/Subscribe alternative";
					logger.warn("Peer {} is polling {} — streaming alternative available", peer, fullMethodName);
				} else {
					warnMsg = "Polling " + fullMethodName + " — no streaming alternative exists";
					logger.warn("Peer {} is polling {} — no streaming alternative exists", peer, fullMethodName);
				}
				if (stateServer != null) {
					stateServer.warnPeer(peer, warnMsg);
				}
			}

			String msg;
			if (cat == Category.CREDENTIAL) {
				msg = "Rate limit exceeded — credential issuance is bounded per caller";
			} else if (cat == Category.HAS_STREAMING) {
				msg = "Rate limit exceeded — use the streaming Watch/Subscribe alternative instead of polling";
			} else {
				msg = "Rate limit exceeded — this boundary should implement a streaming alternative";
			}

			call.close(Status.RESOURCE_EXHAUSTED.withDescription(msg), new Metadata());
			// Return a no-op listener since the call is already closed
			return new ServerCall.Listener<>() {
			};
		}

		return trackActiveCall(call, headers, next, isStreaming);
	}

	/**
	 * True when the caller of the current RPC authenticated with a service or
	 * workload identity rather than a user/CLI token. The value is the verified
	 * caller service path published by the generated SecurityAuthenticator's
	 * caller interceptor, which runs immediately outside this one; that
	 * interceptor leaves it empty for tokens carrying no service identity.
	 */
	private static boolean callerIsService() {
		String servicePath = SecurityAuthenticator.CALLER_SERVICE_PATH_KEY.get();
		return servicePath != null && !servicePath.isEmpty();
	}

	/**
	 * Wraps the call with active RPC/stream tracking.
	 * Increments counters on call start, decrements once the call ends.
	 *
	 * <p>gRPC does not guarantee {@code close()} runs: a client cancellation or a
	 * transport drop ends the call through the listener's {@code onCancel()}
	 * instead. Both endings share one {@code ended} flag so the counters are
	 * decremented exactly once whichever one fires — otherwise every cancelled
	 * call leaked a count and {@link #getActiveRpcs()} / {@link #getActiveStreams()},
	 * which feed health and metrics, drifted upward forever.
	 */
	private <ReqT, RespT> ServerCall.Listener<ReqT> trackActiveCall(
			ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next, boolean isStreaming) {

		activeRpcs.incrementAndGet();
		if (isStreaming) {
			activeStreams.incrementAndGet();
		}

		AtomicBoolean ended = new AtomicBoolean();
		Runnable endOnce = () -> {
			if (ended.compareAndSet(false, true)) {
				activeRpcs.decrementAndGet();
				if (isStreaming) {
					activeStreams.decrementAndGet();
				}
			}
		};

		// Wrap the call to detect when it closes
		ServerCall<ReqT, RespT> wrappedCall = new ForwardingServerCall.SimpleForwardingServerCall<>(call) {
			@Override
			public void close(Status status, Metadata trailers) {
				endOnce.run();
				super.close(status, trailers);
			}
		};

		ServerCall.Listener<ReqT> listener = next.startCall(wrappedCall, headers);

		// Also wrap the listener to catch cancellations
		return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
			@Override
			public void onCancel() {
				endOnce.run();
				super.onCancel();
			}
		};
	}

	/** Returns the total number of RPCs intercepted. */
	public long getTotalRpcs() {
		return totalRpcs.get();
	}

	/** Returns the total number of rate-limited (rejected) RPCs. */
	public long getRateLimitedCount() {
		return rateLimitedCount.get();
	}

	/** Returns the number of currently active gRPC transport connections. */
	public int getActiveConnections() {
		return activeConnections.get();
	}

	/** Returns the number of currently in-flight RPCs. */
	public int getActiveRpcs() {
		return activeRpcs.get();
	}

	/** Returns the number of currently active server-streaming RPCs. */
	public int getActiveStreams() {
		return activeStreams.get();
	}

	/** Called by the ServerTransportFilter when a new connection is established. */
	public void connectionOpened() {
		activeConnections.incrementAndGet();
	}

	/** Called by the ServerTransportFilter when a connection is terminated. */
	public void connectionClosed() {
		activeConnections.decrementAndGet();
	}

	/** Returns per-method RPC counts as a snapshot. */
	public Map<String, Long> getPerMethodCounts() {
		return perMethodCounts.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get()));
	}

	/**
	 * Classify all methods from the registered services into categories.
	 */
	private static ConcurrentHashMap<String, Category> classifyMethods(List<ServerServiceDefinition> services) {
		ConcurrentHashMap<String, Category> result = new ConcurrentHashMap<>();
		Set<String> streamingBoundaries = new HashSet<>();

		for (ServerServiceDefinition def : services) {
			String serviceName = def.getServiceDescriptor().getName();

			// First pass: collect streaming method boundary names
			for (ServerMethodDefinition<?, ?> m : def.getMethods()) {
				MethodDescriptor<?, ?> md = m.getMethodDescriptor();
				if (md.getType() == MethodDescriptor.MethodType.SERVER_STREAMING) {
					String bareName = md.getBareMethodName();
					if (bareName != null) {
						String boundary = stripStreamingPrefix(bareName);
						if (boundary != null) {
							streamingBoundaries.add(serviceName + "/" + boundary);
						}
					}
				}
			}
		}

		for (ServerServiceDefinition def : services) {
			String serviceName = def.getServiceDescriptor().getName();

			for (ServerMethodDefinition<?, ?> m : def.getMethods()) {
				MethodDescriptor<?, ?> md = m.getMethodDescriptor();
				String fullName = md.getFullMethodName();

				// Only classify UNARY methods
				if (md.getType() != MethodDescriptor.MethodType.UNARY) {
					result.put(fullName, Category.EXEMPT);
					continue;
				}

				String bareName = md.getBareMethodName();
				if (bareName == null) {
					result.put(fullName, Category.EXEMPT);
					continue;
				}

				// Credential issuance is a write, but an unbounded one is a
				// brute-force / bulk-minting surface, so it is limited rather
				// than swept into the write exemption below.
				if (bareName.startsWith(CREDENTIAL_PREFIX)) {
					result.put(fullName, Category.CREDENTIAL);
					continue;
				}

				// Check if it's a write verb
				if (isWriteVerb(bareName)) {
					result.put(fullName, Category.EXEMPT);
					continue;
				}

				// Check if it's a read verb
				String boundary = stripReadPrefix(bareName);
				if (boundary != null) {
					// Check if a streaming alternative exists
					if (streamingBoundaries.contains(serviceName + "/" + boundary)) {
						result.put(fullName, Category.HAS_STREAMING);
					} else {
						result.put(fullName, Category.NO_STREAMING);
					}
				} else {
					// Unknown verb pattern — exempt by default
					result.put(fullName, Category.EXEMPT);
				}
			}
		}

		return result;
	}

	/**
	 * Classify and register services built after this interceptor. The gRPC
	 * builder needs the interceptor before the kernel's identity control plane
	 * exists, so those services are not in the constructor's list — and a
	 * method with no category is exempt, which would leave the whole Mint
	 * surface unlimited.
	 */
	public void registerServices(List<ServerServiceDefinition> services) {
		methodCategories.putAll(classifyMethods(services));
	}

	/**
	 * Strip Watch/SubscribeTo prefix from a streaming method name to get the
	 * boundary name.
	 */
	private static String stripStreamingPrefix(String bareName) {
		if (bareName.startsWith("Watch")) {
			return bareName.substring("Watch".length());
		}
		if (bareName.startsWith("SubscribeTo")) {
			return bareName.substring("SubscribeTo".length());
		}
		if (bareName.startsWith("ConsumeFrom")) {
			return bareName.substring("ConsumeFrom".length());
		}
		return null;
	}

	/** Returns true if the method name starts with a write verb prefix. */
	private static boolean isWriteVerb(String bareName) {
		for (String prefix : WRITE_PREFIXES) {
			if (bareName.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Strip a read verb prefix and return the boundary name, or null if no read
	 * prefix matches.
	 */
	private static String stripReadPrefix(String bareName) {
		for (String prefix : READ_PREFIXES) {
			if (bareName.startsWith(prefix) && bareName.length() > prefix.length()) {
				return bareName.substring(prefix.length());
			}
		}
		// Handle exact matches (e.g., bare "Get" is not a read of a boundary)
		return null;
	}

	/**
	 * Remove buckets and warn-dedup entries that have been idle for over 60
	 * seconds.
	 */
	private void cleanupStale() {
		long now = System.nanoTime();
		long staleThresholdNanos = TimeUnit.SECONDS.toNanos(60);

		Iterator<Map.Entry<String, TokenBucket>> it = buckets.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<String, TokenBucket> entry = it.next();
			if (now - entry.getValue().lastRefillNanos > staleThresholdNanos) {
				it.remove();
				warnedKeys.remove(entry.getKey());
			}
		}

		// Also clean warnedKeys that have no corresponding bucket (e.g. added
		// for a rejected call where the bucket was later evicted or never created).
		warnedKeys.keySet().removeIf(key -> !buckets.containsKey(key));
	}

	/**
	 * A simple token bucket that allows up to {@code rate} requests per second.
	 * Thread-safe via synchronization.
	 */
	static final class TokenBucket {
		private final double rate;
		private double tokens;
		volatile long lastRefillNanos;

		TokenBucket(double rate) {
			this.rate = rate;
			this.tokens = rate; // start with a full bucket
			this.lastRefillNanos = System.nanoTime();
		}

		synchronized boolean tryConsume() {
			long now = System.nanoTime();
			double elapsed = (now - lastRefillNanos) / 1_000_000_000.0;
			lastRefillNanos = now;

			tokens = Math.min(rate, tokens + elapsed * rate);

			if (tokens >= 1.0) {
				tokens -= 1.0;
				return true;
			}
			return false;
		}
	}
}
