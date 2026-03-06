// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.backendclient.BackendServer;


import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ForwardingServerCall;
import io.grpc.ForwardingServerCallListener;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerMethodDefinition;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;

/**
 * gRPC interceptor that detects and rate-limits polling of unary read RPCs.
 *
 * <p>Methods are auto-classified into three categories by introspecting registered services:
 * <ul>
 *   <li><b>EXEMPT</b> — write RPCs (Set, Put, Remove, etc.) and streaming RPCs: never limited
 *   <li><b>HAS_STREAMING</b> — unary reads with a Watch/Subscribe counterpart: limited at {@code pollingRate}
 *   <li><b>NO_STREAMING</b> — unary reads without a streaming counterpart: limited at {@code unaryRate}
 * </ul>
 *
 * <p>Rate limiting uses a per-(peer, method) token bucket. Rejected calls receive
 * {@link Status#RESOURCE_EXHAUSTED} with a descriptive message.
 */
public class RateLimitInterceptor implements ServerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitInterceptor.class);

    enum Category { EXEMPT, HAS_STREAMING, NO_STREAMING }

    private static final Set<String> WRITE_PREFIXES = Set.of(
        "Set", "Put", "PutIfAbsent", "Remove", "Delete", "Clear",
        "Offer", "Publish"
    );

    // Sorted longest-first so "GetAll" matches before "Get"
    private static final List<String> READ_PREFIXES = List.of(
        "ContainsKey", "GetAll", "KeySet", "Peek", "Size", "Get"
    );

    private final double pollingRate;
    private final double unaryRate;
    private final Map<String, Category> methodCategories;
    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> warnedKeys = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleaner;
    private final BackendServer backendServer;

    private final AtomicLong totalRpcs = new AtomicLong();
    private final AtomicLong rateLimitedCount = new AtomicLong();
    private final ConcurrentHashMap<String, AtomicLong> perMethodCounts = new ConcurrentHashMap<>();
    private final AtomicInteger activeConnections = new AtomicInteger();
    private final AtomicInteger activeRpcs = new AtomicInteger();
    private final AtomicInteger activeStreams = new AtomicInteger();

    /**
     * @param pollingRate      max req/s per peer per method for RPCs with streaming alternatives (0 = no limit)
     * @param unaryRate        max req/s per peer per method for RPCs without streaming alternatives (0 = no limit)
     * @param services         the registered gRPC services to introspect for method classification
     * @param backendServer  optional backend server for sending rate-limit warnings to clients (nullable)
     */
    public RateLimitInterceptor(double pollingRate, double unaryRate,
                                List<ServerServiceDefinition> services, BackendServer backendServer) {
        this.pollingRate = pollingRate;
        this.unaryRate = unaryRate;
        this.backendServer = backendServer;
        this.methodCategories = classifyMethods(services);
        this.cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "RateLimitCleaner");
            t.setDaemon(true);
            return t;
        });
        cleaner.scheduleAtFixedRate(this::cleanupStale, 60, 60, TimeUnit.SECONDS);

        if (logger.isInfoEnabled()) {
            Map<Category, Integer> counts = new EnumMap<>(Category.class);
            for (Category c : Category.values()) counts.put(c, 0);
            methodCategories.values().forEach(c -> counts.merge(c, 1, Integer::sum));
            logger.info("RateLimitInterceptor initialized: pollingRate={}/s, unaryRate={}/s, " +
                    "methods: {} exempt, {} with streaming alt, {} without streaming alt",
                pollingRate, unaryRate,
                counts.get(Category.EXEMPT),
                counts.get(Category.HAS_STREAMING),
                counts.get(Category.NO_STREAMING));
        }
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {

        String fullMethodName = call.getMethodDescriptor().getFullMethodName();
        totalRpcs.incrementAndGet();
        perMethodCounts.computeIfAbsent(fullMethodName, k -> new AtomicLong()).incrementAndGet();

        Category cat = methodCategories.get(fullMethodName);

        boolean isStreaming = call.getMethodDescriptor().getType() == MethodDescriptor.MethodType.SERVER_STREAMING;

        if (cat == null || cat == Category.EXEMPT) {
            return trackActiveCall(call, headers, next, isStreaming);
        }

        double rate = (cat == Category.HAS_STREAMING) ? pollingRate : unaryRate;
        if (rate <= 0) {
            return trackActiveCall(call, headers, next, isStreaming);
        }

        var remote = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
        String peer = remote != null ? remote.toString() : "unknown";
        String bucketKey = peer + "|" + fullMethodName;

        TokenBucket bucket = buckets.computeIfAbsent(bucketKey, k -> new TokenBucket(rate));

        if (!bucket.tryConsume()) {
            rateLimitedCount.incrementAndGet();
            String warnKey = bucketKey;
            if (warnedKeys.putIfAbsent(warnKey, Boolean.TRUE) == null) {
                String warnMsg;
                if (cat == Category.HAS_STREAMING) {
                    warnMsg = "Polling " + fullMethodName + " — use the streaming Watch/Subscribe alternative";
                    logger.warn("Peer {} is polling {} — streaming alternative available", peer, fullMethodName);
                } else {
                    warnMsg = "Polling " + fullMethodName + " — no streaming alternative exists";
                    logger.warn("Peer {} is polling {} — no streaming alternative exists", peer, fullMethodName);
                }
                if (backendServer != null) {
                    backendServer.warnPeer(peer, warnMsg);
                }
            }

            String msg = (cat == Category.HAS_STREAMING)
                ? "Rate limit exceeded — use the streaming Watch/Subscribe alternative instead of polling"
                : "Rate limit exceeded — this boundary should implement a streaming alternative";

            call.close(Status.RESOURCE_EXHAUSTED.withDescription(msg), new Metadata());
            // Return a no-op listener since the call is already closed
            return new ServerCall.Listener<>() {};
        }

        return trackActiveCall(call, headers, next, isStreaming);
    }

    /**
     * Wraps the call with active RPC/stream tracking.
     * Increments counters on call start, decrements on close.
     */
    private <ReqT, RespT> ServerCall.Listener<ReqT> trackActiveCall(
            ServerCall<ReqT, RespT> call, Metadata headers,
            ServerCallHandler<ReqT, RespT> next, boolean isStreaming) {

        activeRpcs.incrementAndGet();
        if (isStreaming) {
            activeStreams.incrementAndGet();
        }

        // Wrap the call to detect when it closes
        ServerCall<ReqT, RespT> wrappedCall = new ForwardingServerCall.SimpleForwardingServerCall<>(call) {
            private volatile boolean closed;

            @Override
            public void close(Status status, Metadata trailers) {
                if (!closed) {
                    closed = true;
                    activeRpcs.decrementAndGet();
                    if (isStreaming) {
                        activeStreams.decrementAndGet();
                    }
                }
                super.close(status, trailers);
            }
        };

        ServerCall.Listener<ReqT> listener = next.startCall(wrappedCall, headers);

        // Also wrap the listener to catch cancellations
        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
            @Override
            public void onCancel() {
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
    private static Map<String, Category> classifyMethods(List<ServerServiceDefinition> services) {
        Map<String, Category> result = new HashMap<>();
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
     * Strip Watch/SubscribeTo prefix from a streaming method name to get the boundary name.
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
     * Strip a read verb prefix and return the boundary name, or null if no read prefix matches.
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

    /** Remove buckets and warn-dedup entries that have been idle for over 60 seconds. */
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
