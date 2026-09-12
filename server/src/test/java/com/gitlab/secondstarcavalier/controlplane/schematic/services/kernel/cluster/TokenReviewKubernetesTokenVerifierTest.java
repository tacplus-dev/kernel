// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.grpc.Status;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TokenReviewKubernetesTokenVerifierTest {

    private static final String AUDIENCE = "schematic-kernel";
    private static final String TOKEN = "header.payload.signature";

    @Test
    void verifyPostsTokenReviewAndReturnsServiceAccountIdentity() throws Exception {
        AtomicReference<String> requestBody = new AtomicReference<>();
        try (MockTokenReviewServer server = MockTokenReviewServer.responding(exchange -> {
            assertEquals("Bearer reviewer-token", exchange.getRequestHeaders().getFirst("Authorization"));
            assertEquals("application/json", exchange.getRequestHeaders().getFirst("Content-Type"));
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            send(exchange, 201, """
                    {
                      "apiVersion": "authentication.k8s.io/v1",
                      "kind": "TokenReview",
                      "status": {
                        "authenticated": true,
                        "audiences": ["schematic-kernel"],
                        "user": {
                          "username": "system:serviceaccount:schematic:oauth",
                          "uid": "sa-uid",
                          "extra": {
                            "authentication.kubernetes.io/pod-name": ["oauth-abc"],
                            "authentication.kubernetes.io/pod-uid": ["pod-uid"],
                            "ignored": ["value"]
                          }
                        }
                      }
                    }
                    """);
        })) {
            var verifier = newVerifier(server.uri());

            VerifiedK8sIdentity identity = verifier.verify(TOKEN, AUDIENCE);

            assertEquals("schematic", identity.kubernetesNamespace());
            assertEquals("oauth", identity.kubernetesServiceAccount());
            assertEquals("sa-uid", identity.serviceAccountUid());
            assertEquals(List.of(AUDIENCE), identity.audiences());
            assertEquals("oauth-abc", identity.podExtras().get("authentication.kubernetes.io/pod-name"));
            assertEquals("pod-uid", identity.podExtras().get("authentication.kubernetes.io/pod-uid"));
            var json = JsonParser.parseString(requestBody.get()).getAsJsonObject();
            assertEquals(TOKEN, json.getAsJsonObject("spec").get("token").getAsString());
            assertEquals(AUDIENCE, json.getAsJsonObject("spec").getAsJsonArray("audiences").get(0).getAsString());
        }
    }

    @Test
    void verifyRejectsUnauthenticatedReview() throws Exception {
        try (MockTokenReviewServer server = MockTokenReviewServer.json(200, """
                {"status":{"authenticated":false,"error":"bad token"}}
                """)) {
            KubernetesTokenVerifier.K8sTokenVerificationException ex =
                    expectFailure(server.uri(), TOKEN, AUDIENCE);
            assertEquals(Status.UNAUTHENTICATED.getCode(), ex.status().getCode());
            assertTrue(ex.getMessage().contains("bad token"));
        }
    }

    @Test
    void verifyRejectsAudienceMismatch() throws Exception {
        try (MockTokenReviewServer server = MockTokenReviewServer.json(200, """
                {
                  "status": {
                    "authenticated": true,
                    "audiences": ["other"],
                    "user": {"username": "system:serviceaccount:schematic:oauth"}
                  }
                }
                """)) {
            KubernetesTokenVerifier.K8sTokenVerificationException ex =
                    expectFailure(server.uri(), TOKEN, AUDIENCE);
            assertEquals(Status.UNAUTHENTICATED.getCode(), ex.status().getCode());
            assertTrue(ex.getMessage().contains("do not include required kernel audience"));
        }
    }

    @Test
    void verifyRejectsMalformedServiceAccountUsername() throws Exception {
        try (MockTokenReviewServer server = MockTokenReviewServer.json(200, """
                {
                  "status": {
                    "authenticated": true,
                    "audiences": ["schematic-kernel"],
                    "user": {"username": "alice"}
                  }
                }
                """)) {
            KubernetesTokenVerifier.K8sTokenVerificationException ex =
                    expectFailure(server.uri(), TOKEN, AUDIENCE);
            assertEquals(Status.UNAUTHENTICATED.getCode(), ex.status().getCode());
            assertTrue(ex.getMessage().contains("not a service account"));
        }
    }

    @Test
    void verifyMapsHttpFailureToUnavailable() throws Exception {
        try (MockTokenReviewServer server = MockTokenReviewServer.json(503, "api down")) {
            KubernetesTokenVerifier.K8sTokenVerificationException ex =
                    expectFailure(server.uri(), TOKEN, AUDIENCE);
            assertEquals(Status.UNAVAILABLE.getCode(), ex.status().getCode());
            assertTrue(ex.getMessage().contains("HTTP 503"));
        }
    }

    @Test
    void verifyReReadsReviewerTokenPerCall() throws Exception {
        // The kernel's projected SA token rotates; the verifier must re-read it on every call
        // rather than caching it once at construction.
        CopyOnWriteArrayList<String> seenAuthHeaders = new CopyOnWriteArrayList<>();
        try (MockTokenReviewServer server = MockTokenReviewServer.responding(exchange -> {
            seenAuthHeaders.add(exchange.getRequestHeaders().getFirst("Authorization"));
            send(exchange, 201, """
                    {
                      "status": {
                        "authenticated": true,
                        "audiences": ["schematic-kernel"],
                        "user": {"username": "system:serviceaccount:schematic:oauth"}
                      }
                    }
                    """);
        })) {
            AtomicInteger calls = new AtomicInteger();
            Supplier<String> rotating = () -> "reviewer-token-" + calls.incrementAndGet();
            var verifier = new TokenReviewKubernetesTokenVerifier(
                    server.uri(), rotating, HttpClient.newHttpClient(), Duration.ofSeconds(10));

            verifier.verify(TOKEN, AUDIENCE);
            verifier.verify(TOKEN, AUDIENCE);

            assertEquals(2, seenAuthHeaders.size());
            assertEquals("Bearer reviewer-token-1", seenAuthHeaders.get(0));
            assertEquals("Bearer reviewer-token-2", seenAuthHeaders.get(1));
            assertTrue(!seenAuthHeaders.get(0).equals(seenAuthHeaders.get(1)),
                    "successive verify() calls must send different reviewer tokens");
        }
    }

    @Test
    void verifyFailsClosedWhenReviewerTokenUnreadable() throws Exception {
        try (MockTokenReviewServer server = MockTokenReviewServer.json(200, """
                {"status":{"authenticated":true,"audiences":["schematic-kernel"],
                 "user":{"username":"system:serviceaccount:schematic:oauth"}}}
                """)) {
            Supplier<String> failing = () -> {
                throw new java.io.UncheckedIOException(
                        new IOException("token file vanished"));
            };
            var verifier = new TokenReviewKubernetesTokenVerifier(
                    server.uri(), failing, HttpClient.newHttpClient(), Duration.ofSeconds(10));
            try {
                verifier.verify(TOKEN, AUDIENCE);
                fail("expected verifier failure");
            } catch (KubernetesTokenVerifier.K8sTokenVerificationException ex) {
                assertEquals(Status.UNAVAILABLE.getCode(), ex.status().getCode());
                assertTrue(ex.getMessage().contains("unable to read kernel reviewer token"));
                assertTrue(ex.getMessage().contains("token file vanished"));
            }
        }
    }

    @Test
    void inClusterHttpClientFailsClosedWhenCaFileMissing(@TempDir Path dir) {
        // Without the in-cluster CA the client must not silently fall back to the JVM default
        // trust store: that would let any publicly-trusted cert impersonate the API server.
        Path missing = dir.resolve("ca.crt");

        IOException ex = assertThrows(
                IOException.class,
                () -> TokenReviewKubernetesTokenVerifier.inClusterHttpClient(missing));

        assertTrue(ex.getMessage().contains("Kubernetes in-cluster CA file"), ex.getMessage());
        assertTrue(ex.getMessage().contains(missing.toString()), ex.getMessage());
    }

    @Test
    void inClusterHttpClientFailsClosedWhenCaFileEmpty(@TempDir Path dir) throws Exception {
        Path empty = Files.createFile(dir.resolve("ca.crt"));

        IOException ex = assertThrows(
                IOException.class,
                () -> TokenReviewKubernetesTokenVerifier.inClusterHttpClient(empty));

        assertTrue(ex.getMessage().contains("Kubernetes in-cluster CA file"), ex.getMessage());
    }

    private static TokenReviewKubernetesTokenVerifier newVerifier(URI uri) {
        return new TokenReviewKubernetesTokenVerifier(uri, "reviewer-token", HttpClient.newHttpClient());
    }

    private static KubernetesTokenVerifier.K8sTokenVerificationException expectFailure(
            URI uri,
            String token,
            String audience) throws Exception {
        try {
            newVerifier(uri).verify(token, audience);
            fail("expected verifier failure");
            return null;
        } catch (KubernetesTokenVerifier.K8sTokenVerificationException e) {
            return e;
        }
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private static final class MockTokenReviewServer implements AutoCloseable {
        private final HttpServer server;

        static MockTokenReviewServer json(int status, String body) throws IOException {
            return responding(exchange -> send(exchange, status, body));
        }

        static MockTokenReviewServer responding(ExchangeHandler handler) throws IOException {
            return new MockTokenReviewServer(handler);
        }

        private MockTokenReviewServer(ExchangeHandler handler) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/apis/authentication.k8s.io/v1/tokenreviews", exchange -> {
                try {
                    handler.handle(exchange);
                } catch (Throwable t) {
                    byte[] bytes = t.toString().getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(500, bytes.length);
                    exchange.getResponseBody().write(bytes);
                    exchange.close();
                }
            });
            server.start();
        }

        URI uri() {
            return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
