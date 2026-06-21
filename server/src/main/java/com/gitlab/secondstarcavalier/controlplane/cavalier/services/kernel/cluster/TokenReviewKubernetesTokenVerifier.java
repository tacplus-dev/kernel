// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.grpc.Status;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Kubernetes TokenReview-backed verifier for projected service-account tokens.
 *
 * <p>This verifier authenticates incoming workload tokens by asking the local
 * Kubernetes API server to review the presented token for the configured kernel
 * audience. It uses the kernel pod's own projected service-account token only
 * as the reviewer credential.
 */
public final class TokenReviewKubernetesTokenVerifier implements KubernetesTokenVerifier {

    static final String DEFAULT_TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    static final String DEFAULT_CA_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private static final Gson GSON = new Gson();
    private static final String SERVICE_ACCOUNT_USERNAME_PREFIX = "system:serviceaccount:";
    private static final String TOKENREVIEWS_PATH = "/apis/authentication.k8s.io/v1/tokenreviews";

    private final URI tokenReviewUri;
    private final String reviewerToken;
    private final HttpClient client;
    private final Duration timeout;

    TokenReviewKubernetesTokenVerifier(URI apiServerUri, String reviewerToken, HttpClient client) {
        this(apiServerUri, reviewerToken, client, DEFAULT_TIMEOUT);
    }

    TokenReviewKubernetesTokenVerifier(
            URI apiServerUri,
            String reviewerToken,
            HttpClient client,
            Duration timeout) {
        if (apiServerUri == null) {
            throw new IllegalArgumentException("apiServerUri is required");
        }
        if (reviewerToken == null || reviewerToken.isBlank()) {
            throw new IllegalArgumentException("reviewerToken is required");
        }
        this.tokenReviewUri = apiServerUri.resolve(TOKENREVIEWS_PATH);
        this.reviewerToken = reviewerToken.strip();
        this.client = client == null ? HttpClient.newHttpClient() : client;
        this.timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
    }

    static TokenReviewKubernetesTokenVerifier inCluster()
            throws IOException, GeneralSecurityException {
        URI apiServerUri = inClusterApiServerUri();
        String tokenFile = getenvDefault("KERNEL_KUBE_TOKEN_FILE", DEFAULT_TOKEN_FILE);
        String reviewerToken = Files.readString(Path.of(tokenFile), StandardCharsets.UTF_8).strip();
        HttpClient client = inClusterHttpClient();
        return new TokenReviewKubernetesTokenVerifier(apiServerUri, reviewerToken, client);
    }

    @Override
    public VerifiedK8sIdentity verify(String token, String requiredAudience)
            throws K8sTokenVerificationException {
        if (requiredAudience == null || requiredAudience.isBlank()) {
            throw new K8sTokenVerificationException(
                    Status.UNIMPLEMENTED,
                    "kernel Kubernetes token audience is not configured");
        }

        JsonObject body = new JsonObject();
        body.addProperty("apiVersion", "authentication.k8s.io/v1");
        body.addProperty("kind", "TokenReview");
        JsonObject spec = new JsonObject();
        spec.addProperty("token", token);
        JsonArray audiences = new JsonArray();
        audiences.add(requiredAudience);
        spec.add("audiences", audiences);
        body.add("spec", spec);

        HttpRequest request = HttpRequest.newBuilder(tokenReviewUri)
                .timeout(timeout)
                .header("Authorization", "Bearer " + reviewerToken)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body), StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new K8sTokenVerificationException(Status.UNAVAILABLE, "kubernetes TokenReview interrupted");
        } catch (IOException e) {
            throw new K8sTokenVerificationException(
                    Status.UNAVAILABLE,
                    "kubernetes TokenReview request failed: " + e.getMessage());
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new K8sTokenVerificationException(
                    Status.UNAVAILABLE,
                    "kubernetes TokenReview HTTP " + response.statusCode() + ": " + trimBody(response.body()));
        }

        return parseTokenReviewResponse(response.body(), requiredAudience);
    }

    private static VerifiedK8sIdentity parseTokenReviewResponse(String json, String requiredAudience)
            throws K8sTokenVerificationException {
        JsonObject root;
        try {
            root = JsonParser.parseString(json).getAsJsonObject();
        } catch (RuntimeException e) {
            throw new K8sTokenVerificationException(
                    Status.UNAVAILABLE,
                    "kubernetes TokenReview response was not valid JSON");
        }

        JsonObject status = object(root, "status");
        if (status == null) {
            throw new K8sTokenVerificationException(
                    Status.UNAVAILABLE,
                    "kubernetes TokenReview response missing status");
        }
        if (!bool(status, "authenticated")) {
            String err = string(status, "error");
            throw new K8sTokenVerificationException(
                    Status.UNAUTHENTICATED,
                    err == null || err.isBlank() ? "kubernetes TokenReview did not authenticate token" : err);
        }

        List<String> audiences = strings(array(status, "audiences"));
        if (!audiences.contains(requiredAudience)) {
            throw new K8sTokenVerificationException(
                    Status.UNAUTHENTICATED,
                    "kubernetes TokenReview audiences " + audiences
                            + " do not include required kernel audience");
        }

        JsonObject user = object(status, "user");
        String username = user == null ? null : string(user, "username");
        ServiceAccountName serviceAccountName = parseServiceAccountUsername(username);
        String uid = user == null ? "" : nullToEmpty(string(user, "uid"));
        Map<String, String> extras = user == null ? Map.of() : podExtras(object(user, "extra"));
        return new VerifiedK8sIdentity(
                serviceAccountName.namespace(),
                serviceAccountName.name(),
                uid,
                audiences,
                extras);
    }

    private static ServiceAccountName parseServiceAccountUsername(String username)
            throws K8sTokenVerificationException {
        if (username == null || !username.startsWith(SERVICE_ACCOUNT_USERNAME_PREFIX)) {
            throw new K8sTokenVerificationException(
                    Status.UNAUTHENTICATED,
                    "kubernetes TokenReview user is not a service account");
        }
        String rest = username.substring(SERVICE_ACCOUNT_USERNAME_PREFIX.length());
        int sep = rest.indexOf(':');
        if (sep <= 0 || sep == rest.length() - 1) {
            throw new K8sTokenVerificationException(
                    Status.UNAUTHENTICATED,
                    "kubernetes TokenReview service account username is malformed");
        }
        return new ServiceAccountName(rest.substring(0, sep), rest.substring(sep + 1));
    }

    private static URI inClusterApiServerUri() {
        String configured = System.getenv("KERNEL_KUBE_API_URL");
        if (configured != null && !configured.isBlank()) {
            return URI.create(configured);
        }
        String host = System.getenv("KUBERNETES_SERVICE_HOST");
        String port = System.getenv("KUBERNETES_SERVICE_PORT_HTTPS");
        if (port == null || port.isBlank()) {
            port = System.getenv("KUBERNETES_SERVICE_PORT");
        }
        if (host == null || host.isBlank() || port == null || port.isBlank()) {
            throw new IllegalStateException("Kubernetes API endpoint is not configured");
        }
        return URI.create("https://" + host + ":" + port);
    }

    private static HttpClient inClusterHttpClient() throws IOException, GeneralSecurityException {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(DEFAULT_TIMEOUT);
        String caFile = getenvDefault("KERNEL_KUBE_CA_FILE", DEFAULT_CA_FILE);
        Path caPath = Path.of(caFile);
        if (Files.exists(caPath) && Files.size(caPath) > 0) {
            builder.sslContext(sslContextForCA(caPath));
        }
        return builder.build();
    }

    private static SSLContext sslContextForCA(Path caPath)
            throws IOException, GeneralSecurityException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        try (InputStream in = Files.newInputStream(caPath)) {
            int i = 0;
            for (Certificate cert : certFactory.generateCertificates(in)) {
                trustStore.setCertificateEntry("kubernetes-ca-" + i, cert);
                i++;
            }
            if (i == 0) {
                throw new GeneralSecurityException("no certificates found in " + caPath);
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        return sslContext;
    }

    private static Map<String, String> podExtras(JsonObject extra) {
        if (extra == null) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, JsonElement> entry : extra.entrySet()) {
            String key = entry.getKey();
            if (!key.startsWith("authentication.kubernetes.io/pod-")) {
                continue;
            }
            List<String> values = strings(asArray(entry.getValue()));
            if (!values.isEmpty()) {
                out.put(key, values.get(0));
            }
        }
        return out;
    }

    private static String getenvDefault(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static JsonObject object(JsonObject obj, String key) {
        JsonElement el = obj == null ? null : obj.get(key);
        return el != null && el.isJsonObject() ? el.getAsJsonObject() : null;
    }

    private static JsonArray array(JsonObject obj, String key) {
        JsonElement el = obj == null ? null : obj.get(key);
        return asArray(el);
    }

    private static JsonArray asArray(JsonElement el) {
        return el != null && el.isJsonArray() ? el.getAsJsonArray() : null;
    }

    private static boolean bool(JsonObject obj, String key) {
        JsonElement el = obj == null ? null : obj.get(key);
        return el != null && el.isJsonPrimitive() && el.getAsBoolean();
    }

    private static String string(JsonObject obj, String key) {
        JsonElement el = obj == null ? null : obj.get(key);
        return el != null && el.isJsonPrimitive() ? el.getAsString() : null;
    }

    private static List<String> strings(JsonArray arr) {
        if (arr == null) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (JsonElement item : arr) {
            if (item != null && item.isJsonPrimitive()) {
                out.add(item.getAsString());
            }
        }
        return out;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String trimBody(String body) {
        if (body == null) {
            return "";
        }
        String trimmed = body.strip();
        return trimmed.length() <= 4096 ? trimmed : trimmed.substring(0, 4096);
    }

    private record ServiceAccountName(String namespace, String name) {}
}
