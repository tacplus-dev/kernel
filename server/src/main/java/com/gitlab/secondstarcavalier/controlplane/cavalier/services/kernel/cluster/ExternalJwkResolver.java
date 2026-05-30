// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.tacplus.types.libs.key.KeyOuterClass;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves JWKs by {@code kid} for JWT signature verification.
 *
 * <p>Two sources, checked in order:
 * <ol>
 *   <li><b>Internal verifying keys</b> (kernel-signed tokens) — from the local key store.</li>
 *   <li><b>External trusted issuers</b> (IdP-signed tokens) — fetched via OIDC discovery +
 *       JWKS over <b>cert-verified TLS</b>, cached per issuer with a refetch interval.</li>
 * </ol>
 *
 * <p><b>Fail closed.</b> An issuer that is not in the configured trusted set is never
 * contacted and never trusted. A fetch/parse failure, an unknown {@code kid}, or an
 * unsupported key type results in a {@link ResolveException} — the token is rejected.
 * TLS certificate verification is always enforced (system trust, or a per-issuer CA when
 * configured); it is never disabled.
 */
public class ExternalJwkResolver {

    private static final Logger logger = LoggerFactory.getLogger(ExternalJwkResolver.class);

    /** Minimum interval between JWKS (re)fetches for the same issuer. */
    private static final Duration REFETCH_INTERVAL = Duration.ofMinutes(5);
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    /**
     * A trusted external token issuer. {@code jwksUri} and {@code caPem} are optional:
     * an empty {@code jwksUri} triggers OIDC discovery; an empty {@code caPem} uses the
     * system trust store for TLS.
     */
    public record TrustedIssuer(String issuer, String jwksUri, String caPem) {}

    private static final class CachedJwks {
        volatile Map<String, JwkOuterClass.Jwk> keysByKid = Map.of();
        volatile long fetchedAtMillis = 0L;
    }

    private final Supplier<List<JwkOuterClass.Jwk>> localKeysReader;
    private final Supplier<List<TrustedIssuer>> trustedIssuersReader;

    private final HttpClient defaultClient = HttpClient.newBuilder()
            .connectTimeout(HTTP_TIMEOUT)
            .build();
    // Per-issuer HTTP clients for issuers that pin a custom CA.
    private final Map<String, HttpClient> clientByIssuer = new ConcurrentHashMap<>();
    private final Map<String, CachedJwks> cacheByIssuer = new ConcurrentHashMap<>();

    /** Local-keys-only resolver (no external issuers). */
    public ExternalJwkResolver(Supplier<List<JwkOuterClass.Jwk>> localKeysReader) {
        this(localKeysReader, List::of);
    }

    public ExternalJwkResolver(Supplier<List<JwkOuterClass.Jwk>> localKeysReader,
            Supplier<List<TrustedIssuer>> trustedIssuersReader) {
        this.localKeysReader = localKeysReader;
        this.trustedIssuersReader = trustedIssuersReader;
    }

    public void start() {
        logger.info("ExternalJwkResolver started (local keys + {} trusted external issuer(s))",
                trustedIssuersReader.get().size());
    }

    public void stop() {
        // No resources to clean up.
    }

    /**
     * Resolves a JWK by kid. Checks the internal key store first, then the configured
     * trusted external issuer (matched on the token's {@code issuer}).
     *
     * @param kid    the key ID to resolve
     * @param issuer the token issuer (used only to select a trusted external issuer)
     * @return the resolved ImmutableJwk (verifying key)
     * @throws ResolveException if the key cannot be resolved from a trusted source
     */
    public ImmutableJwk resolveKey(String kid, String issuer) throws ResolveException {
        if (kid == null || kid.isEmpty()) {
            throw new ResolveException("missing kid");
        }

        // 1. Internal verifying keys (kernel-signed tokens).
        for (JwkOuterClass.Jwk jwk : localKeysReader.get()) {
            if (kid.equals(jwk.getKid())) {
                try {
                    return ImmutableJwk.from(jwk);
                } catch (Exception e) {
                    throw new ResolveException("failed to load local key " + kid, e);
                }
            }
        }

        // 2. External trusted issuer. Fail closed if the issuer is not trusted.
        if (issuer == null || issuer.isEmpty()) {
            throw new ResolveException("unknown key (no issuer to resolve external key): " + kid);
        }
        TrustedIssuer trusted = findTrustedIssuer(issuer);
        if (trusted == null) {
            throw new ResolveException("issuer not trusted: " + issuer);
        }

        JwkOuterClass.Jwk jwk = resolveExternal(trusted, kid);
        if (jwk == null) {
            throw new ResolveException("unknown key " + kid + " for issuer " + issuer);
        }
        try {
            return ImmutableJwk.from(jwk);
        } catch (Exception e) {
            throw new ResolveException("failed to load external key " + kid, e);
        }
    }

    private TrustedIssuer findTrustedIssuer(String issuer) {
        for (TrustedIssuer t : trustedIssuersReader.get()) {
            if (issuer.equals(t.issuer())) {
                return t;
            }
        }
        return null;
    }

    /**
     * Returns the JWK for {@code kid} from the issuer's cached JWKS, fetching/refreshing
     * as needed. If the kid is absent and the cache is stale, refetches once to pick up
     * key rotation.
     */
    private JwkOuterClass.Jwk resolveExternal(TrustedIssuer trusted, String kid) throws ResolveException {
        CachedJwks cache = cacheByIssuer.computeIfAbsent(trusted.issuer(), k -> new CachedJwks());
        synchronized (cache) {
            JwkOuterClass.Jwk hit = cache.keysByKid.get(kid);
            boolean stale = System.currentTimeMillis() - cache.fetchedAtMillis > REFETCH_INTERVAL.toMillis();
            if (hit != null && !stale) {
                return hit;
            }
            if (hit == null && cache.fetchedAtMillis != 0 && !stale) {
                // Cache is fresh and the kid genuinely isn't there — don't hammer the IdP.
                return null;
            }
            // Refetch (first fetch, stale, or kid-miss on a stale cache → rotation).
            Map<String, JwkOuterClass.Jwk> fetched = fetchJwks(trusted);
            cache.keysByKid = fetched;
            cache.fetchedAtMillis = System.currentTimeMillis();
            return fetched.get(kid);
        }
    }

    private Map<String, JwkOuterClass.Jwk> fetchJwks(TrustedIssuer trusted) throws ResolveException {
        String jwksUri = trusted.jwksUri();
        if (jwksUri == null || jwksUri.isEmpty()) {
            jwksUri = discoverJwksUri(trusted);
        }
        String body = httpGet(trusted, jwksUri);
        JsonObject root;
        try {
            root = JsonParser.parseString(body).getAsJsonObject();
        } catch (Exception e) {
            throw new ResolveException("invalid JWKS JSON from " + jwksUri, e);
        }
        JsonArray keys = root.getAsJsonArray("keys");
        if (keys == null) {
            throw new ResolveException("JWKS from " + jwksUri + " has no 'keys' array");
        }
        Map<String, JwkOuterClass.Jwk> out = new HashMap<>();
        for (var el : keys) {
            try {
                JwkOuterClass.Jwk jwk = jsonToJwk(el.getAsJsonObject());
                if (jwk != null && !jwk.getKid().isEmpty()) {
                    out.put(jwk.getKid(), jwk);
                }
            } catch (Exception e) {
                logger.warn("skipping unparseable JWK from {}: {}", jwksUri, e.getMessage());
            }
        }
        logger.info("fetched {} JWK(s) from {} (issuer {})", out.size(), jwksUri, trusted.issuer());
        return out;
    }

    private String discoverJwksUri(TrustedIssuer trusted) throws ResolveException {
        String wellKnown = trusted.issuer().replaceAll("/+$", "") + "/.well-known/openid-configuration";
        String body = httpGet(trusted, wellKnown);
        try {
            String uri = JsonParser.parseString(body).getAsJsonObject().get("jwks_uri").getAsString();
            if (uri == null || uri.isEmpty()) {
                throw new ResolveException("discovery for " + trusted.issuer() + " has no jwks_uri");
            }
            return uri;
        } catch (ResolveException e) {
            throw e;
        } catch (Exception e) {
            throw new ResolveException("invalid discovery document from " + wellKnown, e);
        }
    }

    private String httpGet(TrustedIssuer trusted, String url) throws ResolveException {
        try {
            HttpClient client = clientFor(trusted);
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(HTTP_TIMEOUT)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new ResolveException("HTTP " + resp.statusCode() + " from " + url);
            }
            return resp.body();
        } catch (ResolveException e) {
            throw e;
        } catch (Exception e) {
            throw new ResolveException("fetch failed for " + url + ": " + e.getMessage(), e);
        }
    }

    /** Default (system-trust) client, or a per-issuer client pinned to the issuer's CA. */
    private HttpClient clientFor(TrustedIssuer trusted) throws ResolveException {
        String caPem = trusted.caPem();
        if (caPem == null || caPem.isEmpty()) {
            return defaultClient;
        }
        HttpClient existing = clientByIssuer.get(trusted.issuer());
        if (existing != null) {
            return existing;
        }
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(HTTP_TIMEOUT)
                .sslContext(sslContextForCa(caPem))
                .build();
        clientByIssuer.put(trusted.issuer(), client);
        return client;
    }

    private static SSLContext sslContextForCa(String caPem) throws ResolveException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            var in = new ByteArrayInputStream(caPem.getBytes(StandardCharsets.UTF_8));
            for (Certificate cert : cf.generateCertificates(in)) {
                ks.setCertificateEntry("ca-" + (i++), cert);
            }
            if (i == 0) {
                throw new ResolveException("no certificates in configured ca_pem");
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (ResolveException e) {
            throw e;
        } catch (Exception e) {
            throw new ResolveException("failed to build SSL context from ca_pem: " + e.getMessage(), e);
        }
    }

    /** Maps a standard JWKS JSON entry to the internal Jwk proto. */
    private static JwkOuterClass.Jwk jsonToJwk(JsonObject o) throws ResolveException {
        String kty = optString(o, "kty");
        KeyOuterClass.KeyType keyType = switch (kty == null ? "" : kty.toUpperCase()) {
            case "RSA" -> KeyOuterClass.KeyType.KEY_TYPE_RSA;
            case "EC" -> KeyOuterClass.KeyType.KEY_TYPE_EC;
            case "OKP" -> KeyOuterClass.KeyType.KEY_TYPE_OKP;
            default -> throw new ResolveException("unsupported kty: " + kty);
        };
        JwkOuterClass.Jwk.Builder b = JwkOuterClass.Jwk.newBuilder().setKty(keyType);
        putIfPresent(o, "kid", b::setKid);
        putIfPresent(o, "alg", b::setAlg);
        putIfPresent(o, "n", b::setN);
        putIfPresent(o, "e", b::setE);
        putIfPresent(o, "crv", b::setCrv);
        putIfPresent(o, "x", b::setX);
        putIfPresent(o, "y", b::setY);
        return b.build();
    }

    private static String optString(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : null;
    }

    private static void putIfPresent(JsonObject o, String key, java.util.function.Consumer<String> setter) {
        String v = optString(o, key);
        if (v != null && !v.isEmpty()) {
            setter.accept(v);
        }
    }

    /** Exception for key resolution errors. */
    public static final class ResolveException extends Exception {
        public ResolveException(String message) {
            super(message);
        }

        public ResolveException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
