// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Supplier;

/**
 * ExternalJwkResolver resolves JWKs by kid from the internal key store.
 *
 * <p>Currently only resolves keys from the locally stored verifying_keys.
 * External OIDC discovery support requires ExternalJwk and IssuerEntry
 * proto types to be added to the kernel proto.
 */
public class ExternalJwkResolver {

    private static final Logger logger = LoggerFactory.getLogger(ExternalJwkResolver.class);

    private final Supplier<List<JwkOuterClass.Jwk>> allKeysReader;

    public ExternalJwkResolver(Supplier<List<JwkOuterClass.Jwk>> allKeysReader) {
        this.allKeysReader = allKeysReader;
    }

    public void start() {
        logger.info("ExternalJwkResolver started (local keys only)");
    }

    public void stop() {
        // No resources to clean up
    }

    /**
     * Resolves a JWK by kid from the internal key store.
     *
     * @param kid    the key ID to resolve
     * @param issuer the token issuer (currently unused)
     * @return the resolved ImmutableJwk
     * @throws ResolveException if the key cannot be found
     */
    public ImmutableJwk resolveKey(String kid, String issuer) throws ResolveException {
        for (JwkOuterClass.Jwk jwk : allKeysReader.get()) {
            if (kid.equals(jwk.getKid())) {
                return ImmutableJwk.from(jwk);
            }
        }
        throw new ResolveException("unknown key: " + kid);
    }

    /**
     * Exception for key resolution errors.
     */
    public static final class ResolveException extends Exception {
        public ResolveException(String message) {
            super(message);
        }

        public ResolveException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
