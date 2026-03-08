// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.x509.ImmutableCertPair;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.x509.X509;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.services.kernel.X509CertExchangerServiceGrpc;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * gRPC service implementing X.509 certificate signing using the node's CA keypair.
 *
 * <p>
 * Signs {@link X509.X509CertRequest} messages using the node's in-memory CA
 * private key (held by {@link CaKeyHolder}). The generated certificate's
 * Subject CN is taken from the request's issuer field.
 */
public class X509CertExchangerService
        extends X509CertExchangerServiceGrpc.X509CertExchangerServiceImplBase {

    private static final Logger logger = LoggerFactory.getLogger(X509CertExchangerService.class);

    private final CaKeyHolder caKeyHolder;

    public X509CertExchangerService(CaKeyHolder caKeyHolder) {
        this.caKeyHolder = caKeyHolder;
    }

    @Override
    public void signCert(X509.X509CertRequest request, StreamObserver<X509.X509Cert> responseObserver) {
        try {
            ImmutableCertPair caPair = caKeyHolder.getActiveCaPair();
            if (caPair == null) {
                responseObserver.onError(Status.UNAVAILABLE
                        .withDescription("CA keypair not yet initialized")
                        .asRuntimeException());
                return;
            }

            X509.X509Cert signed = caPair.sign(request);

            logger.info("Signed certificate: issuer={}, exp={}", request.getIssuer(), request.getExp());
            responseObserver.onNext(signed);
            responseObserver.onCompleted();
        } catch (IllegalArgumentException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription("certificate signing failed: " + e.getMessage())
                    .asRuntimeException());
        } catch (Exception e) {
            logger.error("Certificate signing failed", e);
            responseObserver.onError(Status.INTERNAL
                    .withDescription("certificate signing failed: " + e.getMessage())
                    .asRuntimeException());
        }
    }
}
