// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.x509.X509;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;

final class ServiceIntermediateCa {
	private ServiceIntermediateCa() {
	}

	static ImmutableCertChain reusable(
			String serviceName,
			X509.X509CertChain existing,
			ImmutableCertChain signingCa,
			Logger logger) {
		if (existing == null || existing.getChainCount() == 0) {
			return null;
		}

		try {
			ImmutableCertChain existingChain = ImmutableCertChain.from(existing);
			if (existingChain.getEffectiveKey() == null) {
				logger.warn("Discarding service CA without private key: {}", serviceName);
				return null;
			}

			X509Certificate existingCert = existingChain.leaf().getX509Certificate();
			X509Certificate signingCert = signingCa.leaf().getX509Certificate();
			existingCert.checkValidity();
			signingCert.checkValidity();

			if (!existingCert.getIssuerX500Principal().equals(signingCert.getSubjectX500Principal())) {
				logger.info(
						"Rotating service CA for {}: issuer {} does not match current signing CA subject {}",
						serviceName,
						existingCert.getIssuerX500Principal().getName(),
						signingCert.getSubjectX500Principal().getName());
				return null;
			}

			existingCert.verify(signingCert.getPublicKey());
			return existingChain;
		} catch (Exception e) {
			logger.info("Rotating service CA for {}: existing CA is not valid under current signing CA: {}",
					serviceName, e.getMessage());
			return null;
		}
	}
}
