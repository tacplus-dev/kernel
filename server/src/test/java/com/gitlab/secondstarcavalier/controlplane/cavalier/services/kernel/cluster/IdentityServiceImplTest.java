// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.chassis.x509.ImmutableCertChain;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.key.KeyOuterClass;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.sys.x509.X509;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityServiceImplTest {
	@Test
	void serviceEntitlementsNormalizeConvenienceWildcardsToExactRpcGrants() {
		Entitlements.TokenEntitlements entitlements = Entitlements.TokenEntitlements.newBuilder()
				.addGrants("ANTHROPIC_ANY")
				.addAzp("oauth")
				.build();

		Entitlements.TokenEntitlements normalized =
				IdentityServiceImpl.normalizeServiceEntitlements(entitlements);

		assertTrue(normalized.getGrantsList().contains("ANTHROPIC_PROXY_CREATE_MESSAGE"));
		assertTrue(normalized.getGrantsList().contains("ANTHROPIC_PROXY_GENERATE_MESSAGE_STREAM"));
		assertFalse(normalized.getGrantsList().contains("ANTHROPIC_ANY"));
		assertFalse(normalized.getGrantsList().stream().anyMatch(grant -> grant.endsWith("_ANY")));
		assertTrue(normalized.getAzpList().contains("oauth"));
	}

	@Test
	void serviceIntermediateCaIsRotatedWhenSigningCaChanges() throws Exception {
		ImmutableCertChain oldSigningCa = signingCa("old-signing-ca");
		ImmutableCertChain newSigningCa = signingCa("new-signing-ca");
		X509.X509CertChain serviceCa = serviceCa("oauth", oldSigningCa);

		assertNotNull(ServiceIntermediateCa.reusable(
				"oauth", serviceCa, oldSigningCa, LoggerFactory.getLogger(getClass())));
		assertNull(ServiceIntermediateCa.reusable(
				"oauth", serviceCa, newSigningCa, LoggerFactory.getLogger(getClass())));
	}

	private static ImmutableCertChain signingCa(String name) throws Exception {
		ImmutableKey key = ImmutableKey.from(keyProto(name, generateEcKeyPair()));
		X509.X509Cert cert = ImmutableCertChain.forSelfSigning(key).selfSign(
				name,
				Instant.now().plusSeconds(86_400).getEpochSecond(),
				X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN,
				List.of());
		return ImmutableCertChain.from(X509.X509CertChain.newBuilder()
				.setId(name)
				.setKey(key.getProto())
				.addChain(cert)
				.build());
	}

	private static X509.X509CertChain serviceCa(String serviceName, ImmutableCertChain signingCa)
			throws Exception {
		KeyPair keyPair = generateEcKeyPair();
		KeyOuterClass.PublicKey publicKey = KeyOuterClass.PublicKey.newBuilder()
				.setId(serviceName + "-intermediate-ca")
				.setBase64(Base64.getUrlEncoder().withoutPadding().encodeToString(keyPair.getPublic().getEncoded()))
				.build();
		X509.X509Cert cert = signingCa.sign(X509.X509CertRequest.newBuilder()
				.setKey(publicKey)
				.setExp(Instant.now().plusSeconds(86_400).getEpochSecond())
				.setIssuer(serviceName + " Intermediate CA")
				.setKeyUsage(X509.X509KeyUsage.X509_KEY_USAGE_CERT_SIGN)
				.setIsCa(true)
				.setPathLenConstraint(0)
				.build());
		return X509.X509CertChain.newBuilder()
				.setId(serviceName)
				.setKey(keyProto(serviceName + "-intermediate-ca", keyPair))
				.addChain(cert)
				.build();
	}

	private static KeyPair generateEcKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		return generator.generateKeyPair();
	}

	private static KeyOuterClass.Key keyProto(String id, KeyPair keyPair) {
		String pem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
				+ "\n-----END PRIVATE KEY-----\n";
		return KeyOuterClass.Key.newBuilder()
				.setId(id)
				.setBase64(Base64.getUrlEncoder().withoutPadding().encodeToString(pem.getBytes()))
				.build();
	}
}
