// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.x509.ImmutableCert;
import com.github.tacplusdev.kernel.model.chassis.x509.ImmutableCertChain;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.x509.X509;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsCertServiceImplTest {

	private static final String CALLER_SPIFFE_ID = "spiffe://local.dev/system/services/oauth";
	private static final String CALLER_SERVICE_NAME = "oauth";

	/**
	 * ManageCert used to put {@code init.instance_id} straight into the signed
	 * cert's DNS SANs, unchecked against the caller's verified identity, so a
	 * service holding a valid token of its own could have kernel sign — under a
	 * trusted CA — a cert asserting another service's hostname and then
	 * impersonate that peer in TLS. The instance name must be one the caller
	 * demonstrably owns.
	 */
	@Test
	void manageCertDropsAnInstanceIdDnsSanBelongingToAnotherService() throws Exception {
		long exp = Instant.now().plusSeconds(86_400).getEpochSecond();
		KeyPair callerKey = generateEcKeyPair();

		X509.X509CertRequest signed = TlsCertServiceImpl.kernelCertRequest(
				publicKeyProto("oauth-tls", callerKey),
				CALLER_SPIFFE_ID,
				CALLER_SERVICE_NAME,
				// Spoofed: the caller's token verifies it as "oauth", but it
				// claims the gateway's pod hostname as its instance.
				"gateway-0",
				exp);

		assertEquals(List.of(CALLER_SPIFFE_ID), signed.getUriSansList());
		assertEquals(List.of("oauth", "*.oauth"), signed.getDnsNamesList());

		// And the same holds of the certificate that actually comes out of the
		// signer, which is what a TLS peer sees.
		X509Certificate leaf = signLeaf(signed);
		List<String> sans = sansOf(leaf);
		assertTrue(sans.contains(CALLER_SPIFFE_ID));
		assertTrue(sans.contains("oauth"));
		assertFalse(sans.contains("gateway-0"), "spoofed peer hostname must not be certified");
	}

	/**
	 * The legitimate case the generated service managers exercise on every pod:
	 * instance_id is the pod's own hostname, which is the service name plus an
	 * ordinal. It must survive, or auto_tls hostname verification breaks.
	 */
	@Test
	void manageCertKeepsTheCallersOwnHostnameShapedInstanceId() throws Exception {
		long exp = Instant.now().plusSeconds(86_400).getEpochSecond();
		KeyPair callerKey = generateEcKeyPair();

		for (String own : List.of("oauth-0", "oauth.default.svc", "oauth", "oauth0")) {
			X509.X509CertRequest signed = TlsCertServiceImpl.kernelCertRequest(
					publicKeyProto("oauth-tls", callerKey),
					CALLER_SPIFFE_ID, CALLER_SERVICE_NAME, own, exp);

			assertEquals(CALLER_SERVICE_NAME, signed.getIssuer());
			assertEquals(exp, signed.getExp());
			assertTrue(signed.getDnsNamesList().contains("oauth"));
			assertTrue(signed.getDnsNamesList().contains("*.oauth"));
			assertTrue(signed.getDnsNamesList().contains(own), own + " is a name the caller owns");
			assertTrue(sansOf(signLeaf(signed)).contains(own), own + " must reach the signed cert");
		}
	}

	/** An empty instance_id contributes no SAN rather than an empty DNS name. */
	@Test
	void manageCertEmitsNoEmptyDnsSanForAnAbsentInstanceId() throws Exception {
		X509.X509CertRequest signed = TlsCertServiceImpl.kernelCertRequest(
				publicKeyProto("oauth-tls", generateEcKeyPair()),
				CALLER_SPIFFE_ID, CALLER_SERVICE_NAME, "",
				Instant.now().plusSeconds(86_400).getEpochSecond());

		assertEquals(List.of("oauth", "*.oauth"), signed.getDnsNamesList());
	}

	private static X509Certificate signLeaf(X509.X509CertRequest request) throws Exception {
		ImmutableCertChain intermediateCa = ImmutableCertChain.from(
				serviceCa(CALLER_SERVICE_NAME, signingCa("signing-ca")));
		return ImmutableCert.from(intermediateCa.sign(request)).getX509Certificate();
	}

	private static List<String> sansOf(X509Certificate cert) throws Exception {
		return cert.getSubjectAlternativeNames().stream()
				.map(entry -> String.valueOf(entry.get(1)))
				.toList();
	}

	private static KeyOuterClass.PublicKey publicKeyProto(String id, KeyPair keyPair) {
		return KeyOuterClass.PublicKey.newBuilder()
				.setId(id)
				.setBase64(Base64.getUrlEncoder().withoutPadding()
						.encodeToString(keyPair.getPublic().getEncoded()))
				.build();
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
				.setBase64(Base64.getUrlEncoder().withoutPadding()
						.encodeToString(keyPair.getPublic().getEncoded()))
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
