// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.libs.key.KeyOuterClass;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalSigningKeyTypeTest {
	@Test
	void unspecifiedDefaultsToEd25519() throws ProtoException {
		assertEquals(KeyRotator.SigAlg.ED25519,
				IdentityServiceImpl.externalSigningAlgForKeyType(null));
		assertEquals(KeyRotator.SigAlg.ED25519,
				IdentityServiceImpl.externalSigningAlgForKeyType(
						KeyOuterClass.KeyType.KEY_TYPE_UNDEFINED));
	}

	@Test
	void explicitOkpUsesEd25519() throws ProtoException {
		assertEquals(KeyRotator.SigAlg.ED25519,
				IdentityServiceImpl.externalSigningAlgForKeyType(
						KeyOuterClass.KeyType.KEY_TYPE_OKP));
	}

	@Test
	void explicitEcUsesEs256() throws ProtoException {
		assertEquals(KeyRotator.SigAlg.ES256,
				IdentityServiceImpl.externalSigningAlgForKeyType(
						KeyOuterClass.KeyType.KEY_TYPE_EC));
	}

	@Test
	void explicitRsaIsRejected() {
		ProtoException err = assertThrows(ProtoException.class,
				() -> IdentityServiceImpl.externalSigningAlgForKeyType(
						KeyOuterClass.KeyType.KEY_TYPE_RSA));

		assertTrue(err.getMessage().contains("KEY_TYPE_RSA"));
	}

	@Test
	void requestedEcWithoutActiveKeyIsRejected() {
		KeyRotator keyRotator = new KeyRotator(
				3600,
				7200,
				jwk -> {},
				kid -> {},
				List::of,
				() -> {});

		ProtoException err = assertThrows(ProtoException.class,
				() -> IdentityServiceImpl.externalSigningKeyForRequest(
						keyRotator, KeyOuterClass.KeyType.KEY_TYPE_EC));

		assertTrue(err.getMessage().contains("KEY_TYPE_EC"));
		assertTrue(err.getMessage().contains("ES256"));
	}

	@Test
	void externalAudienceUsesPolicyAudienceWhenProvided() {
		assertEquals("https://api.anthropic.com",
				IdentityServiceImpl.externalAudienceForPolicy(
						"anthropic", List.of("https://api.anthropic.com")));
	}

	@Test
	void externalAudienceSkipsBlankPolicyAudiences() {
		assertEquals("https://api.anthropic.com",
				IdentityServiceImpl.externalAudienceForPolicy(
						"anthropic", List.of("", "  ", "https://api.anthropic.com")));
	}

	@Test
	void externalAudienceFallsBackToCallerAudienceWithoutPolicyAudience() {
		assertEquals("anthropic",
				IdentityServiceImpl.externalAudienceForPolicy("anthropic", List.of()));
		assertEquals("",
				IdentityServiceImpl.externalAudienceForPolicy(null, null));
	}
}
