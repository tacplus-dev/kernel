// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.generated.entitlements.Entitlements;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
}
