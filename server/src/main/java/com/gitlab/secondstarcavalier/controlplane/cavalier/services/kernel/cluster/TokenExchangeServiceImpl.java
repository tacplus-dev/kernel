// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.services.kernel.Kernel;

/**
 * Entitlement-scoping helper used by the consolidated kernel {@code Mint}
 * handler ({@link IdentityServiceImpl}) on a U2S access→service exchange.
 *
 * <p>The standalone TokenExchange gRPC service was folded into the Mint handler
 * when minting was consolidated back into the kernel; only this proven static
 * helper survives — token issuance itself lives in {@link IdentityServiceImpl}.
 */
final class TokenExchangeServiceImpl {

	private TokenExchangeServiceImpl() {
	}

	/**
	 * Scopes a full TokenEntitlements down to only the grants for {@code targetAud}.
	 * Kernel (aud:kernel) tokens carry all entitlements and are returned unchanged.
	 * Per-service routing is fully generated — see the tacplus entitlements Helpers.
	 */
	static Entitlements.TokenEntitlements scopeToService(
			Entitlements.TokenEntitlements entitlements, String targetAud) {
		if (Kernel.getDescriptor().getPackage().equals(targetAud)) {
			return entitlements;
		}
		return com.gitlab.secondstarcavalier.controlplane.cavalier.services.kernel.model.types.generated.entitlements.Helpers
				.scopeToEntitlements(entitlements, targetAud);
	}
}
