// Copyright (c) 2024 Second Star Cavalier, LLC.
package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.grants.Grants;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;

import java.util.List;
import java.util.TreeSet;

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
		if (entitlements == null || targetAud == null || targetAud.isEmpty()) {
			return Entitlements.TokenEntitlements.getDefaultInstance();
		}
		if (Kernel.getDescriptor().getPackage().equals(targetAud)) {
			return entitlements;
		}
		TreeSet<String> scoped = new TreeSet<>();
		for (String grant : entitlements.getGrantsList()) {
			for (String token : Grants.normalize(List.of(grant))) {
				var grantInfo = Grants.lookup(token);
				if (grantInfo.isPresent() && targetAud.equals(grantInfo.get().pkg)) {
					scoped.add(token);
				}
			}
		}
		if (scoped.isEmpty()) {
			return Entitlements.TokenEntitlements.getDefaultInstance();
		}
		// principal_scope survives the narrowing. It says how wide the caller's
		// authority over PRINCIPALS is, which is a property of the caller and not
		// of the service being addressed; dropping it here would make every
		// service-audience token self-scoped no matter what the policy stamped,
		// and every real RPC in this system is made with an aud-scoped token.
		return Entitlements.TokenEntitlements.newBuilder()
				.addAllGrants(scoped)
				.addAllAzp(entitlements.getAzpList())
				.setPrincipalScope(entitlements.getPrincipalScope())
				.build();
	}
}
