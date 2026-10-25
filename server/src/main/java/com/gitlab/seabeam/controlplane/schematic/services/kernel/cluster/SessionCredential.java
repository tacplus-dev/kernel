// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.Struct;
import com.google.protobuf.util.JsonFormat;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;

/**
 * The session credential's claim shape (identity decision record 2026-10-25).
 *
 * <p>A credential is a kernel-signed token — {@code sub = spiffe://<td>/users/<xid>},
 * the long-lived {@code token_use} every authorizer already refuses as an API
 * bearer — distinguished from a legacy single-namespace refresh token by TWO
 * claims it carries and a legacy token never does: {@link #CLAIM_GENERATION}
 * (the per-XID generation) and {@link #CLAIM_PROOFS} (the set of proofs). It is
 * the claim shape that selects the arm, never {@code token_use} alone: the legacy
 * refresh path must never mint from a credential without the proof, generation,
 * link and membership checks, and the credential path must never read a legacy
 * refresh token as a proof set.
 *
 * <p>A credential's {@code namespace} claim is {@code /tenants/people}, the
 * default tenant every person belongs to (a signed user token must carry one).
 * It never selects what the credential mints: the tenant is chosen at the
 * exchange, against the proofs.
 */
final class SessionCredential {

	/** The per-XID generation the credential was minted under; bumped by sign-out-everywhere. */
	static final String CLAIM_GENERATION = "xid_gen";

	/** The proofs, a JSON array of {@link Proof}. */
	static final String CLAIM_PROOFS = "proofs";

	private SessionCredential() {
	}

	/**
	 * One IdP assertion: who spoke, when, for how long, and which tenants it
	 * activates. {@code tenants} is recorded at login and never re-derived at the
	 * exchange — the rule is "the IdP that spoke activates what it routes to", and
	 * re-deriving would let a later claim-matcher change widen an old session.
	 *
	 * @param idpId           the IdP record ({@code google}, {@code apple})
	 * @param providerSubject the IdP's own {@code sub}, verbatim
	 * @param authTime        when the IdP authenticated the person (epoch seconds)
	 * @param exp             when this proof stops vouching (epoch seconds)
	 * @param tenants         the tenant namespaces this proof vouches for; an org
	 *                        proof lists the org and {@code /tenants/people}, a
	 *                        personal proof lists {@code /tenants/people} only
	 * @param claims          the verified IdP claims the broker relayed at login,
	 *                        replayed into OPA for entitlements at every mint from
	 *                        this proof
	 */
	record Proof(String idpId, String providerSubject, long authTime, long exp,
			List<String> tenants, Struct claims) {

		boolean isLive(long nowSeconds) {
			return exp > nowSeconds;
		}

		boolean vouches(String tenantNamespace) {
			return tenants.contains(tenantNamespace);
		}

		/** Same provider identity: the dedupe key of a merge. */
		boolean sameIdentity(String idpId, String providerSubject) {
			return this.idpId.equals(idpId) && this.providerSubject.equals(providerSubject);
		}
	}

	/** Whether a verified kernel-signed token is a session credential, by claim shape. */
	static boolean isCredential(TokenWrapper token) {
		String proofs = token.getCustomField(CLAIM_PROOFS);
		String generation = token.getCustomField(CLAIM_GENERATION);
		return proofs != null && !proofs.isEmpty() && generation != null && !generation.isEmpty();
	}

	/** The XID inside a credential's subject, or null if the subject is not a person. */
	@Nullable
	static String xidOf(TokenWrapper token) {
		String subject = token.getSubject();
		int at = subject.indexOf("/users/");
		if (at < 0 || subject.indexOf('/', at + "/users/".length()) >= 0) {
			return null;
		}
		String xid = subject.substring(at + "/users/".length());
		return xid.isEmpty() ? null : xid;
	}

	static long generationOf(TokenWrapper token) {
		try {
			return Long.parseLong(token.getCustomField(CLAIM_GENERATION));
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	/** The proofs a credential carries. A malformed claim is an empty set, never an exception. */
	static List<Proof> proofsOf(TokenWrapper token) {
		String json = token.getCustomField(CLAIM_PROOFS);
		if (json == null || json.isEmpty()) {
			return List.of();
		}
		try {
			return decode(JsonParser.parseString(json).getAsJsonArray());
		} catch (RuntimeException e) {
			return List.of();
		}
	}

	/** The JSON array the {@link #CLAIM_PROOFS} claim carries. */
	static String encode(List<Proof> proofs) {
		JsonArray array = new JsonArray();
		for (Proof proof : proofs) {
			JsonObject o = new JsonObject();
			o.addProperty("idp_id", proof.idpId());
			o.addProperty("sub", proof.providerSubject());
			o.addProperty("auth_time", proof.authTime());
			o.addProperty("exp", proof.exp());
			JsonArray tenants = new JsonArray();
			proof.tenants().forEach(tenants::add);
			o.add("tenants", tenants);
			try {
				o.add("claims", JsonParser.parseString(JsonFormat.printer().print(proof.claims())));
			} catch (com.google.protobuf.InvalidProtocolBufferException e) {
				throw new IllegalStateException("claims struct could not be serialized", e);
			}
			array.add(o);
		}
		return array.toString();
	}

	private static List<Proof> decode(JsonArray array) {
		List<Proof> proofs = new ArrayList<>(array.size());
		for (JsonElement element : array) {
			JsonObject o = element.getAsJsonObject();
			List<String> tenants = new ArrayList<>();
			for (JsonElement t : o.getAsJsonArray("tenants")) {
				tenants.add(t.getAsString());
			}
			Struct.Builder claims = Struct.newBuilder();
			if (o.has("claims")) {
				try {
					JsonFormat.parser().merge(o.get("claims").toString(), claims);
				} catch (com.google.protobuf.InvalidProtocolBufferException e) {
					throw new IllegalArgumentException("proof claims are not a JSON object", e);
				}
			}
			proofs.add(new Proof(
					o.get("idp_id").getAsString(),
					o.get("sub").getAsString(),
					o.get("auth_time").getAsLong(),
					o.get("exp").getAsLong(),
					List.copyOf(tenants),
					claims.build()));
		}
		return proofs;
	}

	/**
	 * The union of two proof sets, deduplicated by (idp_id, provider_subject)
	 * keeping the fresher {@code auth_time}. Order: {@code base} first, then what
	 * {@code more} adds.
	 */
	static List<Proof> merge(List<Proof> base, List<Proof> more) {
		List<Proof> merged = new ArrayList<>(base);
		for (Proof candidate : more) {
			int existing = -1;
			for (int i = 0; i < merged.size(); i++) {
				if (merged.get(i).sameIdentity(candidate.idpId(), candidate.providerSubject())) {
					existing = i;
					break;
				}
			}
			if (existing < 0) {
				merged.add(candidate);
			} else if (candidate.authTime() > merged.get(existing).authTime()) {
				merged.set(existing, candidate);
			}
		}
		return merged;
	}
}
