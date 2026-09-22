// Copyright (c) 2026 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.cluster;

import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.chassis.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.schematic.services.kernel.model.types.sys.key.KeyOuterClass;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

/**
 * The WebAuthn (passkey) half of a device→person link: the two bindings kernel
 * checks and the signature it verifies. No ceremony state, no challenge store,
 * no network call — everything here is a pure function of the request.
 *
 * <p><b>Why kernel does this and not the broker.</b> {@code personalauth.proto}'s
 * header states the invariant the whole personal-login design rests on:
 * "compromising personalauth forges no personal identity". A broker that parsed
 * the assertion and told kernel whose device it was would make that false by
 * construction. So the broker relays four opaque fields, and kernel recomputes
 * the signed bytes, reads the challenge, and checks the signature itself.
 *
 * <p><b>The two bindings, and why they point in opposite directions.</b> §3 of
 * the identity decision doc requires one request that proves both halves and
 * cannot be assembled from two unrelated ceremonies:
 *
 * <ol>
 *   <li>The IdP's {@code nonce} is the device key's RFC 7638 thumbprint. The key
 *       exists before the login, so the login can name it. An id_token stolen
 *       from any other ceremony names some other key, and an attacker cannot
 *       obtain one naming a key they do not hold without completing an Apple or
 *       Google sign-in with that nonce.</li>
 *   <li>The assertion's {@code challenge} is {@link #loginBinding} of that exact
 *       login. The id_token exists before the assertion, so the assertion can
 *       name it. An assertion captured from any other ceremony carries a
 *       different challenge.</li>
 * </ol>
 *
 * <p>The two orderings are why the binding is not circular and why neither half
 * can be lifted onto another ceremony. Replaying the WHOLE request re-proves the
 * same link, which {@code recordLink} makes idempotent — the same position §2
 * took on the two-IdP proof, for the same reason.
 *
 * <p><b>What is deliberately NOT checked, and why.</b> The RP ID hash in
 * {@code authenticatorData} and the {@code origin} in {@code clientDataJSON} are
 * read by nothing here. Both are checks against a CONFIGURED relying party, and
 * the platform has no relying-party configuration to check them against — a
 * constant compiled into kernel would be a guess that silently locks out every
 * deployment whose origin differs. They are named as a follow-on in the slice's
 * decision doc rather than faked, and their absence costs less here than it
 * would in a password-replacement flow: an assertion obtained by a hostile
 * relying party is still useless without an id_token whose nonce is that key's
 * thumbprint.
 */
final class WebauthnProof {

	/** authenticatorData is rpIdHash(32) || flags(1) || signCount(4), at minimum. */
	private static final int MIN_AUTHENTICATOR_DATA_LENGTH = 37;

	/** Offset of the flags byte in authenticatorData. */
	private static final int FLAGS_OFFSET = 32;

	/** Flags bit 0: the authenticator verified the user was present. */
	private static final int FLAG_USER_PRESENT = 0x01;

	/** The clientDataJSON `type` of an assertion (a registration is "webauthn.create"). */
	private static final String ASSERTION_TYPE = "webauthn.get";

	/**
	 * Separator between the fields {@link #loginBinding} digests. 0x1f (ASCII
	 * unit separator) cannot appear in an issuer URL, an IdP subject or a nonce,
	 * so no two distinct logins can produce one input string.
	 */
	private static final byte FIELD_SEPARATOR = 0x1f;

	/**
	 * Domain tag on an approval binding, so it can never collide with a login
	 * binding. No IdP issuer is this string.
	 */
	private static final String APPROVAL_TAG = "schematic-pending-approval";

	private WebauthnProof() {
	}

	/** A proof that does not hold. The message never echoes any request value. */
	static final class Invalid extends Exception {
		Invalid(String message) {
			super(message);
		}
	}

	/**
	 * The value an id_token's {@code nonce} must carry to be bound to this key:
	 * its JWK thumbprint, RFC 7638.
	 *
	 * <p>The thumbprint rather than the whole key because a nonce is a short
	 * string in a URL, and rather than the credential id because the credential
	 * id is chosen by the authenticator and is not the thing the signature is
	 * checked against. RFC 7638 fixes both the member set and their order, so
	 * client and kernel cannot disagree about what "this key" hashes to.
	 */
	static String thumbprint(JwkOuterClass.Jwk key) throws Invalid {
		String json;
		switch (key.getKty()) {
			case KEY_TYPE_EC:
				json = "{\"crv\":\"" + member(key.getCrv()) + "\",\"kty\":\"EC\",\"x\":\""
						+ member(key.getX()) + "\",\"y\":\"" + member(key.getY()) + "\"}";
				break;
			case KEY_TYPE_OKP:
				json = "{\"crv\":\"" + member(key.getCrv()) + "\",\"kty\":\"OKP\",\"x\":\""
						+ member(key.getX()) + "\"}";
				break;
			case KEY_TYPE_RSA:
				json = "{\"e\":\"" + member(key.getE()) + "\",\"kty\":\"RSA\",\"n\":\""
						+ member(key.getN()) + "\"}";
				break;
			default:
				throw new Invalid("device key type is not one a thumbprint is defined for");
		}
		return base64Url(sha256(json.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * The value the assertion's {@code challenge} must carry to be bound to one
	 * IdP login: a digest over that login's issuer, subject and nonce.
	 *
	 * <p>Not the raw id_token, which kernel never sees — §2 settled that a broker
	 * relays the claims it verified and not the credential itself, and this path
	 * keeps that. The three claims together name one login of one account at one
	 * provider, which is all the binding has to pin down; the FRESHNESS of that
	 * login is the IdP's own, already checked by the broker against the token's
	 * {@code iat}/{@code exp}.
	 */
	static String loginBinding(String issuer, String subject, String nonce) {
		return binding(issuer.getBytes(StandardCharsets.UTF_8),
				subject.getBytes(StandardCharsets.UTF_8),
				nonce.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * The value an APPROVAL assertion's {@code challenge} must carry (identity
	 * decision doc §5): a digest over the pending approval's id, the RPC it
	 * approves, and the hash of the exact request.
	 *
	 * <p>All three, not just the id. The id alone would make the tap mean "I
	 * approve whatever this id turns out to be", and the whole point of §5 is
	 * that the device signature says WHAT was approved. The method and the hash
	 * are also checked against the record for equality by the handler; having
	 * them inside the signed challenge as well is what makes a
	 * same-shaped-but-different request fail even if that comparison were ever
	 * removed.
	 *
	 * <p>Tagged {@link #APPROVAL_TAG} so an approval binding and a login binding
	 * can never be the same digest: without it, a login whose issuer happened to
	 * be an approval id would produce a challenge an approval would accept.
	 */
	static String approvalBinding(String approvalId, String rpcMethod, byte[] requestHash) {
		return binding(APPROVAL_TAG.getBytes(StandardCharsets.UTF_8),
				approvalId.getBytes(StandardCharsets.UTF_8),
				rpcMethod.getBytes(StandardCharsets.UTF_8),
				base64Url(requestHash).getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * base64url(SHA-256(f0 || 0x1f || f1 || ...)). {@link #FIELD_SEPARATOR}
	 * appears in none of the values any caller passes, so no two distinct field
	 * lists can produce one input string.
	 */
	private static String binding(byte[]... fields) {
		int length = fields.length - 1;
		for (byte[] field : fields) {
			length += field.length;
		}
		byte[] input = new byte[length];
		int at = 0;
		for (int i = 0; i < fields.length; i++) {
			if (i > 0) {
				input[at++] = FIELD_SEPARATOR;
			}
			System.arraycopy(fields[i], 0, input, at, fields[i].length);
			at += fields[i].length;
		}
		return base64Url(sha256(input));
	}

	/**
	 * Verifies one assertion against one key and one expected challenge.
	 *
	 * <p>The signed bytes are recomputed here — {@code authenticatorData ||
	 * SHA-256(clientDataJSON)}, as the WebAuthn spec defines them — rather than
	 * taken from the request, so a broker cannot present a signature over
	 * something other than the data it also sent.
	 */
	static void verify(Kernel.WebauthnAssertion assertion, JwkOuterClass.Jwk key,
			String expectedChallenge) throws Invalid {
		byte[] authenticatorData = assertion.getAuthenticatorData().toByteArray();
		if (authenticatorData.length < MIN_AUTHENTICATOR_DATA_LENGTH) {
			throw new Invalid("authenticator data is too short to be a WebAuthn assertion");
		}
		if ((authenticatorData[FLAGS_OFFSET] & FLAG_USER_PRESENT) == 0) {
			throw new Invalid("the authenticator did not record user presence");
		}

		byte[] clientDataJson = assertion.getClientDataJson().toByteArray();
		JsonObject clientData;
		try {
			clientData = JsonParser.parseString(new String(clientDataJson, StandardCharsets.UTF_8))
					.getAsJsonObject();
		} catch (RuntimeException e) {
			throw new Invalid("client data is not a JSON object");
		}
		if (!ASSERTION_TYPE.equals(stringMember(clientData, "type"))) {
			throw new Invalid("client data is not a WebAuthn assertion");
		}
		// THE BINDING. Everything else in this method is WebAuthn hygiene; this
		// line is what says the assertion and the IdP login belong together.
		if (!expectedChallenge.equals(stringMember(clientData, "challenge"))) {
			throw new Invalid("the assertion's challenge does not name the presented login");
		}

		byte[] signed = new byte[authenticatorData.length + 32];
		System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
		System.arraycopy(sha256(clientDataJson), 0, signed, authenticatorData.length, 32);

		try {
			Signature verifier = Signature.getInstance(signatureAlgorithm(key));
			verifier.initVerify(ImmutableJwk.from(key).getPublicKey());
			verifier.update(signed);
			if (!verifier.verify(assertion.getSignature().toByteArray())) {
				throw new Invalid("the assertion's signature does not verify");
			}
		} catch (Invalid e) {
			throw e;
		} catch (Exception e) {
			throw new Invalid("the assertion's signature could not be checked");
		}
	}

	/**
	 * The JCA algorithm for a key, chosen from the KEY TYPE AND CURVE rather than
	 * from the JWK's {@code alg} string. A caller-supplied {@code alg} is an
	 * attacker-supplied choice of verification algorithm; the key's own shape is
	 * not.
	 */
	private static String signatureAlgorithm(JwkOuterClass.Jwk key) throws Invalid {
		if (key.getKty() == KeyOuterClass.KeyType.KEY_TYPE_OKP) {
			return "Ed25519";
		}
		if (key.getKty() == KeyOuterClass.KeyType.KEY_TYPE_RSA) {
			return "SHA256withRSA";
		}
		if (key.getKty() == KeyOuterClass.KeyType.KEY_TYPE_EC) {
			switch (key.getCrv()) {
				case "P-256":
					return "SHA256withECDSA";
				case "P-384":
					return "SHA384withECDSA";
				case "P-521":
					return "SHA512withECDSA";
				default:
					throw new Invalid("device key curve is not one WebAuthn defines");
			}
		}
		throw new Invalid("device key type is not one WebAuthn defines");
	}

	/**
	 * One RFC 7638 member value, rejected if it could break out of the canonical
	 * JSON the thumbprint is taken over. Every member RFC 7638 names is either
	 * base64url ({@code e}, {@code n}, {@code x}, {@code y}) or a registered
	 * curve name, none of which contains a quote or a backslash — so this never
	 * fires on a real key, and a key that does trip it is one whose thumbprint
	 * would otherwise be ambiguous.
	 */
	private static String member(String value) throws Invalid {
		if (value.isEmpty()) {
			throw new Invalid("device key is missing a member its thumbprint is taken over");
		}
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == '"' || c == '\\' || c < 0x20) {
				throw new Invalid("device key member is not a legal JWK value");
			}
		}
		return value;
	}

	private static String stringMember(JsonObject object, String name) {
		try {
			return object.get(name).getAsString();
		} catch (RuntimeException e) {
			return null;
		}
	}

	private static byte[] sha256(byte[] input) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(input);
		} catch (Exception e) {
			// SHA-256 is mandatory in every JRE; an absence here is not recoverable
			// and is not a caller error.
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}

	private static String base64Url(byte[] input) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
	}
}
