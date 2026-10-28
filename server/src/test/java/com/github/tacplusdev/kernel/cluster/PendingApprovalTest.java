// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0
package com.github.tacplusdev.kernel.cluster;

import com.github.tacplusdev.kernel.authz.InMemoryManager;
import com.github.tacplusdev.kernel.model.chassis.key.ImmutableKey;
import com.github.tacplusdev.kernel.model.chassis.servicemanager.Caller;
import com.github.tacplusdev.kernel.model.chassis.spiffe.Spiffe;
import com.github.tacplusdev.kernel.model.chassis.token.TokenWrapper;
import com.github.tacplusdev.kernel.model.s2sm.internal.grpc.clients.vservices.userentitlements.OpaEvalGrpcClient;
import com.github.tacplusdev.kernel.model.types.generated.entitlements.Entitlements;
import com.github.tacplusdev.kernel.model.types.services.kernel.Kernel;
import com.github.tacplusdev.kernel.model.types.sys.errors.ProtoException;
import com.github.tacplusdev.kernel.model.types.sys.jwk.JwkOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.key.KeyOuterClass;
import com.github.tacplusdev.kernel.model.types.sys.tokenrequest.Tokenrequest;
import com.github.tacplusdev.kernel.model.types.vservices.userentitlements.Userentitlements;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.ConfigMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.PrincipalMap;
import com.github.tacplusdev.kernel.tacplusbackend.services.kernel.WorkloadMap;
import com.google.protobuf.ByteString;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * §5 of the identity decision doc: the pending-approval record and the check
 * tacplus's generated {@code (spec.rpc).requires_device} will call.
 *
 * <p>The claim under test is narrow and absolute: <b>only</b> a device of the
 * caller's person — a credential on their XID, {@code Person.devices} — can
 * consume an approval, and <b>only</b> for the exact request it was created for.
 * So most of this class is refusals, and the two that matter most are
 * {@link #anApprovalCannotBeSpentOnASameShapedDifferentRequest()} and
 * {@link #aDeviceOfSomebodyElseCannotApprove()} — a browser session or
 * a delegated agent token can BE the user, which is precisely why being the user
 * is not what this check tests.
 *
 * <p>The setup is the real §3 ceremony, not a hand-seeded registry: the person
 * and the device enrolled on their XID exist because a passkey and an Apple
 * login proved them, through {@code CreateTenantUserLink}. No link registry is
 * consulted (kernel#18): the device is checked against the XID directly.
 */
class PendingApprovalTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final String KERNEL_AUDIENCE = "schematic-kernel";
	private static final String ISSUER = "https://kernel.test/oidc";
	private static final String BROKER_NAME = "device-broker";
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String APPLE_SUB = "001672.9c4f1a33be7d4e1fb0c2.0913";
	private static final String OTHER_APPLE_SUB = "001672.aaaaaaaaaaaaaaaaaaaa.0913";
	private static final String TENANT_NAMESPACE = "/tenants/drpepper";
	private static final Caller CALLER = new Caller("", "test-req");

	/** The RPC being approved, in the form the platform identifies an RPC by. */
	private static final String RPC_METHOD = "profile.Profile/UpdateRuleNode";

	/** The relying party this deployment serves, and the one the passkey signs for. */
	private static final String RP_ID = "example.test";
	private static final String ORIGIN = "https://example.test";
	private static final WebauthnProof.RelyingParty RELYING_PARTY =
			WebauthnProof.RelyingParty.of(RP_ID, java.util.Set.of(ORIGIN));

	private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();
	private final List<Kernel.Delegate> delegates = new ArrayList<>();
	private KeyRotator keyRotator;
	private PrincipalMap principalMap;
	private final ConfigMap configMap = new ConfigMap(new InMemoryManager());
	private IdentityServiceImpl svc;
	private PersonalIdentityServiceImpl personalIdentity;
	private Passkey passkey;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(
				3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();
		delegates.add(delegate(PeopleTenant.NAMESPACE,
				Tokenrequest.AuthBrokerKind.AUTH_BROKER_KIND_DEVICE));
		principalMap = new PrincipalMap(new InMemoryManager());
		svc = new IdentityServiceImpl(
				3600, 900, 86_400, 86_400, 86_400,
				keyRotator,
				() -> verifyingKeys,
				() -> delegates,
				List::of,
				g -> { },
				null,            // serviceEntitlements
				null,            // signingCa
				name -> null,    // serviceCaReader
				(name, chain) -> { }, // serviceCaWriter
				() -> TRUST_DOMAIN,
				ISSUER,
				new FakeOpaEvalGrpcClient(),
				null,            // proxyPolicyOpaClient
				configMap,
				new WorkloadMap(new InMemoryManager()),
				principalMap,
				null,            // writeIdentitySnapshot
				null,            // kubernetesTokenVerifier
				KERNEL_AUDIENCE,
				RELYING_PARTY);
		personalIdentity = new PersonalIdentityServiceImpl(principalMap);
		passkey = Passkey.generate();
		// The §3 ceremony: this passkey and this Apple login become a person with
		// this device enrolled on their XID.
		link(passkey, APPLE_SUB);
	}

	// ------------------------------------------------------------------
	// The primitive working
	// ------------------------------------------------------------------

	/**
	 * The slice in one test. The person proposes; the device taps; kernel says who
	 * approved and with what, and burns the approval.
	 *
	 * <p>Note what the device signs: the challenge kernel returned, which is a
	 * digest over the approval id, the RPC and the request hash. The tap is
	 * therefore a statement about a specific call, not a general "yes".
	 */
	@Test
	void aLinkedDeviceApprovesTheExactRequestItWasAskedAbout() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		Kernel.BrokerPendingApprovalResponse approved = approve(proposed, hash, personCaller());

		assertTrue(approved.getConsumedAtMs() > 0);
		assertEquals(personKey(), approved.getPersonUserKey());
		assertEquals(passkey.credentialId, approved.getDeviceCredentialId());
		// The record is burned in place, not deleted: a replay inside the window
		// has to be answerable as "already used".
		assertEquals(approved.getConsumedAtMs(),
				principalMap.getPendingApprovals(proposed.getApprovalId()).getConsumedAtMs());
	}

	/**
	 * The challenge is kernel's, and it covers the whole approval. Signing
	 * anything else — here the digest for a second, otherwise identical proposal —
	 * is not a tap on this one.
	 */
	@Test
	void anAssertionOverAnotherApprovalsChallengeIsRefused() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse first = propose(personCaller(), hash);
		Kernel.CreatePendingApprovalResponse second = propose(personCaller(), hash);
		assertNotEquals(first.getChallenge(), second.getChallenge(),
				"two approvals of the same request must not share a challenge");

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(first.getApprovalId(), RPC_METHOD, hash, personCaller(),
						passkey.assertFor(second.getChallenge()))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals(0, principalMap.getPendingApprovals(first.getApprovalId()).getConsumedAtMs());
	}

	/** A device can only prove a tap with the private half. */
	@Test
	void aTamperedSignatureApprovesNothing() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);
		Kernel.WebauthnAssertion good = passkey.assertFor(proposed.getChallenge());
		byte[] tampered = good.getSignature().toByteArray();
		tampered[0] ^= 0x01;

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(),
						good.toBuilder().setSignature(ByteString.copyFrom(tampered)).build())));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals(0, principalMap.getPendingApprovals(proposed.getApprovalId())
				.getConsumedAtMs());
	}

	// ------------------------------------------------------------------
	// THE EXACT-REQUEST PIN
	// ------------------------------------------------------------------

	/**
	 * The pin, and the reason the record holds a hash at all. The human approved
	 * "transfer 5"; the request that arrives is the same RPC, the same person, the
	 * same device, the same live approval — and one field different. It must not
	 * go through.
	 *
	 * <p>Both halves of the defence are exercised here at once: the hash the
	 * generated check presents is compared against the record, and it is also
	 * inside the challenge the device signed, so the assertion built for the
	 * approved request cannot cover this one either.
	 */
	@Test
	void anApprovalCannotBeSpentOnASameShapedDifferentRequest() throws Exception {
		byte[] approvedHash = requestHash("transfer 5 to alice");
		byte[] otherHash = requestHash("transfer 5000 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), approvedHash);
		Kernel.WebauthnAssertion tap = passkey.assertFor(proposed.getChallenge());

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, otherHash, personCaller(), tap)));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		// WHICH check refused matters as much as that one did: the hash comparison
		// against the record, not an incidental signature failure. Both would say
		// PERMISSION_DENIED, and only one of them is the pin this test is about.
		assertTrue(ex.getMessage().contains("different request"), ex.getMessage());
		// Still live: a refused attempt must not burn somebody's approval either.
		assertEquals(0, principalMap.getPendingApprovals(proposed.getApprovalId())
				.getConsumedAtMs());
		// And the approved request still goes through, which is what proves the
		// refusal above was about the hash and not about the assertion being stale.
		assertTrue(approve(proposed, approvedHash, personCaller()).getConsumedAtMs() > 0);
	}

	/**
	 * A device signature is not transferable between RPCs either. An approval for
	 * one method presented against another is refused even when everything else —
	 * person, device, hash, expiry — lines up.
	 */
	@Test
	void anApprovalCannotBeSpentOnADifferentRpc() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), "profile.Profile/DeleteRuleNode", hash,
						personCaller(), passkey.assertFor(proposed.getChallenge()))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	// ------------------------------------------------------------------
	// THE RELYING-PARTY CHECK
	// ------------------------------------------------------------------

	/**
	 * §5's approval has no second half — the challenge is all the device signs —
	 * so the relying-party check is the only thing standing between a phishing
	 * page that learned a live challenge and a real approval. The assertion here
	 * is genuine and its challenge is this approval's; it was simply produced for
	 * another domain.
	 */
	@Test
	void anAssertionProducedForAnotherRelyingPartyApprovesNothing() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(),
						passkey.assertFor(proposed.getChallenge(), "attacker.test", ORIGIN))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("different relying party"), ex.getMessage());
		assertEquals(0, principalMap.getPendingApprovals(proposed.getApprovalId())
				.getConsumedAtMs());
	}

	/**
	 * The origin half, and the approval is not burned by the attempt: a refused
	 * tap must leave the person able to approve from the real page.
	 */
	@Test
	void anAssertionCollectedFromAnotherOriginApprovesNothing() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(),
						passkey.assertFor(proposed.getChallenge(), RP_ID,
								"https://phish.example.test"))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertTrue(ex.getMessage().contains("origin this deployment does not serve"),
				ex.getMessage());

		// And the real page still works, which is what proves the refusal was
		// about the origin and not about the approval having been spent.
		assertEquals(0, principalMap.getPendingApprovals(proposed.getApprovalId())
				.getConsumedAtMs());
		Kernel.BrokerPendingApprovalResponse ok = brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(),
						passkey.assertFor(proposed.getChallenge())));
		assertTrue(ok.getConsumedAtMs() > 0);
	}

	// ------------------------------------------------------------------
	// THE DEVICE-OWNERSHIP CHECK
	// ------------------------------------------------------------------

	/**
	 * "Signed by a key of the caller's person. Nothing else counts." This device
	 * is real, enrolled, and holds a live credential — it is simply somebody
	 * else's. Its signature verifies and it still approves nothing.
	 *
	 * <p>This is the test that separates §5 from "a valid WebAuthn assertion". A
	 * check that verified the signature and stopped would pass this.
	 */
	@Test
	void aDeviceOfSomebodyElseCannotApprove() throws Exception {
		Passkey stranger = Passkey.generate();
		link(stranger, OTHER_APPLE_SUB);
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(),
						stranger.assertFor(proposed.getChallenge()))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		// The ownership check refused it, not the signature — the stranger's
		// assertion is perfectly valid, which is the whole point of this test.
		assertTrue(ex.getMessage().contains("not one of the devices of the person"), ex.getMessage());
		assertEquals(0, principalMap.getPendingApprovals(proposed.getApprovalId())
				.getConsumedAtMs());
	}

	/**
	 * Removing a device withdraws the ability to approve, at the very next
	 * attempt: the credential is marked revoked on the person and its perfectly
	 * good signature approves nothing.
	 */
	@Test
	void aRevokedDeviceCannotApprove() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);
		Kernel.WebauthnAssertion tap = passkey.assertFor(proposed.getChallenge());
		new KernelIdentityGraph(principalMap, () -> { }, () -> false)
				.revokeDevice(xid(APPLE_SUB), passkey.credentialId);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(), tap)));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		assertEquals("device approval refused", ex.getMessage());
		assertEquals(0, principalMap.getPendingApprovals(proposed.getApprovalId()).getConsumedAtMs());
	}

	/** A credential kernel has never seen is refused, and says nothing about why. */
	@Test
	void anUnregisteredDeviceCannotApprove() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(),
						Passkey.generate().assertFor(proposed.getChallenge()))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	/**
	 * The approval belongs to the person who proposed it, and the guarded service
	 * reports which of its users it is serving. A second person's call cannot
	 * spend the first person's approval even holding its id.
	 */
	@Test
	void anotherPersonsCallCannotSpendThisApproval() throws Exception {
		Passkey stranger = Passkey.generate();
		link(stranger, OTHER_APPLE_SUB);
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash,
						personCaller(OTHER_APPLE_SUB), passkey.assertFor(proposed.getChallenge()))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	// ------------------------------------------------------------------
	// The record's own lifecycle
	// ------------------------------------------------------------------

	/**
	 * Single-use. A guarded RPC need not be idempotent, so a captured assertion
	 * must not be able to make the same approved transfer twice.
	 */
	@Test
	void anApprovalIsSingleUse() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		Kernel.CreatePendingApprovalResponse proposed = propose(personCaller(), hash);
		Kernel.WebauthnAssertion tap = passkey.assertFor(proposed.getChallenge());

		assertTrue(brokerCall(brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash,
				personCaller(), tap)).getConsumedAtMs() > 0);

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, personCaller(), tap)));
		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	/**
	 * An approval nobody answered in time is not an approval. The expiry is
	 * checked on consumption rather than only swept, so a row the sweep has not
	 * reached yet is still dead.
	 *
	 * <p>The row is written directly here because the RPC will not mint an
	 * already-expired one — the TTL floor is deliberate.
	 */
	@Test
	void anExpiredApprovalCannotBeConsumed() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		String approvalId = UUID.randomUUID().toString();
		long past = System.currentTimeMillis() - 1000;
		principalMap.putPendingApprovals(approvalId, Kernel.PendingApproval.newBuilder()
				.setApprovalId(approvalId)
				.setPersonUserKey(personKey())
				.setRpcMethod(RPC_METHOD)
				.setRequestHash(ByteString.copyFrom(hash))
				.setCreatedAtMs(past - 1000)
				.setExpiresAtMs(past)
				.build());

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(approvalId, RPC_METHOD, hash, personCaller(),
						passkey.assertFor(WebauthnProof.approvalBinding(
								approvalId, RPC_METHOD, hash)))));

		assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
	}

	/** An id nothing has ever minted is NOT_FOUND, and enumerates nothing. */
	@Test
	void anUnknownApprovalIdIsNotFound() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");
		String approvalId = UUID.randomUUID().toString();

		ProtoException ex = assertThrows(ProtoException.class, () -> brokerCall(
				brokerRequest(approvalId, RPC_METHOD, hash, personCaller(),
						passkey.assertFor(WebauthnProof.approvalBinding(
								approvalId, RPC_METHOD, hash)))));

		assertEquals(ProtoException.NOT_FOUND, ex.getCode());
	}

	/**
	 * The cleanup story: creating an approval sweeps the expired ones. There is no
	 * timer to own and nothing to notice if one stopped running, and the registry
	 * stays proportional to what is actually outstanding.
	 */
	@Test
	void creatingAnApprovalSweepsTheExpiredOnes() throws Exception {
		String stale = UUID.randomUUID().toString();
		principalMap.putPendingApprovals(stale, Kernel.PendingApproval.newBuilder()
				.setApprovalId(stale)
				.setPersonUserKey(personKey())
				.setRpcMethod(RPC_METHOD)
				.setRequestHash(ByteString.copyFrom(requestHash("old")))
				.setCreatedAtMs(1)
				.setExpiresAtMs(2)
				.build());

		Kernel.CreatePendingApprovalResponse fresh =
				propose(personCaller(), requestHash("transfer 5 to alice"));

		assertEquals(1, principalMap.proto().getPendingApprovalsCount());
		assertEquals(fresh.getApprovalId(),
				principalMap.proto().getPendingApprovals(0).getApprovalId());
	}

	/**
	 * The TTL is kernel's. A proposer asking for a week gets the ceiling, because
	 * an approval that outlives the call it approves is a standing permission.
	 */
	@Test
	void aRequestedTtlIsCappedByKernel() throws Exception {
		long before = System.currentTimeMillis();
		Kernel.CreatePendingApprovalResponse proposed = personalIdentity.createPendingApproval(
				personCaller(), Kernel.CreatePendingApprovalRequest.newBuilder()
						.setRpcMethod(RPC_METHOD)
						.setRequestHash(ByteString.copyFrom(requestHash("transfer 5 to alice")))
						.setTtlSeconds(604_800)
						.build());

		assertTrue(proposed.getExpiresAtMs() <= before + 600_000 + 5_000,
				"a week-long TTL must come back as the ceiling, not as a week");
		assertTrue(proposed.getExpiresAtMs() > before);
	}

	// ------------------------------------------------------------------
	// Who may propose
	// ------------------------------------------------------------------

	/**
	 * The person is their XID in every tenant: the same person's token for an
	 * org tenant proposes as that person, and the people-tenant token — the one
	 * the device itself holds — consumes it. This is what makes "a browser or
	 * native app proposes" work for a caller standing in any tenant, with no link
	 * registry in between.
	 */
	@Test
	void thePersonsTokenInAnyTenantProposesAsThatPerson() throws Exception {
		byte[] hash = requestHash("transfer 5 to alice");

		Kernel.CreatePendingApprovalResponse proposed =
				propose(owner(TENANT_NAMESPACE, personSubject()), hash);

		assertEquals(personKey(),
				principalMap.getPendingApprovals(proposed.getApprovalId()).getPersonUserKey());
		assertTrue(approve(proposed, hash, personCaller()).getConsumedAtMs() > 0);
	}

	/**
	 * A caller who is not a person cannot propose at all — an ordinary tenant
	 * user, including one whose tenant-scoped subject happens to end in a
	 * person's XID. There is nobody to prompt and no device that could ever sign
	 * it, so the honest answer is a refusal at creation rather than a record
	 * nothing can consume.
	 */
	@Test
	void aCallerWhoIsNotAPersonCannotPropose() {
		for (Caller notAPerson : List.of(
				owner(TENANT_NAMESPACE, "jody@drpepper.example"),
				owner(TENANT_NAMESPACE, Spiffe.userSpiffeId(TRUST_DOMAIN, TENANT_NAMESPACE, xid(APPLE_SUB))))) {
			ProtoException ex = assertThrows(ProtoException.class, () -> propose(
					notAPerson, requestHash("transfer 5 to alice")));
			assertEquals(ProtoException.PERMISSION_DENIED, ex.getCode());
		}
	}

	/** A hash that is not a SHA-256 digest pins the approval to nothing. */
	@Test
	void aRequestHashThatIsNotASha256IsRefused() {
		ProtoException ex = assertThrows(ProtoException.class,
				() -> personalIdentity.createPendingApproval(personCaller(),
						Kernel.CreatePendingApprovalRequest.newBuilder()
								.setRpcMethod(RPC_METHOD)
								.setRequestHash(ByteString.copyFromUtf8("too short"))
								.build()));

		assertEquals(ProtoException.INVALID_ARGUMENT, ex.getCode());
	}

	// ------------------------------------------------------------------
	// Harness
	// ------------------------------------------------------------------

	private Kernel.CreatePendingApprovalResponse propose(Caller caller, byte[] hash)
			throws Exception {
		return personalIdentity.createPendingApproval(caller,
				Kernel.CreatePendingApprovalRequest.newBuilder()
						.setRpcMethod(RPC_METHOD)
						.setRequestHash(ByteString.copyFrom(hash))
						.build());
	}

	private Kernel.BrokerPendingApprovalResponse approve(
			Kernel.CreatePendingApprovalResponse proposed, byte[] hash, Caller caller)
			throws Exception {
		return brokerCall(brokerRequest(proposed.getApprovalId(), RPC_METHOD, hash, caller,
				passkey.assertFor(proposed.getChallenge())));
	}

	private Kernel.BrokerPendingApprovalRequest brokerRequest(String approvalId, String rpcMethod,
			byte[] hash, Caller servedUser, Kernel.WebauthnAssertion assertion) {
		return Kernel.BrokerPendingApprovalRequest.newBuilder()
				.setApprovalId(approvalId)
				.setRpcMethod(rpcMethod)
				.setRequestHash(ByteString.copyFrom(hash))
				.setCallerNamespace(servedUser.getNamespace())
				.setCallerSubject(servedUser.getSubject())
				.setDeviceAssertion(assertion)
				.build();
	}

	private Kernel.BrokerPendingApprovalResponse brokerCall(
			Kernel.BrokerPendingApprovalRequest request) throws Exception {
		return svc.brokerPendingApproval(CALLER, request);
	}

	/**
	 * A verified caller standing in one namespace as one subject. {@code Caller}
	 * wraps the VERIFIED TOKEN PAYLOAD, and both handlers read the minted
	 * {@code namespace} and {@code sub} claims straight out of it — the pair the
	 * link registry is keyed on.
	 */
	private static Caller owner(String namespace, String subject) {
		return new Caller("{\"sub\":\"" + subject + "\",\"namespace\":\"" + namespace + "\"}",
				"test-req");
	}

	private Caller personCaller() {
		return personCaller(APPLE_SUB);
	}

	private Caller personCaller(String appleSub) {
		return owner(PeopleTenant.NAMESPACE, personSubject(appleSub));
	}

	private String personSubject() {
		return personSubject(APPLE_SUB);
	}

	/** The person an Apple login resolved to, found through the link index. */
	private String personSubject(String appleSub) {
		return SpiffeIds.userSubject(TRUST_DOMAIN, xid(appleSub));
	}

	private String xid(String appleSub) {
		return principalMap.getIdentityLinks(IdentityServiceImpl.identityLinkKey("apple", appleSub)).getXid();
	}

	private String personKey() {
		return PeopleTenant.NAMESPACE + "|" + personSubject();
	}

	/**
	 * The §3 ceremony, for real: one passkey and one Apple login whose nonce is
	 * that key's thumbprint create the person and enrol the device on their XID.
	 */
	private void link(Passkey key, String appleSub) throws Exception {
		String nonce = WebauthnProof.thumbprint(key.publicJwk);
		Kernel.CreateTenantUserLinkRequest request = Kernel.CreateTenantUserLinkRequest.newBuilder()
				.setA(Kernel.TenantUserLinkSide.newBuilder()
						.setDeviceAssertion(key.assertFor(
								WebauthnProof.loginBinding(APPLE_ISSUER, appleSub, nonce)))
						.setDevicePublicKey(key.publicJwk)
						.setDeviceLabel("Jody's ThinkPad"))
				.setB(Kernel.TenantUserLinkSide.newBuilder()
						.setClaims(idpClaims(APPLE_ISSUER, appleSub, nonce))
						.setSubject("whatever-the-broker-says"))
				.build();
		io.grpc.Context ctx = io.grpc.Context.current().withValue(
				ClusterServer.RAW_AUTH_TOKEN_KEY, brokerToken());
		io.grpc.Context previous = ctx.attach();
		try {
			svc.createTenantUserLink(CALLER, request);
		} finally {
			ctx.detach(previous);
		}
	}

	private static Struct idpClaims(String issuer, String sub, String nonce) {
		return Struct.newBuilder()
				.putFields("origin_iss", Value.newBuilder().setStringValue(issuer).build())
				.putFields("origin_sub", Value.newBuilder().setStringValue(sub).build())
				.putFields("origin_nonce", Value.newBuilder().setStringValue(nonce).build())
				.build();
	}

	private static Kernel.Delegate delegate(String namespace, Tokenrequest.AuthBrokerKind kind) {
		return Kernel.Delegate.newBuilder()
				.setName(BROKER_NAME)
				.setTenantNamespace(namespace)
				.addAuthBrokerKinds(kind)
				.build();
	}

	/** The people tenant's own device broker: the only caller that may link. */
	private String brokerToken() {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		String subject = TenantServiceSubjects.of(configMap, TRUST_DOMAIN, PeopleTenant.NAMESPACE, BROKER_NAME);
		TokenWrapper t = TokenWrapper.create()
				.setIssuer(ISSUER)
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		return t.getBase64();
	}

	/** A SHA-256 over whatever a request's canonical bytes would be. */
	private static byte[] requestHash(String request) throws Exception {
		return MessageDigest.getInstance("SHA-256").digest(request.getBytes(StandardCharsets.UTF_8));
	}

	/** One passkey, as {@code DeviceWebauthnLinkTest}'s fixture builds one. */
	private static final class Passkey {
		private final String credentialId;
		private final PrivateKey privateKey;
		private final JwkOuterClass.Jwk publicJwk;

		private Passkey(String credentialId, PrivateKey privateKey, JwkOuterClass.Jwk publicJwk) {
			this.credentialId = credentialId;
			this.privateKey = privateKey;
			this.publicJwk = publicJwk;
		}

		static Passkey generate() throws Exception {
			String credentialId = B64.encodeToString(
					UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
			KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
			// Ed25519 X.509 encoding: the last 32 bytes are the raw public key.
			byte[] x509Encoded = pair.getPublic().getEncoded();
			byte[] rawPub = new byte[32];
			System.arraycopy(x509Encoded, x509Encoded.length - 32, rawPub, 0, 32);
			return new Passkey(credentialId, pair.getPrivate(), JwkOuterClass.Jwk.newBuilder()
					.setKid(credentialId)
					.setKty(KeyOuterClass.KeyType.KEY_TYPE_OKP)
					.setAlg("EdDSA")
					.setCrv("Ed25519")
					.setUse(JwkOuterClass.JwkUseType.JWK_USE_TYPE_SIG)
					.setX(B64.encodeToString(rawPub))
					.setCreated(Instant.now().getEpochSecond())
					.build());
		}

		/** A real assertion over the challenge given, as an authenticator produces. */
		Kernel.WebauthnAssertion assertFor(String challenge) throws Exception {
			return assertFor(challenge, RP_ID, ORIGIN);
		}

		/**
		 * The same assertion, but produced for the relying party named — the
		 * fixture a phished ceremony needs. Everything else is identical and the
		 * signature is real, so a test using it fails on the relying party or on
		 * nothing.
		 */
		Kernel.WebauthnAssertion assertFor(String challenge, String rpId, String origin)
				throws Exception {
			byte[] authenticatorData = new byte[37];
			System.arraycopy(sha256(rpId.getBytes(StandardCharsets.UTF_8)), 0,
					authenticatorData, 0, 32);
			authenticatorData[32] = 0x05;
			authenticatorData[36] = 0x01;

			byte[] clientDataJson = ("{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge
					+ "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}")
					.getBytes(StandardCharsets.UTF_8);

			byte[] signed = new byte[authenticatorData.length + 32];
			System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
			System.arraycopy(sha256(clientDataJson), 0, signed, authenticatorData.length, 32);

			Signature signer = Signature.getInstance("Ed25519");
			signer.initSign(privateKey);
			signer.update(signed);

			return Kernel.WebauthnAssertion.newBuilder()
					.setCredentialId(credentialId)
					.setAuthenticatorData(ByteString.copyFrom(authenticatorData))
					.setClientDataJson(ByteString.copyFrom(clientDataJson))
					.setSignature(ByteString.copyFrom(signer.sign()))
					.build();
		}

		private static byte[] sha256(byte[] input) throws Exception {
			return MessageDigest.getInstance("SHA-256").digest(input);
		}
	}

	/** Returns a canned EntitlementEvalResult; the channel throws if ever used. */
	private static class FakeOpaEvalGrpcClient extends OpaEvalGrpcClient {
		FakeOpaEvalGrpcClient() {
			super(UNUSABLE_CHANNEL, () -> "unused-token");
		}

		@Override
		public Userentitlements.EntitlementEvalResult evalEntitlement(
				Userentitlements.EntitlementEvalInput request) {
			return Userentitlements.EntitlementEvalResult.newBuilder()
					.setNamespace(TENANT_NAMESPACE)
					.setTokenEntitlements(Entitlements.TokenEntitlements.newBuilder().build())
					.build();
		}

		private static final Channel UNUSABLE_CHANNEL = new Channel() {
			@Override
			public <ReqT, RespT> ClientCall<ReqT, RespT> newCall(
					MethodDescriptor<ReqT, RespT> methodDescriptor, CallOptions callOptions) {
				throw new UnsupportedOperationException("fake channel must never be used");
			}

			@Override
			public String authority() {
				throw new UnsupportedOperationException("fake channel must never be used");
			}
		};
	}
}
