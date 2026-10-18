// Copyright (c) 2026 Seabeam LLC. All rights reserved.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.PersonalIdentity;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.PersonalIdentityGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.PrincipalMap;

import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Goal B item 2: {@code PersonalIdentity.GetMyIdentity}, end to end through the
 * real generated wrapper, the real {@link Authorizer} (kernel's LOCAL key
 * source) and the real generated {@link PrincipalMap} — the same three pieces
 * {@code ClusterServer} wires in production, so nothing here is more permissive
 * than the running kernel.
 *
 * <p>The security claim under test is that the RPC is self-scoped by
 * construction: {@code GetMyIdentityRequest} is empty and the principal comes
 * out of the verified token's {@code sub}, so principal A holding a valid,
 * correctly-signed token can never read principal B's row. Nothing mints a
 * {@code /people/<pid>} token yet, so the rows are seeded directly through the
 * generated state accessor.
 */
class PersonalIdentityGetMyIdentityTest {

	private static final String TRUST_DOMAIN = "test.schematic.io";
	private static final Metadata.Key<String> AUTHORIZATION =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	private Authorizer authorizer;
	private PrincipalMap principalMap;
	private Server server;
	private ManagedChannel channel;

	@BeforeEach
	void setUp() throws Exception {
		keyRotator = new KeyRotator(3600, 86_400,
				verifyingKeys::add,
				kid -> verifyingKeys.removeIf(j -> j.getKid().equals(kid)),
				() -> verifyingKeys,
				null);
		keyRotator.start();

		authorizer = new Authorizer(new LocalJwkSource(() -> verifyingKeys));
		principalMap = new PrincipalMap(new InMemoryManager());

		var wrapper = new PersonalIdentity(new PersonalIdentityServiceImpl(principalMap, null), authorizer);
		// The production authenticate func (see ClusterServer): token-only, which
		// is what auth_any_user means.
		wrapper.setAuthenticateFunc((PersonalIdentity.Authenticator) targetNamespace ->
				Authorizer.identityClaims(
						authorizer.authenticateWithToken(Authorizer.AUTH_HEADER_CTX_KEY.get())));

		server = ServerBuilder.forPort(0)
				.intercept(Authorizer.headerCaptureInterceptor())
				.addService(wrapper)
				.build()
				.start();
		channel = ManagedChannelBuilder.forAddress("localhost", server.getPort()).usePlaintext().build();
	}

	@AfterEach
	void tearDown() throws Exception {
		if (channel != null) {
			channel.shutdownNow();
		}
		if (server != null) {
			server.shutdownNow();
			server.awaitTermination(5, TimeUnit.SECONDS);
		}
		authorizer.close();
		keyRotator.stop();
	}

	// ========================================================================
	// Fixtures
	// ========================================================================

	/**
	 * Mints a valid, kernel-signed personal-principal token: subject
	 * {@code spiffe://<td>/people/<pid>/users/<pid>}, namespace
	 * {@code /people/<pid>}, exactly the pair the {@code /people} SPIFFE grammar
	 * produces. Nothing in the fleet mints one yet — this is the fixture that
	 * stands in for the mint arm, which is a separate item.
	 */
	private String personTokenFor(String principalId) {
		String namespace = "/" + Spiffe.PEOPLE_SEGMENT + "/" + principalId;
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(Spiffe.userSpiffeId(TRUST_DOMAIN, namespace, principalId))
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("user");
		t.setNamespace(namespace);
		t.sign(signingKey);
		return t.getBase64();
	}

	/** Mints a valid kernel-signed SERVICE token — a caller that is not a person. */
	private String serviceToken(String serviceName) {
		String subject = SpiffeIds.build(TRUST_DOMAIN, serviceName);
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject(subject)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setSubType("service");
		t.setServiceName(serviceName);
		t.setNamespace(Spiffe.namespaceFromSpiffe(subject));
		t.sign(signingKey);
		return t.getBase64();
	}

	private static ClientInterceptor bearer(String token) {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + token);
		return MetadataUtils.newAttachHeadersInterceptor(headers);
	}

	private static Kernel.TenantMembership membership(String tenantNamespace, boolean customer) {
		return Kernel.TenantMembership.newBuilder()
				.setTenantNamespace(tenantNamespace)
				.setProofKind(Kernel.MembershipProofKind.MEMBERSHIP_PROOF_KIND_TENANT_IDP)
				.setCustomer(customer)
				.setProofReference("idp-subject-" + tenantNamespace)
				.setCreatedAtMs(1_000)
				.build();
	}

	private void seed(String principalId, Kernel.TenantMembership... memberships) throws Exception {
		principalMap.putPersonalPrincipals(principalId, Kernel.PersonalPrincipal.newBuilder()
				.setPrincipalId(principalId)
				.addAllMemberships(List.of(memberships))
				.setCreatedAtMs(1_000)
				.build());
	}

	private Kernel.GetMyIdentityResponse getMyIdentityAs(String token) {
		return PersonalIdentityGrpc.newBlockingStub(channel)
				.withInterceptors(bearer(token))
				.getMyIdentity(Kernel.GetMyIdentityRequest.newBuilder().build());
	}

	// ========================================================================
	// Tests
	// ========================================================================

	@Test
	void returnsTheCallersOwnPrincipalIdAndMemberships() throws Exception {
		seed("p-alice", membership("/tenants/acme", false), membership("/tenants/globex", true));

		Kernel.GetMyIdentityResponse response = getMyIdentityAs(personTokenFor("p-alice"));

		assertEquals("p-alice", response.getPrincipalId());
		assertEquals(List.of("/tenants/acme", "/tenants/globex"),
				response.getMembershipsList().stream()
						.map(Kernel.TenantMembership::getTenantNamespace).toList());
		assertTrue(response.getMemberships(1).getCustomer());
		assertEquals(Kernel.MembershipProofKind.MEMBERSHIP_PROOF_KIND_TENANT_IDP,
				response.getMemberships(0).getProofKind());
	}

	@Test
	void aPrincipalWithNoRowIsNotFound() {
		// Registration is a separate item, so this is every caller today.
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> getMyIdentityAs(personTokenFor("p-nobody")));

		assertEquals(Status.Code.NOT_FOUND, e.getStatus().getCode());
	}

	@Test
	void aPrincipalNeverSeesAnotherPrincipalsRow() throws Exception {
		seed("p-alice", membership("/tenants/acme", false));
		seed("p-bob", membership("/tenants/initech", false));

		// Two valid, correctly-signed tokens; the ONLY difference is the subject,
		// and the request carries no principal field to point elsewhere.
		Kernel.GetMyIdentityResponse alice = getMyIdentityAs(personTokenFor("p-alice"));
		Kernel.GetMyIdentityResponse bob = getMyIdentityAs(personTokenFor("p-bob"));

		assertEquals("p-alice", alice.getPrincipalId());
		assertEquals(List.of("/tenants/acme"),
				alice.getMembershipsList().stream()
						.map(Kernel.TenantMembership::getTenantNamespace).toList());

		assertEquals("p-bob", bob.getPrincipalId());
		assertEquals(List.of("/tenants/initech"),
				bob.getMembershipsList().stream()
						.map(Kernel.TenantMembership::getTenantNamespace).toList());
	}

	@Test
	void revokedAndExpiredMembershipsAreNotReturned() throws Exception {
		long past = System.currentTimeMillis() - 60_000;
		long future = System.currentTimeMillis() + 3_600_000;
		seed("p-alice",
				membership("/tenants/live", false),
				membership("/tenants/revoked", false).toBuilder().setRevokedAtMs(past).build(),
				membership("/tenants/expired", false).toBuilder().setExpiresAtMs(past).build(),
				membership("/tenants/still-valid", false).toBuilder().setExpiresAtMs(future).build());

		Kernel.GetMyIdentityResponse response = getMyIdentityAs(personTokenFor("p-alice"));

		assertEquals(List.of("/tenants/live", "/tenants/still-valid"),
				response.getMembershipsList().stream()
						.map(Kernel.TenantMembership::getTenantNamespace).toList());
	}

	@Test
	void aServiceCallerIsRefused() throws Exception {
		seed("p-alice", membership("/tenants/acme", false));

		// A perfectly valid platform-service token. It authenticates, and then the
		// handler refuses it: only a person has a personal identity to read.
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> getMyIdentityAs(serviceToken("opa")));

		assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());
	}

	@Test
	void anUnauthenticatedCallerIsRefused() {
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> PersonalIdentityGrpc.newBlockingStub(channel)
						.getMyIdentity(Kernel.GetMyIdentityRequest.newBuilder().build()));

		assertEquals(Status.Code.UNAUTHENTICATED, e.getStatus().getCode());
	}
}
