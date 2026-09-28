// Copyright (c) 2026 Second Star Cavalier, LLC.
package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.authz.InMemoryManager;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.key.ImmutableKey;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.servicemanager.Auth;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.token.TokenWrapper;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.s2sm.internal.grpc.servers.services.kernel.TenantAdmin;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.common.credentials.Credentials;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.entitlements.Entitlements;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.TenantAdminGrpc;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.jwk.JwkOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;
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
 * F9 — the {@code Caller} the generated wrapper hands a handler must be the
 * authenticated caller, so handler-side identity guards are live code.
 *
 * <p>Drives real gRPC calls against the real generated {@link TenantAdmin}
 * wrapper behind the real chassis {@code Authorizer}, wired exactly as
 * {@code ClusterServer} wires it in production
 * ({@code Auth.requestIdInterceptor()} + {@code Authorizer.headerCaptureInterceptor()} +
 * the wrapper's own {@code checkAuth}), with real kernel-signed cred_pair
 * tokens of the shape {@code IdentityServiceImpl.MintClientToken} mints.
 *
 * <p>The RPC under test is {@code UpdateTenantConfig} and the control is
 * {@code TenantAdminServiceImpl}'s Invariant 3 (self-lockout guard): a tenant
 * admin must not be able to write a config that drops its own cred_pair.
 */
class TenantAdminSelfLockoutTest {

	private static final String TENANT_NS = "/tenants/acme";
	private static final String CALLER_CRED_PAIR = "cp-admin";
	private static final String OTHER_CRED_PAIR = "cp-other";
	private static final Metadata.Key<String> AUTHORIZATION =
			Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

	private final List<JwkOuterClass.Jwk> verifyingKeys = new CopyOnWriteArrayList<>();

	private KeyRotator keyRotator;
	private ConfigMap configMap;
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

		configMap = new ConfigMap(new InMemoryManager());
		seedTenant();

		var authorizer = new com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer(
				new LocalJwkSource(() -> verifyingKeys));
		TenantAdmin.registerMethodAuth(authorizer);

		var impl = new TenantAdminServiceImpl(configMap, () -> "test.schematic.io", () -> {});

		// Same interceptor stack ClusterServer installs in production: the
		// request-id interceptor, then Authorizer.headerCaptureInterceptor() which installs
		// the verified-token slot the wrapper reads the Caller from.
		server = ServerBuilder.forPort(0)
				.intercept(com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.grpcserver.Authorizer.headerCaptureInterceptor())
				.intercept(Auth.requestIdInterceptor())
				.addService(new TenantAdmin(impl, authorizer))
				.build()
				.start();
		channel = ManagedChannelBuilder.forAddress("localhost", server.getPort())
				.usePlaintext()
				.build();
	}

	@AfterEach
	void tearDown() throws Exception {
		channel.shutdownNow();
		server.shutdownNow();
		server.awaitTermination(5, TimeUnit.SECONDS);
		keyRotator.stop();
	}

	/**
	 * The caller holds cp-admin and writes a config that keeps only cp-other.
	 * Invariants 1 and 2 both pass (entitlements are within the ceiling and the
	 * config still holds a TenantAdmin-capable cred_pair), so only the
	 * self-lockout guard stands between the caller and locking itself out.
	 */
	@Test
	void tenantAdminCannotWriteAConfigThatDropsItsOwnCredPair() {
		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> stub().updateTenantConfig(dropCallerRequest()));

		assertEquals(Status.Code.INVALID_ARGUMENT, e.getStatus().getCode());
		assertTrue(e.getStatus().getDescription().contains("self-lockout guard"),
				"description should name the guard, got: " + e.getStatus().getDescription());

		// And the write did not land: cp-admin is still in the stored config.
		assertTrue(storedCredPairIds().contains(CALLER_CRED_PAIR),
				"rejected write must not have been applied, stored ids: " + storedCredPairIds());
	}

	/** A rotation that retains the caller's own cred_pair is still allowed. */
	@Test
	void tenantAdminMayWriteAConfigThatRetainsItsOwnCredPair() {
		stub().updateTenantConfig(Kernel.SetTenantConfigRequest.newBuilder()
				.setTenantNamespace(TENANT_NS)
				.setConfig(configWith(CALLER_CRED_PAIR, "cp-fresh"))
				.build());

		assertTrue(storedCredPairIds().contains("cp-fresh"), "allowed write should land");
		assertTrue(storedCredPairIds().contains(CALLER_CRED_PAIR));
	}

	/**
	 * The guard reads the caller's subject out of the verified payload. A claim
	 * VALUE that is itself a JSON object containing a {@code "sub"} key must not
	 * be able to pass itself off as the top-level one — and with keys serialized
	 * in sorted order, a claim like {@code origin_profile} lands before
	 * {@code sub} in the payload, which is exactly what a scan for the first
	 * {@code "sub"} finds. Against the unfixed extractor the guard reads
	 * cp-other, sees it retained, and lets cp-admin lock itself out.
	 */
	@Test
	void aNestedSubInsideAClaimValueCannotSpoofTheGuard() {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + credPairToken(CALLER_CRED_PAIR, TENANT_NS,
				"{\"sub\":\"cred-pair:" + OTHER_CRED_PAIR + "\"}"));

		StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
				() -> TenantAdminGrpc.newBlockingStub(channel)
						.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
						.updateTenantConfig(dropCallerRequest()));

		assertEquals(Status.Code.INVALID_ARGUMENT, e.getStatus().getCode(),
				"description was: " + e.getStatus().getDescription());
		assertTrue(e.getStatus().getDescription().contains(CALLER_CRED_PAIR),
				"the guard must still name the real subject, got: " + e.getStatus().getDescription());
		assertTrue(storedCredPairIds().contains(CALLER_CRED_PAIR),
				"rejected write must not have been applied, stored ids: " + storedCredPairIds());
	}

	/**
	 * The Caller is the authenticated caller, not just any caller: an admin
	 * acting from ABOVE the tenant (root namespace, cred_pair not in this
	 * tenant) is exempt from the guard and may drop cp-admin.
	 */
	@Test
	void ancestorAdminActingFromAboveIsExemptFromTheGuard() {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + credPairToken("cp-root", "/"));
		TenantAdminGrpc.newBlockingStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
				.updateTenantConfig(dropCallerRequest());

		assertTrue(!storedCredPairIds().contains(CALLER_CRED_PAIR),
				"ancestor's write should land, stored ids: " + storedCredPairIds());
	}

	// ------------------------------------------------------------------
	// fixture
	// ------------------------------------------------------------------

	private TenantAdminGrpc.TenantAdminBlockingStub stub() {
		Metadata headers = new Metadata();
		headers.put(AUTHORIZATION, "Bearer " + credPairToken(CALLER_CRED_PAIR, TENANT_NS));
		return TenantAdminGrpc.newBlockingStub(channel)
				.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));
	}

	/**
	 * Mints a kernel-signed C2S cred_pair token in exactly the shape
	 * {@code IdentityServiceImpl.MintClientToken} produces: subject
	 * {@code cred-pair:<id>}, a {@code namespace} claim, and flat
	 * service_entitlements.
	 */
	private String credPairToken(String credPairId, String namespace) {
		return credPairToken(credPairId, namespace, null);
	}

	/**
	 * @param nestedClaimJson when non-null, a claim whose value is a JSON OBJECT,
	 *                        keyed so it sorts ahead of {@code sub} in the payload
	 */
	private String credPairToken(String credPairId, String namespace, String nestedClaimJson) {
		ImmutableKey signingKey = keyRotator.getActiveSigningKey(KeyRotator.SigAlg.ED25519);
		long now = Instant.now().getEpochSecond();
		TokenWrapper t = TokenWrapper.create()
				.setIssuer("https://kernel.test/oidc")
				.setSubject("cred-pair:" + credPairId)
				.setAudience("kernel")
				.setIssuedAt(now)
				.setExpiration(now + 3600)
				.setJTI(UUID.randomUUID().toString());
		t.setNamespace(namespace);
		if (nestedClaimJson != null) {
			t.setCustomField("origin_profile", nestedClaimJson);
		}
		t.setServiceEntitlements(tenantAdminEntitlements());
		t.sign(signingKey);
		return t.getBase64();
	}

	private static Entitlements.TokenEntitlements tenantAdminEntitlements() {
		return Entitlements.TokenEntitlements.newBuilder()
				.addGrants("KERNEL_TENANT_ADMIN_UPDATE_TENANT_CONFIG")
				.addGrants("KERNEL_TENANT_ADMIN_GET_TENANT_CONFIG")
				.build();
	}

	private Kernel.SetTenantConfigRequest dropCallerRequest() {
		return Kernel.SetTenantConfigRequest.newBuilder()
				.setTenantNamespace(TENANT_NS)
				.setConfig(configWith(OTHER_CRED_PAIR))
				.build();
	}

	private TenantConfigOuterClass.TenantConfig configWith(String... credPairIds) {
		Credentials.KernelTenantConfig.Builder kernel = Credentials.KernelTenantConfig.newBuilder();
		for (String id : credPairIds) {
			kernel.addCredPairs(credPair(id));
		}
		return TenantConfigOuterClass.TenantConfig.newBuilder().setKernel(kernel.build()).build();
	}

	private Credentials.CredPair credPair(String id) {
		return Credentials.CredPair.newBuilder()
				.setId(id)
				.setTenantName(TENANT_NS)
				.setPublicKey(verifyingKeys.get(0))
				.setEntitlements(tenantAdminEntitlements())
				.addNamespaces("*")
				.build();
	}

	private void seedTenant() throws Exception {
		configMap.putTenants(TENANT_NS, Kernel.Tenant.newBuilder()
				.setName("acme")
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.setConstraints(Kernel.Constraints.newBuilder()
						.setEntitlementsCeiling(TenantAdminServiceImpl.buildFullEntitlements())
						.build())
				.build());
		configMap.putTenantConfigs(TENANT_NS, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(TENANT_NS)
				.setConfig(configWith(CALLER_CRED_PAIR, OTHER_CRED_PAIR))
				.build());
	}

	private List<String> storedCredPairIds() {
		return configMap.getTenantConfigs(TENANT_NS).getConfig().getKernel().getCredPairsList()
				.stream().map(Credentials.CredPair::getId).toList();
	}
}
