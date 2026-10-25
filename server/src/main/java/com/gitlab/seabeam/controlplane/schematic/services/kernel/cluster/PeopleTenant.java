// Copyright (c) 2026 Seabeam LLC. All rights reserved.

package com.gitlab.seabeam.controlplane.schematic.services.kernel.cluster;

import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.chassis.spiffe.Spiffe;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.generated.tenant_config.TenantConfigOuterClass;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.kernel.Kernel;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.services.oauth.Oauth;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.model.types.sys.errors.ProtoException;
import com.gitlab.seabeam.controlplane.schematic.services.kernel.tacplusbackend.services.kernel.ConfigMap;

import com.google.protobuf.Timestamp;
import java.time.Instant;
import java.util.List;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The reserved {@code people} tenant: the one deliberate special case in the
 * namespace tree, stated here rather than hidden.
 *
 * <p>It is the DEFAULT tenant: every person ({@code spiffe://<td>/users/<xid>})
 * is a member from first login, and a person's personal token is this tenant's
 * access token. Everything about the tenant except three things is ordinary.
 * The three:
 *
 * <ol>
 *   <li><b>The platform knows it exists ahead of time.</b> Kernel creates the
 *       tenant record and its oauth config slice at every boot
 *       ({@link #seed}); no operator creates it through {@code TenantAdmin},
 *       which refuses the name.</li>
 *   <li><b>Its IdP set is fixed.</b> Apple and Google, and only those. A
 *       deployment supplies client credentials; the issuer URL comes from
 *       {@link #issuerUrl} here, so there is no configuration that could point
 *       the tenant at a third issuer.</li>
 *   <li><b>It has no admin.</b> Nothing seeds a cred_pair into its
 *       TenantConfig, and {@code TenantAdmin.SetTenantConfig} refuses the
 *       namespace, so no token is ever entitled to administer it.</li>
 * </ol>
 *
 * <p>Decision record: {@code identity-session-credential-2026-10-25}, which
 * replaces the provider-keyed user row of
 * {@code identity-people-tenant-devices-private-2026-09-21} §1 with the XID.
 * Both supersede the {@code /people/<principal_id>} root the device path
 * ({@code PersonalPrincipal}) still uses; that path moves in the record's step 4.
 */
final class PeopleTenant {

	private static final Logger logger = LoggerFactory.getLogger(PeopleTenant.class);

	/** The tenant's leaf name — reserved fleet-wide. */
	static final String NAME = "people";

	/** The canonical namespace every person's SPIFFE id is rooted at. */
	static final String NAMESPACE = "/" + Spiffe.TENANTS_SEGMENT + "/" + NAME;

	/**
	 * The two fixed issuers. A login whose verified {@code origin_iss} is not one
	 * of these is refused at the mint, so "the IdP set is fixed" holds even if a
	 * broker is somehow configured with a third provider.
	 */
	private static final String APPLE_ISSUER = "https://appleid.apple.com";
	private static final String GOOGLE_ISSUER = "https://accounts.google.com";

	/**
	 * The scopes the tenant requests from both providers: OIDC's own minimum.
	 * {@code openid} is what makes the response an id_token at all, and
	 * {@code email} is what lets a person recognise which account they used. The
	 * {@code sub} this tenant keys people on is in every id_token regardless.
	 */
	private static final List<String> SCOPES = List.of("openid", "email");

	private PeopleTenant() {
	}

	/** The fixed issuer URL for {@code provider}, or null if the enum value names none. */
	@Nullable
	static String issuerUrl(Kernel.PeopleIdpProvider provider) {
		return switch (provider) {
			case PEOPLE_IDP_PROVIDER_APPLE -> APPLE_ISSUER;
			case PEOPLE_IDP_PROVIDER_GOOGLE -> GOOGLE_ISSUER;
			default -> null;
		};
	}

	/** The provider whose fixed issuer is {@code issuer}, or null if it is neither. */
	@Nullable
	static Kernel.PeopleIdpProvider providerForIssuer(String issuer) {
		if (APPLE_ISSUER.equals(issuer)) {
			return Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_APPLE;
		}
		if (GOOGLE_ISSUER.equals(issuer)) {
			return Kernel.PeopleIdpProvider.PEOPLE_IDP_PROVIDER_GOOGLE;
		}
		return null;
	}

	/**
	 * The fixed IdP record id of a provider ({@code apple}, {@code google}): the
	 * {@code idp_id} half of an {@code IdentityLink}. Pre-registered and fixed,
	 * never the issuer URL, which is a mutable attribute of the record.
	 */
	static String idpId(Kernel.PeopleIdpProvider provider) {
		return switch (provider) {
			case PEOPLE_IDP_PROVIDER_APPLE -> "apple";
			case PEOPLE_IDP_PROVIDER_GOOGLE -> "google";
			default -> throw new IllegalArgumentException("no idp id for " + provider);
		};
	}

	/**
	 * Creates the tenant record and writes the fixed Apple/Google provider set
	 * into its {@code oauth} config slice. Kernel runs this at every boot, after
	 * the disk snapshot is rehydrated, the same shape and for the same reason as
	 * {@code TenantAdminServiceImpl.seedRootCredPairs}: the bundle stays
	 * authoritative for the client credentials it declares, while the tenant's
	 * {@code created_at} and anything else on its record survive the restart.
	 *
	 * <p>The oauth slice is REPLACED rather than merged. It is the fixed IdP set:
	 * a provider that disappears from the bundle must disappear from the tenant,
	 * or removing a provider would take a restart plus a second, manual deletion
	 * through an admin surface this tenant deliberately does not have.
	 *
	 * <p>No cred_pair is written — this tenant has no admin.
	 *
	 * @param configMap   kernel ConfigState accessor
	 * @param credentials the bundle's {@code Config.people_idp_credentials}
	 */
	static void seed(ConfigMap configMap, List<Kernel.PeopleIdpCredential> credentials)
			throws ProtoException {
		Oauth.OAuthTenantConfig.Builder oauth = Oauth.OAuthTenantConfig.newBuilder();
		for (Kernel.PeopleIdpCredential credential : credentials) {
			String issuer = issuerUrl(credential.getProvider());
			if (issuer == null) {
				// The enum's zero value names no provider. Refusing is the point of
				// a closed enum: a typo in the bundle must not seed a tenant that
				// accepts an issuer nobody named.
				throw new ProtoException(ProtoException.INVALID_ARGUMENT,
						"people_idp_credentials entry names no provider");
			}
			oauth.addProviders(Oauth.OAuthProvider.newBuilder()
					.setIssuerUrl(issuer)
					.setClientId(credential.getClientId())
					.setClientSecret(credential.getClientSecret())
					.addAllAllowedScopes(SCOPES)
					.setEnable(true));
		}

		Kernel.Tenant existing = configMap.getTenants(NAMESPACE);
		Timestamp now = Timestamp.newBuilder()
				.setSeconds(Instant.now().getEpochSecond()).build();
		configMap.putTenants(NAMESPACE, Kernel.Tenant.newBuilder()
				.setName(NAME)
				.setStatus(Kernel.TenantStatus.TENANT_STATUS_ACTIVE)
				.setCreatedAt(existing.getName().isEmpty() ? now : existing.getCreatedAt())
				.setUpdatedAt(now)
				.build());

		TenantConfigOuterClass.TenantConfig.Builder cfg =
				configMap.getTenantConfigs(NAMESPACE).getConfig().toBuilder();
		cfg.setOauth(oauth.build());
		configMap.putTenantConfigs(NAMESPACE, Kernel.TenantConfigEntry.newBuilder()
				.setTenantName(NAMESPACE)
				.setConfig(cfg.build())
				.build());

		logger.info("Seeded reserved tenant {} with {} fixed IdP provider(s)",
				NAMESPACE, oauth.getProvidersCount());
	}
}
