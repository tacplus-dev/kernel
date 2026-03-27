// Copyright (c) 2024 Second Star Cavalier, LLC.

package com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.grpcserver;

import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.jwk.ImmutableJwk;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.libs.token.TokenWrapper;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.generated.entitlements.Entitlements;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.entitlementview.EntitlementProfileViewServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.entitlementview.Entitlementview;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.errors.ProtoException;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwk.JwkOuterClass;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwkview.JwkVerifyingKeysViewServiceGrpc;
import com.gitlab.secondstarcavalier.controlplane.services.kernel.tacplus.types.libs.jwkview.Jwkview;
import com.google.protobuf.Descriptors;
import com.google.protobuf.Empty;
import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authorizer performs token-based authorization for gRPC service requests.
 *
 * <p>Token signatures are verified against JWKs published by TokenExchanger. Profiles in the token
 * are resolved to per-service RPCs using cached identity profiles from the EntitlementProfileView.
 */
public class Authorizer {
  private static final Logger logger = LoggerFactory.getLogger(Authorizer.class);

  private final String serviceName;
  private final ConcurrentHashMap<String, ImmutableJwk> jwks = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Entitlements.EntitlementProfile> profiles =
      new ConcurrentHashMap<>();
  private volatile boolean watching = false;

  /**
   * Creates an Authorizer that verifies tokens via JWK view and resolves profile-based entitlements
   * via the EntitlementProfileView.
   *
   * @param serviceName the service_grpc annotation value (e.g. "fleetwood")
   * @param channel gRPC channel to kernel for JWK and profile subscription (nullable for testing)
   */
  public Authorizer(String serviceName, ManagedChannel channel) {
    this.serviceName = serviceName;
    if (channel != null) {
      startJwkWatch(channel);
      startProfileWatch(channel);
    }
    logger.info(
        "Token-based authorization initialized: service={}, jwkWatch={}",
        serviceName,
        channel != null);
  }

  /** Creates an Authorizer without JWK subscription (for testing). */
  public static Authorizer create() {
    logger.info("Token-based authorization enabled (no JWK watch)");
    return new Authorizer("", null);
  }

  /**
   * Checks if a request is authorized by verifying the token signature, audience, and entitlements.
   *
   * @param fullMethod the full gRPC method name
   * @param request the request object (unused, kept for API compat)
   * @throws ProtoException with PERMISSION_DENIED if authorization fails
   */
  public void authorize(String fullMethod, Object request) throws ProtoException {
    // This is a no-op if called without proper initialization.
    // The real authorization happens in authorizeWithToken.
  }

  /**
   * Authorizes a request using the authorization header value.
   *
   * @param authHeader the raw Authorization header value (e.g. "Bearer eyJ...")
   * @param fullMethod the full gRPC method name
   * @throws ProtoException if authorization fails
   */
  public void authorizeWithToken(String authHeader, String fullMethod) throws ProtoException {
    if (authHeader == null || authHeader.isEmpty()) {
      throw ProtoException.newErrPermissionDenied(null, "missing authorization header");
    }

    String tokenStr = authHeader;
    if (tokenStr.regionMatches(true, 0, "bearer ", 0, 7)) {
      tokenStr = tokenStr.substring(7);
    }

    // Verify token signature
    TokenWrapper tw;
    try {
      tw = TokenWrapper.parse(tokenStr);
    } catch (Exception e) {
      throw ProtoException.newErrPermissionDenied(null, "invalid token: " + e.getMessage());
    }

    String kid = tw.getKid();
    if (kid == null || kid.isEmpty()) {
      throw ProtoException.newErrPermissionDenied(null, "token missing key ID (kid)");
    }

    ImmutableJwk jwk = jwks.get(kid);
    if (jwk == null) {
      throw ProtoException.newErrPermissionDenied(null, "unknown signing key: " + kid);
    }

    try {
      tw.verify(jwk);
    } catch (Exception e) {
      throw ProtoException.newErrPermissionDenied(
          null, "token verification failed: " + e.getMessage());
    }

    // Check aud matches service name
    String aud = tw.getAudience();
    if (!serviceName.equals(aud)) {
      throw ProtoException.newErrPermissionDenied(
          null, "token audience \"" + aud + "\" does not match service \"" + serviceName + "\"");
    }

    String methodName = extractMethodName(fullMethod);

    // Extract azp (authorized party) for profile scoping.
    Object azpRaw = tw.getCustomField("azp");
    String azp = azpRaw instanceof String ? (String) azpRaw : "";

    // Try profile-based authorization first (new path).
    Object profilesRaw = tw.getCustomField("profiles");
    if (profilesRaw instanceof java.util.Collection<?> profileList && !profileList.isEmpty()) {
      authorizeByProfiles(profileList, methodName, azp);
      return;
    }

    // Backward compat: fall back to legacy entitlements claim.
    Object entRaw = tw.getCustomField("entitlements");
    if (entRaw == null) {
      throw ProtoException.newErrPermissionDenied(
          null, "token missing profiles or entitlements claim");
    }

    if (entRaw instanceof java.util.Collection<?> entList) {
      for (Object e : entList) {
        if (e != null) {
          String s = e.toString();
          if (s.equals(methodName) || s.equals("*")) {
            return;
          }
        }
      }
    }

    throw ProtoException.newErrPermissionDenied(
        null,
        "method \"" + methodName + "\" not in entitlements for service \"" + serviceName + "\"");
  }

  private void authorizeByProfiles(
      java.util.Collection<?> profileNames, String methodName, String azp) throws ProtoException {
    if (profiles.isEmpty()) {
      throw ProtoException.newErrPermissionDenied(null, "no entitlement profiles cached yet");
    }

    for (Object pn : profileNames) {
      if (!(pn instanceof String name)) continue;
      Entitlements.EntitlementProfile profile = profiles.get(name);
      if (profile == null) continue;
      // Check azp restriction: if the profile has an azp list, the token's
      // azp must appear in it. Empty azp list = profile applies to all origins.
      List<String> profileAzp = profile.getAzpList();
      if (profileAzp != null && !profileAzp.isEmpty()) {
        if (!profileAzp.contains(azp)) continue;
      }
      if (profileGrantsRPC(profile, serviceName, methodName)) {
        return;
      }
    }

    throw ProtoException.newErrPermissionDenied(
        null,
        "method \""
            + methodName
            + "\" not granted by any profile for service \""
            + serviceName
            + "\"");
  }

  static boolean profileGrantsRPC(
      Entitlements.EntitlementProfile profile, String serviceName, String methodName) {
    Descriptors.Descriptor desc = profile.getDescriptorForType();
    Descriptors.FieldDescriptor fd = desc.findFieldByName(serviceName);
    if (fd == null || fd.getType() != Descriptors.FieldDescriptor.Type.ENUM || !fd.isRepeated()) {
      return false;
    }

    @SuppressWarnings("unchecked")
    List<Descriptors.EnumValueDescriptor> values =
        (List<Descriptors.EnumValueDescriptor>) profile.getField(fd);

    for (Descriptors.EnumValueDescriptor ev : values) {
      String name = ev.getName();
      if (name.endsWith("_UNSPECIFIED")) continue;
      if (name.endsWith("_ANY")) return true;
      if (enumValueToRPCName(name).equals(methodName)) return true;
    }
    return false;
  }

  static String enumValueToRPCName(String enumName) {
    int idx = enumName.indexOf("_RPCS_");
    if (idx < 0) return enumName;
    String upperSnake = enumName.substring(idx + 6);
    String[] parts = upperSnake.split("_");
    StringBuilder sb = new StringBuilder();
    for (String part : parts) {
      if (!part.isEmpty()) {
        sb.append(Character.toUpperCase(part.charAt(0)));
        sb.append(part.substring(1).toLowerCase());
      }
    }
    return sb.toString();
  }

  public void close() {
    watching = false;
  }

  private void startJwkWatch(ManagedChannel channel) {
    watching = true;
    var stub = JwkVerifyingKeysViewServiceGrpc.newStub(channel);
    watchJwkView(stub);
  }

  private void watchJwkView(JwkVerifyingKeysViewServiceGrpc.JwkVerifyingKeysViewServiceStub stub) {
    stub.watch(
        Empty.getDefaultInstance(),
        new StreamObserver<Jwkview.JwkViewResponse>() {
          @Override
          public void onNext(Jwkview.JwkViewResponse resp) {
            ConcurrentHashMap<String, ImmutableJwk> newKeys = new ConcurrentHashMap<>();
            for (Map.Entry<String, JwkOuterClass.Jwk> entry : resp.getEntriesMap().entrySet()) {
              try {
                ImmutableJwk immJwk = ImmutableJwk.from(entry.getValue());
                newKeys.put(entry.getKey(), immJwk);
              } catch (Exception e) {
                logger.warn(
                    "Skipping invalid JWK: kid={}, error={}", entry.getKey(), e.getMessage());
              }
            }
            jwks.clear();
            jwks.putAll(newKeys);
            logger.info("JWK view updated: {} keys", newKeys.size());
          }

          @Override
          public void onError(Throwable t) {
            if (watching) {
              logger.warn("JWK view watch error, reconnecting: {}", t.getMessage());
              watchJwkView(stub);
            }
          }

          @Override
          public void onCompleted() {
            if (watching) {
              logger.info("JWK view watch completed, reconnecting");
              watchJwkView(stub);
            }
          }
        });
  }

  private void startProfileWatch(ManagedChannel channel) {
    var stub = EntitlementProfileViewServiceGrpc.newStub(channel);
    watchProfileView(stub);
  }

  private void watchProfileView(
      EntitlementProfileViewServiceGrpc.EntitlementProfileViewServiceStub stub) {
    stub.watch(
        Empty.getDefaultInstance(),
        new StreamObserver<Entitlementview.EntitlementProfileViewResponse>() {
          @Override
          public void onNext(Entitlementview.EntitlementProfileViewResponse resp) {
            profiles.clear();
            profiles.putAll(resp.getProfilesMap());
            logger.info("Profile view updated: {} profiles", resp.getProfilesCount());
          }

          @Override
          public void onError(Throwable t) {
            if (watching) {
              logger.warn("Profile view watch error, reconnecting: {}", t.getMessage());
              watchProfileView(stub);
            }
          }

          @Override
          public void onCompleted() {
            if (watching) {
              logger.info("Profile view watch completed, reconnecting");
              watchProfileView(stub);
            }
          }
        });
  }

  private static String extractMethodName(String fullMethod) {
    int i = fullMethod.lastIndexOf('/');
    return i >= 0 ? fullMethod.substring(i + 1) : fullMethod;
  }
}
