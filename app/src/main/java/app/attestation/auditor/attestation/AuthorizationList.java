/* Copyright 2019, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package app.attestation.auditor.attestation;

import static app.attestation.auditor.attestation.AuthorizationList.UserAuthType.FINGERPRINT;
import static app.attestation.auditor.attestation.AuthorizationList.UserAuthType.PASSWORD;
import static app.attestation.auditor.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_ANY;
import static app.attestation.auditor.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_NONE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ACTIVE_DATE_TIME;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ALGORITHM;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ALLOW_WHILE_ON_BODY;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ALL_APPLICATIONS;
import static app.attestation.auditor.attestation.Constants.KM_TAG_APPLICATION_ID;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_APPLICATION_ID;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_BRAND;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_DEVICE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_IMEI;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_MANUFACTURER;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_MEID;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_MODEL;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_PRODUCT;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_SECOND_IMEI;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ATTESTATION_ID_SERIAL;
import static app.attestation.auditor.attestation.Constants.KM_TAG_AUTH_TIMEOUT;
import static app.attestation.auditor.attestation.Constants.KM_TAG_BOOT_PATCH_LEVEL;
import static app.attestation.auditor.attestation.Constants.KM_TAG_CREATION_DATE_TIME;
import static app.attestation.auditor.attestation.Constants.KM_TAG_DEVICE_UNIQUE_ATTESTATION;
import static app.attestation.auditor.attestation.Constants.KM_TAG_DIGEST;
import static app.attestation.auditor.attestation.Constants.KM_TAG_EC_CURVE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_IDENTITY_CREDENTIAL_KEY;
import static app.attestation.auditor.attestation.Constants.KM_TAG_KEY_SIZE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_NO_AUTH_REQUIRED;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ORIGIN;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ORIGINATION_EXPIRE_DATE_TIME;
import static app.attestation.auditor.attestation.Constants.KM_TAG_OS_PATCH_LEVEL;
import static app.attestation.auditor.attestation.Constants.KM_TAG_OS_VERSION;
import static app.attestation.auditor.attestation.Constants.KM_TAG_PADDING;
import static app.attestation.auditor.attestation.Constants.KM_TAG_PURPOSE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ROLLBACK_RESISTANCE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ROLLBACK_RESISTANT;
import static app.attestation.auditor.attestation.Constants.KM_TAG_ROOT_OF_TRUST;
import static app.attestation.auditor.attestation.Constants.KM_TAG_RSA_PUBLIC_EXPONENT;
import static app.attestation.auditor.attestation.Constants.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED;
import static app.attestation.auditor.attestation.Constants.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED;
import static app.attestation.auditor.attestation.Constants.KM_TAG_UNLOCKED_DEVICE_REQUIRED;
import static app.attestation.auditor.attestation.Constants.KM_TAG_USAGE_EXPIRE_DATE_TIME;
import static app.attestation.auditor.attestation.Constants.KM_TAG_USER_AUTH_TYPE;
import static app.attestation.auditor.attestation.Constants.KM_TAG_VENDOR_PATCH_LEVEL;
import static app.attestation.auditor.attestation.Constants.UINT32_MAX;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
//import static com.google.common.collect.Streams.stream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
@Immutable
public class AuthorizationList {
  /** Specifies the types of user authenticators that may be used to authorize this key. */
  public enum UserAuthType {
    USER_AUTH_TYPE_NONE,
    PASSWORD,
    FINGERPRINT,
    USER_AUTH_TYPE_ANY
  }

  /**
   * Asymmetric algorithms from
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Algorithm.aidl
   */
  public enum Algorithm {
    RSA,
    EC,
  }

  private static final ImmutableMap<Algorithm, Integer> ALGORITHM_TO_ASN1 =
      ImmutableMap.of(Algorithm.RSA, 1, Algorithm.EC, 3);
  private static final ImmutableMap<Integer, Algorithm> ASN1_TO_ALGORITHM =
      ImmutableMap.of(1, Algorithm.RSA, 3, Algorithm.EC);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl
   */
  public enum EcCurve {
    P_224,
    P_256,
    P_384,
    P_521,
    CURVE_25519
  }

  private static final ImmutableMap<EcCurve, Integer> EC_CURVE_TO_ASN1 =
      ImmutableMap.of(
          EcCurve.P_224,
          0,
          EcCurve.P_256,
          1,
          EcCurve.P_384,
          2,
          EcCurve.P_521,
          3,
          EcCurve.CURVE_25519,
          4);
  private static final ImmutableMap<Integer, EcCurve> ASN1_TO_EC_CURVE =
      ImmutableMap.of(
          0,
          EcCurve.P_224,
          1,
          EcCurve.P_256,
          2,
          EcCurve.P_384,
          3,
          EcCurve.P_521,
          4,
          EcCurve.CURVE_25519);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/PaddingMode.aidl
   */
  public enum PaddingMode {
    NONE,
    RSA_OAEP,
    RSA_PSS,
    RSA_PKCS1_1_5_ENCRYPT,
    RSA_PKCS1_1_5_SIGN,
    PKCS7
  }

  static final ImmutableMap<PaddingMode, Integer> PADDING_MODE_TO_ASN1 =
      ImmutableMap.of(
          PaddingMode.NONE,
          1,
          PaddingMode.RSA_OAEP,
          2,
          PaddingMode.RSA_PSS,
          3,
          PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
          4,
          PaddingMode.RSA_PKCS1_1_5_SIGN,
          5,
          PaddingMode.PKCS7,
          64);
  static final ImmutableMap<Integer, PaddingMode> ASN1_TO_PADDING_MODE =
      ImmutableMap.of(
          1,
          PaddingMode.NONE,
          2,
          PaddingMode.RSA_OAEP,
          3,
          PaddingMode.RSA_PSS,
          4,
          PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
          5,
          PaddingMode.RSA_PKCS1_1_5_SIGN,
          64,
          PaddingMode.PKCS7);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Digest.aidl
   */
  public enum DigestMode {
    NONE,
    MD5,
    SHA1,
    SHA_2_224,
    SHA_2_256,
    SHA_2_384,
    SHA_2_512
  }

  static final ImmutableMap<DigestMode, Integer> DIGEST_MODE_TO_ASN1 =
      ImmutableMap.of(
          DigestMode.NONE,
          0,
          DigestMode.MD5,
          1,
          DigestMode.SHA1,
          2,
          DigestMode.SHA_2_224,
          3,
          DigestMode.SHA_2_256,
          4,
          DigestMode.SHA_2_384,
          5,
          DigestMode.SHA_2_512,
          6);
  static final ImmutableMap<Integer, DigestMode> ASN1_TO_DIGEST_MODE =
      ImmutableMap.of(
          0,
          DigestMode.NONE,
          1,
          DigestMode.MD5,
          2,
          DigestMode.SHA1,
          3,
          DigestMode.SHA_2_224,
          4,
          DigestMode.SHA_2_256,
          5,
          DigestMode.SHA_2_384,
          6,
          DigestMode.SHA_2_512);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyOrigin.aidl
   */
  public enum KeyOrigin {
    GENERATED,
    DERIVED,
    IMPORTED,
    RESERVED,
    SECURELY_IMPORTED
  }

  static final ImmutableMap<KeyOrigin, Integer> KEY_ORIGIN_TO_ASN1 =
      ImmutableMap.of(
          KeyOrigin.GENERATED,
          0,
          KeyOrigin.IMPORTED,
          1,
          KeyOrigin.DERIVED,
          2,
          KeyOrigin.RESERVED,
          3,
          KeyOrigin.SECURELY_IMPORTED,
          4);
  static final ImmutableMap<Integer, KeyOrigin> ASN1_TO_KEY_ORIGIN =
      ImmutableMap.of(
          0,
          KeyOrigin.GENERATED,
          1,
          KeyOrigin.IMPORTED,
          2,
          KeyOrigin.DERIVED,
          3,
          KeyOrigin.RESERVED,
          4,
          KeyOrigin.SECURELY_IMPORTED);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl
   */
  public enum OperationPurpose {
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    WRAP_KEY,
    AGREE_KEY,
    ATTEST_KEY
  }

  static final ImmutableMap<OperationPurpose, Integer> OPERATION_PURPOSE_TO_ASN1 =
      ImmutableMap.of(
          OperationPurpose.ENCRYPT,
          0,
          OperationPurpose.DECRYPT,
          1,
          OperationPurpose.SIGN,
          2,
          OperationPurpose.VERIFY,
          3,
          OperationPurpose.WRAP_KEY,
          5,
          OperationPurpose.AGREE_KEY,
          6,
          OperationPurpose.ATTEST_KEY,
          7);
  static final ImmutableMap<Integer, OperationPurpose> ASN1_TO_OPERATION_PURPOSE =
      ImmutableMap.of(
          0,
          OperationPurpose.ENCRYPT,
          1,
          OperationPurpose.DECRYPT,
          2,
          OperationPurpose.SIGN,
          3,
          OperationPurpose.VERIFY,
          5,
          OperationPurpose.WRAP_KEY,
          6,
          OperationPurpose.AGREE_KEY,
          7,
          OperationPurpose.ATTEST_KEY);

  public final ImmutableSet<OperationPurpose> purpose;
  public final Optional<Algorithm> algorithm;
  public final Optional<Integer> keySize;
  public final ImmutableSet<DigestMode> digest;
  public final ImmutableSet<PaddingMode> padding;
  public final Optional<EcCurve> ecCurve;
  public final Optional<Long> rsaPublicExponent;
  public final boolean rollbackResistance;
  public final Optional<Instant> activeDateTime;
  public final Optional<Instant> originationExpireDateTime;
  public final Optional<Instant> usageExpireDateTime;
  public final boolean noAuthRequired;
  public final ImmutableSet<UserAuthType> userAuthType;
  public final Optional<Duration> authTimeout;
  public final boolean allowWhileOnBody;
  public final boolean trustedUserPresenceRequired;
  public final boolean trustedConfirmationRequired;
  public final boolean unlockedDeviceRequired;
  public final boolean allApplications;
  public final Optional<ByteString> applicationId;
  public final Optional<Instant> creationDateTime;
  public final Optional<KeyOrigin> origin;
  public final boolean rollbackResistant;
  public final Optional<RootOfTrust> rootOfTrust;
  public final Optional<Integer> osVersion;
  public final Optional<Integer> osPatchLevel;
  public final Optional<AttestationApplicationId> attestationApplicationId;
  public final Optional<ByteString> attestationApplicationIdBytes;
  public final Optional<ByteString> attestationIdBrand;
  public final Optional<ByteString> attestationIdDevice;
  public final Optional<ByteString> attestationIdProduct;
  public final Optional<ByteString> attestationIdSerial;
  public final Optional<ByteString> attestationIdImei;
  public final Optional<ByteString> attestationIdSecondImei;
  public final Optional<ByteString> attestationIdMeid;
  public final Optional<ByteString> attestationIdManufacturer;
  public final Optional<ByteString> attestationIdModel;
  public final Optional<Integer> vendorPatchLevel;
  public final Optional<Integer> bootPatchLevel;
  public final boolean individualAttestation;
  public final boolean identityCredentialKey;
  public final ImmutableList<Integer> unorderedTags;

  private AuthorizationList(ASN1Encodable[] authorizationList, int attestationVersion) {
    ParsedAuthorizationMap parsedAuthorizationMap = getAuthorizationMap(authorizationList);

    this.purpose =
        parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PURPOSE).stream()
            .flatMap(key -> Utils.streamOfNullable(ASN1_TO_OPERATION_PURPOSE.get(key)))
            .collect(toImmutableSet());
    this.algorithm =
        parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ALGORITHM)
            .map(ASN1_TO_ALGORITHM::get);
    this.keySize = parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_KEY_SIZE);
    this.digest =
        parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_DIGEST).stream()
            .flatMap(key -> Utils.streamOfNullable(ASN1_TO_DIGEST_MODE.get(key)))
            .collect(toImmutableSet());
    this.padding =
        parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PADDING).stream()
            .flatMap(key -> Utils.streamOfNullable(ASN1_TO_PADDING_MODE.get(key)))
            .collect(toImmutableSet());
    this.ecCurve =
        parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_EC_CURVE)
            .map(ASN1_TO_EC_CURVE::get);
    this.rsaPublicExponent =
        parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_RSA_PUBLIC_EXPONENT);
    this.rollbackResistance =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANCE);
    this.activeDateTime =
        parsedAuthorizationMap.findOptionalInstantMillisAuthorizationListEntry(KM_TAG_ACTIVE_DATE_TIME);
    this.originationExpireDateTime =
        parsedAuthorizationMap.findOptionalInstantMillisAuthorizationListEntry(
            KM_TAG_ORIGINATION_EXPIRE_DATE_TIME);
    this.usageExpireDateTime =
        parsedAuthorizationMap.findOptionalInstantMillisAuthorizationListEntry(
            KM_TAG_USAGE_EXPIRE_DATE_TIME);
    this.noAuthRequired =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_NO_AUTH_REQUIRED);
    this.userAuthType = parsedAuthorizationMap.findUserAuthType(KM_TAG_USER_AUTH_TYPE);
    this.authTimeout =
        parsedAuthorizationMap.findOptionalDurationSecondsAuthorizationListEntry(KM_TAG_AUTH_TIMEOUT);
    this.allowWhileOnBody =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ALLOW_WHILE_ON_BODY);
    this.trustedUserPresenceRequired =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED);
    this.trustedConfirmationRequired =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED);
    this.unlockedDeviceRequired =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_UNLOCKED_DEVICE_REQUIRED);
    this.allApplications =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ALL_APPLICATIONS);
    this.applicationId =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_APPLICATION_ID);
    this.creationDateTime =
        parsedAuthorizationMap.findOptionalInstantMillisAuthorizationListEntry(KM_TAG_CREATION_DATE_TIME);
    this.origin =
        parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGIN)
            .map(ASN1_TO_KEY_ORIGIN::get);
    this.rollbackResistant =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANT);
    this.rootOfTrust =
        parsedAuthorizationMap. findAuthorizationListEntry(KM_TAG_ROOT_OF_TRUST)
            .map(ASN1Sequence.class::cast)
            .map(rootOfTrust -> RootOfTrust.createRootOfTrust(rootOfTrust, attestationVersion));
    this.osVersion =parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_VERSION);
    this.osPatchLevel =
        parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_PATCH_LEVEL);
    this.attestationApplicationId =
        parsedAuthorizationMap.findAuthorizationListEntry(KM_TAG_ATTESTATION_APPLICATION_ID)
            .map(ASN1OctetString.class::cast)
            .map(ASN1OctetString::getOctets)
            .map(AttestationApplicationId::createAttestationApplicationId);
    this.attestationApplicationIdBytes =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_APPLICATION_ID);
    this.attestationIdBrand =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_BRAND);
    this.attestationIdDevice =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_DEVICE);
    this.attestationIdProduct =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(
            KM_TAG_ATTESTATION_ID_PRODUCT);
    this.attestationIdSerial =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SERIAL);
    this.attestationIdImei =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_IMEI);
    this.attestationIdSecondImei =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(
            KM_TAG_ATTESTATION_ID_SECOND_IMEI);
    this.attestationIdMeid =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MEID);
    this.attestationIdManufacturer =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(
            KM_TAG_ATTESTATION_ID_MANUFACTURER);
    this.attestationIdModel =
        parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MODEL);
    this.vendorPatchLevel =
        parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_VENDOR_PATCH_LEVEL);
    this.bootPatchLevel =
        parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_BOOT_PATCH_LEVEL);
    this.individualAttestation =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_DEVICE_UNIQUE_ATTESTATION);
    this.identityCredentialKey =
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_IDENTITY_CREDENTIAL_KEY);
    this.unorderedTags = parsedAuthorizationMap.getUnorderedTags();

  }

  private AuthorizationList(Builder builder) {
    this.purpose = builder.purpose;
    this.algorithm = Optional.ofNullable(builder.algorithm);
    this.keySize = Optional.ofNullable(builder.keySize);
    this.digest = builder.digest;
    this.padding = builder.padding;
    this.ecCurve = Optional.ofNullable(builder.ecCurve);
    this.rsaPublicExponent = Optional.ofNullable(builder.rsaPublicExponent);
    this.rollbackResistance = builder.rollbackResistance;
    this.activeDateTime = Optional.ofNullable(builder.activeDateTime);
    this.originationExpireDateTime = Optional.ofNullable(builder.originationExpireDateTime);
    this.usageExpireDateTime = Optional.ofNullable(builder.usageExpireDateTime);
    this.noAuthRequired = builder.noAuthRequired;
    this.userAuthType = builder.userAuthType;
    this.authTimeout = Optional.ofNullable(builder.authTimeout);
    this.allowWhileOnBody = builder.allowWhileOnBody;
    this.trustedUserPresenceRequired = builder.trustedUserPresenceRequired;
    this.trustedConfirmationRequired = builder.trustedConfirmationRequired;
    this.unlockedDeviceRequired = builder.unlockedDeviceRequired;
    this.allApplications = builder.allApplications;
    this.applicationId = Optional.ofNullable(builder.applicationId);
    this.creationDateTime = Optional.ofNullable(builder.creationDateTime);
    this.origin = Optional.ofNullable(builder.origin);
    this.rollbackResistant = builder.rollbackResistant;
    this.rootOfTrust = Optional.ofNullable(builder.rootOfTrust);
    this.osVersion = Optional.ofNullable(builder.osVersion);
    this.osPatchLevel = Optional.ofNullable(builder.osPatchLevel);
    this.attestationApplicationId = Optional.ofNullable(builder.attestationApplicationId);
    this.attestationApplicationIdBytes = Optional.ofNullable(builder.attestationApplicationIdBytes);
    this.attestationIdBrand = Optional.ofNullable(builder.attestationIdBrand);
    this.attestationIdDevice = Optional.ofNullable(builder.attestationIdDevice);
    this.attestationIdProduct = Optional.ofNullable(builder.attestationIdProduct);
    this.attestationIdSerial = Optional.ofNullable(builder.attestationIdSerial);
    this.attestationIdImei = Optional.ofNullable(builder.attestationIdImei);
    this.attestationIdSecondImei = Optional.ofNullable(builder.attestationIdSecondImei);
    this.attestationIdMeid = Optional.ofNullable(builder.attestationIdMeid);
    this.attestationIdManufacturer = Optional.ofNullable(builder.attestationIdManufacturer);
    this.attestationIdModel = Optional.ofNullable(builder.attestationIdModel);
    this.vendorPatchLevel = Optional.ofNullable(builder.vendorPatchLevel);
    this.bootPatchLevel = Optional.ofNullable(builder.bootPatchLevel);
    this.individualAttestation = builder.individualAttestation;
    this.identityCredentialKey = builder.identityCredentialKey;
    this.unorderedTags = builder.unorderedTags;
  }

  static AuthorizationList createAuthorizationList(
      ASN1Encodable[] authorizationList, int attestationVersion) {
    return new AuthorizationList(authorizationList, attestationVersion);
  }

  private static ParsedAuthorizationMap getAuthorizationMap(ASN1Encodable[] authorizationList) {
    // authorizationMap must retain the order of authorizationList, otherwise
    // the code searching for out of order tags below will break. Helpfully
    // a ImmutableMap preserves insertion order.
    //
    // https://guava.dev/releases/23.0/api/docs/com/google/common/collect/ImmutableCollection.html
    ImmutableMap<Integer, ASN1Object> authorizationMap =
        Arrays.stream(authorizationList)
            .map(ASN1TaggedObject::getInstance)
            .collect(
                toImmutableMap(
                    ASN1TaggedObject::getTagNo,
                    obj -> ASN1Util.getExplicitContextBaseObject(obj, obj.getTagNo())));

    List<Integer> unorderedTags = new ArrayList<>();
    int previousTag = 0;
    for (int currentTag : authorizationMap.keySet()) {
      if (previousTag > currentTag) {
        unorderedTags.add(previousTag);
      }
      previousTag = currentTag;
    }
    return new ParsedAuthorizationMap(authorizationMap, ImmutableList.copyOf(unorderedTags));
  }

  @VisibleForTesting
  static ImmutableSet<UserAuthType> userAuthTypeToEnum(long userAuthType) {
    if (userAuthType == 0) {
      return ImmutableSet.of(USER_AUTH_TYPE_NONE);
    }

    ImmutableSet.Builder<UserAuthType> builder = ImmutableSet.builder();

    if ((userAuthType & 1L) == 1L) {
      builder.add(PASSWORD);
    }
    if ((userAuthType & 2L) == 2L) {
      builder.add(FINGERPRINT);
    }
    if (userAuthType == UINT32_MAX) {
      builder.add(USER_AUTH_TYPE_ANY);
    }

    ImmutableSet<UserAuthType> result = builder.build();
    if (result.isEmpty()) {
      throw new IllegalArgumentException("Invalid User Auth Type.");
    }

    return result;
  }

  private static Long userAuthTypeToLong(Set<UserAuthType> userAuthType) {
    if (userAuthType.contains(USER_AUTH_TYPE_NONE)) {
      return 0L;
    }

    long result = 0L;

    for (UserAuthType type : userAuthType) {
      switch (type) {
        case PASSWORD:
          result |= 1L;
          break;
        case FINGERPRINT:
          result |= 2L;
          break;
        case USER_AUTH_TYPE_ANY:
          result |= UINT32_MAX;
          break;
        default:
          break;
      }
    }

    if (result == 0) {
      throw new IllegalArgumentException("Invalid User Auth Type.");
    }

    return result;
  }

  public ASN1Sequence toAsn1Sequence() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    addOptionalIntegerSet(
        KM_TAG_PURPOSE,
        this.purpose.stream()
            .flatMap(key -> Utils.streamOfNullable(OPERATION_PURPOSE_TO_ASN1.get(key)))
            .collect(toImmutableSet()),
        vector);
    addOptionalInteger(KM_TAG_ALGORITHM, this.algorithm.map(ALGORITHM_TO_ASN1::get), vector);
    addOptionalInteger(KM_TAG_KEY_SIZE, this.keySize, vector);
    addOptionalIntegerSet(
        KM_TAG_DIGEST,
        this.digest.stream()
            .flatMap(key -> Utils.streamOfNullable(DIGEST_MODE_TO_ASN1.get(key)))
            .collect(toImmutableSet()),
        vector);
    addOptionalIntegerSet(
        KM_TAG_PADDING,
        this.padding.stream()
            .flatMap(key -> Utils.streamOfNullable(PADDING_MODE_TO_ASN1.get(key)))
            .collect(toImmutableSet()),
        vector);
    addOptionalInteger(KM_TAG_EC_CURVE, this.ecCurve.map(EC_CURVE_TO_ASN1::get), vector);
    addOptionalLong(KM_TAG_RSA_PUBLIC_EXPONENT, this.rsaPublicExponent, vector);
    addBoolean(KM_TAG_ROLLBACK_RESISTANCE, this.rollbackResistance, vector);
    addOptionalInstant(KM_TAG_ACTIVE_DATE_TIME, this.activeDateTime, vector);
    addOptionalInstant(KM_TAG_ORIGINATION_EXPIRE_DATE_TIME, this.originationExpireDateTime, vector);
    addOptionalInstant(KM_TAG_USAGE_EXPIRE_DATE_TIME, this.usageExpireDateTime, vector);
    addBoolean(KM_TAG_NO_AUTH_REQUIRED, this.noAuthRequired, vector);
    addOptionalUserAuthType(KM_TAG_USER_AUTH_TYPE, this.userAuthType, vector);
    addOptionalDuration(KM_TAG_AUTH_TIMEOUT, this.authTimeout, vector);
    addBoolean(KM_TAG_ALLOW_WHILE_ON_BODY, this.allowWhileOnBody, vector);
    addBoolean(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED, this.trustedUserPresenceRequired, vector);
    addBoolean(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED, this.trustedConfirmationRequired, vector);
    addBoolean(KM_TAG_UNLOCKED_DEVICE_REQUIRED, this.unlockedDeviceRequired, vector);
    addBoolean(KM_TAG_ALL_APPLICATIONS, this.allApplications, vector);
    addOptionalOctetString(KM_TAG_APPLICATION_ID, this.applicationId, vector);
    addOptionalInstant(KM_TAG_CREATION_DATE_TIME, this.creationDateTime, vector);
    addOptionalInteger(KM_TAG_ORIGIN, this.origin.map(KEY_ORIGIN_TO_ASN1::get), vector);
    addBoolean(KM_TAG_ROLLBACK_RESISTANT, this.rollbackResistant, vector);
    addOptionalRootOfTrust(KM_TAG_ROOT_OF_TRUST, this.rootOfTrust, vector);
    addOptionalInteger(KM_TAG_OS_VERSION, this.osVersion, vector);
    addOptionalInteger(KM_TAG_OS_PATCH_LEVEL, this.osPatchLevel, vector);
    addOptionalAttestationApplicationId(
        KM_TAG_ATTESTATION_APPLICATION_ID,
        this.attestationApplicationId,
        this.attestationApplicationIdBytes,
        vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_BRAND, this.attestationIdBrand, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_DEVICE, this.attestationIdDevice, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_PRODUCT, this.attestationIdProduct, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_SERIAL, this.attestationIdSerial, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_IMEI, this.attestationIdImei, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_SECOND_IMEI, this.attestationIdSecondImei, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_MEID, this.attestationIdMeid, vector);
    addOptionalOctetString(
        KM_TAG_ATTESTATION_ID_MANUFACTURER, this.attestationIdManufacturer, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_MODEL, this.attestationIdModel, vector);
    addOptionalInteger(KM_TAG_VENDOR_PATCH_LEVEL, this.vendorPatchLevel, vector);
    addOptionalInteger(KM_TAG_BOOT_PATCH_LEVEL, this.bootPatchLevel, vector);
    addBoolean(KM_TAG_DEVICE_UNIQUE_ATTESTATION, this.individualAttestation, vector);
    return new DERSequence(vector);
  }

  private static void addOptionalIntegerSet(
      int tag, Set<Integer> entry, ASN1EncodableVector vector) {
    if (!entry.isEmpty()) {
      ASN1EncodableVector tmp = new ASN1EncodableVector();
      entry.forEach((Integer value) -> tmp.add(new ASN1Integer(value.longValue())));
      vector.add(new DERTaggedObject(tag, new DERSet(tmp)));
    }
  }

  private static void addOptionalInstant(
      int tag, Optional<Instant> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get().toEpochMilli())));
    }
  }

  private static void addOptionalDuration(
      int tag, Optional<Duration> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get().getSeconds())));
    }
  }

  private static void addBoolean(int tag, boolean entry, ASN1EncodableVector vector) {
    if (entry) {
      vector.add(new DERTaggedObject(tag, DERNull.INSTANCE));
    }
  }

  private static void addOptionalInteger(
      int tag, Optional<Integer> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get())));
    }
  }

  private static void addOptionalLong(int tag, Optional<Long> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get())));
    }
  }

  private static void addOptionalOctetString(
      int tag, Optional<ByteString> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new DEROctetString(entry.get().toByteArray())));
    }
  }

  private static void addOptionalUserAuthType(
      int tag, Set<UserAuthType> entry, ASN1EncodableVector vector) {
    if (!entry.isEmpty()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(userAuthTypeToLong(entry))));
    }
  }

  private static void addOptionalRootOfTrust(
      int tag, Optional<RootOfTrust> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, entry.get().toAsn1Sequence()));
    }
  }

  private static void addOptionalAttestationApplicationId(
      int tag,
      Optional<AttestationApplicationId> objectEntry,
      Optional<ByteString> byteEntry,
      ASN1EncodableVector vector) {
    if (objectEntry.isPresent()) {
      try {
        vector.add(
            new DERTaggedObject(
                tag, new DEROctetString(objectEntry.get().toAsn1Sequence().getEncoded())));
      } catch (Exception e) {
        addOptionalOctetString(KM_TAG_ATTESTATION_APPLICATION_ID, byteEntry, vector);
      }
    } else if (byteEntry.isPresent()) {
      addOptionalOctetString(KM_TAG_ATTESTATION_APPLICATION_ID, byteEntry, vector);
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for an AuthorizationList. Any field not set will be made an Optional.empty or set with
   * the default value.
   */
  public static final class Builder {

    ImmutableSet<OperationPurpose> purpose = ImmutableSet.of();
    Algorithm algorithm;
    Integer keySize;
    ImmutableSet<DigestMode> digest = ImmutableSet.of();
    ImmutableSet<PaddingMode> padding = ImmutableSet.of();
    EcCurve ecCurve;
    Long rsaPublicExponent;
    boolean rollbackResistance;
    Instant activeDateTime;
    Instant originationExpireDateTime;
    Instant usageExpireDateTime;
    boolean noAuthRequired;
    ImmutableSet<UserAuthType> userAuthType = ImmutableSet.of();
    Duration authTimeout;
    boolean allowWhileOnBody;
    boolean trustedUserPresenceRequired;
    boolean trustedConfirmationRequired;
    boolean unlockedDeviceRequired;
    boolean allApplications;
    ByteString applicationId;
    Instant creationDateTime;
    KeyOrigin origin;
    boolean rollbackResistant;
    RootOfTrust rootOfTrust;
    Integer osVersion;
    Integer osPatchLevel;
    AttestationApplicationId attestationApplicationId;
    ByteString attestationApplicationIdBytes;
    ByteString attestationIdBrand;
    ByteString attestationIdDevice;
    ByteString attestationIdProduct;
    ByteString attestationIdSerial;
    ByteString attestationIdImei;
    ByteString attestationIdSecondImei;
    ByteString attestationIdMeid;
    ByteString attestationIdManufacturer;
    ByteString attestationIdModel;
    Integer vendorPatchLevel;
    Integer bootPatchLevel;
    boolean individualAttestation;
    boolean identityCredentialKey;
    ImmutableList<Integer> unorderedTags;

    @CanIgnoreReturnValue
    public Builder setPurpose(Set<OperationPurpose> purpose) {
      this.purpose = ImmutableSet.copyOf(purpose);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAlgorithm(Algorithm algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setKeySize(Integer keySize) {
      this.keySize = keySize;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setDigest(Set<DigestMode> digest) {
      this.digest = ImmutableSet.copyOf(digest);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPadding(Set<PaddingMode> padding) {
      this.padding = ImmutableSet.copyOf(padding);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setEcCurve(EcCurve ecCurve) {
      this.ecCurve = ecCurve;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setRsaPublicExponent(Long rsaPublicExponent) {
      this.rsaPublicExponent = rsaPublicExponent;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setRollbackResistance(boolean rollbackResistance) {
      this.rollbackResistance = rollbackResistance;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setActiveDateTime(Instant activeDateTime) {
      this.activeDateTime = activeDateTime;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setOriginationExpireDateTime(Instant originationExpireDateTime) {
      this.originationExpireDateTime = originationExpireDateTime;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setUsageExpireDateTime(Instant usageExpireDateTime) {
      this.usageExpireDateTime = usageExpireDateTime;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setNoAuthRequired(boolean noAuthRequired) {
      this.noAuthRequired = noAuthRequired;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setUserAuthType(Set<UserAuthType> userAuthType) {
      this.userAuthType = ImmutableSet.copyOf(userAuthType);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAuthTimeout(Duration authTimeout) {
      this.authTimeout = authTimeout;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAllowWhileOnBody(boolean allowWhileOnBody) {
      this.allowWhileOnBody = allowWhileOnBody;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setTrustedUserPresenceRequired(boolean trustedUserPresenceRequired) {
      this.trustedUserPresenceRequired = trustedUserPresenceRequired;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setTrustedConfirmationRequired(boolean trustedConfirmationRequired) {
      this.trustedConfirmationRequired = trustedConfirmationRequired;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setUnlockedDeviceRequired(boolean unlockedDeviceRequired) {
      this.unlockedDeviceRequired = unlockedDeviceRequired;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAllApplications(boolean allApplications) {
      this.allApplications = allApplications;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setApplicationId(ByteString applicationId) {
      this.applicationId = applicationId;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setCreationDateTime(Instant creationDateTime) {
      this.creationDateTime = creationDateTime;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setOrigin(KeyOrigin origin) {
      this.origin = origin;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setRollbackResistant(boolean rollbackResistant) {
      this.rollbackResistant = rollbackResistant;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setRootOfTrust(RootOfTrust rootOfTrust) {
      this.rootOfTrust = rootOfTrust;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setOsVersion(Integer osVersion) {
      this.osVersion = osVersion;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setOsPatchLevel(Integer osPatchLevel) {
      this.osPatchLevel = osPatchLevel;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationApplicationId(AttestationApplicationId attestationApplicationId) {
      this.attestationApplicationId = attestationApplicationId;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationApplicationIdBytes(ByteString attestationApplicationIdBytes) {
      this.attestationApplicationIdBytes = attestationApplicationIdBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdBrand(ByteString attestationIdBrand) {
      this.attestationIdBrand = attestationIdBrand;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdDevice(ByteString attestationIdDevice) {
      this.attestationIdDevice = attestationIdDevice;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdProduct(ByteString attestationIdProduct) {
      this.attestationIdProduct = attestationIdProduct;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdSerial(ByteString attestationIdSerial) {
      this.attestationIdSerial = attestationIdSerial;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdImei(ByteString attestationIdImei) {
      this.attestationIdImei = attestationIdImei;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdSecondImei(ByteString attestationIdSecondImei) {
      this.attestationIdSecondImei = attestationIdSecondImei;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdMeid(ByteString attestationIdMeid) {
      this.attestationIdMeid = attestationIdMeid;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdManufacturer(ByteString attestationIdManufacturer) {
      this.attestationIdManufacturer = attestationIdManufacturer;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAttestationIdModel(ByteString attestationIdModel) {
      this.attestationIdModel = attestationIdModel;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVendorPatchLevel(Integer vendorPatchLevel) {
      this.vendorPatchLevel = vendorPatchLevel;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setBootPatchLevel(Integer bootPatchLevel) {
      this.bootPatchLevel = bootPatchLevel;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIndividualAttestation(boolean individualAttestation) {
      this.individualAttestation = individualAttestation;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdentityCredentialKey(boolean identityCredentialKey) {
      this.identityCredentialKey = identityCredentialKey;
      return this;
    }

    public AuthorizationList build() {
      return new AuthorizationList(this);
    }
  }


  /**
   * This data structure holds the parsed attest record authorizations mapped to their authorization
   * tags and a list of unordered authorization tags found in this authorization list.
   */
  private static class ParsedAuthorizationMap {
    private final ImmutableMap<Integer, ASN1Object> authorizationMap;
    private final ImmutableList<Integer> unorderedTags;

    private ParsedAuthorizationMap(
        ImmutableMap<Integer, ASN1Object> authorizationMap, ImmutableList<Integer> unorderedTags) {
      this.authorizationMap = authorizationMap;
      this.unorderedTags = unorderedTags;
    }

    private ImmutableList<Integer> getUnorderedTags() {
      return unorderedTags;
    }

    private Optional<ASN1Object> findAuthorizationListEntry(int tag) {
      return Optional.ofNullable(authorizationMap.get(tag));
    }

    private ImmutableSet<Integer> findIntegerSetAuthorizationListEntry(int tag) {
      ASN1Set asn1Set =
              findAuthorizationListEntry(tag).map(ASN1Set.class::cast).orElse(null);
      if (asn1Set == null) {
        return ImmutableSet.of();
      }
      return Utils.stream(asn1Set).map(ASN1Parsing::getIntegerFromAsn1).collect(toImmutableSet());
    }

    private Optional<Duration> findOptionalDurationSecondsAuthorizationListEntry(int tag) {
      Optional<Integer> seconds = findOptionalIntegerAuthorizationListEntry(tag);
      return seconds.map(Duration::ofSeconds);
    }

    private Optional<Integer> findOptionalIntegerAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag)
              .map(ASN1Integer.class::cast)
              .map(ASN1Parsing::getIntegerFromAsn1);
    }

    private Optional<Instant> findOptionalInstantMillisAuthorizationListEntry(int tag) {
      Optional<Long> millis = findOptionalLongAuthorizationListEntry(tag);
      return millis.map(Instant::ofEpochMilli);
    }

    private Optional<Long> findOptionalLongAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag)
              .map(ASN1Integer.class::cast)
              .map(value -> value.getValue().longValue());
    }

    private boolean findBooleanAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag).isPresent();
    }

    private Optional<ByteString> findOptionalByteArrayAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag)
          .map(ASN1OctetString.class::cast)
          .map(ASN1OctetString::getOctets)
          .map(ByteString::copyFrom);
    }

    private ImmutableSet<UserAuthType> findUserAuthType(int tag) {
      Optional<Long> userAuthType = findOptionalLongAuthorizationListEntry(tag);
      return userAuthType.map(AuthorizationList::userAuthTypeToEnum).orElse(ImmutableSet.of());
    }
  }
}
