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

/** Key Attestation constants */
public class Constants {

  // The Google root public key corresponding to the private key that must
  // have been used to self-sign the root of a real attestation certificate
  // chain from a compliant device.
  // (Note, the sample chain used here is not signed with the Google root CA.)
  public static final String GOOGLE_ROOT_CA_PUB_KEY =
      "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU"
          + "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j"
          + "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y"
          + "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X"
          + "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI"
          + "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB"
          + "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q"
          + "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp"
          + "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7"
          + "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82"
          + "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+"
          + "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";
  public static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
  static final int ATTESTATION_VERSION_INDEX = 0;
  static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
  static final int KEYMASTER_VERSION_INDEX = 2;
  static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
  static final int ATTESTATION_CHALLENGE_INDEX = 4;
  static final int UNIQUE_ID_INDEX = 5;
  static final int SW_ENFORCED_INDEX = 6;
  static final int TEE_ENFORCED_INDEX = 7;
  // Authorization list tags. The list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  public static final int KM_TAG_PURPOSE = 1;
  public static final int KM_TAG_ALGORITHM = 2;
  public static final int KM_TAG_KEY_SIZE = 3;
  public static final int KM_TAG_DIGEST = 5;
  public static final int KM_TAG_PADDING = 6;
  public static final int KM_TAG_EC_CURVE = 10;
  public static final int KM_TAG_RSA_PUBLIC_EXPONENT = 200;
  public static final int KM_TAG_ROLLBACK_RESISTANCE = 303;
  public static final int KM_TAG_ACTIVE_DATE_TIME = 400;
  public static final int KM_TAG_ORIGINATION_EXPIRE_DATE_TIME = 401;
  public static final int KM_TAG_USAGE_EXPIRE_DATE_TIME = 402;
  public static final int KM_TAG_NO_AUTH_REQUIRED = 503;
  public static final int KM_TAG_USER_AUTH_TYPE = 504;
  public static final int KM_TAG_AUTH_TIMEOUT = 505;
  public static final int KM_TAG_ALLOW_WHILE_ON_BODY = 506;
  public static final int KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507;
  public static final int KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 508;
  public static final int KM_TAG_UNLOCKED_DEVICE_REQUIRED = 509;
  public static final int KM_TAG_ALL_APPLICATIONS = 600;
  public static final int KM_TAG_APPLICATION_ID = 601;
  public static final int KM_TAG_CREATION_DATE_TIME = 701;
  public static final int KM_TAG_ORIGIN = 702;
  public static final int KM_TAG_ROLLBACK_RESISTANT = 703;
  public static final int KM_TAG_ROOT_OF_TRUST = 704;
  public static final int KM_TAG_OS_VERSION = 705;
  public static final int KM_TAG_OS_PATCH_LEVEL = 706;
  public static final int KM_TAG_ATTESTATION_APPLICATION_ID = 709;
  public static final int KM_TAG_ATTESTATION_ID_BRAND = 710;
  public static final int KM_TAG_ATTESTATION_ID_DEVICE = 711;
  public static final int KM_TAG_ATTESTATION_ID_PRODUCT = 712;
  public static final int KM_TAG_ATTESTATION_ID_SERIAL = 713;
  public static final int KM_TAG_ATTESTATION_ID_IMEI = 714;
  public static final int KM_TAG_ATTESTATION_ID_MEID = 715;
  public static final int KM_TAG_ATTESTATION_ID_MANUFACTURER = 716;
  public static final int KM_TAG_ATTESTATION_ID_MODEL = 717;
  public static final int KM_TAG_VENDOR_PATCH_LEVEL = 718;
  public static final int KM_TAG_BOOT_PATCH_LEVEL = 719;
  public static final int KM_TAG_DEVICE_UNIQUE_ATTESTATION = 720;
  public static final int KM_TAG_IDENTITY_CREDENTIAL_KEY = 721;
  public static final int KM_TAG_ATTESTATION_ID_SECOND_IMEI = 723;
  static final int ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX = 0;
  static final int ROOT_OF_TRUST_DEVICE_LOCKED_INDEX = 1;
  static final int ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX = 2;
  static final int ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3;
  static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
  static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
  static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;
  static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;
  // Some security values. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
  static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
  static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;
  static final int KM_VERIFIED_BOOT_STATE_VERIFIED = 0;
  static final int KM_VERIFIED_BOOT_STATE_SELF_SIGNED = 1;
  static final int KM_VERIFIED_BOOT_STATE_UNVERIFIED = 2;
  static final int KM_VERIFIED_BOOT_STATE_FAILED = 3;
  // Unsigned max value of 32-bit integer, 2^32 - 1
  static final long UINT32_MAX = (((long) Integer.MAX_VALUE) << 1) + 1;

  private Constants() {}
}