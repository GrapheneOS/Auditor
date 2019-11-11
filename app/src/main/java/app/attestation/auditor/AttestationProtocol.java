package app.attestation.auditor;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Build;
import android.os.UserManager;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.accessibility.AccessibilityManager;

import androidx.preference.PreferenceManager;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.common.primitives.Bytes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

import javax.security.auth.x500.X500Principal;

import app.attestation.auditor.attestation.Attestation;
import app.attestation.auditor.attestation.AttestationApplicationId;
import app.attestation.auditor.attestation.AttestationPackageInfo;
import app.attestation.auditor.attestation.AuthorizationList;
import app.attestation.auditor.attestation.RootOfTrust;

import static android.security.keystore.KeyProperties.DIGEST_SHA256;
import static android.security.keystore.KeyProperties.KEY_ALGORITHM_EC;

class AttestationProtocol {
    private static final String TAG = "AttestationProtocol";

    // Developer previews set osVersion to 0 as a placeholder value.
    private static final int DEVELOPER_PREVIEW_OS_VERSION = 0;

    // Settings.Global.ADD_USERS_WHEN_LOCKED is a private API
    private static final String ADD_USERS_WHEN_LOCKED = "add_users_when_locked";

    private static final int CLOCK_SKEW_MS = 60 * 1000;
    private static final int EXPIRE_OFFSET_MS = 5 * 60 * 1000 + CLOCK_SKEW_MS;

    private static final String KEYSTORE_ALIAS_FRESH = "fresh_attestation_key";
    private static final String KEYSTORE_ALIAS_PERSISTENT_PREFIX = "persistent_attestation_key_";

    // Global preferences
    private static final String KEY_CHALLENGE_INDEX = "challenge_index";

    // Per-Auditee preferences
    private static final String PREFERENCES_DEVICE_PREFIX = "device-";
    private static final String KEY_PINNED_CERTIFICATE = "pinned_certificate_";
    private static final String KEY_PINNED_CERTIFICATE_LENGTH = "pinned_certificate_length";
    private static final String KEY_PINNED_VERIFIED_BOOT_KEY = "pinned_verified_boot_key";
    private static final String KEY_PINNED_OS_VERSION = "pinned_os_version";
    private static final String KEY_PINNED_OS_PATCH_LEVEL = "pinned_os_patch_level";
    private static final String KEY_PINNED_VENDOR_PATCH_LEVEL = "pinned_vendor_patch_level";
    private static final String KEY_PINNED_BOOT_PATCH_LEVEL = "pinned_boot_patch_level";
    private static final String KEY_PINNED_APP_VERSION = "pinned_app_version";
    private static final String KEY_PINNED_SECURITY_LEVEL = "pinned_security_level";
    private static final String KEY_VERIFIED_TIME_FIRST = "verified_time_first";
    private static final String KEY_VERIFIED_TIME_LAST = "verified_time_last";

    private static final int CHALLENGE_LENGTH = 32;
    static final String EC_CURVE = "secp256r1";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithECDSA";
    static final String KEY_DIGEST = DIGEST_SHA256;
    private static final HashFunction FINGERPRINT_HASH_FUNCTION = Hashing.sha256();
    private static final int FINGERPRINT_LENGTH = FINGERPRINT_HASH_FUNCTION.bits() / 8;

    private static final int SECURITY_LEVEL_STRONGBOX = 2;
    private static final boolean PREFER_STRONGBOX = true;

    // Challenge message:
    //
    // byte maxVersion = PROTOCOL_VERSION
    // byte[] challenge index (length: CHALLENGE_LENGTH)
    // byte[] challenge (length: CHALLENGE_LENGTH)
    //
    // The challenge index is randomly generated by Auditor and used for all future challenge
    // messages from that Auditor. It's used on the Auditee as an index to choose the correct
    // persistent key to satisfy the Auditor, rather than only supporting pairing with one. In
    // theory, the Auditor could authenticate to the Auditee, but this app already provides a
    // better way to do that by doing the same process in reverse for a supported device.
    //
    // The challenge is randomly generated by the Auditor and serves the security function of
    // enforcing that the results are fresh. It's returned inside the attestation certificate
    // which has a signature from the device's provisioned key (not usable by the OS) and the
    // outer signature from the hardware-backed key generated for the initial pairing.
    //
    // Attestation message:
    //
    // The Auditor will eventually start trying to be backwards compatible with older Auditee app
    // versions but not the other way around.
    //
    // Compression is done with raw DEFLATE (no zlib wrapper) with a preset dictionary generated from
    // sample certificates.
    //
    // signed message {
    // byte version = min(maxVersion, PROTOCOL_VERSION)
    // short compressedChainLength
    // byte[] compressedChain { [short encodedCertificateLength, byte[] encodedCertificate] }
    // byte[] fingerprint (length: FINGERPRINT_LENGTH)
    // int osEnforcedFlags
    // }
    // byte[] signature (rest of message)
    //
    // For each audit, the Auditee generates a fresh hardware-backed key with key attestation
    // using the provided challenge. It reports back the certificate chain to be verified by the
    // Auditor. The public key certificate of the generated key is signed by a key provisioned on
    // the device (not usable by the OS) chaining up to a known Pixel 2 (XL) intermediate and the
    // Google root. The certificate contains the key attestation metadata including the important
    // fields with the lock state, verified boot state, the verified boot public key fingerprint
    // and the OS version / patch level:
    //
    // https://developer.android.com/training/articles/security-key-attestation.html#certificate_schema
    //
    // The Auditee keeps the first hardware-backed key generated for a challenge index and uses it
    // to sign all future attestations. The fingerprint of the persistent key is included in the
    // attestation message for the Auditor to find the corresponding pinning data. Other keys are
    // never actually used, only generated for fresh key attestation data.
    //
    // The OS can use the persistent generated hardware-backed key for signing but cannot obtain
    // the private key. The key isn't be usable if verified boot fails or the OS is downgraded and
    // the keys are protected against replay attacks via the Replay Protected Memory Block.
    // Devices launching with Android P or later can provide a StrongBox Keymaster to support
    // storing the keys in a dedicated hardware security module to substantially reduce the attack
    // surface for obtaining the keys. StrongBox is paired with the TEE and the TEE corroborates
    // the validity of the keys and attestation. The Pixel 3 and 3 XL are the first devices with a
    // StrongBox implementation via the Titan M security chip.
    //
    // https://android-developers.googleblog.com/2018/10/building-titan-better-security-through.html
    //
    // The attestation API could be improved with better guarantees about the certificate chain
    // remaining the same, including rollback indexes in key attestation metadata and adding a
    // per-app-install generated intermediate to the chain to be pinned with the others.
    //
    // The attestation message also includes osEnforcedFlags with data obtained at the OS level,
    // which is vulnerable to tampering by an attacker with control over the OS. However, the OS
    // did get verified by verified boot so without a verified boot bypass they would need to keep
    // exploiting it after booting. The bootloader / TEE verified OS version / OS patch level are
    // a useful mitigation as they reveal that the OS isn't upgraded even if an attacker has root.
    //
    // The Auditor saves the initial certificate chain, using the initial certificate to verify
    // the outer signature and the rest of the chain for pinning the expected chain. It enforces
    // downgrade protection for the OS version/patch (bootloader/TEE enforced) and app version (OS
    // enforced) by keeping them updated.
    private static final byte PROTOCOL_VERSION = 1;
    private static final byte PROTOCOL_VERSION_MINIMUM = 1;
    // can become longer in the future, but this is the minimum length
    static final byte CHALLENGE_MESSAGE_LENGTH = 1 + CHALLENGE_LENGTH * 2;
    private static final int MAX_ENCODED_CHAIN_LENGTH = 3000;
    private static final int MAX_MESSAGE_SIZE = 2953;

    private static final int OS_ENFORCED_FLAGS_NONE = 0;
    private static final int OS_ENFORCED_FLAGS_USER_PROFILE_SECURE = 1;
    private static final int OS_ENFORCED_FLAGS_ACCESSIBILITY = 1 << 1;
    private static final int OS_ENFORCED_FLAGS_DEVICE_ADMIN = 1 << 2;
    private static final int OS_ENFORCED_FLAGS_ADB_ENABLED = 1 << 3;
    private static final int OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED = 1 << 4;
    private static final int OS_ENFORCED_FLAGS_ENROLLED_FINGERPRINTS = 1 << 5;
    private static final int OS_ENFORCED_FLAGS_DENY_NEW_USB = 1 << 6;
    private static final int OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM = 1 << 7;
    private static final int OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED = 1 << 8;
    private static final int OS_ENFORCED_FLAGS_SYSTEM_USER = 1 << 9;
    private static final int OS_ENFORCED_FLAGS_ALL =
            OS_ENFORCED_FLAGS_USER_PROFILE_SECURE |
            OS_ENFORCED_FLAGS_ACCESSIBILITY |
            OS_ENFORCED_FLAGS_DEVICE_ADMIN |
            OS_ENFORCED_FLAGS_ADB_ENABLED |
            OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED |
            OS_ENFORCED_FLAGS_ENROLLED_FINGERPRINTS |
            OS_ENFORCED_FLAGS_DENY_NEW_USB |
            OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM |
            OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED |
            OS_ENFORCED_FLAGS_SYSTEM_USER;

    private static final String ATTESTATION_APP_PACKAGE_NAME = "app.attestation.auditor";
    private static final int ATTESTATION_APP_MINIMUM_VERSION = 5;
    private static final String ATTESTATION_APP_SIGNATURE_DIGEST_DEBUG =
            "17727D8B61D55A864936B1A7B4A2554A15151F32EBCF44CDAA6E6C3258231890";
    private static final String ATTESTATION_APP_SIGNATURE_DIGEST_RELEASE =
            "990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C";
    private static final int OS_VERSION_MINIMUM = 80000;
    private static final int OS_PATCH_LEVEL_MINIMUM = 201801;
    private static final int VENDOR_PATCH_LEVEL_MINIMUM = 201808;
    private static final int BOOT_PATCH_LEVEL_MINIMUM = 201809;

    // Split displayed fingerprint into groups of 4 characters
    private static final int FINGERPRINT_SPLIT_INTERVAL = 4;

    private static class DeviceInfo {
        final int name;
        final int attestationVersion;
        final int keymasterVersion;
        final boolean rollbackResistant;
        final boolean perUserEncryption;
        final int osName;

        DeviceInfo(final int name, final int attestationVersion, final int keymasterVersion,
                final boolean rollbackResistant, final boolean perUserEncryption, final int osName) {
            this.name = name;
            this.attestationVersion = attestationVersion;
            this.keymasterVersion = keymasterVersion;
            this.rollbackResistant = rollbackResistant;
            this.perUserEncryption = perUserEncryption;
            this.osName = osName;
        }
    }

    private static final boolean isStrongBoxSupported = ImmutableSet.of(
            "Pixel 3",
            "Pixel 3 XL",
            "Pixel 3a",
            "Pixel 3a XL",
            "SM-N970U",
            "SM-N975U").contains(Build.MODEL);

    private static final ImmutableSet<Integer> extraPatchLevelMissing = ImmutableSet.of(
            R.string.device_sm_a705fn,
            R.string.device_sm_g970f,
            R.string.device_sm_g975f,
            R.string.device_sm_n970f,
            R.string.device_sm_n970u,
            R.string.device_sm_n975u,
            R.string.device_sm_t510);

    private static final ImmutableMap<String, String> fingerprintsMigration = ImmutableMap
            .<String, String>builder()
            // GrapheneOS Pixel 3
            .put("0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF", // v2
                    "213AA4392BF7CABB9676C2680E134FB5FD3E5937D7E607B4EB907CB0A9D9E400") // v1
            // GrapheneOS Pixel 3 XL
            .put("06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451", // v2
                    "60D551860CC7FD32A9DC65FB3BCEB87A5E5C1F88928026F454A234D69B385580") // v1
            // Stock OS Pixel 3 and Pixel 3 XL
            .put("61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C", // v2
                    "B799391AFAE3B35522D1EDC5C70A3746B097BDD1CABD59F72BB049705C7A03EF") // v1
            .build();

    private static final ImmutableMap<String, DeviceInfo> fingerprintsCustomOS = ImmutableMap
            .<String, DeviceInfo>builder()
            // GrapheneOS
            .put("B094E48B27C6E15661223CEFF539CF35E481DEB4E3250331E973AC2C15CAD6CD",
                    new DeviceInfo(R.string.device_pixel_2, 2, 3, true, true, R.string.os_graphene))
            .put("B6851E9B9C0EBB7185420BD0E79D20A84CB15AB0B018505EFFAA4A72B9D9DAC7",
                    new DeviceInfo(R.string.device_pixel_2_xl, 2, 3, true, true, R.string.os_graphene))
            .put("213AA4392BF7CABB9676C2680E134FB5FD3E5937D7E607B4EB907CB0A9D9E400", // v1
                    new DeviceInfo(R.string.device_pixel_3, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF", // v2
                    new DeviceInfo(R.string.device_pixel_3, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("60D551860CC7FD32A9DC65FB3BCEB87A5E5C1F88928026F454A234D69B385580", // v1
                    new DeviceInfo(R.string.device_pixel_3_xl, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451", // v2
                    new DeviceInfo(R.string.device_pixel_3_xl, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("8FF8B9B4F831114963669E04EA4F849F33F3744686A0B33B833682746645ABC8",
                    new DeviceInfo(R.string.device_pixel_3a, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("91943FAA75DCB6392AE87DA18CA57D072BFFB80BC30F8FAFC7FFE13D76C5736E",
                    new DeviceInfo(R.string.device_pixel_3a_xl, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            // CalyxOS
            .put("BCEBF6844F6B0FA2ABE8E62A9D0D57A324D0C02CEFDFA019FD49832F9ED39105",
                    new DeviceInfo(R.string.device_pixel_2_generic, 2, 3, true, true, R.string.os_calyx))
            .put("B4DE537A5F4B8FDAB6789EB2C06EC6E065E48A79EDD493A91F635004DD89F3E2",
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false /* uses new API */, true, R.string.os_calyx))
            .build();
    private static final ImmutableMap<String, DeviceInfo> fingerprintsStock = ImmutableMap
            .<String, DeviceInfo>builder()
            .put("5341E6B2646979A70E57653007A1F310169421EC9BDD9F1A5648F75ADE005AF1",
                    new DeviceInfo(R.string.device_huawei, 2, 3, false, true, R.string.os_stock))
            .put("7E2E8CC82A77CA74554457E5DF3A3ED82E7032B3182D17FE17919BC6E989FF09",
                    new DeviceInfo(R.string.device_huawei_honor_7a_pro, 2, 3, false, true, R.string.os_stock))
            .put("DFC2920C81E136FDD2A510478FDA137B262DC51D449EDD7D0BDB554745725CFE",
                    new DeviceInfo(R.string.device_nokia, 2, 3, true, true, R.string.os_stock))
            .put("4D790FA0A5FE81D6B352B90AFE430684D9BC817518CD24C50E6343395F7C51F2",
                    new DeviceInfo(R.string.device_nokia_3_1, 2, 3, false, false, R.string.os_stock))
            .put("893A17FD918235DB2865F7F6439EB0134A45B766AA452E0675BAC6CFB5A773AA",
                    new DeviceInfo(R.string.device_nokia_7_1, 2, 3, true, true, R.string.os_stock))
            .put("6101853DFF451FAE5B137DF914D5E6C15C659337F2C405AC50B513A159071958",
                    new DeviceInfo(R.string.device_oneplus_6_a6003, 2, 3, true, true, R.string.os_stock))
            .put("1B90B7D1449D697FB2732A7D2DFA405D587254593F5137F7B6E64F7A0CE03BFD",
                    new DeviceInfo(R.string.device_oneplus_6t_a6013, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("4B9201B11685BE6710E2B2BA8482F444E237E0C8A3D1F7F447FE29C37CECC559",
                    new DeviceInfo(R.string.device_oneplus_7_pro_gm1913, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("1962B0538579FFCE9AC9F507C46AFE3B92055BAC7146462283C85C500BE78D82",
                    new DeviceInfo(R.string.device_pixel_2, 2, 3, true, true, R.string.os_stock))
            .put("171616EAEF26009FC46DC6D89F3D24217E926C81A67CE65D2E3A9DC27040C7AB",
                    new DeviceInfo(R.string.device_pixel_2_xl, 2, 3, true, true, R.string.os_stock))
            .put("B799391AFAE3B35522D1EDC5C70A3746B097BDD1CABD59F72BB049705C7A03EF", // v1
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C", // v2
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("E75B86C52C7496255A95FB1E2B1C044BFA9D5FE34DD1E4EEBD752EEF0EA89875",
                    new DeviceInfo(R.string.device_pixel_3a_generic, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("72376CAACF11726D4922585732429FB97D0D1DD69F0D2E0770B9E61D14ADDE65",
                    new DeviceInfo(R.string.device_sm_a705fn, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("33D9484FD512E610BCF00C502827F3D55A415088F276C6506657215E622FA770",
                    new DeviceInfo(R.string.device_sm_g960f, 1, 2, false, false, R.string.os_stock))
            .put("266869F7CF2FB56008EFC4BE8946C8F84190577F9CA688F59C72DD585E696488",
                    new DeviceInfo(R.string.device_sm_g960_na, 1, 2, false, false, R.string.os_stock))
            .put("12E8460A7BAF709F3B6CF41C7E5A37C6EB4D11CB36CF7F61F7793C8DCDC3C2E4",
                    new DeviceInfo(R.string.device_sm_g9600, 1, 2, false, false, R.string.os_stock))
            .put("D1C53B7A931909EC37F1939B14621C6E4FD19BF9079D195F86B3CEA47CD1F92D",
                    new DeviceInfo(R.string.device_sm_g965f, 1, 2, false, false, R.string.os_stock))
            .put("A4A544C2CFBAEAA88C12360C2E4B44C29722FC8DBB81392A6C1FAEDB7BF63010",
                    new DeviceInfo(R.string.device_sm_g965_msm, 1, 2, false, false, R.string.os_stock))
            .put("9D77474FA4FEA6F0B28636222FBCEE2BB1E6FF9856C736C85B8EA6E3467F2BBA",
                    new DeviceInfo(R.string.device_sm_g970f, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("08B2B5C6EC8F54C00C505756E1EF516BB4537B2F02D640410D287A43FCF92E3F",
                    new DeviceInfo(R.string.device_sm_g975f, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("F0FC0AF47D3FE4F27D79CF629AD6AC42AA1EEDE0A29C0AE109A91BBD1E7CD76D",
                    new DeviceInfo(R.string.device_sm_j260a, 1, 2, false, false, R.string.os_stock))
            .put("410102030405060708090001020304050607080900010203040506070809005A",
                    new DeviceInfo(R.string.device_sm_j260f, 1, 2, false, false, R.string.os_stock))
            .put("D6B902D9E77DFC0FB3627FFEFA6D05405932EBB3A6ED077874B5E2A0CCBDB632",
                    new DeviceInfo(R.string.device_sm_j260t1, 1, 2, false, false, R.string.os_stock))
            .put("4558C1AFB30D1B46CB93F85462BC7D7FCF70B0103B9DBB0FE96DD828F43F29FC",
                    new DeviceInfo(R.string.device_sm_j337a, 1, 2, false, false, R.string.os_stock))
            .put("45E3AB5D61A03915AE10BF0465B186CB5D9A2FB6A46BEFAA76E4483BBA5A358D",
                    new DeviceInfo(R.string.device_sm_j337t, 1, 2, false, false, R.string.os_stock))
            .put("D95279A8F2E832FD68D919DBF33CFE159D5A1179686DB0BD2D7BBBF2382C4DD3",
                    new DeviceInfo(R.string.device_sm_j720f, 1, 2, false, false, R.string.os_stock))
            .put("BB053A5F64D3E3F17C4611340FF2BBE2F605B832A9FA412B2C87F2A163ECE2FB",
                    new DeviceInfo(R.string.device_sm_j737t1, 1, 2, false, false, R.string.os_stock))
            .put("4E0570011025D01386D057B2B382969F804DCD19E001344535CF0CFDB8AD7CFE",
                    new DeviceInfo(R.string.device_sm_m205f, 1, 2, false, false, R.string.os_stock))
            .put("2A7E4954C9F703F3AC805AC660EA1727B981DB39B1E0F41E4013FA2586D3DF7F",
                    new DeviceInfo(R.string.device_sm_n960f, 1, 2, false, false, R.string.os_stock))
            .put("173ACFA8AE9EDE7BBD998F45A49231F3A4BDDF0779345732E309446B46B5641B",
                    new DeviceInfo(R.string.device_sm_n960u, 1, 2, false, false, R.string.os_stock))
            .put("E94BC43B97F98CD10C22CD9D8469DBE621116ECFA624FE291A1D53CF3CD685D1",
                    new DeviceInfo(R.string.device_sm_n970f, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("466011C44BBF883DB38CF96617ED35C796CE2552C5357F9230258329E943DB70",
                    new DeviceInfo(R.string.device_sm_n970u, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("52946676088007755EB586B3E3F3E8D3821BE5DF73513E6C13640507976420E6",
                    new DeviceInfo(R.string.device_sm_n975u, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("F3688C02D9676DEDB6909CADE364C271901FD66EA4F691AEB8B8921195E469C5",
                    new DeviceInfo(R.string.device_sm_s367vl, 1, 2, false, false, R.string.os_stock))
            .put("106592D051E54388C6E601DFD61D59EB1674A8B93216C65C5B3E1830B73D3B82",
                    new DeviceInfo(R.string.device_sm_t510, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("87790149AED63553B768456AAB6DAAD5678CD87BDEB2BF3649467085349C34E0",
                    new DeviceInfo(R.string.device_sm_t835, 1, 2, false, false, R.string.os_stock))
            .put("4285AD64745CC79B4499817F264DC16BF2AF5163AF6C328964F39E61EC84693E",
                    new DeviceInfo(R.string.device_sony_xperia_xa2, 2, 3, true, true, R.string.os_stock))
            .put("54A9F21E9CFAD3A2D028517EF333A658302417DB7FB75E0A109A019646CC5F39",
                    new DeviceInfo(R.string.device_sony_xperia_xz1, 2, 3, true, true, R.string.os_stock))
            .put("BC3B5E121974113939B8A2FE758F9B923F1D195F038D2FD1C04929F886E83BB5",
                    new DeviceInfo(R.string.device_sony_xperia_xz2, 2, 3, false, true, R.string.os_stock))
            .put("94B8B4E3260B4BF8211A02CF2F3DE257A127CFFB2E4047D5580A752A5E253DE0",
                    new DeviceInfo(R.string.device_sony_xperia_xz2_compact, 2, 3, true, true, R.string.os_stock))
            .put("728800FEBB119ADD74519618AFEDB715E1C39FE08A4DE37D249BF54ACF1CE00F",
                    new DeviceInfo(R.string.device_blackberry_key2, 2, 3, true, true, R.string.os_stock))
            .put("1194659B40EA291245E54A3C4EC4AA5B7077BD244D65C7DD8C0A2DBB9DB1FB35",
                    new DeviceInfo(R.string.device_bq_aquaris_x2_pro, 2, 3, true, false, R.string.os_stock))
            .put("A9C6758D509600D0EB94FA8D2BF6EE7A6A6097F0CCEF94A755DDE065AA1AA1B0",
                    new DeviceInfo(R.string.device_xiaomi_mi_a2, 2, 3, true, false, R.string.os_stock))
            .put("6FA710B639848C9D47378937A1AFB1B6A52DDA738BEB6657E2AE70A15B40541A",
                    new DeviceInfo(R.string.device_xiaomi_mi_a2_lite, 2, 3, true, false, R.string.os_stock))
            .put("84BC8445A29B5444A2D1629C9774C8626DAFF3574D865EC5067A78FAEC96B013",
                    new DeviceInfo(R.string.device_xiaomi_mi_9, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("1CC39488D2F85DEE0A8E0903CDC4124CFDF2BE2531ED6060B678057ED2CB89B4",
                    new DeviceInfo(R.string.device_htc, 2, 3, true, false, R.string.os_stock))
            .put("80BAB060807CFFA45D4747DF1AD706FEE3AE3F645F80CF14871DDBE27E14C30B",
                    new DeviceInfo(R.string.device_moto_g7, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("C2224571C9CD5C89200A7311B1E37AA9CF751E2E19753E8D3702BCA00BE1D42C",
                    new DeviceInfo(R.string.device_motorola_one_vision, 2, 3, false, true, R.string.os_stock))
            .put("1F6D98D1B0E1F1CE1C872BD36C668F9DFDBE0D47594789E1540DF4E6198F657D",
                    new DeviceInfo(R.string.device_vivo_1807, 2, 3, true, false, R.string.os_stock))
            .put("C55635636999E9D0A0588D24402256B7F9F3AEE07B4F7E4E003F09FF0190AFAE",
                    new DeviceInfo(R.string.device_revvl_2, 2, 3, false, false, R.string.os_stock))
            .put("341C50D577DC5F3D5B46E8BFA22C22D1E5FC7D86D4D860E70B89222A7CBFC893",
                    new DeviceInfo(R.string.device_oppo_cph1831, 2, 3, true, false, R.string.os_stock))
            .put("41BF0A26BB3AFDCCCC40F7B685083522EB5BF1C492F0EC4847F351265313CB07",
                    new DeviceInfo(R.string.device_oppo_cph1903, 2, 3, true, false, R.string.os_stock))
            .put("7E19E217072BE6CB7A4C6F673FD3FB62DC51B3E204E7475838747947A3920DD8",
                    new DeviceInfo(R.string.device_oppo_cph1909, 2, 3, false, false, R.string.os_stock))
            .put("0D5F986943D0CE0D4F9783C27EEBE175BE359927DB8B6546B667279A81133C3C",
                    new DeviceInfo(R.string.device_lg_q710al, 2, 3, false, false, R.string.os_stock))
            .put("D20078F2AF2A7D3ECA3064018CB8BD47FBCA6EE61ABB41BA909D3C529CB802F4",
                    new DeviceInfo(R.string.device_lm_q720, 3, 4, false /* uses new API */, false, R.string.os_stock))
            .put("54EC644C21FD8229E3B0066513337A8E2C8EF3098A3F974B6A1CFE456A683DAE",
                    new DeviceInfo(R.string.device_rmx1941, 2, 3, false, true, R.string.os_stock))
            .build();

    private static final ImmutableMap<String, DeviceInfo> fingerprintsStrongBoxCustomOS = ImmutableMap
            .<String, DeviceInfo>builder()
            // GrapheneOS
            .put("0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF",
                    new DeviceInfo(R.string.device_pixel_3, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451",
                    new DeviceInfo(R.string.device_pixel_3_xl, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("73D6C63A07610404FE16A4E07DD24E41A70D331E9D3EF7BBA2D087E4761EB63A",
                    new DeviceInfo(R.string.device_pixel_3a, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            .put("3F36E3482E1FF82986576552CB4FD08AF09F8B09D3832314341E04C42D2919A4",
                    new DeviceInfo(R.string.device_pixel_3a_xl, 3, 4, false /* uses new API */, true, R.string.os_graphene))
            // CalyxOS
            .put("B4DE537A5F4B8FDAB6789EB2C06EC6E065E48A79EDD493A91F635004DD89F3E2",
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false /* uses new API */, true, R.string.os_calyx))
            .build();
    private static final ImmutableMap<String, DeviceInfo> fingerprintsStrongBoxStock = ImmutableMap
            .<String, DeviceInfo>builder()
            .put("61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C",
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("8CA89AF1A6DAA74B00810849356DE929CFC4498EF36AF964757BDE8A113BF46D",
                    new DeviceInfo(R.string.device_pixel_3a_generic, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("3D3DEB132A89551D0A700D230BABAE4E3E80E3C7926ACDD7BAEDF9B57AD316D0",
                    new DeviceInfo(R.string.device_sm_n970u, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .put("9AC63842137D92C119A1B1BE2C9270B9EBB6083BBE6350B7823571942B5869F0",
                    new DeviceInfo(R.string.device_sm_n975u, 3, 4, false /* uses new API */, true, R.string.os_stock))
            .build();

    private static byte[] getChallengeIndex(final Context context) {
        final SharedPreferences global = PreferenceManager.getDefaultSharedPreferences(context);
        final String challengeIndexSerialized = global.getString(KEY_CHALLENGE_INDEX, null);
        if (challengeIndexSerialized != null) {
            return BaseEncoding.base64().decode(challengeIndexSerialized);
        } else {
            final byte[] challengeIndex = getChallenge();
            global.edit()
                    .putString(KEY_CHALLENGE_INDEX, BaseEncoding.base64().encode(challengeIndex))
                    .apply();
            return challengeIndex;
        }
    }

    private static byte[] getChallenge() {
        final SecureRandom random = new SecureRandom();
        final byte[] challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        return challenge;
    }

    static byte[] getChallengeMessage(final Context context) {
        return Bytes.concat(new byte[]{PROTOCOL_VERSION}, getChallengeIndex(context), getChallenge());
    }

    private static byte[] getFingerprint(final Certificate certificate)
            throws CertificateEncodingException {
        return FINGERPRINT_HASH_FUNCTION.hashBytes(certificate.getEncoded()).asBytes();
    }

    private static class Verified {
        final int device;
        final String verifiedBootKey;
        final byte[] verifiedBootHash;
        final int osName;
        final int osVersion;
        final int osPatchLevel;
        final int vendorPatchLevel;
        final int bootPatchLevel;
        final int appVersion;
        final int securityLevel;
        final boolean perUserEncryption;

        Verified(final int device, final String verifiedBootKey, final byte[] verifiedBootHash,
                final int osName, final int osVersion, final int osPatchLevel,
                final int vendorPatchLevel, final int bootPatchLevel, final int appVersion,
                final int securityLevel, final boolean perUserEncryption) {
            this.device = device;
            this.verifiedBootKey = verifiedBootKey;
            this.verifiedBootHash = verifiedBootHash;
            this.osName = osName;
            this.osVersion = osVersion;
            this.osPatchLevel = osPatchLevel;
            this.vendorPatchLevel = vendorPatchLevel;
            this.bootPatchLevel = bootPatchLevel;
            this.appVersion = appVersion;
            this.securityLevel = securityLevel;
            this.perUserEncryption = perUserEncryption;
        }
    }

    private static X509Certificate generateCertificate(final InputStream in)
            throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    private static X509Certificate generateCertificate(final Resources resources, final int id)
            throws CertificateException, IOException {
        try (final InputStream stream = resources.openRawResource(id)) {
            return generateCertificate(stream);
        }
    }

    private static Verified verifyStateless(final Certificate[] certificates,
            final byte[] challenge, final Certificate root) throws GeneralSecurityException {

        verifyCertificateSignatures(certificates);

        // check that the root certificate is the Google key attestation root
        if (!Arrays.equals(root.getEncoded(), certificates[certificates.length - 1].getEncoded())) {
            throw new GeneralSecurityException("root certificate is not the Google key attestation root");
        }

        final Attestation attestation = new Attestation((X509Certificate) certificates[0]);

        final int attestationSecurityLevel = attestation.getAttestationSecurityLevel();

        // enforce hardware-based attestation
        if (attestationSecurityLevel != Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT &&
                attestationSecurityLevel != SECURITY_LEVEL_STRONGBOX) {
            throw new GeneralSecurityException("attestation security level is not valid");
        }
        if (attestation.getKeymasterSecurityLevel() != attestationSecurityLevel) {
            throw new GeneralSecurityException("keymaster security level is not valid");
        }

        // prevent replay attacks
        if (!Arrays.equals(attestation.getAttestationChallenge(), challenge)) {
            throw new GeneralSecurityException("challenge mismatch");
        }

        // enforce communicating with the attestation app via OS level security
        final AuthorizationList softwareEnforced = attestation.getSoftwareEnforced();
        final AttestationApplicationId attestationApplicationId = softwareEnforced.getAttestationApplicationId();
        final List<AttestationPackageInfo> infos = attestationApplicationId.getAttestationPackageInfos();
        if (infos.size() != 1) {
            throw new GeneralSecurityException("wrong number of attestation packages");
        }
        final AttestationPackageInfo info = infos.get(0);
        if (!ATTESTATION_APP_PACKAGE_NAME.equals(info.getPackageName())) {
            throw new GeneralSecurityException("wrong attestation app package name");
        }
        final int appVersion = Math.toIntExact(info.getVersion()); // int for compatibility
        if (appVersion < ATTESTATION_APP_MINIMUM_VERSION) {
            throw new GeneralSecurityException("attestation app is too old");
        }
        final List<byte[]> signatureDigests = attestationApplicationId.getSignatureDigests();
        if (signatureDigests.size() != 1) {
            throw new GeneralSecurityException("wrong number of attestation app signature digests");
        }
        final String signatureDigest = BaseEncoding.base16().encode(signatureDigests.get(0));
        if (!ATTESTATION_APP_SIGNATURE_DIGEST_RELEASE.equals(signatureDigest)) {
            if (!BuildConfig.DEBUG || !ATTESTATION_APP_SIGNATURE_DIGEST_DEBUG.equals(signatureDigest)) {
                throw new GeneralSecurityException("wrong attestation app signature digest");
            }
        }

        final AuthorizationList teeEnforced = attestation.getTeeEnforced();

        // verified boot security checks
        final RootOfTrust rootOfTrust = teeEnforced.getRootOfTrust();
        if (rootOfTrust == null) {
            throw new GeneralSecurityException("missing root of trust");
        }
        if (!rootOfTrust.isDeviceLocked()) {
            throw new GeneralSecurityException("device is not locked");
        }
        final int verifiedBootState = rootOfTrust.getVerifiedBootState();
        final String verifiedBootKey = BaseEncoding.base16().encode(rootOfTrust.getVerifiedBootKey());
        final DeviceInfo device;
        if (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED) {
            if (attestationSecurityLevel == SECURITY_LEVEL_STRONGBOX) {
                device = fingerprintsStrongBoxCustomOS.get(verifiedBootKey);
            } else {
                device = fingerprintsCustomOS.get(verifiedBootKey);
            }
        } else if (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_VERIFIED) {
            if (attestationSecurityLevel == SECURITY_LEVEL_STRONGBOX) {
                device = fingerprintsStrongBoxStock.get(verifiedBootKey);
            } else {
                device = fingerprintsStock.get(verifiedBootKey);
            }
        } else {
            throw new GeneralSecurityException("verified boot state is not verified or self signed");
        }

        if (device == null) {
            throw new GeneralSecurityException("invalid verified boot key fingerprint: " + verifiedBootKey);
        }

        // OS version sanity checks
        final int osVersion = teeEnforced.getOsVersion();
        if (osVersion == DEVELOPER_PREVIEW_OS_VERSION) {
            if (!BuildConfig.DEBUG) {
                throw new GeneralSecurityException("OS version is not a production release");
            }
        } else if (osVersion < OS_VERSION_MINIMUM) {
            throw new GeneralSecurityException("OS version too old: " + osVersion);
        }
        final int osPatchLevel = teeEnforced.getOsPatchLevel();
        if (osPatchLevel < OS_PATCH_LEVEL_MINIMUM) {
            throw new GeneralSecurityException("OS patch level too old: " + osPatchLevel);
        }
        final int vendorPatchLevel;
        if (teeEnforced.getVendorPatchLevel() == null) {
            vendorPatchLevel = 0;
        } else {
            vendorPatchLevel = teeEnforced.getVendorPatchLevel();
            if (vendorPatchLevel < VENDOR_PATCH_LEVEL_MINIMUM && !extraPatchLevelMissing.contains(device.name)) {
                throw new GeneralSecurityException("Vendor patch level too old: " + vendorPatchLevel);
            }
        }
        final int bootPatchLevel;
        if (teeEnforced.getBootPatchLevel() == null) {
            bootPatchLevel = 0;
        } else {
            bootPatchLevel = teeEnforced.getBootPatchLevel();
            if (bootPatchLevel < BOOT_PATCH_LEVEL_MINIMUM && !extraPatchLevelMissing.contains(device.name)) {
                throw new GeneralSecurityException("Boot patch level too old: " + bootPatchLevel);
            }
        }

        // key sanity checks
        if (teeEnforced.getOrigin() != AuthorizationList.KM_ORIGIN_GENERATED) {
            throw new GeneralSecurityException("not a generated key");
        }
        if (teeEnforced.isAllApplications()) {
            throw new GeneralSecurityException("expected key only usable by attestation app");
        }
        if (device.rollbackResistant && !teeEnforced.isRollbackResistant()) {
            throw new GeneralSecurityException("expected rollback resistant key");
        }

        // version sanity checks
        final int attestationVersion = attestation.getAttestationVersion();
        if (attestationVersion < device.attestationVersion) {
            throw new GeneralSecurityException("attestation version " + attestationVersion + " below " + device.attestationVersion);
        }
        final int keymasterVersion = attestation.getKeymasterVersion();
        if (keymasterVersion < device.keymasterVersion) {
            throw new GeneralSecurityException("keymaster version " + keymasterVersion + " below " + device.keymasterVersion);
        }

        final byte[] verifiedBootHash = rootOfTrust.getVerifiedBootHash();
        if (attestationVersion >= 3 && verifiedBootHash == null) {
            throw new GeneralSecurityException("verifiedBootHash expected for attestation version >= 3");
        }

        return new Verified(device.name, verifiedBootKey, verifiedBootHash, device.osName,
                osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel, appVersion,
                attestationSecurityLevel, device.perUserEncryption);
    }

    private static void verifyCertificateSignatures(Certificate[] certChain)
            throws GeneralSecurityException {
        for (int i = 1; i < certChain.length; ++i) {
            final PublicKey pubKey = certChain[i].getPublicKey();
            try {
                ((X509Certificate) certChain[i - 1]).checkValidity();
                certChain[i - 1].verify(pubKey);
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                    | NoSuchProviderException | SignatureException e) {
                throw new GeneralSecurityException("Failed to verify certificate "
                        + certChain[i - 1] + " with public key " + certChain[i].getPublicKey(), e);
            }
            if (i == certChain.length - 1) {
                // Last cert is self-signed.
                try {
                    ((X509Certificate) certChain[i]).checkValidity();
                    certChain[i].verify(pubKey);
                } catch (CertificateException e) {
                    throw new GeneralSecurityException(
                            "Root cert " + certChain[i] + " is not correctly self-signed", e);
                }
            }
        }
    }

    private static void appendVerifiedInformation(final Context context,
            final StringBuilder builder, final Verified verified, final String fingerprint) {
        builder.append(context.getString(R.string.device, context.getString(verified.device)));
        builder.append(context.getString(R.string.os, context.getString(verified.osName)));

        if (verified.osVersion == DEVELOPER_PREVIEW_OS_VERSION) {
            builder.append(context.getString(R.string.os_version,
                    context.getString(R.string.os_version_developer_preview)));
        } else {
            final String osVersion = String.format(Locale.US, "%06d", verified.osVersion);
            builder.append(context.getString(R.string.os_version,
                        Integer.parseInt(osVersion.substring(0, 2)) + "." +
                        Integer.parseInt(osVersion.substring(2, 4)) + "." +
                        Integer.parseInt(osVersion.substring(4, 6))));
        }

        final String osPatchLevel = Integer.toString(verified.osPatchLevel);
        builder.append(context.getString(R.string.os_patch_level,
                osPatchLevel.substring(0, 4) + "-" + osPatchLevel.substring(4, 6)));

        final String vendorPatchLevel = Integer.toString(verified.vendorPatchLevel);
        if (verified.vendorPatchLevel != 0) {
            builder.append(context.getString(R.string.vendor_patch_level,
                    vendorPatchLevel.substring(0, 4) + "-" + vendorPatchLevel.substring(4, 6)));
        }

        final String bootPatchLevel = Integer.toString(verified.bootPatchLevel);
        if (verified.bootPatchLevel != 0) {
            builder.append(context.getString(R.string.boot_patch_level,
                    bootPatchLevel.substring(0, 4) + "-" + bootPatchLevel.substring(4, 6)));
        }

        if (verified.verifiedBootHash != null) {
            builder.append(context.getString(R.string.verified_boot_hash,
                    BaseEncoding.base16().encode(verified.verifiedBootHash)));
        }

        final String securityLevel;
        if (verified.securityLevel == SECURITY_LEVEL_STRONGBOX) {
            securityLevel = context.getString(R.string.security_level_strongbox);
        } else {
            securityLevel = context.getString(R.string.security_level_tee);
        }
        builder.append(context.getString(R.string.security_level, securityLevel));

        final StringBuilder splitFingerprint = new StringBuilder();
        for (int i = 0; i < fingerprint.length(); i += FINGERPRINT_SPLIT_INTERVAL) {
            splitFingerprint.append(fingerprint.substring(i,
                    Math.min(fingerprint.length(), i + FINGERPRINT_SPLIT_INTERVAL)));
            if (i + FINGERPRINT_SPLIT_INTERVAL < fingerprint.length()) {
                splitFingerprint.append("-");
            }
        }
        builder.append(context.getString(R.string.identity, splitFingerprint.toString()));
    }

    private static void verifySignature(final PublicKey key, final ByteBuffer message,
            final byte[] signature) throws GeneralSecurityException {
        final Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(key);
        sig.update(message);
        if (!sig.verify(signature)) {
            throw new GeneralSecurityException("signature verification failed");
        }
    }

    static class VerificationResult {
        final boolean strong;
        final String teeEnforced;
        final String osEnforced;

        VerificationResult(final boolean strong, final String teeEnforced,
                final String osEnforced) {
            this.strong = strong;
            this.teeEnforced = teeEnforced;
            this.osEnforced = osEnforced;
        }
    }

    private static String toYesNoString(final Context context, final boolean value) {
        return value ? context.getString(R.string.yes) : context.getString(R.string.no);
    }

    private static VerificationResult verify(final Context context, final byte[] fingerprint,
            final byte[] challenge, final ByteBuffer signedMessage, final byte[] signature,
            final Certificate[] attestationCertificates, final boolean userProfileSecure,
            final boolean accessibility, final boolean deviceAdmin,
            final boolean deviceAdminNonSystem, final boolean adbEnabled,
            final boolean addUsersWhenLocked, final boolean enrolledFingerprints,
            final boolean denyNewUsb, final boolean oemUnlockAllowed, final boolean systemUser)
            throws GeneralSecurityException, IOException {
        final String fingerprintHex = BaseEncoding.base16().encode(fingerprint);
        final byte[] currentFingerprint = getFingerprint(attestationCertificates[0]);
        final boolean hasPersistentKey = !Arrays.equals(currentFingerprint, fingerprint);

        final SharedPreferences preferences =
                context.getSharedPreferences(PREFERENCES_DEVICE_PREFIX + fingerprintHex,
                        Context.MODE_PRIVATE);
        if (hasPersistentKey && !preferences.contains(KEY_PINNED_CERTIFICATE_LENGTH)) {
            throw new GeneralSecurityException(
                    "Pairing data for this Auditee is missing. Cannot perform paired attestation.\n" +
                    "\nEither the initial pairing was incomplete or the device is compromised.\n" +
                    "\nIf the initial pairing was simply not completed, clear the pairing data on either the Auditee or the Auditor via the menu and try again.\n");
        }

        final Verified verified = verifyStateless(attestationCertificates, challenge,
            generateCertificate(context.getResources(), R.raw.google_root));

        final StringBuilder teeEnforced = new StringBuilder();

        if (hasPersistentKey) {
            if (attestationCertificates.length != preferences.getInt(KEY_PINNED_CERTIFICATE_LENGTH, 0)) {
                throw new GeneralSecurityException("certificate chain mismatch");
            }
            for (int i = 1; i < attestationCertificates.length; i++) {
                final byte[] b = BaseEncoding.base64().decode(preferences.getString(KEY_PINNED_CERTIFICATE + i, ""));
                if (!Arrays.equals(attestationCertificates[i].getEncoded(), b)) {
                    throw new GeneralSecurityException("certificate chain mismatch");
                }
            }

            final byte[] persistentCertificateEncoded = BaseEncoding.base64().decode(preferences.getString(KEY_PINNED_CERTIFICATE + "0", ""));
            final Certificate persistentCertificate = generateCertificate(
                    new ByteArrayInputStream(persistentCertificateEncoded));
            if (!Arrays.equals(fingerprint, getFingerprint(persistentCertificate))) {
                throw new GeneralSecurityException("corrupt Auditor pinning data");
            }
            verifySignature(persistentCertificate.getPublicKey(), signedMessage, signature);

            final String pinnedVerifiedBootKey = preferences.getString(KEY_PINNED_VERIFIED_BOOT_KEY, null);
            if (!verified.verifiedBootKey.equals(pinnedVerifiedBootKey)) {
                final String legacyFingerprint = fingerprintsMigration.get(verified.verifiedBootKey);
                if (legacyFingerprint != null && legacyFingerprint.equals(pinnedVerifiedBootKey)) {
                    Log.d(TAG, "migration from legacy fingerprint " + legacyFingerprint + " to " + verified.verifiedBootKey);
                } else {
                    throw new GeneralSecurityException("pinned verified boot key mismatch");
                }
            }
            if (verified.osVersion != DEVELOPER_PREVIEW_OS_VERSION &&
                    verified.osVersion < preferences.getInt(KEY_PINNED_OS_VERSION, Integer.MAX_VALUE)) {
                throw new GeneralSecurityException("OS version downgrade detected");
            }
            if (verified.osPatchLevel < preferences.getInt(KEY_PINNED_OS_PATCH_LEVEL, Integer.MAX_VALUE)) {
                throw new GeneralSecurityException("OS patch level downgrade detected");
            }
            if (verified.vendorPatchLevel < preferences.getInt(KEY_PINNED_VENDOR_PATCH_LEVEL, 0)) {
                throw new GeneralSecurityException("Vendor patch level downgrade detected");
            }
            if (verified.bootPatchLevel < preferences.getInt(KEY_PINNED_BOOT_PATCH_LEVEL, 0)) {
                throw new GeneralSecurityException("Boot patch level downgrade detected");
            }
            final int pinnedAppVersion = preferences.getInt(KEY_PINNED_APP_VERSION, Integer.MAX_VALUE);
            if (verified.appVersion < pinnedAppVersion) {
                throw new GeneralSecurityException("App version downgraded");
            }
            if (verified.securityLevel != preferences.getInt(KEY_PINNED_SECURITY_LEVEL, Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT)) {
                throw new GeneralSecurityException("Security level mismatch");
            }

            appendVerifiedInformation(context, teeEnforced, verified, fingerprintHex);
            teeEnforced.append(context.getString(R.string.first_verified,
                    new Date(preferences.getLong(KEY_VERIFIED_TIME_FIRST, 0))));
            teeEnforced.append(context.getString(R.string.last_verified,
                    new Date(preferences.getLong(KEY_VERIFIED_TIME_LAST, 0))));

            final SharedPreferences.Editor editor = preferences.edit();
            // handle migration to v2 verified boot key fingerprint
            editor.putString(KEY_PINNED_VERIFIED_BOOT_KEY, verified.verifiedBootKey);
            editor.putInt(KEY_PINNED_OS_VERSION, verified.osVersion);
            editor.putInt(KEY_PINNED_OS_PATCH_LEVEL, verified.osPatchLevel);
            if (verified.vendorPatchLevel != 0) {
                editor.putInt(KEY_PINNED_VENDOR_PATCH_LEVEL, verified.vendorPatchLevel);
            }
            if (verified.bootPatchLevel != 0) {
                editor.putInt(KEY_PINNED_BOOT_PATCH_LEVEL, verified.bootPatchLevel);
            }
            editor.putInt(KEY_PINNED_APP_VERSION, verified.appVersion);
            editor.putInt(KEY_PINNED_SECURITY_LEVEL, verified.securityLevel); // new field
            editor.putLong(KEY_VERIFIED_TIME_LAST, new Date().getTime());
            editor.apply();
        } else {
            verifySignature(attestationCertificates[0].getPublicKey(), signedMessage, signature);

            final SharedPreferences.Editor editor = preferences.edit();

            editor.putInt(KEY_PINNED_CERTIFICATE_LENGTH, attestationCertificates.length);
            for (int i = 0; i < attestationCertificates.length; i++) {
                final String encoded = BaseEncoding.base64().encode(
                        attestationCertificates[i].getEncoded());
                editor.putString(KEY_PINNED_CERTIFICATE + i, encoded);
            }

            editor.putString(KEY_PINNED_VERIFIED_BOOT_KEY, verified.verifiedBootKey);
            editor.putInt(KEY_PINNED_OS_VERSION, verified.osVersion);
            editor.putInt(KEY_PINNED_OS_PATCH_LEVEL, verified.osPatchLevel);
            if (verified.vendorPatchLevel != 0) {
                editor.putInt(KEY_PINNED_VENDOR_PATCH_LEVEL, verified.vendorPatchLevel);
            }
            if (verified.bootPatchLevel != 0) {
                editor.putInt(KEY_PINNED_BOOT_PATCH_LEVEL, verified.bootPatchLevel);
            }
            editor.putInt(KEY_PINNED_APP_VERSION, verified.appVersion);
            editor.putInt(KEY_PINNED_SECURITY_LEVEL, verified.securityLevel);

            final long now = new Date().getTime();
            editor.putLong(KEY_VERIFIED_TIME_FIRST, now);
            editor.putLong(KEY_VERIFIED_TIME_LAST, now);

            editor.apply();

            appendVerifiedInformation(context, teeEnforced, verified, fingerprintHex);
        }

        final StringBuilder osEnforced = new StringBuilder();
        osEnforced.append(context.getString(R.string.auditor_app_version, verified.appVersion));
        osEnforced.append(context.getString(R.string.user_profile_secure,
                toYesNoString(context, userProfileSecure)));
        osEnforced.append(context.getString(R.string.enrolled_fingerprints,
                toYesNoString(context, enrolledFingerprints)));
        osEnforced.append(context.getString(R.string.accessibility,
                toYesNoString(context, accessibility)));

        final String deviceAdminState;
        if (deviceAdminNonSystem) {
            deviceAdminState = context.getString(R.string.device_admin_non_system);
        } else if (deviceAdmin) {
            deviceAdminState = context.getString(R.string.device_admin_system);
        } else {
            deviceAdminState = context.getString(R.string.no);
        }
        osEnforced.append(context.getString(R.string.device_admin, deviceAdminState));

        osEnforced.append(context.getString(R.string.adb_enabled,
                toYesNoString(context, adbEnabled)));
        osEnforced.append(context.getString(R.string.add_users_when_locked,
                toYesNoString(context, addUsersWhenLocked)));
        osEnforced.append(context.getString(R.string.deny_new_usb,
                toYesNoString(context, denyNewUsb)));
        osEnforced.append(context.getString(R.string.oem_unlock_allowed,
                toYesNoString(context, oemUnlockAllowed)));
        if (verified.appVersion >= 14) {
            osEnforced.append(context.getString(R.string.system_user,
                    toYesNoString(context, systemUser)));
        }

        return new VerificationResult(hasPersistentKey, teeEnforced.toString(), osEnforced.toString());
    }

    static VerificationResult verifySerialized(final Context context, final byte[] attestationResult,
            final byte[] challengeMessage) throws DataFormatException, GeneralSecurityException, IOException {
        final ByteBuffer deserializer = ByteBuffer.wrap(attestationResult);
        final byte version = deserializer.get();
        if (version > PROTOCOL_VERSION) {
            throw new GeneralSecurityException("invalid protocol version: " + version);
        } else if (version < PROTOCOL_VERSION_MINIMUM) {
            throw new GeneralSecurityException("Auditee protocol version too old: " + version);
        }

        final short compressedChainLength = deserializer.getShort();
        final byte[] compressedChain = new byte[compressedChainLength];
        deserializer.get(compressedChain);

        final byte[] chain = new byte[MAX_ENCODED_CHAIN_LENGTH];
        final Inflater inflater = new Inflater(true);
        inflater.setInput(compressedChain);
        final int dictionary = R.raw.deflate_dictionary_1;
        try (final InputStream stream = context.getResources().openRawResource(dictionary)) {
            inflater.setDictionary(ByteStreams.toByteArray(stream));
        }
        final int chainLength = inflater.inflate(chain);
        if (!inflater.finished()) {
            throw new GeneralSecurityException("certificate chain is too large");
        }
        inflater.end();
        Log.d(TAG, "encoded length: " + chainLength + ", compressed length: " + compressedChain.length);

        final ByteBuffer chainDeserializer = ByteBuffer.wrap(chain, 0, chainLength);
        final List<Certificate> certs = new ArrayList<>();
        while (chainDeserializer.hasRemaining()) {
            final short encodedLength = chainDeserializer.getShort();
            final byte[] encoded = new byte[encodedLength];
            chainDeserializer.get(encoded);
            certs.add(generateCertificate(new ByteArrayInputStream(encoded)));
        }
        final Certificate[] certificates = certs.toArray(new Certificate[certs.size() + 1]);

        final byte[] fingerprint = new byte[FINGERPRINT_LENGTH];
        deserializer.get(fingerprint);

        final int osEnforcedFlags;
        osEnforcedFlags = deserializer.getInt();
        if ((osEnforcedFlags & ~OS_ENFORCED_FLAGS_ALL) != 0) {
            Log.w(TAG, "unknown OS enforced flag set (flags: " + Integer.toBinaryString(osEnforcedFlags) + ")");
        }
        final boolean userProfileSecure = (osEnforcedFlags & OS_ENFORCED_FLAGS_USER_PROFILE_SECURE) != 0;
        final boolean accessibility = (osEnforcedFlags & OS_ENFORCED_FLAGS_ACCESSIBILITY) != 0;
        final boolean deviceAdmin = (osEnforcedFlags & OS_ENFORCED_FLAGS_DEVICE_ADMIN) != 0;
        final boolean deviceAdminNonSystem = (osEnforcedFlags & OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM) != 0;
        final boolean adbEnabled = (osEnforcedFlags & OS_ENFORCED_FLAGS_ADB_ENABLED) != 0;
        final boolean addUsersWhenLocked = (osEnforcedFlags & OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED) != 0;
        final boolean enrolledFingerprints = (osEnforcedFlags & OS_ENFORCED_FLAGS_ENROLLED_FINGERPRINTS) != 0;
        final boolean denyNewUsb = (osEnforcedFlags & OS_ENFORCED_FLAGS_DENY_NEW_USB) != 0;
        final boolean oemUnlockAllowed = (osEnforcedFlags & OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED) != 0;
        final boolean systemUser = (osEnforcedFlags & OS_ENFORCED_FLAGS_SYSTEM_USER) != 0;

        if (deviceAdminNonSystem && !deviceAdmin) {
            throw new GeneralSecurityException("invalid device administrator state");
        }

        final int signatureLength = deserializer.remaining();
        final byte[] signature = new byte[signatureLength];
        deserializer.get(signature);

        certificates[certificates.length - 1] = generateCertificate(context.getResources(), R.raw.google_root);

        deserializer.rewind();
        deserializer.limit(deserializer.capacity() - signature.length);

        final byte[] challenge = Arrays.copyOfRange(challengeMessage, 1 + CHALLENGE_LENGTH, 1 + CHALLENGE_LENGTH * 2);
        return verify(context, fingerprint, challenge, deserializer.asReadOnlyBuffer(), signature,
                certificates, userProfileSecure, accessibility, deviceAdmin, deviceAdminNonSystem,
                adbEnabled, addUsersWhenLocked, enrolledFingerprints, denyNewUsb, oemUnlockAllowed,
                systemUser);
    }

    static class AttestationResult {
        final boolean pairing;
        final byte[] serialized;

        AttestationResult(final boolean pairing, final byte[] serialized) {
            this.pairing = pairing;
            this.serialized = serialized;
        }
    }

    @TargetApi(28)
    static void enableStrongBox(final KeyGenParameterSpec.Builder builder) {
        builder.setIsStrongBoxBacked(true);
    }

    // Need FingerprintManager until BiometricManager is available in API 29+
    @SuppressWarnings("deprecation")
    static boolean hasEnrolledFingerprints(final Context context) {
        return context.getSystemService(android.hardware.fingerprint.FingerprintManager.class)
                .hasEnrolledFingerprints();
    }

    static AttestationResult generateSerialized(final Context context, final byte[] challengeMessage,
            String index, final String statePrefix) throws GeneralSecurityException, IOException {
        if (challengeMessage.length < CHALLENGE_MESSAGE_LENGTH) {
            throw new GeneralSecurityException("challenge message is too small");
        }

        final byte maxVersion = challengeMessage[0];
        if (maxVersion <= PROTOCOL_VERSION && challengeMessage.length != CHALLENGE_MESSAGE_LENGTH) {
            throw new GeneralSecurityException("challenge message is not the expected size");
        }
        if (maxVersion < PROTOCOL_VERSION_MINIMUM) {
            throw new GeneralSecurityException("Auditor protocol version too old: " + maxVersion);
        }
        final byte[] challengeIndex = Arrays.copyOfRange(challengeMessage, 1, 1 + CHALLENGE_LENGTH);
        final byte[] challenge = Arrays.copyOfRange(challengeMessage, 1 + CHALLENGE_LENGTH, 1 + CHALLENGE_LENGTH * 2);

        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (index == null) {
            index = BaseEncoding.base16().encode(challengeIndex);
        }

        final String persistentKeystoreAlias =
                statePrefix + KEYSTORE_ALIAS_PERSISTENT_PREFIX + index;

        // generate a new key for fresh attestation results unless the persistent key is not yet created
        keyStore.deleteEntry(statePrefix + KEYSTORE_ALIAS_FRESH);
        final boolean hasPersistentKey = keyStore.containsAlias(persistentKeystoreAlias);
        final String attestationKeystoreAlias;
        final boolean useStrongBox;
        if (hasPersistentKey) {
            attestationKeystoreAlias = statePrefix + KEYSTORE_ALIAS_FRESH;
            final X509Certificate persistent =
                (X509Certificate) keyStore.getCertificate(persistentKeystoreAlias);
            final String dn = persistent.getIssuerX500Principal().getName(X500Principal.RFC1779);
            useStrongBox = dn.contains("StrongBox");
        } else {
            attestationKeystoreAlias = persistentKeystoreAlias;
            useStrongBox = isStrongBoxSupported && PREFER_STRONGBOX;
        }

        final Date startTime = new Date(new Date().getTime() - CLOCK_SKEW_MS);
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(attestationKeystoreAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                .setDigests(KEY_DIGEST)
                .setAttestationChallenge(challenge)
                .setKeyValidityStart(startTime);
        if (hasPersistentKey) {
            builder.setKeyValidityEnd(new Date(startTime.getTime() + EXPIRE_OFFSET_MS));
        }
        if (useStrongBox) {
            enableStrongBox(builder);
        }
        generateKeyPair(KEY_ALGORITHM_EC, builder.build());

        try {
            final byte[] fingerprint =
                    getFingerprint(keyStore.getCertificate(persistentKeystoreAlias));

            final Certificate[] attestationCertificates = keyStore.getCertificateChain(attestationKeystoreAlias);

            // sanity check on the device being verified before sending it off to the verifying device
            final Verified verified = verifyStateless(attestationCertificates, challenge,
                    attestationCertificates[attestationCertificates.length - 1]);

            // OS-enforced checks and information

            final DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);

            final List<ComponentName> activeAdmins = dpm.getActiveAdmins();
            final boolean deviceAdmin = activeAdmins != null && activeAdmins.size() > 0;
            boolean deviceAdminNonSystem = false;
            if (activeAdmins != null) {
                for (final ComponentName name : activeAdmins) {
                    final PackageManager pm = context.getPackageManager();
                    try {
                        final ApplicationInfo info = pm.getApplicationInfo(name.getPackageName(), 0);
                        if ((info.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {
                            deviceAdminNonSystem = true;
                        }
                    } catch (final PackageManager.NameNotFoundException e) {
                        throw new GeneralSecurityException(e);
                    }
                }
            }

            final int encryptionStatus = dpm.getStorageEncryptionStatus();
            if (verified.perUserEncryption) {
                if (encryptionStatus != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER) {
                    throw new GeneralSecurityException("invalid encryption status");
                }
            } else {
                if (encryptionStatus != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE &&
                        encryptionStatus != DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY) {
                    throw new GeneralSecurityException("invalid encryption status");
                }
            }
            final KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
            final boolean userProfileSecure = keyguard.isDeviceSecure();
            if (userProfileSecure && !keyguard.isKeyguardSecure()) {
                throw new GeneralSecurityException("keyguard state inconsistent");
            }
            final boolean enrolledFingerprints = hasEnrolledFingerprints(context);

            final AccessibilityManager am = context.getSystemService(AccessibilityManager.class);
            final boolean accessibility = am.isEnabled();

            final boolean adbEnabled = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) != 0;
            final boolean addUsersWhenLocked = Settings.Global.getInt(context.getContentResolver(),
                    ADD_USERS_WHEN_LOCKED, 0) != 0;

            final String denyNewUsbValue =
                    SystemProperties.get("persist.security.deny_new_usb", "disabled");
            final boolean denyNewUsb = !denyNewUsbValue.equals("disabled");

            final String oemUnlockAllowedValue = SystemProperties.get("sys.oem_unlock_allowed", "0");
            final boolean oemUnlockAllowed = oemUnlockAllowedValue.equals("1");

            final UserManager userManager = context.getSystemService(UserManager.class);
            final boolean systemUser = userManager.isSystemUser();

            // Serialization

            final ByteBuffer serializer = ByteBuffer.allocate(MAX_MESSAGE_SIZE);

            final byte version = (byte) Math.min(PROTOCOL_VERSION, maxVersion);
            serializer.put(version);

            final ByteBuffer chainSerializer = ByteBuffer.allocate(MAX_ENCODED_CHAIN_LENGTH);
            final int certificateCount = attestationCertificates.length - 1;
            for (int i = 0; i < certificateCount; i++) {
                final byte[] encoded = attestationCertificates[i].getEncoded();
                if (encoded.length > Short.MAX_VALUE) {
                    throw new RuntimeException("encoded certificate too long");
                }
                chainSerializer.putShort((short) encoded.length);
                chainSerializer.put(encoded);
            }
            chainSerializer.flip();
            final byte[] chain = new byte[chainSerializer.remaining()];
            chainSerializer.get(chain);

            if (chain.length > MAX_ENCODED_CHAIN_LENGTH) {
                throw new RuntimeException("encoded certificate chain too long");
            }

            final ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
            final int dictionary = R.raw.deflate_dictionary_1;
            try (final InputStream stream = context.getResources().openRawResource(dictionary)) {
                deflater.setDictionary(ByteStreams.toByteArray(stream));
            }
            final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(byteStream, deflater);
            deflaterStream.write(chain);
            deflaterStream.finish();
            final byte[] compressed = byteStream.toByteArray();
            Log.d(TAG, "encoded length: " + chain.length + ", compressed length: " + compressed.length);

            if (compressed.length > Short.MAX_VALUE) {
                throw new RuntimeException("compressed chain too long");
            }
            serializer.putShort((short) compressed.length);
            serializer.put(compressed);

            if (fingerprint.length != FINGERPRINT_LENGTH) {
                throw new RuntimeException("fingerprint length mismatch");
            }
            serializer.put(fingerprint);

            int osEnforcedFlags = OS_ENFORCED_FLAGS_NONE;
            if (userProfileSecure) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_USER_PROFILE_SECURE;
            }
            if (accessibility) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_ACCESSIBILITY;
            }
            if (deviceAdmin) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_DEVICE_ADMIN;
            }
            if (deviceAdminNonSystem) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM;
            }
            if (adbEnabled) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_ADB_ENABLED;
            }
            if (addUsersWhenLocked) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED;
            }
            if (enrolledFingerprints) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_ENROLLED_FINGERPRINTS;
            }
            if (denyNewUsb) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_DENY_NEW_USB;
            }
            if (oemUnlockAllowed) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED;
            }
            if (systemUser) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_SYSTEM_USER;
            }
            serializer.putInt(osEnforcedFlags);

            final ByteBuffer message = serializer.duplicate();
            message.flip();

            final Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initSign((PrivateKey) keyStore.getKey(persistentKeystoreAlias, null));
            sig.update(message);
            final byte[] signature = sig.sign();

            serializer.put(signature);

            serializer.flip();
            final byte[] serialized = new byte[serializer.remaining()];
            serializer.get(serialized);

            return new AttestationResult(!hasPersistentKey, serialized);
        } catch (final GeneralSecurityException | IOException e) {
            if (!hasPersistentKey) {
                keyStore.deleteEntry(persistentKeystoreAlias);
            }
            throw e;
        }
    }

    static void generateKeyPair(final String algorithm, final KeyGenParameterSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, IOException {
        // Handle RuntimeExceptions caused by a broken keystore. A common issue involves users
        // unlocking the device and wiping the encrypted TEE attestation keys from the persist
        // partition. Additionally, some non-CTS compliant devices or operating systems have a
        // non-existent or broken implementation. No one has reported these uncaught exceptions,
        // presumably because they know their device or OS is broken, but the crash reports are
        // being spammed to the Google Play error collection and causing it to think the app is
        // unreliable.
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                    "AndroidKeyStore");
            keyPairGenerator.initialize(spec);
            keyPairGenerator.generateKeyPair();
        } catch (final ProviderException e) {
            throw new IOException(e);
        }
    }

    static void clearAuditee() throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (alias.startsWith(KEYSTORE_ALIAS_PERSISTENT_PREFIX)) {
                Log.d(TAG, "deleting key " + alias);
                keyStore.deleteEntry(alias);
            }
        }
    }

    static void clearAuditee(final String statePrefix, final String index)
            throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        final String alias = statePrefix + KEYSTORE_ALIAS_PERSISTENT_PREFIX + index;
        Log.d(TAG, "deleting key " + alias);
        keyStore.deleteEntry(alias);
    }

    static void clearAuditor(final Context context) {
        PreferenceManager.getDefaultSharedPreferences(context)
                .edit().remove(KEY_CHALLENGE_INDEX).apply();

        final File dir = new File(context.getFilesDir().getParent() + "/shared_prefs/");
        for (final String file : dir.list()) {
            if (file.startsWith(PREFERENCES_DEVICE_PREFIX)) {
                final String name = file.replace(".xml", "");
                Log.d(TAG, "delete SharedPreferences " + name);
                context.deleteSharedPreferences(name);
            }
        }
    }
}
