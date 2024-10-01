package app.attestation.auditor;

import android.annotation.SuppressLint;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.SecurityStateManager;
import android.os.UserManager;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.accessibility.AccessibilityManager;

import androidx.biometric.BiometricManager;
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
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

import app.attestation.auditor.attestation.AttestationApplicationId;
import app.attestation.auditor.attestation.AttestationApplicationId.AttestationPackageInfo;
import app.attestation.auditor.attestation.AuthorizationList;
import app.attestation.auditor.attestation.ParsedAttestationRecord;
import app.attestation.auditor.attestation.RootOfTrust;

import static android.security.keystore.KeyProperties.DIGEST_SHA256;

import static androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK;
import static androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS;

class AttestationProtocol {
    private static final String TAG = "AttestationProtocol";

    // Settings.Global.ADD_USERS_WHEN_LOCKED is a private API
    private static final String ADD_USERS_WHEN_LOCKED = "add_users_when_locked";

    private static final int CLOCK_SKEW_MS = 5 * 60 * 1000;
    private static final int EXPIRATION_MS = 5 * 60 * 1000;

    private static final String KEYSTORE_ALIAS_FRESH = "fresh_attestation_key";
    private static final String KEYSTORE_ALIAS_PERSISTENT_PREFIX = "persistent_attestation_key_";
    private static final String KEYSTORE_ALIAS_ATTEST_PREFIX = "attest_key_";

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
    private static final String KEY_PINNED_APP_VARIANT = "pinned_app_variant";
    private static final String KEY_PINNED_SECURITY_LEVEL = "pinned_security_level";
    private static final String KEY_VERIFIED_TIME_FIRST = "verified_time_first";
    private static final String KEY_VERIFIED_TIME_LAST = "verified_time_last";

    private static final int RANDOM_TOKEN_LENGTH = 32;
    static final String EC_CURVE = "secp256r1";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithECDSA";
    static final String KEY_DIGEST = DIGEST_SHA256;
    private static final HashFunction FINGERPRINT_HASH_FUNCTION = Hashing.sha256();
    private static final int FINGERPRINT_LENGTH = FINGERPRINT_HASH_FUNCTION.bits() / 8;

    private static final boolean PREFER_STRONGBOX = true;

    // Challenge message:
    //
    // byte maxVersion = PROTOCOL_VERSION
    // byte[] challenge index (length: RANDOM_TOKEN_LENGTH)
    // byte[] challenge (length: RANDOM_TOKEN_LENGTH)
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
    // For backwards compatibility the Auditor device sends its maximum supported version, and
    // the Auditee uses the highest version it supports.
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
    // int autoRebootSeconds (-1 for unknown)
    // byte portSecurityMode (-1 for unknown)
    // byte userCount (-1 for unknown)
    // }
    // byte[] signature (rest of message)
    //
    // Protocol version changes:
    //
    // 6: autoRebootSeconds added
    // 6: portSecurityMode added
    // 6: userCount added
    //
    // n/a
    //
    // For each audit, the Auditee generates a fresh hardware-backed key with key attestation
    // using the provided challenge. It reports back the certificate chain to be verified by the
    // Auditor. The public key certificate of the generated key is signed by a key provisioned on
    // the device (not usable by the OS) chaining up to an intermediate and the Google root. The
    // certificate contains the key attestation metadata including the important fields with the
    // lock state, verified boot state, the verified boot public key fingerprint and the OS
    // version / patch level:
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
    private static final byte PROTOCOL_VERSION = 6;
    private static final byte PROTOCOL_VERSION_MINIMUM = 5;
    // can become longer in the future, but this is the minimum length
    static final byte CHALLENGE_MESSAGE_LENGTH = 1 + RANDOM_TOKEN_LENGTH * 2;
    private static final int MAX_ENCODED_CHAIN_LENGTH = 5000;
    private static final int MAX_MESSAGE_SIZE = 2953;

    private static final int OS_ENFORCED_FLAGS_NONE = 0;
    private static final int OS_ENFORCED_FLAGS_USER_PROFILE_SECURE = 1;
    private static final int OS_ENFORCED_FLAGS_ACCESSIBILITY = 1 << 1;
    private static final int OS_ENFORCED_FLAGS_DEVICE_ADMIN = 1 << 2;
    private static final int OS_ENFORCED_FLAGS_ADB_ENABLED = 1 << 3;
    private static final int OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED = 1 << 4;
    private static final int OS_ENFORCED_FLAGS_ENROLLED_BIOMETRICS = 1 << 5;
    private static final int OS_ENFORCED_FLAGS_DENY_NEW_USB = 1 << 6; // obsolete since version 86
    private static final int OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM = 1 << 7;
    private static final int OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED = 1 << 8;
    private static final int OS_ENFORCED_FLAGS_SYSTEM_USER = 1 << 9;
    private static final int OS_ENFORCED_FLAGS_ALL =
            OS_ENFORCED_FLAGS_USER_PROFILE_SECURE |
            OS_ENFORCED_FLAGS_ACCESSIBILITY |
            OS_ENFORCED_FLAGS_DEVICE_ADMIN |
            OS_ENFORCED_FLAGS_ADB_ENABLED |
            OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED |
            OS_ENFORCED_FLAGS_ENROLLED_BIOMETRICS |
            OS_ENFORCED_FLAGS_DENY_NEW_USB |
            OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM |
            OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED |
            OS_ENFORCED_FLAGS_SYSTEM_USER;

    private static final String AUDITOR_APP_PACKAGE_NAME_RELEASE = "app.attestation.auditor";
    private static final String AUDITOR_APP_PACKAGE_NAME_PLAY = "app.attestation.auditor.play";
    private static final String AUDITOR_APP_PACKAGE_NAME_DEBUG = "app.attestation.auditor.debug";
    private static final String AUDITOR_APP_SIGNATURE_DIGEST_RELEASE =
            "990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C";
    private static final String AUDITOR_APP_SIGNATURE_DIGEST_PLAY =
            "075335BD7B54C965222B5284D2A1FDEF1198AE45EC7B09A4934287A0E3A243C7";
    private static final String AUDITOR_APP_SIGNATURE_DIGEST_DEBUG =
            "17727D8B61D55A864936B1A7B4A2554A15151F32EBCF44CDAA6E6C3258231890";
    private static final byte AUDITOR_APP_VARIANT_RELEASE = 0;
    private static final byte AUDITOR_APP_VARIANT_PLAY = 1;
    private static final byte AUDITOR_APP_VARIANT_DEBUG = 2;

    private static final int AUDITOR_APP_MINIMUM_VERSION = 73;
    private static final int OS_VERSION_MINIMUM = 120000;
    private static final int OS_PATCH_LEVEL_MINIMUM = 202110;
    private static final int VENDOR_PATCH_LEVEL_MINIMUM = 20211005;
    private static final int BOOT_PATCH_LEVEL_MINIMUM = 20211005;

    // Split displayed fingerprint into groups of 4 characters
    private static final int FINGERPRINT_SPLIT_INTERVAL = 4;

    public record DeviceInfo(int name, int attestationVersion, int keymasterVersion,
            // API for detecting this was replaced in keymaster v3 but the new one isn't used yet
            boolean rollbackResistant,
            boolean enforceStrongBox, int osName) {

        boolean hasPogoPins() {
            return name == R.string.device_pixel_tablet;
        }
    }

    private static final boolean isStrongBoxSupported = ImmutableSet.of(
            "Pixel 3",
            "Pixel 3 XL",
            "Pixel 3a",
            "Pixel 3a XL",
            "Pixel 4",
            "Pixel 4 XL",
            "Pixel 4a",
            "Pixel 4a (5G)",
            "Pixel 5",
            "Pixel 5a",
            "Pixel 6",
            "Pixel 6 Pro",
            "Pixel 6a",
            "Pixel 7",
            "Pixel 7 Pro",
            "Pixel 7a",
            "Pixel Tablet",
            "Pixel Fold",
            "Pixel 8",
            "Pixel 8 Pro",
            "Pixel 8a",
            "Pixel 9",
            "Pixel 9 Pro",
            "Pixel 9 Pro XL",
            "Pixel 9 Pro Fold",
            "SM-N970U",
            "SM-N975U").contains(Build.MODEL);

    // Pixel 6, Pixel 6 Pro and Pixel 6a forgot to declare the attest key feature when it shipped in Android 12
    private static final boolean alwaysHasAttestKey = ImmutableSet.of(
            "Pixel 6",
            "Pixel 6 Pro",
            "Pixel 6a").contains(Build.MODEL);

    private static final ImmutableSet<Integer> extraPatchLevelMissing = ImmutableSet.of(
            R.string.device_sm_g970f,
            R.string.device_sm_g975f,
            R.string.device_sm_n970f,
            R.string.device_sm_n970u,
            R.string.device_sm_n975u);

    private static final ImmutableMap<String, DeviceInfo> fingerprintsCustomOS = ImmutableMap
            .<String, DeviceInfo>builder()
            // GrapheneOS
            .put("0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF",
                    new DeviceInfo(R.string.device_pixel_3, 3, 4, false, true, R.string.os_graphene))
            .put("06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451",
                    new DeviceInfo(R.string.device_pixel_3_xl, 3, 4, false, true, R.string.os_graphene))
            .put("8FF8B9B4F831114963669E04EA4F849F33F3744686A0B33B833682746645ABC8",
                    new DeviceInfo(R.string.device_pixel_3a, 3, 4, false, true, R.string.os_graphene))
            .put("91943FAA75DCB6392AE87DA18CA57D072BFFB80BC30F8FAFC7FFE13D76C5736E",
                    new DeviceInfo(R.string.device_pixel_3a_xl, 3, 4, false, true, R.string.os_graphene))
            .put("80EF268700EE42686F779A47B4A155FE1FFC2EEDF836B4803CAAB8FA61439746",
                    new DeviceInfo(R.string.device_pixel_4, 3, 4, false, true, R.string.os_graphene))
            .put("3F15FDCB82847FED97427CE00563B8F9FF34627070DE5FDB17ACA7849AB98CC8",
                    new DeviceInfo(R.string.device_pixel_4_xl, 3, 4, false, true, R.string.os_graphene))
            .put("9F2454A1657B1B5AD7F2336B39A2611F7A40B2E0DDFD0D6553A359605928DF29",
                    new DeviceInfo(R.string.device_pixel_4a, 3, 4, false, true, R.string.os_graphene))
            .put("DCEC2D053D3EC4F1C9BE414AA07E4D7D7CBD12040AD2F8831C994A83A0536866",
                    new DeviceInfo(R.string.device_pixel_4a_5g, 3, 4, false, true, R.string.os_graphene))
            .put("36A99EAB7907E4FB12A70E3C41C456BCBE46C13413FBFE2436ADEE2B2B61120F",
                    new DeviceInfo(R.string.device_pixel_5, 3, 4, false, true, R.string.os_graphene))
            .put("0ABDDEDA03B6CE10548C95E0BEA196FAA539866F929BCDF7ECA84B4203952514",
                    new DeviceInfo(R.string.device_pixel_5a, 3, 4, false, true, R.string.os_graphene))
            .put("F0A890375D1405E62EBFD87E8D3F475F948EF031BBF9DDD516D5F600A23677E8",
                    new DeviceInfo(R.string.device_pixel_6, 100, 100, false, true, R.string.os_graphene))
            .put("439B76524D94C40652CE1BF0D8243773C634D2F99BA3160D8D02AA5E29FF925C",
                    new DeviceInfo(R.string.device_pixel_6_pro, 100, 100, false, true, R.string.os_graphene))
            .put("08C860350A9600692D10C8512F7B8E80707757468E8FBFEEA2A870C0A83D6031",
                    new DeviceInfo(R.string.device_pixel_6a, 100, 100, false, true, R.string.os_graphene))
            .put("3EFE5392BE3AC38AFB894D13DE639E521675E62571A8A9B3EF9FC8C44FD17FA1",
                    new DeviceInfo(R.string.device_pixel_7, 200, 200, false, true, R.string.os_graphene))
            .put("BC1C0DD95664604382BB888412026422742EB333071EA0B2D19036217D49182F",
                    new DeviceInfo(R.string.device_pixel_7_pro, 200, 200, false, true, R.string.os_graphene))
            .put("508D75DEA10C5CBC3E7632260FC0B59F6055A8A49DD84E693B6D8899EDBB01E4",
                    new DeviceInfo(R.string.device_pixel_7a, 200, 200, false, true, R.string.os_graphene))
            .put("94DF136E6C6AA08DC26580AF46F36419B5F9BAF46039DB076F5295B91AAFF230",
                    new DeviceInfo(R.string.device_pixel_tablet, 200, 200, false, true, R.string.os_graphene))
            .put("EE0C9DFEF6F55A878538B0DBF7E78E3BC3F1A13C8C44839B095FE26DD5FE2842",
                    new DeviceInfo(R.string.device_pixel_fold, 200, 200, false, true, R.string.os_graphene))
            .put("CD7479653AA88208F9F03034810EF9B7B0AF8A9D41E2000E458AC403A2ACB233",
                    new DeviceInfo(R.string.device_pixel_8, 300, 300, false, true, R.string.os_graphene))
            .put("896DB2D09D84E1D6BB747002B8A114950B946E5825772A9D48BA7EB01D118C1C",
                    new DeviceInfo(R.string.device_pixel_8_pro, 300, 300, false, true, R.string.os_graphene))
            .put("096B8BD6D44527A24AC1564B308839F67E78202185CBFF9CFDCB10E63250BC5E",
                    new DeviceInfo(R.string.device_pixel_8a, 300, 300, false, true, R.string.os_graphene))
            .put("9E6A8F3E0D761A780179F93ACD5721BA1AB7C8C537C7761073C0A754B0E932DE",
                    new DeviceInfo(R.string.device_pixel_9, 300, 300, false, true, R.string.os_graphene))
            .put("F729CAB861DA1B83FDFAB402FC9480758F2AE78EE0B61C1F2137DD1AB7076E86",
                    new DeviceInfo(R.string.device_pixel_9_pro, 300, 300, false, true, R.string.os_graphene))
            .put("55D3C2323DB91BB91F20D38D015E85112D038F6B6B5738FE352C1A80DBA57023",
                    new DeviceInfo(R.string.device_pixel_9_pro_xl, 300, 300, false, true, R.string.os_graphene))
            .put("AF4D2C6E62BE0FEC54F0271B9776FF061DD8392D9F51CF6AB1551D346679E24C",
                    new DeviceInfo(R.string.device_pixel_9_pro_fold, 300, 300, false, true, R.string.os_graphene))
            .build();
    private static final ImmutableMap<String, DeviceInfo> fingerprintsStock = ImmutableMap
            .<String, DeviceInfo>builder()
            .put("4B9201B11685BE6710E2B2BA8482F444E237E0C8A3D1F7F447FE29C37CECC559",
                    new DeviceInfo(R.string.device_oneplus_7_pro_gm1913, 3, 4, false, false, R.string.os_stock))
            .put("61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C",
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false, true, R.string.os_stock))
            .put("E75B86C52C7496255A95FB1E2B1C044BFA9D5FE34DD1E4EEBD752EEF0EA89875",
                    new DeviceInfo(R.string.device_pixel_3a_generic, 3, 4, false, true, R.string.os_stock))
            .put("AE6316B4753C61F5855B95B9B98484AF784F2E83648D0FCC8107FCA752CAEA34",
                    new DeviceInfo(R.string.device_pixel_4_generic, 3, 4, false, true, R.string.os_stock))
            .put("879CD3F18EA76E244D4D4AC3BCB9C337C13B4667190B19035AFE2536550050F1",
                    new DeviceInfo(R.string.device_pixel_4a, 3, 4, false, true, R.string.os_stock))
            .put("88265D85BA9E1E2F6036A259D880D2741031ACA445840137395B6D541C0FC7FC",
                    new DeviceInfo(R.string.device_pixel_5_generic, 3, 4, false, true, R.string.os_stock))
            .put("1DD694CE00BF131AD61CEB576B7DCC41CF7F9B2C418F4C12B2B8F3E9A1EA911D",
                    new DeviceInfo(R.string.device_pixel_5a, 3, 4, false, true, R.string.os_stock))
            .put("0F6E75C80183B5DEC074B0054D4271E99389EBE4B136B0819DE1F150BA0FF9D7",
                    new DeviceInfo(R.string.device_pixel_6, 100, 100, false, true, R.string.os_stock))
            .put("42ED1BCA352FABD428F34E8FCEE62776F4CB2C66E06F82E5A59FF4495267BFC2",
                    new DeviceInfo(R.string.device_pixel_6_pro, 100, 100, false, true, R.string.os_stock))
            .put("9AC4174153D45E4545B0F49E22FE63273999B6AC1CB6949C3A9F03EC8807EEE9",
                    new DeviceInfo(R.string.device_pixel_6a, 100, 100, false, true, R.string.os_stock))
            .put("8B2C4CD539F5075E8E7CF212ADB3DB0413FBD77D321199C73D5A473C51F2E10D",
                    new DeviceInfo(R.string.device_pixel_7, 200, 200, false, true, R.string.os_stock))
            .put("26AC4C60BEB1E378357CAD0C3061347AF8DF6FBABBB0D8CEA2445855EE01E368",
                    new DeviceInfo(R.string.device_pixel_7_pro, 200, 200, false, true, R.string.os_stock))
            .put("003F1ADE9D476E612B00F2983E6AD7DCD15E6A80CC2DBB008DA7D6839ED73A8F",
                    new DeviceInfo(R.string.device_pixel_7a, 200, 200, false, true, R.string.os_stock))
            .put("C72E569827EC2E19A1073D927E3B6A1C6C8322DA795D5CE44BF3B95031B37C0A",
                    new DeviceInfo(R.string.device_pixel_tablet, 200, 200, false, true, R.string.os_stock))
            .put("3BBD4712D8714812E762D3FB6D2D5724800C3342B1835CDBC1D3634AE59D646E",
                    new DeviceInfo(R.string.device_pixel_fold, 200, 200, false, true, R.string.os_stock))
            .put("64DEF0828FF5D3EAC65C3F5CEF46C1D855FE0A5D8525E90FB94FC3DBA9988C87",
                    new DeviceInfo(R.string.device_pixel_8, 300, 300, false, true, R.string.os_stock))
            .put("E5362DDF4676E8AA134DB520749BCB1F44FE6556F5E7BFAB130CB6343476FC15",
                    new DeviceInfo(R.string.device_pixel_8_pro, 300, 300, false, true, R.string.os_stock))
            .put("9DE25FB02BB5530D44149D148437C82E267E557322530AA6F03B0AC2E92931DA",
                    new DeviceInfo(R.string.device_pixel_8a, 300, 300, false, true, R.string.os_stock))
            .put("ACB5A4DD184E2C44CFA6A53D2D5C5E8674C9498A59F8AE8019942AC1FCEB1E6C",
                    new DeviceInfo(R.string.device_pixel_9, 300, 300, false, true, R.string.os_stock))
            .put("06035F636BDB7F299A94B51C7D5645A913551327FFC5452B00C5830476D3208E",
                    new DeviceInfo(R.string.device_pixel_9_pro, 300, 300, false, true, R.string.os_stock))
            .put("D05975CFD778082E3D1623C91419F6D8634E579A786592118CCEA057537579B7",
                    new DeviceInfo(R.string.device_pixel_9_pro_xl, 300, 300, false, true, R.string.os_stock))
            .put("800E9093D29614F5BC3FC76A0E819BA0A5C0C94A7D6A17C53E7D017D346B7172",
                    new DeviceInfo(R.string.device_pixel_9_pro_fold, 300, 300, false, true, R.string.os_stock))
            .put("9D77474FA4FEA6F0B28636222FBCEE2BB1E6FF9856C736C85B8EA6E3467F2BBA",
                    new DeviceInfo(R.string.device_sm_g970f, 3, 4, false, false, R.string.os_stock))
            .put("08B2B5C6EC8F54C00C505756E1EF516BB4537B2F02D640410D287A43FCF92E3F",
                    new DeviceInfo(R.string.device_sm_g975f, 3, 4, false, false, R.string.os_stock))
            .put("E94BC43B97F98CD10C22CD9D8469DBE621116ECFA624FE291A1D53CF3CD685D1",
                    new DeviceInfo(R.string.device_sm_n970f, 3, 4, false, false, R.string.os_stock))
            .put("466011C44BBF883DB38CF96617ED35C796CE2552C5357F9230258329E943DB70",
                    new DeviceInfo(R.string.device_sm_n970u, 3, 4, false, true, R.string.os_stock))
            .put("52946676088007755EB586B3E3F3E8D3821BE5DF73513E6C13640507976420E6",
                    new DeviceInfo(R.string.device_sm_n975u, 3, 4, false, true, R.string.os_stock))
            .build();

    private static final ImmutableMap<String, DeviceInfo> fingerprintsStrongBoxCustomOS = ImmutableMap
            .<String, DeviceInfo>builder()
            // GrapheneOS
            .put("0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF",
                    new DeviceInfo(R.string.device_pixel_3, 3, 4, false, true, R.string.os_graphene))
            .put("06DD526EE9B1CB92AA19D9835B68B4FF1A48A3AD31D813F27C9A7D6C271E9451",
                    new DeviceInfo(R.string.device_pixel_3_xl, 3, 4, false, true, R.string.os_graphene))
            .put("73D6C63A07610404FE16A4E07DD24E41A70D331E9D3EF7BBA2D087E4761EB63A",
                    new DeviceInfo(R.string.device_pixel_3a, 3, 4, false, true, R.string.os_graphene))
            .put("3F36E3482E1FF82986576552CB4FD08AF09F8B09D3832314341E04C42D2919A4",
                    new DeviceInfo(R.string.device_pixel_3a_xl, 3, 4, false, true, R.string.os_graphene))
            .put("80EF268700EE42686F779A47B4A155FE1FFC2EEDF836B4803CAAB8FA61439746",
                    new DeviceInfo(R.string.device_pixel_4, 3, 4, false, true, R.string.os_graphene))
            .put("3F15FDCB82847FED97427CE00563B8F9FF34627070DE5FDB17ACA7849AB98CC8",
                    new DeviceInfo(R.string.device_pixel_4_xl, 3, 4, false, true, R.string.os_graphene))
            .put("9F2454A1657B1B5AD7F2336B39A2611F7A40B2E0DDFD0D6553A359605928DF29",
                    new DeviceInfo(R.string.device_pixel_4a, 3, 4, false, true, R.string.os_graphene))
            .put("DCEC2D053D3EC4F1C9BE414AA07E4D7D7CBD12040AD2F8831C994A83A0536866",
                    new DeviceInfo(R.string.device_pixel_4a_5g, 4, 41, false, true, R.string.os_graphene))
            .put("36A99EAB7907E4FB12A70E3C41C456BCBE46C13413FBFE2436ADEE2B2B61120F",
                    new DeviceInfo(R.string.device_pixel_5, 4, 41, false, true, R.string.os_graphene))
            .put("0ABDDEDA03B6CE10548C95E0BEA196FAA539866F929BCDF7ECA84B4203952514",
                    new DeviceInfo(R.string.device_pixel_5a, 4, 41, false, true, R.string.os_graphene))
            .put("F0A890375D1405E62EBFD87E8D3F475F948EF031BBF9DDD516D5F600A23677E8",
                    new DeviceInfo(R.string.device_pixel_6, 100, 100, false, true, R.string.os_graphene))
            .put("439B76524D94C40652CE1BF0D8243773C634D2F99BA3160D8D02AA5E29FF925C",
                    new DeviceInfo(R.string.device_pixel_6_pro, 100, 100, false, true, R.string.os_graphene))
            .put("08C860350A9600692D10C8512F7B8E80707757468E8FBFEEA2A870C0A83D6031",
                    new DeviceInfo(R.string.device_pixel_6a, 100, 100, false, true, R.string.os_graphene))
            .put("3EFE5392BE3AC38AFB894D13DE639E521675E62571A8A9B3EF9FC8C44FD17FA1",
                    new DeviceInfo(R.string.device_pixel_7, 100, 100, false, true, R.string.os_graphene))
            .put("BC1C0DD95664604382BB888412026422742EB333071EA0B2D19036217D49182F",
                    new DeviceInfo(R.string.device_pixel_7_pro, 100, 100, false, true, R.string.os_graphene))
            .put("508D75DEA10C5CBC3E7632260FC0B59F6055A8A49DD84E693B6D8899EDBB01E4",
                    new DeviceInfo(R.string.device_pixel_7a, 100, 100, false, true, R.string.os_graphene))
            .put("94DF136E6C6AA08DC26580AF46F36419B5F9BAF46039DB076F5295B91AAFF230",
                    new DeviceInfo(R.string.device_pixel_tablet, 100, 100, false, true, R.string.os_graphene))
            .put("EE0C9DFEF6F55A878538B0DBF7E78E3BC3F1A13C8C44839B095FE26DD5FE2842",
                    new DeviceInfo(R.string.device_pixel_fold, 100, 100, false, true, R.string.os_graphene))
            .put("CD7479653AA88208F9F03034810EF9B7B0AF8A9D41E2000E458AC403A2ACB233",
                    new DeviceInfo(R.string.device_pixel_8, 300, 300, false, true, R.string.os_graphene))
            .put("896DB2D09D84E1D6BB747002B8A114950B946E5825772A9D48BA7EB01D118C1C",
                    new DeviceInfo(R.string.device_pixel_8_pro, 300, 300, false, true, R.string.os_graphene))
            .put("096B8BD6D44527A24AC1564B308839F67E78202185CBFF9CFDCB10E63250BC5E",
                    new DeviceInfo(R.string.device_pixel_8a, 300, 300, false, true, R.string.os_graphene))
            .put("9E6A8F3E0D761A780179F93ACD5721BA1AB7C8C537C7761073C0A754B0E932DE",
                    new DeviceInfo(R.string.device_pixel_9, 300, 300, false, true, R.string.os_graphene))
            .put("F729CAB861DA1B83FDFAB402FC9480758F2AE78EE0B61C1F2137DD1AB7076E86",
                    new DeviceInfo(R.string.device_pixel_9_pro, 300, 300, false, true, R.string.os_graphene))
            .put("55D3C2323DB91BB91F20D38D015E85112D038F6B6B5738FE352C1A80DBA57023",
                    new DeviceInfo(R.string.device_pixel_9_pro_xl, 300, 300, false, true, R.string.os_graphene))
            .put("AF4D2C6E62BE0FEC54F0271B9776FF061DD8392D9F51CF6AB1551D346679E24C",
                    new DeviceInfo(R.string.device_pixel_9_pro_fold, 300, 300, false, true, R.string.os_graphene))
            .build();
    private static final ImmutableMap<String, DeviceInfo> fingerprintsStrongBoxStock = ImmutableMap
            .<String, DeviceInfo>builder()
            .put("61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C",
                    new DeviceInfo(R.string.device_pixel_3_generic, 3, 4, false, true, R.string.os_stock))
            .put("8CA89AF1A6DAA74B00810849356DE929CFC4498EF36AF964757BDE8A113BF46D",
                    new DeviceInfo(R.string.device_pixel_3a_generic, 3, 4, false, true, R.string.os_stock))
            .put("AE6316B4753C61F5855B95B9B98484AF784F2E83648D0FCC8107FCA752CAEA34",
                    new DeviceInfo(R.string.device_pixel_4_generic, 3, 4, false, true, R.string.os_stock))
            .put("879CD3F18EA76E244D4D4AC3BCB9C337C13B4667190B19035AFE2536550050F1",
                    new DeviceInfo(R.string.device_pixel_4a, 3, 4, false, true, R.string.os_stock))
            .put("88265D85BA9E1E2F6036A259D880D2741031ACA445840137395B6D541C0FC7FC",
                    new DeviceInfo(R.string.device_pixel_5_generic, 4, 41, false, true, R.string.os_stock))
            .put("1DD694CE00BF131AD61CEB576B7DCC41CF7F9B2C418F4C12B2B8F3E9A1EA911D",
                    new DeviceInfo(R.string.device_pixel_5a, 4, 41, false, true, R.string.os_stock))
            .put("0F6E75C80183B5DEC074B0054D4271E99389EBE4B136B0819DE1F150BA0FF9D7",
                    new DeviceInfo(R.string.device_pixel_6, 100, 100, false, true, R.string.os_stock))
            .put("42ED1BCA352FABD428F34E8FCEE62776F4CB2C66E06F82E5A59FF4495267BFC2",
                    new DeviceInfo(R.string.device_pixel_6_pro, 100, 100, false, true, R.string.os_stock))
            .put("9AC4174153D45E4545B0F49E22FE63273999B6AC1CB6949C3A9F03EC8807EEE9",
                    new DeviceInfo(R.string.device_pixel_6a, 100, 100, false, true, R.string.os_stock))
            .put("8B2C4CD539F5075E8E7CF212ADB3DB0413FBD77D321199C73D5A473C51F2E10D",
                    new DeviceInfo(R.string.device_pixel_7, 100, 100, false, true, R.string.os_stock))
            .put("26AC4C60BEB1E378357CAD0C3061347AF8DF6FBABBB0D8CEA2445855EE01E368",
                    new DeviceInfo(R.string.device_pixel_7_pro, 100, 100, false, true, R.string.os_stock))
            .put("003F1ADE9D476E612B00F2983E6AD7DCD15E6A80CC2DBB008DA7D6839ED73A8F",
                    new DeviceInfo(R.string.device_pixel_7a, 100, 100, false, true, R.string.os_stock))
            .put("C72E569827EC2E19A1073D927E3B6A1C6C8322DA795D5CE44BF3B95031B37C0A",
                    new DeviceInfo(R.string.device_pixel_tablet, 100, 100, false, true, R.string.os_stock))
            .put("3BBD4712D8714812E762D3FB6D2D5724800C3342B1835CDBC1D3634AE59D646E",
                    new DeviceInfo(R.string.device_pixel_fold, 100, 100, false, true, R.string.os_stock))
            .put("64DEF0828FF5D3EAC65C3F5CEF46C1D855FE0A5D8525E90FB94FC3DBA9988C87",
                    new DeviceInfo(R.string.device_pixel_8, 300, 300, false, true, R.string.os_stock))
            .put("E5362DDF4676E8AA134DB520749BCB1F44FE6556F5E7BFAB130CB6343476FC15",
                    new DeviceInfo(R.string.device_pixel_8_pro, 300, 300, false, true, R.string.os_stock))
            .put("9DE25FB02BB5530D44149D148437C82E267E557322530AA6F03B0AC2E92931DA",
                    new DeviceInfo(R.string.device_pixel_8a, 300, 300, false, true, R.string.os_stock))
            .put("ACB5A4DD184E2C44CFA6A53D2D5C5E8674C9498A59F8AE8019942AC1FCEB1E6C",
                    new DeviceInfo(R.string.device_pixel_9, 300, 300, false, true, R.string.os_stock))
            .put("06035F636BDB7F299A94B51C7D5645A913551327FFC5452B00C5830476D3208E",
                    new DeviceInfo(R.string.device_pixel_9_pro, 300, 300, false, true, R.string.os_stock))
            .put("D05975CFD778082E3D1623C91419F6D8634E579A786592118CCEA057537579B7",
                    new DeviceInfo(R.string.device_pixel_9_pro_xl, 300, 300, false, true, R.string.os_stock))
            .put("800E9093D29614F5BC3FC76A0E819BA0A5C0C94A7D6A17C53E7D017D346B7172",
                    new DeviceInfo(R.string.device_pixel_9_pro_fold, 300, 300, false, true, R.string.os_stock))
            .put("3D3DEB132A89551D0A700D230BABAE4E3E80E3C7926ACDD7BAEDF9B57AD316D0",
                    new DeviceInfo(R.string.device_sm_n970u, 3, 4, false, true, R.string.os_stock))
            .put("9AC63842137D92C119A1B1BE2C9270B9EBB6083BBE6350B7823571942B5869F0",
                    new DeviceInfo(R.string.device_sm_n975u, 3, 4, false, true, R.string.os_stock))
            .build();

    private static byte[] getChallengeIndex(final Context context) {
        final SharedPreferences global = PreferenceManager.getDefaultSharedPreferences(context);
        final String challengeIndexSerialized = global.getString(KEY_CHALLENGE_INDEX, null);
        if (challengeIndexSerialized != null) {
            return BaseEncoding.base64().decode(challengeIndexSerialized);
        } else {
            final byte[] challengeIndex = generateRandomToken();
            global.edit()
                    .putString(KEY_CHALLENGE_INDEX, BaseEncoding.base64().encode(challengeIndex))
                    .apply();
            return challengeIndex;
        }
    }

    private static byte[] readRawResource(final Context context, final int id) {
        try (final InputStream stream = context.getResources().openRawResource(id)) {
            return ByteStreams.toByteArray(stream);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static final SecureRandom random = new SecureRandom();

    private static byte[] generateRandomToken() {
        final byte[] challenge = new byte[RANDOM_TOKEN_LENGTH];
        random.nextBytes(challenge);
        return challenge;
    }

    static byte[] getChallengeMessage(final Context context) {
        return Bytes.concat(new byte[]{PROTOCOL_VERSION}, getChallengeIndex(context), generateRandomToken());
    }

    private static byte[] getFingerprint(final Certificate certificate)
            throws CertificateEncodingException {
        return FINGERPRINT_HASH_FUNCTION.hashBytes(certificate.getEncoded()).asBytes();
    }

    private record Verified(int device, String verifiedBootKey, byte[] verifiedBootHash,
            int osName, int osVersion, int osPatchLevel, int vendorPatchLevel, int bootPatchLevel,
            int appVersion, int appVariant, int securityLevel, boolean attestKey) {

        boolean hasPogoPins() {
            return device == R.string.device_pixel_tablet;
        }
    }

    private static X509Certificate generateCertificate(final InputStream in)
            throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    private static Verified verifyStateless(final Certificate[] certificates,
            final byte[] challenge, final boolean hasPersistentKey, final byte[][] validRoots)
            throws GeneralSecurityException {

        verifyCertificateSignatures(certificates, hasPersistentKey);

        // check that the root certificate is a valid key attestation root
        final byte[] root = certificates[certificates.length - 1].getEncoded();
        if (!Arrays.stream(validRoots).anyMatch(v -> Arrays.equals(v, root))) {
            throw new GeneralSecurityException("root certificate is not a valid key attestation root");
        }

        final ParsedAttestationRecord attestation;
        try {
            attestation = ParsedAttestationRecord.createParsedAttestationRecord(List.of((X509Certificate) certificates[0]));
        } catch (final IOException | ParsedAttestationRecord.KeyDescriptionMissingException e) {
            throw new GeneralSecurityException(e);
        }

        final ParsedAttestationRecord.SecurityLevel attestationSecurityLevelEnum = attestation.attestationSecurityLevel;

        // enforce hardware-based attestation
        if (attestationSecurityLevelEnum != ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT &&
                attestationSecurityLevelEnum != ParsedAttestationRecord.SecurityLevel.STRONG_BOX) {
            throw new GeneralSecurityException("attestation security level is not valid");
        }
        if (attestation.keymasterSecurityLevel != attestationSecurityLevelEnum) {
            throw new GeneralSecurityException("keymaster security level does not match attestation security level");
        }

        // prevent replay attacks
        if (!Arrays.equals(attestation.attestationChallenge, challenge)) {
            throw new GeneralSecurityException("challenge mismatch");
        }

        // enforce communicating with the Auditor app via OS level security
        final AuthorizationList softwareEnforced = attestation.softwareEnforced;
        final AttestationApplicationId attestationApplicationId = softwareEnforced.attestationApplicationId
                .orElseThrow(() -> new GeneralSecurityException("key has no applicationId supplied"));
        final List<AttestationPackageInfo> infos = attestationApplicationId.packageInfos;
        if (infos.size() != 1) {
            throw new GeneralSecurityException("invalid number of attestation packages: " + infos.size());
        }
        final AttestationPackageInfo info = infos.get(0);
        final List<byte[]> signatureDigests = attestationApplicationId.signatureDigests;
        if (signatureDigests.size() == 0) {
            throw new GeneralSecurityException("Auditor signing keys are missing from the attestation data.\n\nThis is known to happen after a system_server crash causes a soft reboot, which can be resolved by a full reboot of the device.");
        } else if (signatureDigests.size() != 1) {
            throw new GeneralSecurityException("invalid number of Auditor app signing keys: " + signatureDigests.size());
        }
        final String signatureDigest = BaseEncoding.base16().encode(signatureDigests.get(0));
        final byte appVariant;
        final String packageName = info.packageName;
        if (AUDITOR_APP_PACKAGE_NAME_RELEASE.equals(packageName)) {
            if (!AUDITOR_APP_SIGNATURE_DIGEST_RELEASE.equals(signatureDigest)) {
                throw new GeneralSecurityException("invalid Auditor app signing key");
            }
            appVariant = AUDITOR_APP_VARIANT_RELEASE;
        } else if (AUDITOR_APP_PACKAGE_NAME_PLAY.equals(packageName)) {
            if (!AUDITOR_APP_SIGNATURE_DIGEST_PLAY.equals(signatureDigest)) {
                throw new GeneralSecurityException("invalid Auditor app signing key");
            }
            appVariant = AUDITOR_APP_VARIANT_PLAY;
        } else if (AUDITOR_APP_PACKAGE_NAME_DEBUG.equals(packageName)) {
            if (!BuildConfig.DEBUG) {
                throw new GeneralSecurityException("Auditor debug builds are only trusted by other Auditor debug builds");
            }
            if (!AUDITOR_APP_SIGNATURE_DIGEST_DEBUG.equals(signatureDigest)) {
                throw new GeneralSecurityException("invalid Auditor app signing key");
            }
            appVariant = AUDITOR_APP_VARIANT_DEBUG;
        } else {
            throw new GeneralSecurityException("invalid Auditor app package name: " + packageName);
        }
        final int appVersion = Math.toIntExact(info.version); // int for compatibility
        if (appVersion < AUDITOR_APP_MINIMUM_VERSION) {
            throw new GeneralSecurityException("Auditor app is too old: " + appVersion);
        }

        final AuthorizationList teeEnforced = attestation.teeEnforced;

        // verified boot security checks
        final RootOfTrust rootOfTrust = teeEnforced.rootOfTrust.orElse(null);
        if (rootOfTrust == null) {
            throw new GeneralSecurityException("missing root of trust");
        }
        if (!rootOfTrust.deviceLocked) {
            throw new GeneralSecurityException("device is not locked");
        }
        final RootOfTrust.VerifiedBootState verifiedBootState = rootOfTrust.verifiedBootState;
        final String verifiedBootKey = BaseEncoding.base16().encode(rootOfTrust.verifiedBootKey);
        final DeviceInfo device;
        if (verifiedBootState == RootOfTrust.VerifiedBootState.SELF_SIGNED) {
            if (attestationSecurityLevelEnum == ParsedAttestationRecord.SecurityLevel.STRONG_BOX) {
                device = fingerprintsStrongBoxCustomOS.get(verifiedBootKey);
            } else {
                device = fingerprintsCustomOS.get(verifiedBootKey);
            }
        } else if (verifiedBootState == RootOfTrust.VerifiedBootState.VERIFIED) {
            if (attestationSecurityLevelEnum == ParsedAttestationRecord.SecurityLevel.STRONG_BOX) {
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

        // enforce StrongBox for new pairings with devices supporting it
        if (!hasPersistentKey && device.enforceStrongBox &&
                attestationSecurityLevelEnum != ParsedAttestationRecord.SecurityLevel.STRONG_BOX) {
            throw new GeneralSecurityException("non-StrongBox security level for device supporting it");
        }

        // OS version sanity checks
        final int osVersion = teeEnforced.osVersion.orElse(0);
        if (osVersion < OS_VERSION_MINIMUM) {
            throw new GeneralSecurityException("OS version too old: " + osVersion);
        }
        final int osPatchLevel = teeEnforced.osPatchLevel.orElse(0);
        if (osPatchLevel < OS_PATCH_LEVEL_MINIMUM) {
            throw new GeneralSecurityException("OS patch level too old: " + osPatchLevel);
        }
        final int vendorPatchLevel = teeEnforced.vendorPatchLevel.orElse(0);
        if (vendorPatchLevel < VENDOR_PATCH_LEVEL_MINIMUM && !extraPatchLevelMissing.contains(device.name)) {
            throw new GeneralSecurityException("Vendor patch level too old: " + vendorPatchLevel);
        }
        final int bootPatchLevel = teeEnforced.bootPatchLevel.orElse(0);
        if (bootPatchLevel < BOOT_PATCH_LEVEL_MINIMUM && !extraPatchLevelMissing.contains(device.name)) {
            throw new GeneralSecurityException("Boot patch level too old: " + bootPatchLevel);
        }

        // key sanity checks
        if (!teeEnforced.purpose.equals(
                ImmutableSet.of(AuthorizationList.OperationPurpose.SIGN, AuthorizationList.OperationPurpose.VERIFY))) {
            throw new GeneralSecurityException("key has invalid purposes");
        }
        if (teeEnforced.origin.orElseThrow(() -> new GeneralSecurityException("key has missing origin")) != AuthorizationList.KeyOrigin.GENERATED) {
            throw new GeneralSecurityException("key not origin generated");
        }
        if (teeEnforced.allApplications) {
            throw new GeneralSecurityException("expected key only usable by Auditor app");
        }
        if (device.rollbackResistant && !teeEnforced.rollbackResistant) {
            throw new GeneralSecurityException("expected rollback resistant key");
        }

        // version sanity checks
        final int attestationVersion = attestation.attestationVersion;
        Log.d(TAG, "attestationVersion: " + attestationVersion);
        if (attestationVersion < device.attestationVersion) {
            throw new GeneralSecurityException("attestation version " + attestationVersion + " below " + device.attestationVersion);
        }
        final int keymasterVersion = attestation.keymasterVersion;
        Log.d(TAG, "keymasterVersion: " + keymasterVersion);
        if (keymasterVersion < device.keymasterVersion) {
            throw new GeneralSecurityException("keymaster version " + keymasterVersion + " below " + device.keymasterVersion);
        }

        final byte[] verifiedBootHash = rootOfTrust.verifiedBootHash.orElse(null);
        if (attestationVersion >= 3 && verifiedBootHash == null) {
            throw new GeneralSecurityException("verifiedBootHash expected for attestation version >= 3");
        }

        boolean attestKey = false;
        try {
            final ParsedAttestationRecord attestation1 = ParsedAttestationRecord.createParsedAttestationRecord(
                    List.of((X509Certificate) certificates[1]));

            if (attestation1.attestationSecurityLevel != attestation.attestationSecurityLevel) {
                throw new GeneralSecurityException("attest key attestation security level does not match");
            }

            if (attestation1.keymasterSecurityLevel != attestation.keymasterSecurityLevel) {
                throw new GeneralSecurityException("attest key keymaster security level does not match");
            }

            final AuthorizationList teeEnforced1 = attestation1.teeEnforced;

            // verified boot security checks
            final RootOfTrust rootOfTrust1 = teeEnforced1.rootOfTrust.orElse(null);
            if (rootOfTrust1 == null) {
                throw new GeneralSecurityException("attest key missing root of trust");
            }
            if (rootOfTrust1.deviceLocked != rootOfTrust.deviceLocked) {
                throw new GeneralSecurityException("attest key lock state does not match");
            }
            if (rootOfTrust1.verifiedBootState != rootOfTrust.verifiedBootState) {
                throw new GeneralSecurityException("attest key verified boot state does not match");
            }
            if (!Arrays.equals(rootOfTrust1.verifiedBootKey, rootOfTrust.verifiedBootKey)) {
                throw new GeneralSecurityException("attest key verified boot key does not match");
            }

            // key sanity checks
            if (!teeEnforced1.purpose.equals(ImmutableSet.of(AuthorizationList.OperationPurpose.ATTEST_KEY))) {
                throw new GeneralSecurityException("attest key has invalid purposes");
            }
            if (teeEnforced1.origin.orElse(null) != AuthorizationList.KeyOrigin.GENERATED) {
                throw new GeneralSecurityException("attest key not origin generated");
            }
            if (teeEnforced1.allApplications) {
                throw new GeneralSecurityException("expected attest key only usable by Auditor app");
            }
            if (device.rollbackResistant && !teeEnforced1.rollbackResistant) {
                throw new GeneralSecurityException("expected rollback resistant attest key");
            }

            if (!hasPersistentKey) {
                if (!Arrays.equals(attestation1.attestationChallenge, attestation.attestationChallenge)) {
                    throw new GeneralSecurityException("attest key challenge does not match");
                }

                if (!attestation1.softwareEnforced.attestationApplicationId.orElseThrow(() ->
                        new GeneralSecurityException("missing attest key application")).equals(attestationApplicationId)) {
                    throw new GeneralSecurityException("attest key application does not match");
                }

                // version sanity checks
                if (attestation1.attestationVersion != attestation.attestationVersion) {
                    throw new GeneralSecurityException("attest key attestation version does not match");
                }
                if (attestation1.keymasterVersion != attestation.keymasterVersion) {
                    throw new GeneralSecurityException("attest key keymaster version does not match");
                }

                // OS version sanity checks
                if (!teeEnforced1.osVersion.equals(teeEnforced.osVersion)) {
                    throw new GeneralSecurityException("attest key OS version does not match");
                }
                if (!teeEnforced1.osPatchLevel.equals(teeEnforced.osPatchLevel)) {
                    throw new GeneralSecurityException("attest key OS patch level does not match");
                }
                if (!teeEnforced1.vendorPatchLevel.equals(teeEnforced.vendorPatchLevel)) {
                    throw new GeneralSecurityException("attest key vendor patch level does not match");
                }
                if (!teeEnforced1.bootPatchLevel.equals(teeEnforced.bootPatchLevel)) {
                    throw new GeneralSecurityException("attest key boot patch level does not match");
                }

                if (!Arrays.equals(rootOfTrust1.verifiedBootHash.orElse(new byte[0]), rootOfTrust.verifiedBootHash.orElse(new byte[0]))) {
                    throw new GeneralSecurityException("attest key verified boot hash does not match");
                }
            }

            attestKey = true;
        } catch (final IOException e) {
            throw new GeneralSecurityException(e);
        } catch (final ParsedAttestationRecord.KeyDescriptionMissingException ignored) {}

        // enforce attest key for new pairings with devices supporting it
        if (!hasPersistentKey && attestationVersion >= 100 && !attestKey) {
            throw new GeneralSecurityException("missing per-pairing attest key for device supporting it");
        }

        for (int i = 2; i < certificates.length; i++) {
            try {
                ParsedAttestationRecord.createParsedAttestationRecord(List.of((X509Certificate) certificates[i]));
            } catch (final IOException e) {
                throw new GeneralSecurityException(e);
            } catch (final ParsedAttestationRecord.KeyDescriptionMissingException e) {
                continue;
            }
            throw new GeneralSecurityException("only initial key and attest key should have attestation extension");
        }

        return new Verified(device.name, verifiedBootKey, verifiedBootHash, device.osName,
                osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel, appVersion, appVariant,
                ParsedAttestationRecord.securityLevelToInt(attestationSecurityLevelEnum), attestKey);
    }

    // Only checks expiry beyond the initial certificate for the initial pairing since the
    // certificates are short lived when remote provisioning is in use and we prevent rotation by
    // using the attest key feature to provide permanent pairing-specific certificate chains in
    // order to pin them.
    private static void verifyCertificateSignatures(final Certificate[] certChain, final boolean hasPersistentKey)
            throws GeneralSecurityException {
        for (int i = 1; i < certChain.length; ++i) {
            try {
                if (i == 1 || !hasPersistentKey) {
                    ((X509Certificate) certChain[i - 1]).checkValidity();
                }
                certChain[i - 1].verify(certChain[i].getPublicKey());
            } catch (final GeneralSecurityException e) {
                throw new GeneralSecurityException("Failed to verify certificate "
                        + certChain[i - 1] + " with public key " + certChain[i].getPublicKey(), e);
            }
        }

        // Last cert is self-signed.
        final int i = certChain.length - 1;
        try {
            if (i == 0 || !hasPersistentKey) {
                ((X509Certificate) certChain[i]).checkValidity();
            }
            certChain[i].verify(certChain[i].getPublicKey());
        } catch (CertificateException e) {
            throw new GeneralSecurityException(
                    "Root cert " + certChain[i] + " is not correctly self-signed", e);
        }
    }

    private static String formatPatchLevel(final int patchLevel) {
        final String s = Integer.toString(patchLevel);
        return s.substring(0, 4) + "-" + s.substring(4, 6) +
                (s.length() >= 8 ? "-" + s.substring(6, 8) : "");
    }

    private static void appendVerifiedInformation(final Context context,
            final StringBuilder builder, final Verified verified, final String fingerprint,
            final boolean attestKeyMigration) {
        final StringBuilder splitFingerprint = new StringBuilder();
        for (int i = 0; i < fingerprint.length(); i += FINGERPRINT_SPLIT_INTERVAL) {
            splitFingerprint.append(fingerprint.substring(i,
                    Math.min(fingerprint.length(), i + FINGERPRINT_SPLIT_INTERVAL)));
            if (i + FINGERPRINT_SPLIT_INTERVAL < fingerprint.length()) {
                splitFingerprint.append("-");
            }
        }
        builder.append(context.getString(R.string.identity, splitFingerprint.toString()));

        final String securityLevel;
        if (verified.securityLevel == ParsedAttestationRecord.securityLevelToInt(ParsedAttestationRecord.SecurityLevel.STRONG_BOX)) {
            if (verified.attestKey && !attestKeyMigration) {
                securityLevel = context.getString(R.string.security_level_strongbox_attest_key);
            } else {
                securityLevel = context.getString(R.string.security_level_strongbox);
            }
        } else {
            if (verified.attestKey && !attestKeyMigration) {
                securityLevel = context.getString(R.string.security_level_tee_attest_key);
            } else {
                securityLevel = context.getString(R.string.security_level_tee);
            }
        }
        builder.append(context.getString(R.string.security_level, securityLevel));

        builder.append(context.getString(R.string.device, context.getString(verified.device)));
        builder.append(context.getString(R.string.os, context.getString(verified.osName)));

        final String osVersion = String.format(Locale.US, "%06d", verified.osVersion);
        builder.append(context.getString(R.string.os_version,
                    Integer.parseInt(osVersion.substring(0, 2)) + "." +
                    Integer.parseInt(osVersion.substring(2, 4)) + "." +
                    Integer.parseInt(osVersion.substring(4, 6))));

        builder.append(context.getString(R.string.os_patch_level, formatPatchLevel(verified.osPatchLevel)));

        if (verified.vendorPatchLevel != 0) {
            builder.append(context.getString(R.string.vendor_patch_level, formatPatchLevel(verified.vendorPatchLevel)));
        }

        if (verified.bootPatchLevel != 0) {
            builder.append(context.getString(R.string.boot_patch_level, formatPatchLevel(verified.bootPatchLevel)));
        }

        builder.append(context.getString(R.string.verified_boot_key_hash,
                    verified.verifiedBootKey));

        if (verified.verifiedBootHash != null) {
            builder.append(context.getString(R.string.verified_boot_hash,
                    BaseEncoding.base16().encode(verified.verifiedBootHash)));
        }
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

    record VerificationResult(boolean strong, String teeEnforced, String osEnforced, String history) {
    }

    private static String toYesNoString(final Context context, final boolean value) {
        return value ? context.getString(R.string.yes) : context.getString(R.string.no);
    }

    record SecurityStateExt(int autoRebootSeconds, byte portSecurityMode, byte userCount) {
        static int UNKNOWN_VALUE = -1;
        static int INVALID_VALUE = -2;
        static SecurityStateExt UNKNOWN = new SecurityStateExt(
                UNKNOWN_VALUE, (byte) UNKNOWN_VALUE, (byte) UNKNOWN_VALUE);
    }

    private static VerificationResult verify(final Context context, final byte[] fingerprint,
            final byte[] challenge, final ByteBuffer signedMessage, final byte[] signature,
            final Certificate[] attestationCertificates, final boolean userProfileSecure,
            final boolean accessibility, final boolean deviceAdmin,
            final boolean deviceAdminNonSystem, final boolean adbEnabled,
            final boolean addUsersWhenLocked, final boolean enrolledBiometrics,
            final boolean oemUnlockAllowed, final boolean systemUser,
            SecurityStateExt securityStateExt)
            throws GeneralSecurityException {
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

        final Verified verified = verifyStateless(attestationCertificates, challenge, hasPersistentKey,
                new byte[][]{readRawResource(context, R.raw.google_root_0),
                    readRawResource(context, R.raw.google_root_1),
                    readRawResource(context, R.raw.google_root_2),
                    readRawResource(context, R.raw.google_root_3)});

        final StringBuilder teeEnforced = new StringBuilder();
        final StringBuilder history = new StringBuilder();

        boolean attestKeyMigration = false;
        if (hasPersistentKey) {
            final int chainOffset;
            if (attestationCertificates.length != preferences.getInt(KEY_PINNED_CERTIFICATE_LENGTH, 0)) {
                if (attestationCertificates.length == 5 && preferences.getInt(KEY_PINNED_CERTIFICATE_LENGTH, 0) == 4) {
                    // backwards compatible use of attest key without the security benefits for
                    // forward compatibility with remote provisioning
                    chainOffset = 1;
                    attestKeyMigration = true;
                } else {
                    throw new GeneralSecurityException("certificate chain length mismatch");
                }
            } else {
                chainOffset = 0;
            }
            for (int i = 1 + chainOffset; i < attestationCertificates.length; i++) {
                final byte[] b = BaseEncoding.base64().decode(preferences.getString(KEY_PINNED_CERTIFICATE + (i - chainOffset), ""));
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
                throw new GeneralSecurityException("pinned verified boot key mismatch");
            }
            if (verified.osVersion < preferences.getInt(KEY_PINNED_OS_VERSION, Integer.MAX_VALUE)) {
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
            final int pinnedAppVariant = preferences.getInt(KEY_PINNED_APP_VARIANT, 0);
            if (verified.appVariant < pinnedAppVariant) {
                throw new GeneralSecurityException("App version downgraded");
            }
            if (verified.securityLevel != preferences.getInt(KEY_PINNED_SECURITY_LEVEL,
                    ParsedAttestationRecord.securityLevelToInt(ParsedAttestationRecord.SecurityLevel.TRUSTED_ENVIRONMENT))) {
                throw new GeneralSecurityException("Security level mismatch");
            }

            history.append(context.getString(R.string.first_verified,
                    new Date(preferences.getLong(KEY_VERIFIED_TIME_FIRST, 0))));
            history.append(context.getString(R.string.last_verified,
                    new Date(preferences.getLong(KEY_VERIFIED_TIME_LAST, 0))));

            final SharedPreferences.Editor editor = preferences.edit();
            editor.putInt(KEY_PINNED_OS_VERSION, verified.osVersion);
            editor.putInt(KEY_PINNED_OS_PATCH_LEVEL, verified.osPatchLevel);
            if (verified.vendorPatchLevel != 0) {
                editor.putInt(KEY_PINNED_VENDOR_PATCH_LEVEL, verified.vendorPatchLevel);
            }
            if (verified.bootPatchLevel != 0) {
                editor.putInt(KEY_PINNED_BOOT_PATCH_LEVEL, verified.bootPatchLevel);
            }
            editor.putInt(KEY_PINNED_APP_VERSION, verified.appVersion);
            editor.putInt(KEY_PINNED_APP_VARIANT, verified.appVariant);
            editor.putInt(KEY_PINNED_SECURITY_LEVEL, verified.securityLevel); // new field
            editor.putLong(KEY_VERIFIED_TIME_LAST, System.currentTimeMillis());
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
            editor.putInt(KEY_PINNED_APP_VARIANT, verified.appVariant);
            editor.putInt(KEY_PINNED_SECURITY_LEVEL, verified.securityLevel);

            final long now = System.currentTimeMillis();
            editor.putLong(KEY_VERIFIED_TIME_FIRST, now);
            editor.putLong(KEY_VERIFIED_TIME_LAST, now);

            editor.apply();
        }

        appendVerifiedInformation(context, teeEnforced, verified, fingerprintHex, attestKeyMigration);

        final StringBuilder osEnforced = new StringBuilder();
        osEnforced.append(context.getString(R.string.auditor_app_version, verified.appVersion));

        final String appVariant;
        if (verified.appVariant == AUDITOR_APP_VARIANT_RELEASE) {
            appVariant = context.getString(R.string.auditor_app_variant_release);
        } else if (verified.appVariant == AUDITOR_APP_VARIANT_PLAY) {
            appVariant = context.getString(R.string.auditor_app_variant_play);
        } else {
            appVariant = context.getString(R.string.auditor_app_variant_debug);
        }
        osEnforced.append(context.getString(R.string.auditor_app_variant, appVariant));

        osEnforced.append(context.getString(R.string.user_profile_secure,
                toYesNoString(context, userProfileSecure)));
        osEnforced.append(context.getString(R.string.enrolled_biometrics,
                toYesNoString(context, enrolledBiometrics)));
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
        osEnforced.append(context.getString(R.string.oem_unlock_allowed,
                toYesNoString(context, oemUnlockAllowed)));
        osEnforced.append(context.getString(R.string.system_user,
                toYesNoString(context, systemUser)));

        final int usbcPortSecurityModePrefix;
        if (verified.hasPogoPins()) {
            usbcPortSecurityModePrefix = R.string.usbc_port_and_pogo_pins;
        } else {
            usbcPortSecurityModePrefix = R.string.usbc_port_security_mode;
        }

        final int usbcPortSecurityModeOffRes;
        if (verified.hasPogoPins()) {
            usbcPortSecurityModeOffRes = R.string.usbc_port_and_pogo_pins_security_mode_off;
        } else {
            usbcPortSecurityModeOffRes = R.string.usbc_port_security_mode_off;
        }

        final byte usbcPortSecurityMode = securityStateExt.portSecurityMode();
        final int usbcPortSecurityModeValueRes;
        if (usbcPortSecurityMode == SecurityStateExt.UNKNOWN_VALUE) {
            usbcPortSecurityModeValueRes = R.string.unknown_value;
        } else if (usbcPortSecurityMode == SecurityStateExt.INVALID_VALUE) {
            usbcPortSecurityModeValueRes = R.string.invalid_value;
        } else {
            usbcPortSecurityModeValueRes = switch (usbcPortSecurityMode) {
                case 0 -> usbcPortSecurityModeOffRes;
                case 1 -> R.string.usbc_port_security_mode_charging_only;
                case 2 -> R.string.usbc_port_security_mode_charging_only_when_locked;
                case 3 -> R.string.usbc_port_security_mode_charging_only_when_locked_afu;
                case 4 -> R.string.usbc_port_security_mode_on;
                default -> throw new IllegalArgumentException();
            };
        }
        osEnforced.append(context.getString(usbcPortSecurityModePrefix,
                context.getString(usbcPortSecurityModeValueRes)));

        final int autoRebootSeconds = securityStateExt.autoRebootSeconds();
        final String autoRebootValueString;
        if (autoRebootSeconds == SecurityStateExt.UNKNOWN_VALUE) {
            autoRebootValueString = context.getString(R.string.unknown_value);
        } else if (autoRebootSeconds == SecurityStateExt.INVALID_VALUE) {
            autoRebootValueString = context.getString(R.string.invalid_value);
        } else {
            final Duration duration = Duration.ofSeconds(autoRebootSeconds);
            StringBuilder autoRebootValueStrBuilder = new StringBuilder();

            long hoursDuration = duration.toHours();
            if (hoursDuration > 1) {
                autoRebootValueStrBuilder.append(
                        context.getString(R.string.auto_reboot_hours_plural_value, hoursDuration));
            } else if (hoursDuration == 1) {
                autoRebootValueStrBuilder.append(
                        context.getString(R.string.auto_reboot_hours_singular_value));
            }

            int minutesPart = duration.toMinutesPart();
            if (minutesPart > 1) {
                if (autoRebootValueStrBuilder.length() != 0) {
                    autoRebootValueStrBuilder.append(", ");
                }
                autoRebootValueStrBuilder.append(
                        context.getString(R.string.auto_reboot_minutes_plural_value, minutesPart));
            } else if (minutesPart == 1) {
                if (autoRebootValueStrBuilder.length() != 0) {
                    autoRebootValueStrBuilder.append(", ");
                }
                autoRebootValueStrBuilder.append(
                        context.getString(R.string.auto_reboot_minutes_singular_value));
            }

            int secondsPart = duration.toSecondsPart();
            if (secondsPart > 1) {
                if (autoRebootValueStrBuilder.length() != 0) {
                    autoRebootValueStrBuilder.append(", ");
                }
                autoRebootValueStrBuilder.append(
                        context.getString(R.string.auto_reboot_seconds_plural_value, secondsPart));
            } else if (secondsPart == 1) {
                if (autoRebootValueStrBuilder.length() != 0) {
                    autoRebootValueStrBuilder.append(", ");
                }
                autoRebootValueStrBuilder.append(
                        context.getString(R.string.auto_reboot_seconds_singular_value));
            }

            autoRebootValueString = autoRebootValueStrBuilder.toString();
        }
        osEnforced.append(context.getString(R.string.auto_reboot_timeout, autoRebootValueString));

        final byte userCount = securityStateExt.userCount();
        final String userCountValueString;
        if (userCount == SecurityStateExt.UNKNOWN_VALUE) {
            userCountValueString = context.getString(R.string.unknown_value);
        } else if (userCount == SecurityStateExt.INVALID_VALUE) {
            userCountValueString = context.getString(R.string.invalid_value);
        } else {
            userCountValueString = String.valueOf(securityStateExt.userCount());
        }
        osEnforced.append(context.getString(R.string.user_count, userCountValueString));

        return new VerificationResult(hasPersistentKey, teeEnforced.toString(), osEnforced.toString(), history.toString());
    }

    private static Certificate[] decodeChain(final byte[] dictionary, final byte[] compressedChain)
            throws DataFormatException, GeneralSecurityException {
        final byte[] chain = new byte[MAX_ENCODED_CHAIN_LENGTH];
        final Inflater inflater = new Inflater(true);
        inflater.setInput(compressedChain);
        inflater.setDictionary(dictionary);
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
        return certs.toArray(new Certificate[0]);
    }

    private static byte[] encodeChain(final byte[] dictionary, final Certificate[] certificates)
            throws CertificateEncodingException, IOException {
        final ByteBuffer chainSerializer = ByteBuffer.allocate(MAX_ENCODED_CHAIN_LENGTH);
        for (Certificate certificate : certificates) {
            final byte[] encoded = certificate.getEncoded();
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
        final Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        deflater.setDictionary(dictionary);
        final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(byteStream, deflater);
        deflaterStream.write(chain);
        deflaterStream.finish();
        final byte[] compressed = byteStream.toByteArray();
        Log.d(TAG, "encoded length: " + chain.length + ", compressed length: " + compressed.length);

        return compressed;
    }

    static VerificationResult verifySerialized(final Context context, final byte[] attestationResult,
            final byte[] challengeMessage) throws DataFormatException, GeneralSecurityException {
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

        final int dictionary = R.raw.deflate_dictionary_4;
        final Certificate[] certificates =
                decodeChain(readRawResource(context, dictionary), compressedChain);

        final byte[] fingerprint = new byte[FINGERPRINT_LENGTH];
        deserializer.get(fingerprint);

        final int osEnforcedFlags = deserializer.getInt();
        if ((osEnforcedFlags & ~OS_ENFORCED_FLAGS_ALL) != 0) {
            Log.w(TAG, "unknown OS enforced flag set (flags: " + Integer.toBinaryString(osEnforcedFlags) + ")");
        }
        final boolean userProfileSecure = (osEnforcedFlags & OS_ENFORCED_FLAGS_USER_PROFILE_SECURE) != 0;
        final boolean accessibility = (osEnforcedFlags & OS_ENFORCED_FLAGS_ACCESSIBILITY) != 0;
        final boolean deviceAdmin = (osEnforcedFlags & OS_ENFORCED_FLAGS_DEVICE_ADMIN) != 0;
        final boolean deviceAdminNonSystem = (osEnforcedFlags & OS_ENFORCED_FLAGS_DEVICE_ADMIN_NON_SYSTEM) != 0;
        final boolean adbEnabled = (osEnforcedFlags & OS_ENFORCED_FLAGS_ADB_ENABLED) != 0;
        final boolean addUsersWhenLocked = (osEnforcedFlags & OS_ENFORCED_FLAGS_ADD_USERS_WHEN_LOCKED) != 0;
        final boolean enrolledBiometrics = (osEnforcedFlags & OS_ENFORCED_FLAGS_ENROLLED_BIOMETRICS) != 0;
        final boolean oemUnlockAllowed = (osEnforcedFlags & OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED) != 0;
        final boolean systemUser = (osEnforcedFlags & OS_ENFORCED_FLAGS_SYSTEM_USER) != 0;

        if (deviceAdminNonSystem && !deviceAdmin) {
            throw new GeneralSecurityException("invalid device administrator state");
        }

        final SecurityStateExt securityStateExt;
        if (version >= 6) {
            final int autoRebootSeconds = deserializer.getInt();
            final byte portSecurityMode = deserializer.get();
            final byte userCount = deserializer.get();
            securityStateExt = new SecurityStateExt(autoRebootSeconds, portSecurityMode, userCount);
        } else {
            securityStateExt = SecurityStateExt.UNKNOWN;
        }

        final int signatureLength = deserializer.remaining();
        final byte[] signature = new byte[signatureLength];
        deserializer.get(signature);

        deserializer.rewind();
        deserializer.limit(deserializer.capacity() - signature.length);

        final byte[] challenge = Arrays.copyOfRange(challengeMessage, 1 + RANDOM_TOKEN_LENGTH, 1 + RANDOM_TOKEN_LENGTH * 2);
        return verify(context, fingerprint, challenge, deserializer.asReadOnlyBuffer(), signature,
                certificates, userProfileSecure, accessibility, deviceAdmin, deviceAdminNonSystem,
                adbEnabled, addUsersWhenLocked, enrolledBiometrics, oemUnlockAllowed, systemUser,
                securityStateExt);
    }

    record AttestationResult(boolean pairing, byte[] serialized) {
    }

    static KeyGenParameterSpec.Builder getKeyBuilder(final String alias, final int purposes,
            final boolean useStrongBox, final byte[] challenge, final boolean temporary) {
        final long now = System.currentTimeMillis();
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                .setDigests(KEY_DIGEST)
                .setAttestationChallenge(challenge)
                .setKeyValidityStart(new Date(now - CLOCK_SKEW_MS));
        if (temporary) {
            builder.setKeyValidityEnd(new Date(now + CLOCK_SKEW_MS + EXPIRATION_MS));
        }
        if (useStrongBox) {
            builder.setIsStrongBoxBacked(true);
        }
        return builder;
    }

    static void generateAttestKey(final String alias, final byte[] challenge, final boolean useStrongBox) throws
            GeneralSecurityException, IOException {
        generateKeyPair(getKeyBuilder(alias, KeyProperties.PURPOSE_ATTEST_KEY,
                useStrongBox, challenge, false).build());
    }

    static Certificate getCertificate(final KeyStore keyStore, final String alias)
            throws GeneralSecurityException {
        final Certificate result = keyStore.getCertificate(alias);
        if (result == null) {
            throw new GeneralSecurityException("invalid hardware keystore state");
        }
        return result;
    }

    static Certificate[] getCertificateChain(final KeyStore keyStore, final String alias)
            throws GeneralSecurityException {
        final Certificate[] result = keyStore.getCertificateChain(alias);
        if (result == null) {
            throw new GeneralSecurityException("invalid hardware keystore state");
        }
        return result;
    }

    @SuppressWarnings("deprecation")
    static ApplicationInfo getApplicationInfo(final PackageManager pm, final String packageName,
            final int flags) throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return pm.getApplicationInfo(packageName, flags);
        }
        return pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(flags));
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
        final byte version = (byte) Math.min(PROTOCOL_VERSION, maxVersion);
        final byte[] challengeIndex = Arrays.copyOfRange(challengeMessage, 1, 1 + RANDOM_TOKEN_LENGTH);
        final byte[] challenge = Arrays.copyOfRange(challengeMessage, 1 + RANDOM_TOKEN_LENGTH, 1 + RANDOM_TOKEN_LENGTH * 2);

        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (index == null) {
            index = BaseEncoding.base16().encode(challengeIndex);
        }

        final String attestKeystoreAlias =
                statePrefix + KEYSTORE_ALIAS_ATTEST_PREFIX + index;
        final String persistentKeystoreAlias =
                statePrefix + KEYSTORE_ALIAS_PERSISTENT_PREFIX + index;

        final PackageManager pm = context.getPackageManager();

        // generate a new key for fresh attestation results unless the persistent key is not yet created
        final boolean hasPersistentKey = keyStore.containsAlias(persistentKeystoreAlias);
        final String attestationKeystoreAlias;
        final boolean useStrongBox;
        @SuppressLint("InlinedApi")
        final boolean canUseAttestKey = (alwaysHasAttestKey || pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY));
        final boolean useAttestKey;
        if (hasPersistentKey) {
            final String freshKeyStoreAlias = statePrefix + KEYSTORE_ALIAS_FRESH;
            keyStore.deleteEntry(freshKeyStoreAlias);
            attestationKeystoreAlias = freshKeyStoreAlias;

            final PrivateKey key = (PrivateKey) keyStore.getKey(persistentKeystoreAlias, null);
            final KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            final KeyInfo keyinfo = factory.getKeySpec(key, KeyInfo.class);
            useStrongBox = keyinfo.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX;

            final boolean hasAttestKey = keyStore.containsAlias(attestKeystoreAlias);
            if (hasAttestKey) {
                useAttestKey = true;
            } else {
                if (canUseAttestKey) {
                    generateAttestKey(attestKeystoreAlias, challenge, useStrongBox);
                    useAttestKey = true;
                } else {
                    useAttestKey = false;
                }
            }
        } else {
            attestationKeystoreAlias = persistentKeystoreAlias;
            useStrongBox = isStrongBoxSupported && PREFER_STRONGBOX;
            useAttestKey = canUseAttestKey;

            if (useAttestKey) {
                generateAttestKey(attestKeystoreAlias, challenge, useStrongBox);
            }
        }

        final KeyGenParameterSpec.Builder builder = getKeyBuilder(attestationKeystoreAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY, useStrongBox, challenge,
                hasPersistentKey);
        if (useAttestKey) {
            builder.setAttestKeyAlias(attestKeystoreAlias);
        }
        generateKeyPair(builder.build());

        try {
            final byte[] fingerprint =
                    getFingerprint(getCertificate(keyStore, persistentKeystoreAlias));

            final Certificate[] attestationCertificates;

            if (useAttestKey) {
                final Certificate[] attestCertificates = getCertificateChain(keyStore, attestKeystoreAlias);
                attestationCertificates = new Certificate[1 + attestCertificates.length];
                System.arraycopy(attestCertificates, 0, attestationCertificates, 1, attestCertificates.length);
                attestationCertificates[0] = getCertificate(keyStore, attestationKeystoreAlias);
            } else {
                attestationCertificates = getCertificateChain(keyStore, attestationKeystoreAlias);
            }

            // OS-enforced checks and information

            final DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);

            final List<ComponentName> activeAdmins = dpm.getActiveAdmins();
            final boolean deviceAdmin = activeAdmins != null && activeAdmins.size() > 0;
            boolean deviceAdminNonSystem = false;
            if (activeAdmins != null) {
                for (final ComponentName name : activeAdmins) {
                    try {
                        final ApplicationInfo info = getApplicationInfo(pm, name.getPackageName(), 0);
                        if ((info.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {
                            deviceAdminNonSystem = true;
                        }
                    } catch (final PackageManager.NameNotFoundException e) {
                        throw new GeneralSecurityException(e);
                    }
                }
            }

            if (dpm.getStorageEncryptionStatus() == DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED) {
                throw new GeneralSecurityException("encryption not enabled");
            }

            final KeyguardManager keyguard = context.getSystemService(KeyguardManager.class);
            final boolean userProfileSecure = keyguard.isDeviceSecure();
            if (userProfileSecure && !keyguard.isKeyguardSecure()) {
                throw new GeneralSecurityException("keyguard state inconsistent");
            }
            final BiometricManager biometricManager = BiometricManager.from(context);
            final boolean enrolledBiometrics = biometricManager.canAuthenticate(BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS;

            final AccessibilityManager am = context.getSystemService(AccessibilityManager.class);
            final boolean accessibility = am.isEnabled();

            final boolean adbEnabled = Settings.Global.getInt(context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) != 0;
            final boolean addUsersWhenLocked = Settings.Global.getInt(context.getContentResolver(),
                    ADD_USERS_WHEN_LOCKED, 0) != 0;

            final String oemUnlockAllowedValue = SystemProperties.get("sys.oem_unlock_allowed", "0");
            final boolean oemUnlockAllowed = oemUnlockAllowedValue.equals("1");

            final UserManager userManager = context.getSystemService(UserManager.class);
            final boolean systemUser = userManager.isSystemUser();

            final Bundle extraSecurityState;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                SecurityStateManager securityStateManager =
                        context.getSystemService(SecurityStateManager.class);

                if (securityStateManager != null) {
                    Bundle extraSecurityStateTmp = Bundle.EMPTY;
                    try {
                        Bundle globalSecurityState = securityStateManager.getGlobalSecurityState();
                        String securityStateExtKey = "android.ext.SECURITY_STATE_EXT";
                        extraSecurityStateTmp = globalSecurityState.getBundle(securityStateExtKey);
                    } catch (SecurityException e) {
                        Log.e(TAG, "", e);
                        String message = e.getMessage();
                        if (message == null || !message.startsWith("get package info")
                                || !message.endsWith("requires "
                                + "android.permission.INTERACT_ACROSS_USERS_FULL or "
                                + "android.permission.INTERACT_ACROSS_USERS to access user 0.")) {
                            throw new GeneralSecurityException(e);
                        }
                    }
                    extraSecurityState = extraSecurityStateTmp != null ? extraSecurityStateTmp : Bundle.EMPTY;
                } else {
                    extraSecurityState = Bundle.EMPTY;
                }
            } else {
                extraSecurityState = Bundle.EMPTY;
            }

            // Serialization

            final ByteBuffer serializer = ByteBuffer.allocate(MAX_MESSAGE_SIZE);

            serializer.put(version);

            final byte[] compressed;
            final int dictionary = R.raw.deflate_dictionary_4;
            compressed = encodeChain(readRawResource(context, dictionary), attestationCertificates);

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
            if (enrolledBiometrics) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_ENROLLED_BIOMETRICS;
            }
            if (oemUnlockAllowed) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_OEM_UNLOCK_ALLOWED;
            }
            if (systemUser) {
                osEnforcedFlags |= OS_ENFORCED_FLAGS_SYSTEM_USER;
            }
            if (extraSecurityState != Bundle.EMPTY) {
            }
            serializer.putInt(osEnforcedFlags);

            if (version >= 6) {
                String autoRebootTimeoutKey = "android.ext.AUTO_REBOOT_TIMEOUT";
                final int autoRebootMilliseconds =
                        extraSecurityState.getInt(autoRebootTimeoutKey, SecurityStateExt.UNKNOWN_VALUE);
                final int autoRebootSeconds;
                if (autoRebootMilliseconds == SecurityStateExt.UNKNOWN_VALUE) {
                    autoRebootSeconds = SecurityStateExt.UNKNOWN_VALUE;
                } else if (autoRebootMilliseconds < TimeUnit.SECONDS.toMillis(20)) {
                    autoRebootSeconds = SecurityStateExt.INVALID_VALUE;
                } else {
                    autoRebootSeconds = (int) (Math.ceil((double) autoRebootMilliseconds / TimeUnit.SECONDS.toMillis(1)));
                }
                serializer.putInt(autoRebootSeconds);

                String portSecurityModeKey = "android.ext.USB_PORT_SECURITY_MODE";
                final int portSecurityModeRaw = extraSecurityState.getInt(portSecurityModeKey, SecurityStateExt.UNKNOWN_VALUE);
                final byte portSecurityMode;
                if (portSecurityModeRaw == SecurityStateExt.UNKNOWN_VALUE) {
                    portSecurityMode = (byte) SecurityStateExt.UNKNOWN_VALUE;
                } else if (portSecurityModeRaw > Byte.MAX_VALUE || portSecurityModeRaw < 0) {
                    portSecurityMode = (byte) SecurityStateExt.INVALID_VALUE;
                } else {
                    portSecurityMode = (byte) portSecurityModeRaw;
                }
                serializer.put(portSecurityMode);

                String userCountKey = "android.ext.USER_COUNT";
                final int userCountRaw = extraSecurityState.getInt(userCountKey, SecurityStateExt.UNKNOWN_VALUE);
                final byte userCount;
                if (userCountRaw == SecurityStateExt.UNKNOWN_VALUE) {
                    userCount = (byte) SecurityStateExt.UNKNOWN_VALUE;
                } else if (userCountRaw > Byte.MAX_VALUE || userCountRaw < 0) {
                    userCount = (byte) SecurityStateExt.INVALID_VALUE;
                } else {
                    userCount = (byte) userCountRaw;
                }
                serializer.put(userCount);
            }

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

    static void generateKeyPair(final KeyGenParameterSpec spec)
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
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore");
            keyPairGenerator.initialize(spec);
            keyPairGenerator.generateKeyPair();
        } catch (final ProviderException e) {
            throw new IOException(e);
        }
    }

    static void deleteKey(final KeyStore keyStore, final String alias) throws GeneralSecurityException {
        Log.d(TAG, "deleting key " + alias);
        keyStore.deleteEntry(alias);
    }

    static void clearAuditee() throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (alias.startsWith(KEYSTORE_ALIAS_ATTEST_PREFIX) || alias.startsWith(KEYSTORE_ALIAS_PERSISTENT_PREFIX)) {
                deleteKey(keyStore, alias);
            }
        }
    }

    static void clearAuditee(final String statePrefix, final String index)
            throws GeneralSecurityException, IOException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        deleteKey(keyStore, statePrefix + KEYSTORE_ALIAS_ATTEST_PREFIX + index);
        deleteKey(keyStore, statePrefix + KEYSTORE_ALIAS_PERSISTENT_PREFIX + index);
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
