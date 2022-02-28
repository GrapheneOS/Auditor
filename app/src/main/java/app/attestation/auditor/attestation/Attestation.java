/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package app.attestation.auditor.attestation;

import androidx.annotation.NonNull;

import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Sequence;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Parses an attestation certificate and provides an easy-to-use interface for examining the
 * contents.
 */
public class Attestation {
    static final String EAT_OID = "1.3.6.1.4.1.11129.2.1.25";
    static final String ASN1_OID = "1.3.6.1.4.1.11129.2.1.17";
    static final String KEY_USAGE_OID = "2.5.29.15"; // Standard key usage extension.
    static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
    static final int ATTESTATION_VERSION_INDEX = 0;
    static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
    static final int KEYMASTER_VERSION_INDEX = 2;
    static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
    static final int ATTESTATION_CHALLENGE_INDEX = 4;
    static final int UNIQUE_ID_INDEX = 5;
    static final int SW_ENFORCED_INDEX = 6;
    static final int TEE_ENFORCED_INDEX = 7;

    public static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
    public static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;

    // Known KeyMaster/KeyMint versions. This is the version number
    // which appear in the keymasterVersion field.
    public static final int KM_VERSION_KEYMASTER_1 = 10;
    public static final int KM_VERSION_KEYMASTER_1_1 = 11;
    public static final int KM_VERSION_KEYMASTER_2 = 20;
    public static final int KM_VERSION_KEYMASTER_3 = 30;
    public static final int KM_VERSION_KEYMASTER_4 = 40;
    public static final int KM_VERSION_KEYMASTER_4_1 = 41;
    public static final int KM_VERSION_KEYMINT_1 = 100;

    private final int attestationVersion;
    private final int attestationSecurityLevel;
    private final int keymasterVersion;
    private final int keymasterSecurityLevel;
    private final byte[] attestationChallenge;
    private final byte[] uniqueId;
    private final AuthorizationList softwareEnforced;
    private final AuthorizationList teeEnforced;
    private final Set<String> unexpectedExtensionOids;

    /**
     * Constructs an {@code Attestation} object from the provided {@link X509Certificate},
     * extracting the attestation data from the attestation extension.
     *
     * <p>This method ensures that at most one attestation extension is included in the certificate.
     *
     * @throws CertificateParsingException if the certificate does not contain a properly-formatted
     *     attestation extension, if it contains multiple attestation extensions, or if the
     *     attestation extension can not be parsed.
     */
    public Attestation(X509Certificate x509Cert) throws CertificateParsingException {
        ASN1Sequence seq = getAttestationSequence(x509Cert);

        attestationVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_VERSION_INDEX));
        attestationSecurityLevel = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX));
        keymasterVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_VERSION_INDEX));
        keymasterSecurityLevel = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX));

        attestationChallenge =
                Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(Attestation.ATTESTATION_CHALLENGE_INDEX));

        uniqueId = Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(Attestation.UNIQUE_ID_INDEX));

        softwareEnforced = new AuthorizationList(seq.getObjectAt(SW_ENFORCED_INDEX));
        teeEnforced = new AuthorizationList(seq.getObjectAt(TEE_ENFORCED_INDEX));
        unexpectedExtensionOids = retrieveUnexpectedExtensionOids(x509Cert);
    }

    public static String securityLevelToString(int attestationSecurityLevel) {
        switch (attestationSecurityLevel) {
            case KM_SECURITY_LEVEL_SOFTWARE:
                return "Software";
            case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                return "TEE";
            case KM_SECURITY_LEVEL_STRONG_BOX:
                return "StrongBox";
            default:
                return "Unknown";
        }
    }

    public int getAttestationVersion() {
        return attestationVersion;
    }

    public int getAttestationSecurityLevel() {
        return attestationSecurityLevel;
    }

    // Returns one of the KM_VERSION_* values define above.
    public int getKeymasterVersion() {
        return keymasterVersion;
    }

    public int getKeymasterSecurityLevel() {
        return keymasterSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return attestationChallenge;
    }

    public byte[] getUniqueId() {
        return uniqueId;
    }

    public AuthorizationList getSoftwareEnforced() {
        return softwareEnforced;
    }

    public AuthorizationList getTeeEnforced() {
        return teeEnforced;
    }

    public Set<String> getUnexpectedExtensionOids() {
        return unexpectedExtensionOids;
    }

    @NonNull
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("Extension type: " + getClass());
        s.append("\nAttest version: " + attestationVersion);
        s.append("\nAttest security: " + securityLevelToString(getAttestationSecurityLevel()));
        s.append("\nKM version: " + keymasterVersion);
        s.append("\nKM security: " + securityLevelToString(keymasterSecurityLevel));

        s.append("\nChallenge");
        String stringChallenge =
                attestationChallenge != null ? new String(attestationChallenge) : "null";
        if (CharMatcher.ascii().matchesAllOf(stringChallenge)) {
            s.append(": [" + stringChallenge + "]");
        } else {
            s.append(" (base64): [" + BaseEncoding.base64().encode(attestationChallenge) + "]");
        }
        if (uniqueId != null) {
            s.append("\nUnique ID (base64): [" + BaseEncoding.base64().encode(uniqueId) + "]");
        }

        s.append("\n-- SW enforced --");
        s.append(softwareEnforced);
        s.append("\n-- TEE enforced --");
        s.append(teeEnforced);

        return s.toString();
    }

    private ASN1Sequence getAttestationSequence(X509Certificate x509Cert)
            throws CertificateParsingException {
        byte[] attestationExtensionBytes = x509Cert.getExtensionValue(KEY_DESCRIPTION_OID);
        if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
            throw new CertificateParsingException(
                    "Did not find extension with OID " + KEY_DESCRIPTION_OID);
        }
        return Asn1Utils.getAsn1SequenceFromBytes(attestationExtensionBytes);
    }

    Set<String> retrieveUnexpectedExtensionOids(X509Certificate x509Cert) {
        return new ImmutableSet.Builder<String>()
                .addAll(
                        x509Cert.getCriticalExtensionOIDs().stream()
                                .filter(s -> !KEY_USAGE_OID.equals(s))
                                .iterator())
                .addAll(
                        x509Cert.getNonCriticalExtensionOIDs().stream()
                                .filter(s -> !ASN1_OID.equals(s) && !EAT_OID.equals(s))
                                .iterator())
                .build();
    }
}
