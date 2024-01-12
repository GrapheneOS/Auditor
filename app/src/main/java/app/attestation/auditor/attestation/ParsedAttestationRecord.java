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

import static app.attestation.auditor.attestation.Constants.ATTESTATION_CHALLENGE_INDEX;
import static app.attestation.auditor.attestation.Constants.ATTESTATION_SECURITY_LEVEL_INDEX;
import static app.attestation.auditor.attestation.Constants.ATTESTATION_VERSION_INDEX;
import static app.attestation.auditor.attestation.Constants.KEYMASTER_SECURITY_LEVEL_INDEX;
import static app.attestation.auditor.attestation.Constants.KEYMASTER_VERSION_INDEX;
import static app.attestation.auditor.attestation.Constants.KEY_DESCRIPTION_OID;
import static app.attestation.auditor.attestation.Constants.KM_SECURITY_LEVEL_SOFTWARE;
import static app.attestation.auditor.attestation.Constants.KM_SECURITY_LEVEL_STRONG_BOX;
import static app.attestation.auditor.attestation.Constants.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
import static app.attestation.auditor.attestation.Constants.SW_ENFORCED_INDEX;
import static app.attestation.auditor.attestation.Constants.TEE_ENFORCED_INDEX;
import static app.attestation.auditor.attestation.Constants.UNIQUE_ID_INDEX;

import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/** Java representation of Key Attestation extension data. */
@Immutable
public class ParsedAttestationRecord {

  public final int attestationVersion;
  public final SecurityLevel attestationSecurityLevel;
  public final int keymasterVersion;
  public final SecurityLevel keymasterSecurityLevel;
  public final ByteString attestationChallenge;
  public final ByteString uniqueId;
  public final AuthorizationList softwareEnforced;
  public final AuthorizationList teeEnforced;

  @SuppressWarnings("Immutable")
  public final PublicKey attestedKey;

  private ParsedAttestationRecord(ASN1Sequence extensionData, PublicKey attestedKey) {
    this.attestationVersion =
        ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX));
    this.attestationSecurityLevel =
        securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)));
    this.keymasterVersion =
        ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_VERSION_INDEX));
    this.keymasterSecurityLevel =
        securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX)));
    this.attestationChallenge =
        ByteString.copyFrom(
            ASN1OctetString.getInstance(extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX))
                .getOctets());
    this.uniqueId =
        ByteString.copyFrom(
            ASN1OctetString.getInstance(extensionData.getObjectAt(UNIQUE_ID_INDEX)).getOctets());
    this.softwareEnforced =
        AuthorizationList.createAuthorizationList(
            ASN1Sequence.getInstance(extensionData.getObjectAt(SW_ENFORCED_INDEX)).toArray(),
            attestationVersion);
    this.teeEnforced =
        AuthorizationList.createAuthorizationList(
            ASN1Sequence.getInstance(extensionData.getObjectAt(TEE_ENFORCED_INDEX)).toArray(),
            attestationVersion);
    this.attestedKey = attestedKey;
  }

  private ParsedAttestationRecord(
      int attestationVersion,
      SecurityLevel attestationSecurityLevel,
      int keymasterVersion,
      SecurityLevel keymasterSecurityLevel,
      ByteString attestationChallenge,
      ByteString uniqueId,
      AuthorizationList softwareEnforced,
      AuthorizationList teeEnforced,
      PublicKey attestedKey) {
    this.attestationVersion = attestationVersion;
    this.attestationSecurityLevel = attestationSecurityLevel;
    this.keymasterVersion = keymasterVersion;
    this.keymasterSecurityLevel = keymasterSecurityLevel;
    this.attestationChallenge = attestationChallenge;
    this.uniqueId = uniqueId;
    this.softwareEnforced = softwareEnforced;
    this.teeEnforced = teeEnforced;
    this.attestedKey = attestedKey;
  }

  public static ParsedAttestationRecord createParsedAttestationRecord(List<X509Certificate> certs)
      throws KeyDescriptionMissingException, IOException {

    // Parse the attestation record that is closest to the root. This prevents an adversary from
    // attesting an attestation record of their choice with an otherwise trusted chain using the
    // following attack:
    // 1) having the TEE attest a key under the adversary's control,
    // 2) using that key to sign a new leaf certificate with an attestation extension that has their
    //    chosen attestation record, then
    // 3) appending that certificate to the original certificate chain.
    for (int i = certs.size() - 1; i >= 0; i--) {
      byte[] attestationExtensionBytes = certs.get(i).getExtensionValue(KEY_DESCRIPTION_OID);
      if (attestationExtensionBytes != null && attestationExtensionBytes.length != 0) {
        return new ParsedAttestationRecord(
            extractAttestationSequence(attestationExtensionBytes), certs.get(i).getPublicKey());
      }
    }

    throw new KeyDescriptionMissingException("Couldn't find the keystore attestation extension data.");
  }

  public static class KeyDescriptionMissingException extends Exception {
    private KeyDescriptionMissingException(final String message) {
      super(message);
    }
  }

  public static ParsedAttestationRecord create(ASN1Sequence extensionData, PublicKey attestedKey) {
    return new ParsedAttestationRecord(extensionData, attestedKey);
  }

  public static ParsedAttestationRecord create(
      int attestationVersion,
      SecurityLevel attestationSecurityLevel,
      int keymasterVersion,
      SecurityLevel keymasterSecurityLevel,
      ByteString attestationChallenge,
      ByteString uniqueId,
      AuthorizationList softwareEnforced,
      AuthorizationList teeEnforced,
      PublicKey attestedKey) {
    return new ParsedAttestationRecord(
        attestationVersion,
        attestationSecurityLevel,
        keymasterVersion,
        keymasterSecurityLevel,
        attestationChallenge,
        uniqueId,
        softwareEnforced,
        teeEnforced,
        attestedKey);
  }

  private static SecurityLevel securityLevelToEnum(int securityLevel) {
    switch (securityLevel) {
      case KM_SECURITY_LEVEL_SOFTWARE:
        return SecurityLevel.SOFTWARE;
      case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
        return SecurityLevel.TRUSTED_ENVIRONMENT;
      case KM_SECURITY_LEVEL_STRONG_BOX:
        return SecurityLevel.STRONG_BOX;
      default:
        throw new IllegalArgumentException("Invalid security level.");
    }
  }

  public static int securityLevelToInt(SecurityLevel securityLevel) {
    switch (securityLevel) {
      case SOFTWARE:
        return KM_SECURITY_LEVEL_SOFTWARE;
      case TRUSTED_ENVIRONMENT:
        return KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
      case STRONG_BOX:
        return KM_SECURITY_LEVEL_STRONG_BOX;
    }
    throw new IllegalArgumentException("Invalid security level.");
  }

  private static ASN1Sequence extractAttestationSequence(byte[] attestationExtensionBytes)
      throws IOException {
    ASN1Sequence decodedSequence;
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(attestationExtensionBytes)) {
      // The extension contains one object, a sequence, in the
      // Distinguished Encoding Rules (DER)-encoded form. Get the DER
      // bytes.
      byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream.readObject()).getOctets();
      // Decode the bytes as an ASN1 sequence object.
      try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
        decodedSequence = (ASN1Sequence) seqInputStream.readObject();
      }
    }
    return decodedSequence;
  }

  public ASN1Sequence toAsn1Sequence() {
    ASN1Encodable[] vector = new ASN1Encodable[8];
    vector[ATTESTATION_VERSION_INDEX] = new ASN1Integer(this.attestationVersion);
    vector[ATTESTATION_SECURITY_LEVEL_INDEX] =
        new ASN1Enumerated(securityLevelToInt(this.attestationSecurityLevel));
    vector[KEYMASTER_VERSION_INDEX] = new ASN1Integer(this.keymasterVersion);
    vector[KEYMASTER_SECURITY_LEVEL_INDEX] =
        new ASN1Enumerated(securityLevelToInt(this.keymasterSecurityLevel));
    vector[ATTESTATION_CHALLENGE_INDEX] =
        new DEROctetString(this.attestationChallenge.toByteArray());
    vector[UNIQUE_ID_INDEX] = new DEROctetString(this.uniqueId.toByteArray());
    if (this.softwareEnforced != null) {
      vector[SW_ENFORCED_INDEX] = this.softwareEnforced.toAsn1Sequence();
    }
    if (this.teeEnforced != null) {
      vector[TEE_ENFORCED_INDEX] = this.teeEnforced.toAsn1Sequence();
    }
    return new DERSequence(vector);
  }

  /**
   * This indicates the extent to which a software feature, such as a key pair, is protected based
   * on its location within the device.
   */
  public enum SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONG_BOX
  }
}
