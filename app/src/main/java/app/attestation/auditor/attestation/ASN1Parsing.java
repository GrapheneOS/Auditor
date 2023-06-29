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

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;

/** Utils to get java representation of ASN1 types. */
class ASN1Parsing {

  static boolean getBooleanFromAsn1(ASN1Encodable asn1Value) {
    return getBooleanFromAsn1(asn1Value, true);
  }

  static boolean getBooleanFromAsn1(ASN1Encodable asn1Value, boolean strict) {
    if (asn1Value instanceof ASN1Boolean) {
      if (strict) {
        return Utils.getBooleanFromAsn1Strict((ASN1Boolean) asn1Value);
      }
      return ((ASN1Boolean) asn1Value).isTrue();
    } else {
      throw new IllegalArgumentException(
          "Boolean value expected; found " + asn1Value.getClass().getName() + " instead.");
    }
  }

  static int getIntegerFromAsn1(ASN1Encodable asn1Value) {
    return getIntegerFromAsn1(asn1Value, true);
  }

  static int getIntegerFromAsn1(ASN1Encodable asn1Value, boolean strict) {
    if (asn1Value instanceof ASN1Integer) {
      return Utils.intValueFromBigInteger(((ASN1Integer) asn1Value).getValue(), strict);
    } else if (asn1Value instanceof ASN1Enumerated) {
      return Utils.intValueFromBigInteger(((ASN1Enumerated) asn1Value).getValue(), strict);
    } else {
      throw new IllegalArgumentException(
          "Integer value expected; found " + asn1Value.getClass().getName() + " instead.");
    }
  }

  private ASN1Parsing() {}
}
