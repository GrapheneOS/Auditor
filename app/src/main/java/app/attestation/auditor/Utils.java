package app.attestation.auditor;

import com.google.common.io.BaseEncoding;

import java.util.Locale;

class Utils {
    static String logFormatBytes(final byte[] bytes) {
        return String.format(Locale.US, "%d binary bytes logged here as base64 (%s)", bytes.length,
                BaseEncoding.base64().encode(bytes));
    }
}
