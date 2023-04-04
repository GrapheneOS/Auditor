package app.attestation.auditor

import com.google.common.io.BaseEncoding
import java.util.Locale

internal object Utils {
    @JvmStatic
    fun logFormatBytes(bytes: ByteArray): String {
        return String.format(
            Locale.US,
            "%d binary bytes logged here as base64 (%s)",
            bytes.size,
            BaseEncoding.base64().encode(bytes)
        )
    }
}