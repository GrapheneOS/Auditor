package app.attestation.auditor

import com.google.common.io.BaseEncoding

internal object Utils {
    @JvmStatic
    fun logFormatBytes(bytes: ByteArray): String {
        val encodedBytes = BaseEncoding.base64().encode(bytes)
        return "${bytes.size} binary bytes logged here as base64 ($encodedBytes)"
    }
}