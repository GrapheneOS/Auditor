package app.attestation.auditor

import java.io.IOException
import java.util.Scanner

object SystemProperties {
    @JvmStatic
    fun get(key: String, def: String): String {
        try {
            val process = ProcessBuilder("getprop", key, def).start()
            Scanner(process.inputStream).use {
                return it.nextLine().trim()
            }
        } catch (_: IOException) {
            return def
        }
    }
}
