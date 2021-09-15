package app.attestation.auditor;

import java.io.IOException;
import java.util.Scanner;

class SystemProperties {
    public static String get(final String key, final String def) {
        try {
            final Process process = new ProcessBuilder("getprop", key, def).start();
            try (Scanner scanner = new Scanner(process.getInputStream())) {
                return scanner.nextLine().trim();
            }
        } catch (IOException e) {}
        return def;
    }
}
