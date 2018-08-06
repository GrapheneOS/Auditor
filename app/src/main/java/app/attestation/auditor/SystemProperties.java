package app.attestation.auditor;

import java.io.IOException;
import java.util.Scanner;

class SystemProperties {
    public static String get(final String key, final String def) {
        Scanner scanner = null;
        try {
            final Process process = new ProcessBuilder("getprop", key, def).start();
            scanner = new Scanner(process.getInputStream());
            return scanner.nextLine().trim();
        } catch (IOException e) {
            return def;
        } finally {
            if (scanner != null) {
                scanner.close();
            }
        }
    }
}
