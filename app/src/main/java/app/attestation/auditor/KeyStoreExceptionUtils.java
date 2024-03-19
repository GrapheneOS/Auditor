package app.attestation.auditor;

import android.os.Build;
import android.security.KeyStoreException;

class KeyStoreExceptionUtils {

    // See KeymasterDefs#KM_ERROR_CANNOT_ATTEST_IDS
    private static final int PRIVATE_CANNOT_ATTEST_ID_ERROR_CODE = -66;
    // See KeymaserDefs#sErrorCodeToString
    private static final String CANNOT_ATTEST_ID_MESSAGE = "Unable to attest device ids";

    static boolean isUnableToAttestDeviceInfoError(KeyStoreException exception) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return exception.getNumericErrorCode() == KeyStoreException.ERROR_ID_ATTESTATION_FAILURE;
        }

        String localizedMessage = exception.getLocalizedMessage();
        if (localizedMessage == null) {
            return false;
        }

        return localizedMessage.contains(CANNOT_ATTEST_ID_MESSAGE)
                || localizedMessage.contains(Integer.toString(PRIVATE_CANNOT_ATTEST_ID_ERROR_CODE));
    }
}
