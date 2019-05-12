package app.attestation.auditor;

import android.app.IntentService;
import android.app.PendingIntent;
import android.content.Intent;
import android.util.Log;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.security.GeneralSecurityException;
import java.util.zip.DataFormatException;

public class VerifyAttestationService extends IntentService {
    private static final String TAG = "VerifyAttestationService";

    static final String EXTRA_CHALLENGE_MESSAGE = "app.attestation.auditor.CHALLENGE_MESSAGE";
    static final String EXTRA_SERIALIZED = "app.attestation.auditor.SERIALIZED";
    static final String EXTRA_PENDING_RESULT = "app.attestation.auditor.PENDING_RESULT";

    static final String EXTRA_STRONG = "app.attestation.auditor.STRONG";
    static final String EXTRA_TEE_ENFORCED = "app.attestation.auditor.TEE_ENFORCED";
    static final String EXTRA_OS_ENFORCED = "app.attestation.auditor.OS_ENFORCED";
    static final String EXTRA_ERROR = "app.attestation.auditor.ERROR";
    static final String EXTRA_CLEAR = "app.attestation.auditor.CLEAR";

    static final int RESULT_CODE = 0;

    public VerifyAttestationService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(final Intent intent) {
        Log.d(TAG, "intent service started");

        if (intent.getBooleanExtra(EXTRA_CLEAR, false)) {
            AttestationProtocol.clearAuditor(this);
            return;
        }

        final byte[] challengeMessage = intent.getByteArrayExtra(EXTRA_CHALLENGE_MESSAGE);
        if (challengeMessage == null) {
            throw new RuntimeException("no challenge message");
        }
        final byte[] serialized = intent.getByteArrayExtra(EXTRA_SERIALIZED);
        if (serialized == null) {
            throw new RuntimeException("no serialized attestation");
        }
        final PendingIntent pending = intent.getParcelableExtra(EXTRA_PENDING_RESULT);
        if (pending == null) {
            throw new RuntimeException("no pending intent");
        }

        final Intent resultIntent = new Intent();

        try {
            final AttestationProtocol.VerificationResult result = AttestationProtocol.verifySerialized(this, serialized, challengeMessage);
            resultIntent.putExtra(EXTRA_STRONG, result.strong);
            resultIntent.putExtra(EXTRA_TEE_ENFORCED, result.teeEnforced);
            resultIntent.putExtra(EXTRA_OS_ENFORCED, result.osEnforced);
        } catch (final DataFormatException | GeneralSecurityException | IOException e) {
            Log.e(TAG, "attestation generation error", e);
            resultIntent.putExtra(EXTRA_ERROR, e.getMessage());
        } catch (final BufferUnderflowException | NegativeArraySizeException e) {
            Log.e(TAG, "attestation generation error", e);
            resultIntent.putExtra(EXTRA_ERROR, "Invalid attestation format");
        }

        try {
            pending.send(this, RESULT_CODE, resultIntent);
        } catch (PendingIntent.CanceledException e) {
            Log.e(TAG, "pending intent cancelled", e);
        }
    }
}
