package app.attestation.auditor;

import android.app.IntentService;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class GenerateAttestationService extends IntentService {
    private static final String TAG = "GenerateAttestationService";

    static final String EXTRA_CHALLENGE_MESSAGE = "app.attestation.auditor.CHALLENGE_MESSAGE";
    static final String EXTRA_PENDING_RESULT = "app.attestation.auditor.PENDING_RESULT";

    static final String EXTRA_PAIRING = "app.attestation.auditor.PAIRING";
    static final String EXTRA_ATTESTATION = "app.attestation.auditor.ATTESTATION";
    static final String EXTRA_ATTESTATION_ERROR = "app.attestation.auditor.ATTESTATION_ERROR";
    static final String EXTRA_CLEAR = "app.attestation.auditor.CLEAR";
    static final String EXTRA_CLEAR_STATE_PREFIX = "app.attestation.auditor.CLEAR_STATE_PREFIX";
    static final String EXTRA_CLEAR_INDEX = "app.attestation.auditor.CLEAR_INDEX";

    static final int RESULT_CODE = 0;

    public GenerateAttestationService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(final Intent intent) {
        Log.d(TAG, "intent service started");

        if (intent.getBooleanExtra(EXTRA_CLEAR, false)) {
            try {
                final String statePrefix = intent.getStringExtra(EXTRA_CLEAR_STATE_PREFIX);
                if (statePrefix != null) {
                    final String index = intent.getStringExtra(EXTRA_CLEAR_INDEX);
                    AttestationProtocol.clearAuditee(statePrefix, index);
                } else {
                    AttestationProtocol.clearAuditee();
                }
            } catch (final GeneralSecurityException | IOException e) {
                Log.e(TAG, "clearAuditee", e);
            }
            return;
        }

        final byte[] challengeMessage = intent.getByteArrayExtra(EXTRA_CHALLENGE_MESSAGE);
        if (challengeMessage == null) {
            throw new RuntimeException("no challenge message");
        }
        PendingIntent initialPending = null;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            initialPending = intent.getParcelableExtra(EXTRA_PENDING_RESULT);
        } else {
            initialPending = intent.getParcelableExtra(EXTRA_PENDING_RESULT, PendingIntent.class);
        }
        final PendingIntent pending = initialPending;
        if (pending == null) {
            throw new RuntimeException("no pending intent");
        }

        final Intent resultIntent = new Intent();

        try {
            final AttestationProtocol.AttestationResult result =
                    AttestationProtocol.generateSerialized(this, challengeMessage, null, "");
            resultIntent.putExtra(EXTRA_PAIRING, result.pairing);
            resultIntent.putExtra(EXTRA_ATTESTATION, result.serialized);
        } catch (final GeneralSecurityException | IOException e) {
            Log.e(TAG, "attestation generation error", e);
            resultIntent.putExtra(EXTRA_ATTESTATION_ERROR, e.getMessage());
        }

        try {
            pending.send(this, RESULT_CODE, resultIntent);
        } catch (PendingIntent.CanceledException e) {
            Log.e(TAG, "pending intent cancelled", e);
        }
    }
}
