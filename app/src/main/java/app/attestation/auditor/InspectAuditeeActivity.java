package app.attestation.auditor;

import android.os.Bundle;
import android.util.Log;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.util.Date;

public class InspectAuditeeActivity extends AppCompatActivity {

    private static final String TAG = "InspectAuditeeActivity";

    public static final String INTENT_KEY_FINGERPRINT = "fingerprintHex";

    private void addSummaryField(final String fieldName, final String fieldValue) {
        final TableLayout summaryContainer = findViewById(R.id.summary);
        final TableRow fieldContainer = (TableRow) getLayoutInflater().inflate(R.layout.content_auditee_summary_field, summaryContainer, false);
        final TextView fieldLabel = fieldContainer.findViewById(R.id.name);
        final TextView fieldContent = fieldContainer.findViewById(R.id.value);
        fieldLabel.setText(fieldName);
        fieldContent.setText(fieldValue);
        summaryContainer.addView(fieldContainer);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_inspectauditee);

        final String fingerprint_hex = getIntent().getStringExtra(INTENT_KEY_FINGERPRINT);
        if (fingerprint_hex == null || fingerprint_hex.isBlank()) {
            Log.e(TAG, "auditee fingerprint not provided");
            return;
        }
        addSummaryField("fingerprint", fingerprint_hex);

        final AttestationProtocol.AuditeeSummary summary = AttestationProtocol.getAuditorSummary(
                this,
                fingerprint_hex
        );
        if (summary == null) {
            Log.e(TAG,"auditee was not found");
            return;
        }
        addSummaryField("first verified", new Date(summary.verifiedTimeFirst()).toString());
        addSummaryField("last verified", new Date(summary.verifiedTimeLast()).toString());
        addSummaryField("verified boot key", summary.verifiedBootKey());
        addSummaryField("pinned OS version", String.valueOf(summary.pinnedOsVersion()));
        addSummaryField("pinned OS patch level", String.valueOf(summary.pinnedOsPatchLevel()));
        addSummaryField("pinned vendor patch level", String.valueOf(summary.pinnedVendorPatchLevel()));
        addSummaryField("pinned boot patch level", String.valueOf(summary.pinnedBootPatchLevel()));
        addSummaryField("pinned app version", String.valueOf(summary.pinnedAppVersion()));
        addSummaryField("pinned app variant", String.valueOf(summary.pinnedAppVariant()));
        addSummaryField("pinned security level", String.valueOf(summary.pinnedSecurityLevel()));
    }

}