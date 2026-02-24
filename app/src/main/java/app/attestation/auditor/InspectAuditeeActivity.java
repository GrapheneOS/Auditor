package app.attestation.auditor;

import android.os.Bundle;
import android.util.Log;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;

import java.util.Date;

public class InspectAuditeeActivity extends AppCompatActivity {

    private static final String TAG = "InspectAuditeeActivity";

    public static final String INTENT_KEY_FINGERPRINT = "fingerprint_hex";

    private void addSummaryFieldToTable(int tableId, final String fieldName, final String fieldValue) {
        final TableLayout summaryContainer = findViewById(tableId);
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

        // set up back button
        final MaterialToolbar toolbar = findViewById(R.id.inspect_auditee_toolbar);
        setSupportActionBar(toolbar);
        final ActionBar supportActionBar = getSupportActionBar();
        if (supportActionBar != null) {
            supportActionBar.setDisplayHomeAsUpEnabled(true);
        }
        toolbar.setNavigationOnClickListener(v -> {
            finish();
        });

        // load auditee information
        final String fingerprint_hex = getIntent().getStringExtra(INTENT_KEY_FINGERPRINT);
        if (fingerprint_hex == null || fingerprint_hex.isBlank()) {
            Log.e(TAG, "auditee fingerprint not provided");
            return;
        }
        final AttestationProtocol.AuditeeSummary summary = AttestationProtocol.getAuditorSummary(
                this,
                fingerprint_hex
        );

        addSummaryFieldToTable(R.id.summary_hardware, "fingerprint", fingerprint_hex);
        addSummaryFieldToTable(R.id.summary_hardware, "pinned security level", String.valueOf(summary.pinnedSecurityLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, "pinned OS version", String.valueOf(summary.pinnedOsVersion()));
        addSummaryFieldToTable(R.id.summary_hardware, "pinned OS patch level", String.valueOf(summary.pinnedOsPatchLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, "pinned vendor patch level", String.valueOf(summary.pinnedVendorPatchLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, "pinned boot patch level", String.valueOf(summary.pinnedBootPatchLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, "verified boot key", summary.verifiedBootKey());

        addSummaryFieldToTable(R.id.summary_os, "pinned app version", String.valueOf(summary.pinnedAppVersion()));
        addSummaryFieldToTable(R.id.summary_os, "pinned app variant", String.valueOf(summary.pinnedAppVariant()));

        addSummaryFieldToTable(R.id.summary_history, "first verified", new Date(summary.verifiedTimeFirst()).toString());
        addSummaryFieldToTable(R.id.summary_history, "last verified", new Date(summary.verifiedTimeLast()).toString());
    }

}