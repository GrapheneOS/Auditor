package app.attestation.auditor;

import android.os.Bundle;
import android.util.Log;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.appbar.MaterialToolbar;

import java.util.Date;

public class InspectAuditeeActivity extends AppCompatActivity {

    private static final String TAG = "InspectAuditeeActivity";

    public static final String INTENT_KEY_FINGERPRINT = "fingerprint_hex";

    private void addSummaryFieldToTable(int tableId, final int fieldNameId, final String fieldValue) {
        final TableLayout summaryContainer = findViewById(tableId);
        final TableRow fieldContainer = (TableRow) getLayoutInflater().inflate(R.layout.content_inspectauditee_summary_row, summaryContainer, false);
        final TextView fieldLabel = fieldContainer.findViewById(R.id.name);
        final TextView fieldContent = fieldContainer.findViewById(R.id.value);
        fieldLabel.setText(fieldNameId);
        fieldContent.setText(fieldValue);
        summaryContainer.addView(fieldContainer);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        EdgeToEdge.enable(this);
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
        final String fingerprintHex = getIntent().getStringExtra(INTENT_KEY_FINGERPRINT);
        if (fingerprintHex == null || fingerprintHex.isBlank()) {
            Log.e(TAG, "auditee fingerprint not provided");
            Toast.makeText(
                    this,
                    R.string.inspect_auditee_error_message_missing_fingerprint,
                    Toast.LENGTH_SHORT
            ).show();
            finish();
            return;
        }
        final AttestationProtocol.AuditeeSummary summary = AttestationProtocol.getAuditorSummary(
                this,
                fingerprintHex
        );

        // display auditee information
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_fingerprint, fingerprintHex);
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_pinned_security_level, String.valueOf(summary.pinnedSecurityLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_pinned_os_version, String.valueOf(summary.pinnedOsVersion()));
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_pinned_os_patch_level, String.valueOf(summary.pinnedOsPatchLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_pinned_vendor_patch_level, String.valueOf(summary.pinnedVendorPatchLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_pinned_boot_patch_level, String.valueOf(summary.pinnedBootPatchLevel()));
        addSummaryFieldToTable(R.id.summary_hardware, R.string.inspect_auditee_field_name_verified_boot_key, summary.verifiedBootKey());
        addSummaryFieldToTable(R.id.summary_os, R.string.inspect_auditee_field_name_pinned_app_version, String.valueOf(summary.pinnedAppVersion()));
        addSummaryFieldToTable(R.id.summary_os, R.string.inspect_auditee_field_name_pinned_app_variant, String.valueOf(summary.pinnedAppVariant()));
        addSummaryFieldToTable(R.id.summary_history, R.string.inspect_auditee_field_name_first_verified, new Date(summary.verifiedTimeFirst()).toString());
        addSummaryFieldToTable(R.id.summary_history, R.string.inspect_auditee_field_name_last_verified, new Date(summary.verifiedTimeLast()).toString());
    }

}