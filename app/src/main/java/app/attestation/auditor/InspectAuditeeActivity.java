package app.attestation.auditor;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.util.Date;

import app.attestation.auditor.databinding.ActivityInspectauditeeBinding;

public class InspectAuditeeActivity extends AppCompatActivity {

    private static final String TAG = "InspectAuditeeActivity";

    public static final String INTENT_KEY_FINGERPRINT = "fingerprint_hex";

    private ActivityInspectauditeeBinding binding;

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

        binding = ActivityInspectauditeeBinding.inflate(getLayoutInflater());
        final View rootView = binding.getRoot();
        setContentView(rootView);

        // set up back button
        setSupportActionBar(binding.inspectAuditeeToolbar);
        final ActionBar supportActionBar = getSupportActionBar();
        if (supportActionBar != null) {
            supportActionBar.setDisplayHomeAsUpEnabled(true);
        }
        binding.inspectAuditeeToolbar.setNavigationOnClickListener(v -> {
            finish();
        });

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (@NonNull View v, @NonNull WindowInsetsCompat insets) -> {
            final Insets barInsets = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            final Insets cutoutInsets = insets.getInsets(WindowInsetsCompat.Type.displayCutout());

            int leftInsets = barInsets.left + cutoutInsets.left;
            int rightInsets = barInsets.right + cutoutInsets.right;

            binding.inspectAuditeeToolbar.setPadding(leftInsets, 0, rightInsets, 0);
            binding.summaryContainer.setPadding(leftInsets, 0, rightInsets, barInsets.bottom);

            return insets;
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