package app.attestation.auditor

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    @SuppressLint("UnsafeProtectedBroadcastReceiver") // not exported
    override fun onReceive(context: Context, intent: Intent) {
        RemoteVerifyJob.restore(context)
    }
}