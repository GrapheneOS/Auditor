package app.attestation.auditor

import android.app.Application
import com.google.android.material.color.DynamicColors

class AuditorApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        DynamicColors.applyToActivitiesIfAvailable(this)
    }
}
