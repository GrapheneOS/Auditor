package app.attestation.auditor;

import android.content.Context;

/// singleton so lazy-initialized statics can access Resources.
public class AttestationContext {
    private static AttestationContext mInstance;
    private Context context;

    static AttestationContext getInstance() {
        if (mInstance == null) synchronized(AttestationContext.class) {
            mInstance = new AttestationContext();
        } 

        return mInstance;
    }

    void initialize(Context context) {
        this.context = context;
    }

    Context activityContext() {
        return context;
    }
}
