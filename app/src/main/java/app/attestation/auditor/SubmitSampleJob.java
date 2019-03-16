package app.attestation.auditor;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.system.Os;
import android.system.StructUtsname;
import android.util.Log;

import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;
import java.util.Properties;

import static android.security.keystore.KeyProperties.KEY_ALGORITHM_EC;

public class SubmitSampleJob extends JobService {
    private static final String TAG = "SubmitSampleJob";
    private static final int JOB_ID = 2;
    private static final String SUBMIT_URL = "https://" + RemoteVerifyJob.DOMAIN + "/submit";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;
    private static final int NOTIFICATION_ID = 2;
    private static final String NOTIFICATION_CHANNEL_ID = "sample_submission";

    private static final String KEYSTORE_ALIAS_SAMPLE = "sample_attestation_key";

    private SubmitTask task;

    static boolean isScheduled(final Context context) {
        return context.getSystemService(JobScheduler.class).getPendingJob(JOB_ID) != null;
    }

    static void schedule(final Context context) {
        final ComponentName serviceName = new ComponentName(context, SubmitSampleJob.class);
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler.schedule(new JobInfo.Builder(JOB_ID, serviceName)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .build()) == JobScheduler.RESULT_FAILURE) {
            throw new RuntimeException("job schedule failed");
        }
    }

    private class SubmitTask extends AsyncTask<Void, Void, Boolean> {
        final JobParameters params;

        SubmitTask(final JobParameters params) {
            this.params = params;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            jobFinished(params, success);
        }

        @Override
        protected Boolean doInBackground(final Void... params) {
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(SUBMIT_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setDoOutput(true);

                final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);

                keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);
                final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS_SAMPLE,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec(AttestationProtocol.EC_CURVE))
                        .setDigests(AttestationProtocol.KEY_DIGEST)
                        .setAttestationChallenge("sample".getBytes());
                AttestationProtocol.generateKeyPair(KEY_ALGORITHM_EC, builder.build());
                final Certificate[] certs = keyStore.getCertificateChain(KEYSTORE_ALIAS_SAMPLE);
                keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);

                Certificate[] strongBoxCerts = null;
                if (Build.VERSION.SDK_INT >= 28) {
                    try {
                        builder.setIsStrongBoxBacked(true);
                        AttestationProtocol.generateKeyPair(KEY_ALGORITHM_EC, builder.build());
                        strongBoxCerts = keyStore.getCertificateChain(KEYSTORE_ALIAS_SAMPLE);
                        keyStore.deleteEntry(KEYSTORE_ALIAS_SAMPLE);
                    } catch (final StrongBoxUnavailableException ignored) {}
                }

                final Process process = new ProcessBuilder("getprop").start();
                try (final InputStream propertyStream = process.getInputStream();
                        final OutputStream output = connection.getOutputStream()) {
                    for (final Certificate cert : certs) {
                        output.write(BaseEncoding.base64().encode(cert.getEncoded()).getBytes());
                        output.write("\n".getBytes());
                    }

                    if (strongBoxCerts != null) {
                        output.write("StrongBox\n".getBytes());
                        for (final Certificate cert : strongBoxCerts) {
                            output.write(BaseEncoding.base64().encode(cert.getEncoded()).getBytes());
                            output.write("\n".getBytes());
                        }
                    }

                    ByteStreams.copy(propertyStream, output);

                    final StructUtsname utsname = Os.uname();
                    output.write(utsname.toString().getBytes());
                    output.write("\n".getBytes());

                    final Properties javaProps = System.getProperties();
                    final Enumeration<?> javaPropNames = javaProps.propertyNames();
                    while (javaPropNames.hasMoreElements()) {
                        final String name = (String) javaPropNames.nextElement();
                        final String value = javaProps.getProperty(name);
                        output.write(name.getBytes());
                        output.write("=".getBytes());
                        output.write(value.getBytes());
                        output.write("\n".getBytes());
                    }
                }

                final int responseCode = connection.getResponseCode();
                if (responseCode != 200) {
                    throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException e) {
                Log.e(TAG, "submit failure", e);
                return true;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }

            final Context context = SubmitSampleJob.this;
            final NotificationManager manager = context.getSystemService(NotificationManager.class);
            final NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID,
                    context.getString(R.string.sample_submission_notification_channel),
                    NotificationManager.IMPORTANCE_LOW);
            manager.createNotificationChannel(channel);
            manager.notify(NOTIFICATION_ID, new Notification.Builder(context, NOTIFICATION_CHANNEL_ID)
                    .setContentTitle(context.getString(R.string.sample_submission_notification_title))
                    .setContentText(context.getString(R.string.sample_submission_notification_content))
                    .setShowWhen(true)
                    .setSmallIcon(R.drawable.baseline_cloud_upload_white_24)
                    .build());

            return false;
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        task = new SubmitTask(params);
        task.executeOnExecutor(AsyncTask.SERIAL_EXECUTOR);
        return true;
    }

    @Override
    public boolean onStopJob(final JobParameters params) {
        task.cancel(true);
        return true;
    }
}
