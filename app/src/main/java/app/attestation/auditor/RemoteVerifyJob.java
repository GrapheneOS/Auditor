package app.attestation.auditor;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.util.Log;

import androidx.preference.PreferenceManager;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;

import app.attestation.auditor.AttestationProtocol.AttestationResult;

@TargetApi(26)
public class RemoteVerifyJob extends JobService {
    private static final String TAG = "RemoteVerifyJob";
    private static final int PERIODIC_JOB_ID = 0;
    private static final int FIRST_RUN_JOB_ID = 1;
    static final String DOMAIN = "attestation.app";
    private static final String CHALLENGE_URL = "https://" + DOMAIN + "/challenge";
    private static final String VERIFY_URL = "https://" + DOMAIN + "/verify";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;
    private static final int DEFAULT_INTERVAL = 4 * 60 * 60;
    private static final int MIN_INTERVAL = 60 * 60;
    private static final int MAX_INTERVAL = 7 * 24 * 60 * 60;
    private static final int OVERRIDE_OFFSET_MS = 10 * 60 * 1000;
    static final String STATE_PREFIX = "remote_";
    static final String KEY_USER_ID = "remote_user_id";
    static final String KEY_SUBSCRIBE_KEY = "remote_subscribe_key";
    private static final int NOTIFICATION_ID = 1;
    private static final String NOTIFICATION_CHANNEL_ID = "remote_verification";

    private RemoteVerifyTask task;

    static boolean isEnabled(final Context context) {
        return PreferenceManager.getDefaultSharedPreferences(context).contains(KEY_USER_ID);
    }

    static boolean isScheduled(final Context context) {
        return context.getSystemService(JobScheduler.class).getPendingJob(PERIODIC_JOB_ID) != null;
    }

    static void restore(final Context context) {
        if (isEnabled(context) && !isScheduled(context)) {
            Log.d(TAG, "remote attestation is enabled but job was not scheduled, rescheduling it");
            schedule(context, DEFAULT_INTERVAL);
        }
    }

    static void schedule(final Context context, int interval) {
        if (interval < MIN_INTERVAL) {
            interval = MIN_INTERVAL;
            Log.e(TAG, "invalid interval " + interval + " clamped to MIN_INTERVAL " + MIN_INTERVAL);
        } else if (interval > MAX_INTERVAL) {
            interval = MAX_INTERVAL;
            Log.e(TAG, "invalid interval " + interval + " clamped to MAX_INTERVAL " + MAX_INTERVAL);
        }
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        final JobInfo jobInfo = scheduler.getPendingJob(PERIODIC_JOB_ID);
        final long intervalMillis = interval * 1000;
        final long flexMillis = intervalMillis / 10;
        if (jobInfo != null &&
                jobInfo.getIntervalMillis() == intervalMillis &&
                jobInfo.getFlexMillis() == flexMillis) {
            Log.d(TAG, "job already registered");
            return;
        }
        final ComponentName serviceName = new ComponentName(context, RemoteVerifyJob.class);
        if (jobInfo == null) {
            if (scheduler.schedule(new JobInfo.Builder(FIRST_RUN_JOB_ID, serviceName)
                        .setOverrideDeadline(intervalMillis - OVERRIDE_OFFSET_MS)
                        .setPersisted(true)
                        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                        .build()) == JobScheduler.RESULT_FAILURE) {
                throw new RuntimeException("job schedule failed");
            }
        }
        if (scheduler.schedule(new JobInfo.Builder(PERIODIC_JOB_ID, serviceName)
                .setPeriodic(intervalMillis, flexMillis)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .build()) == JobScheduler.RESULT_FAILURE) {
            throw new RuntimeException("job schedule failed");
        }
    }

    static void cancel(final Context context) {
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        scheduler.cancel(PERIODIC_JOB_ID);
        scheduler.cancel(FIRST_RUN_JOB_ID);
    }

    private class RemoteVerifyTask extends AsyncTask<Void, Void, Boolean> {
        final JobParameters params;

        RemoteVerifyTask(final JobParameters params) {
            this.params = params;
        }

        @Override
        protected void onPostExecute(final Boolean failure) {
            jobFinished(params, failure);
        }

        @Override
        protected Boolean doInBackground(final Void... params) {
            final Context context = RemoteVerifyJob.this;
            boolean failure = false;
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(CHALLENGE_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setRequestMethod("POST");

                final DataInputStream input = new DataInputStream(connection.getInputStream());
                final byte[] challengeMessage = new byte[AttestationProtocol.CHALLENGE_MESSAGE_LENGTH];
                input.readFully(challengeMessage);
                input.close();

                Log.d(TAG, "received random challenge: " + Utils.logFormatBytes(challengeMessage));

                final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
                final long userId = preferences.getLong(KEY_USER_ID, -1);
                if (userId == -1) {
                    throw new IOException("missing userId");
                }
                final String subscribeKey = preferences.getString(KEY_SUBSCRIBE_KEY, null);
                if (subscribeKey == null) {
                    throw new IOException("missing subscribeKey");
                }

                final AttestationResult result = AttestationProtocol.generateSerialized(
                        context, challengeMessage, Long.toString(userId), STATE_PREFIX);

                connection = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setDoOutput(true);
                final String extra = result.pairing ? " " + subscribeKey : "";
                connection.setRequestProperty("Authorization", "Auditor " + userId + extra);

                final OutputStream output = connection.getOutputStream();
                output.write(result.serialized);
                output.close();

                final int responseCode = connection.getResponseCode();
                if (responseCode == 200) {
                    try (final InputStream postResponse = connection.getInputStream()) {
                        final BufferedReader postReader = new BufferedReader(new InputStreamReader(postResponse));
                        final String[] tokens = postReader.readLine().split(" ");
                        if (tokens.length < 2) {
                            throw new GeneralSecurityException("missing fields");
                        }
                        preferences.edit().putString(KEY_SUBSCRIBE_KEY, tokens[0]).apply();
                        schedule(context, Integer.parseInt(tokens[1]));
                    }
                } else {
                    if (result.pairing) {
                        AttestationProtocol.clearAuditee(STATE_PREFIX, Long.toString(userId));
                    }
                    throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException | NumberFormatException e) {
                Log.e(TAG, "remote verify failure", e);
                failure = true;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }

            final NotificationManager manager = context.getSystemService(NotificationManager.class);
            final NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID,
                    context.getString(R.string.remote_verification_notification_channel),
                    NotificationManager.IMPORTANCE_MIN);
            channel.setShowBadge(false);
            manager.createNotificationChannel(channel);
            manager.notify(NOTIFICATION_ID, new Notification.Builder(context, NOTIFICATION_CHANNEL_ID)
                    .setContentTitle(context.getString(R.string.remote_verification_notification_title))
                    .setContentText(context.getString(failure ?
                            R.string.remote_verification_notification_failure :
                            R.string.remote_verification_notification_success))
                    .setShowWhen(true)
                    .setSmallIcon(R.drawable.baseline_security_white_24)
                    .build());

            return failure;
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        if (params.getJobId() == FIRST_RUN_JOB_ID && params.isOverrideDeadlineExpired()) {
            Log.d(TAG, "override deadline expired");
            return false;
        }
        task = new RemoteVerifyTask(params);
        task.executeOnExecutor(AsyncTask.SERIAL_EXECUTOR);
        return true;
    }

    @Override
    public boolean onStopJob(final JobParameters params) {
        task.cancel(true);
        return true;
    }
}
