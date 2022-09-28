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
import android.os.Build;
import android.text.Html;
import android.text.Spanned;
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
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.List;

import app.attestation.auditor.AttestationProtocol.AttestationResult;

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
    private static final int ESTIMATED_DOWNLOAD_BYTES = 4 * 1024;
    private static final int ESTIMATED_UPLOAD_BYTES = 8 * 1024;
    static final String STATE_PREFIX = "remote_";
    static final String KEY_USER_ID = "remote_user_id";
    static final String KEY_SUBSCRIBE_KEY = "remote_subscribe_key";
    static final String KEY_INTERVAL = "remote_interval";
    private static final int NOTIFICATION_ID = 1;
    private static final String NOTIFICATION_CHANNEL_SUCCESS_ID = "remote_verification";
    private static final String NOTIFICATION_CHANNEL_FAILURE_ID = "remote_verification_failure";

    static final ExecutorService executor = Executors.newSingleThreadExecutor();
    private Future<?> task;

    static boolean isEnabled(final Context context) {
        return PreferenceManager.getDefaultSharedPreferences(context).contains(KEY_USER_ID);
    }

    static boolean isScheduled(final Context context) {
        return context.getSystemService(JobScheduler.class).getPendingJob(PERIODIC_JOB_ID) != null;
    }

    static void restore(final Context context) {
        if (isEnabled(context)) {
            schedule(context, PreferenceManager.getDefaultSharedPreferences(context).getInt(KEY_INTERVAL, DEFAULT_INTERVAL));
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
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                        jobInfo.getEstimatedNetworkDownloadBytes() == ESTIMATED_DOWNLOAD_BYTES &&
                        jobInfo.getEstimatedNetworkUploadBytes() == ESTIMATED_UPLOAD_BYTES) &&
                jobInfo.getIntervalMillis() == intervalMillis &&
                jobInfo.getFlexMillis() == flexMillis) {
            Log.d(TAG, "job already registered");
            return;
        }
        final ComponentName serviceName = new ComponentName(context, RemoteVerifyJob.class);
        if (jobInfo == null) {
            final JobInfo.Builder builder = new JobInfo.Builder(FIRST_RUN_JOB_ID, serviceName)
                    .setPersisted(true)
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setEstimatedNetworkBytes(ESTIMATED_DOWNLOAD_BYTES, ESTIMATED_UPLOAD_BYTES);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                builder.setExpedited(true);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                builder.setPriority(JobInfo.PRIORITY_MAX);
            }
            if (scheduler.schedule(builder.build()) == JobScheduler.RESULT_FAILURE) {
                throw new RuntimeException("job schedule failed");
            }
        }
        final JobInfo.Builder builder = new JobInfo.Builder(PERIODIC_JOB_ID, serviceName)
                .setPeriodic(intervalMillis, flexMillis)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setEstimatedNetworkBytes(ESTIMATED_DOWNLOAD_BYTES, ESTIMATED_UPLOAD_BYTES);
        }
        if (scheduler.schedule(builder.build()) == JobScheduler.RESULT_FAILURE) {
            throw new RuntimeException("job schedule failed");
        }
    }

    static void cancel(final Context context) {
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        scheduler.cancel(PERIODIC_JOB_ID);
        scheduler.cancel(FIRST_RUN_JOB_ID);
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        task = executor.submit(() -> {
            final Context context = RemoteVerifyJob.this;
            boolean failure = false;
            HttpURLConnection connection = null;
            String exceptionMessage = null;
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
                        final int interval = Integer.parseInt(tokens[1]);
                        preferences.edit().putString(KEY_SUBSCRIBE_KEY, tokens[0]).putInt(KEY_INTERVAL, interval).apply();
                        schedule(context, interval);
                    }
                } else {
                    if (result.pairing) {
                        AttestationProtocol.clearAuditee(STATE_PREFIX, Long.toString(userId));
                    }
                    throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException | NumberFormatException e) {
                Log.e(TAG, "remote verify failure", e);
                exceptionMessage = e.toString();
                failure = true;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }

            final NotificationManager manager = context.getSystemService(NotificationManager.class);

            final List<NotificationChannel> channels = new ArrayList<>();

            final NotificationChannel successChannel = new NotificationChannel(NOTIFICATION_CHANNEL_SUCCESS_ID,
                    context.getString(R.string.remote_verification_notification_success_channel),
                    NotificationManager.IMPORTANCE_MIN);
            successChannel.setShowBadge(false);
            channels.add(successChannel);

            final NotificationChannel failureChannel = new NotificationChannel(NOTIFICATION_CHANNEL_FAILURE_ID,
                    context.getString(R.string.remote_verification_notification_failure_channel),
                    NotificationManager.IMPORTANCE_MIN);
            failureChannel.setShowBadge(false);
            channels.add(failureChannel);

            manager.createNotificationChannels(channels);

            if (failure) {
                String errorMessage = context.getString(R.string.remote_verification_notification_failure_content) +
                        "<br><br><tt>" + exceptionMessage + "</tt>";
                Spanned styledText = Html.fromHtml(errorMessage, Html.FROM_HTML_MODE_LEGACY);

                manager.notify(NOTIFICATION_ID, new Notification.Builder(context,
                        NOTIFICATION_CHANNEL_FAILURE_ID)
                        .setContentTitle(context.getString(
                                R.string.remote_verification_notification_failure_title))
                        .setContentText(styledText)
                        .setShowWhen(true)
                        .setSmallIcon(R.drawable.baseline_security_white_24)
                        .setStyle(new Notification.BigTextStyle()
                                .bigText(styledText))
                        .build());
            } else {
                manager.notify(NOTIFICATION_ID, new Notification.Builder(context,
                        NOTIFICATION_CHANNEL_SUCCESS_ID)
                        .setContentTitle(context.getString(
                                R.string.remote_verification_notification_success_title))
                        .setContentText(context.getString(
                                R.string.remote_verification_notification_success_content))
                        .setShowWhen(true)
                        .setSmallIcon(R.drawable.baseline_security_white_24)
                        .build());
            }

            jobFinished(params, failure);
        });
        return true;
    }

    @Override
    public boolean onStopJob(final JobParameters params) {
        task.cancel(true);
        return true;
    }
}
