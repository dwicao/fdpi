package io.github.romanvht.byedpi.services

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.github.romanvht.byedpi.R
import io.github.romanvht.byedpi.activities.DiagnosticActivity
import io.github.romanvht.byedpi.data.DiagnosticConfig
import io.github.romanvht.byedpi.data.DiagnosticState
import io.github.romanvht.byedpi.diagnostic.DiagnosticRunner
import io.github.romanvht.byedpi.utility.registerNotificationChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Foreground service that owns a diagnostic run. Modelled on [TestService]:
 * StateFlow state, a single sequential job, a stop action, and a notification
 * so the run survives the screen turning off. Kept fully separate from
 * ServiceManager/VPN — diagnostics never start or stop the tunnel.
 */
class DiagnosticService : Service() {

    companion object {
        private const val TAG = "DiagnosticService"
        private const val CHANNEL = "Diagnostic"
        private const val NOTIFICATION_ID = 6
        const val START_ACTION = "io.github.romanvht.byedpi.DIAGNOSTIC_START"
        const val STOP_ACTION = "io.github.romanvht.byedpi.DIAGNOSTIC_STOP"

        private val mutableState = MutableStateFlow(DiagnosticState())
        val state: StateFlow<DiagnosticState> = mutableState.asStateFlow()
        val isRunning: Boolean get() = state.value.isRunning

        /**
         * Requests a run. Config is passed through the intent as primitives
         * because a Service intent cannot carry arbitrary objects.
         */
        fun start(context: Context, config: DiagnosticConfig) {
            if (isRunning) return
            val intent = Intent(context, DiagnosticService::class.java).setAction(START_ACTION)
                .putExtra("url", config.url)
                .putExtra("timeoutMs", config.timeoutMs)
                .putExtra("abortBps", config.abortBps)
                .putExtra("abortAfterMs", config.abortAfterMs)
                .putExtra("tests", config.tests.toIntArray())
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop() {
            if (!isRunning) return
            mutableState.value = state.value.copy(isStopping = true)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var testJob: Job? = null
    private var lastStartId = 0

    override fun onCreate() {
        super.onCreate()
        registerNotificationChannel(this, CHANNEL, R.string.diagnostic_title)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        when (intent?.action) {
            START_ACTION -> {
                try {
                    startForeground()
                    if (!isRunning && testJob == null) {
                        val config = readConfig(intent)
                        startTesting(config)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start diagnostic", e)
                    mutableState.value = state.value.copy(
                        isRunning = false, isStopping = false, failed = true,
                    )
                    stopSelfResult(startId)
                }
            }
            STOP_ACTION -> stop()
            else -> if (testJob == null) stopSelfResult(startId)
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun readConfig(intent: Intent): DiagnosticConfig = DiagnosticConfig(
        url = intent.getStringExtra("url") ?: DiagnosticConfig.DEFAULT_URL,
        timeoutMs = intent.getLongExtra("timeoutMs", 25_000L),
        abortBps = intent.getLongExtra("abortBps", 30L * 1024),
        abortAfterMs = intent.getLongExtra("abortAfterMs", 10_000L),
        tests = intent.getIntArrayExtra("tests")?.toSet() ?: setOf(1),
    )

    private fun startTesting(config: DiagnosticConfig) {
        val previous = state.value
        mutableState.value = previous.copy(
            runId = previous.runId + 1,
            isRunning = true,
            isStopping = false,
            failed = false,
            log = emptyList(),
            rows = emptyList(),
            currentTest = 0,
            totalTests = 0,
        )

        testJob = scope.launch(start = CoroutineStart.LAZY) {
            val job = coroutineContext[Job]
            // Flip isStopping to true as soon as the UI asks to stop, so the
            // runner's cancellation path and the UI agree.
            val stopWatcher = launch {
                state.collect { if (it.isStopping) job?.cancel() }
            }
            try {
                DiagnosticRunner(applicationContext) { s -> mutableState.value = s }
                    .run(config, previous.runId)
            } finally {
                stopWatcher.cancel()
                mutableState.value = state.value.copy(isRunning = false, isStopping = false)
                testJob = null
                stopForegroundCompat()
                stopSelfResult(lastStartId)
            }
        }
        testJob?.start()
    }

    private fun stop() {
        if (!isRunning) return
        mutableState.value = state.value.copy(isStopping = true)
    }

    private fun startForeground() {
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    private fun stopForegroundCompat() {
        @Suppress("DEPRECATION")
        stopForeground(true)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, DiagnosticActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, DiagnosticService::class.java).setAction(STOP_ACTION),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_speed)
            .setContentTitle(getString(R.string.diagnostic_title))
            .setContentText(getString(R.string.diagnostic_running))
            .setContentIntent(open)
            .addAction(0, getString(R.string.test_stop), stop)
            .setOngoing(true)
            .build()
    }
}
