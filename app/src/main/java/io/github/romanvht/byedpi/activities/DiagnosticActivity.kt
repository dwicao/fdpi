package io.github.romanvht.byedpi.activities

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.WindowManager
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import io.github.romanvht.byedpi.R
import io.github.romanvht.byedpi.data.DiagnosticConfig
import io.github.romanvht.byedpi.data.DiagnosticRow
import io.github.romanvht.byedpi.data.DiagnosticState
import io.github.romanvht.byedpi.services.DiagnosticService
import io.github.romanvht.byedpi.utility.ClipboardUtils
import io.github.romanvht.byedpi.diagnostic.SpeedAccumulator
import kotlinx.coroutines.launch

/**
 * Diagnostic test harness (Pass 1: TLS fingerprint matrix).
 *
 * Deliberately modelled on [TestActivity]: collect [DiagnosticService.state]
 * under repeatOnLifecycle, drive one start/stop button, and expose a copy-log
 * action whose output matches the external script format so results can be
 * pasted straight back into a chat.
 */
class DiagnosticActivity : BaseActivity() {

    private lateinit var urlEditText: EditText
    private lateinit var timeoutEditText: EditText
    private lateinit var abortEditText: EditText
    private lateinit var test1CheckBox: CheckBox
    private lateinit var startStopButton: MaterialButton
    private lateinit var exportButton: MaterialButton
    private lateinit var progressTextView: TextView
    private lateinit var resultsTextView: TextView
    private lateinit var logScrollView: ScrollView
    private lateinit var logTextView: TextView

    private var lastState = DiagnosticState()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_diagnostic)
        setupToolbar()

        urlEditText = findViewById(R.id.urlEditText)
        timeoutEditText = findViewById(R.id.timeoutEditText)
        abortEditText = findViewById(R.id.abortEditText)
        test1CheckBox = findViewById(R.id.test1CheckBox)
        startStopButton = findViewById(R.id.startStopButton)
        exportButton = findViewById(R.id.exportButton)
        progressTextView = findViewById(R.id.progressTextView)
        resultsTextView = findViewById(R.id.resultsTextView)
        logScrollView = findViewById(R.id.logScrollView)
        logTextView = findViewById(R.id.logTextView)

        // Seed from defaults; a previous run's state is re-rendered below.
        urlEditText.setText(DiagnosticConfig.DEFAULT_URL)
        timeoutEditText.setText((DiagnosticConfig().timeoutMs / 1000).toString())
        abortEditText.setText((DiagnosticConfig().abortBps / 1024).toString())

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                DiagnosticService.state.collect { render(it) }
            }
        }

        startStopButton.setOnClickListener {
            startStopButton.isClickable = false
            if (DiagnosticService.isRunning) DiagnosticService.stop()
            else DiagnosticService.start(this, readConfig())
            startStopButton.postDelayed({ startStopButton.isClickable = true }, 1000)
        }

        exportButton.setOnClickListener { exportResults() }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (!DiagnosticService.isRunning) finish()
                // While running, back is ignored so an accidental tap cannot
                // discard a measurement in flight.
            }
        })

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        render(DiagnosticService.state.value)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.menu_diagnostic, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        R.id.action_copy_log -> {
            ClipboardUtils.copy(this, buildLog(), getString(R.string.diagnostics))
            true
        }
        android.R.id.home -> {
            onBackPressedDispatcher.onBackPressed()
            true
        }
        else -> super.onOptionsItemSelected(item)
    }

    private fun readConfig(): DiagnosticConfig {
        val timeoutSec = timeoutEditText.text.toString().toLongOrNull() ?: 25L
        val abortKb = abortEditText.text.toString().toLongOrNull() ?: 30L
        val tests = mutableSetOf<Int>()
        if (test1CheckBox.isChecked) tests.add(1)
        if (tests.isEmpty()) tests.add(1)
        return DiagnosticConfig(
            url = urlEditText.text.toString().trim()
                .ifEmpty { DiagnosticConfig.DEFAULT_URL },
            timeoutMs = (timeoutSec * 1000).coerceIn(1_000, 120_000),
            abortBps = abortKb * 1024,
            abortAfterMs = 10_000L,
            tests = tests,
        )
    }

    private fun render(state: DiagnosticState) {
        val isRunning = state.isRunning
        startStopButton.text = getString(if (isRunning) R.string.test_stop else R.string.test_start)
        if (isRunning) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        exportButton.isEnabled = !isRunning && state.rows.isNotEmpty()

        progressTextView.text = when {
            isRunning && state.totalTests > 0 ->
                getString(R.string.diagnostic_progress, state.currentTest, state.totalTests)
            isRunning -> ""
            state.failed -> getString(R.string.diagnostic_failed)
            state.rows.isNotEmpty() -> getString(R.string.diagnostic_complete)
            else -> ""
        }

        resultsTextView.text = renderTable(state.rows)
        logTextView.text = buildLog(state)

        // Only auto-scroll when the text actually changed, so a user reading
        // older lines is not yanked back down every frame.
        if (lastState.log != state.log) {
            logScrollView.post { logScrollView.fullScroll(ScrollView.FOCUS_DOWN) }
        }
        lastState = state
    }

    private fun renderTable(rows: List<DiagnosticRow>): String {
        if (rows.isEmpty()) return getString(R.string.diagnostic_no_results)
        val sb = StringBuilder()
        sb.appendLine("%-14s %-11s %-9s %9s %9s %9s %s".format(
            "stack", "route", "proto", "avg", "peak", "bytes", "verdict",
        ))
        rows.sortedByDescending { it.avgBps }.forEach { r ->
            sb.appendLine("%-14s %-11s %-9s %9s %9s %9s %s".format(
                r.stack.label,
                r.route.label,
                r.protocol,
                SpeedAccumulator.human(r.avgBps),
                SpeedAccumulator.human(r.peakBps),
                SpeedAccumulator.humanBytes(r.bytes),
                r.verdict.name,
            ))
        }
        return sb.toString().trimEnd()
    }

    private fun buildLog(state: DiagnosticState = lastState): String {
        if (state.log.isEmpty() && state.rows.isEmpty()) return ""
        val sb = StringBuilder()
        state.log.forEach { sb.appendLine(it) }
        if (state.rows.isNotEmpty()) {
            sb.appendLine("--- results ---")
            state.rows.forEach { r ->
                val warm = r.warmupProtocol?.let { "warmup=$it -> " } ?: ""
                sb.appendLine(
                    "${r.stack.label}/${r.route.label} ${warm}proto=${r.protocol} " +
                        "${r.urlCount} URLs " +
                        "avg=${SpeedAccumulator.human(r.avgBps)} " +
                        "peak=${SpeedAccumulator.human(r.peakBps)} " +
                        "bytes=${SpeedAccumulator.humanBytes(r.bytes)} " +
                        "first3s=${SpeedAccumulator.human(r.first3sBps)} " +
                        "last3s=${SpeedAccumulator.human(r.last3sBps)} " +
                        "ratio=${"%.2f".format(r.burstRatio)} ${r.verdict}" +
                        (r.error?.let { " err=$it" } ?: "")
                )
            }
        }
        return sb.toString()
    }

    private fun exportResults() {
        val json = buildJson(lastState)
        if (json.isBlank()) {
            Toast.makeText(this, R.string.diagnostic_no_results, Toast.LENGTH_SHORT).show()
            return
        }
        val intent = Intent(this, FileActivity::class.java)
            .putExtra(FileActivity.EXTRA_MODE, FileActivity.MODE_CREATE)
            .putExtra(FileActivity.EXTRA_TYPE, FileActivity.TYPE_DIAGNOSTIC)
        exportLauncher.launch(intent)
    }

    private val exportLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != RESULT_OK) return@registerForActivityResult
        val path = result.data?.getStringExtra(FileActivity.EXTRA_PATH) ?: return@registerForActivityResult
        try {
            java.io.File(path).writeText(buildJson(lastState))
            Toast.makeText(this, R.string.export_success, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, R.string.export_failed, Toast.LENGTH_SHORT).show()
        }
    }

    private fun buildJson(state: DiagnosticState): String {
        if (state.rows.isEmpty()) return ""
        // Hand-rolled so we do not pull Gson annotations into the data model.
        val sb = StringBuilder()
        sb.append("{")
        sb.append("\"runId\":${state.runId},")
        sb.append("\"url\":\"${lastState.rows.first().url.replace("\"", "\\\"")}\",")
        sb.append("\"rows\":[")
        state.rows.forEachIndexed { i, r ->
            if (i > 0) sb.append(",")
            sb.append("{")
            sb.append("\"stack\":\"${r.stack.label}\",")
            sb.append("\"route\":\"${r.route.label}\",")
            sb.append("\"protocol\":\"${r.protocol}\",")
            sb.append("\"avgBps\":${r.avgBps},")
            sb.append("\"peakBps\":${r.peakBps},")
            sb.append("\"bytes\":${r.bytes},")
            sb.append("\"millis\":${r.millis},")
            sb.append("\"first3sBps\":${r.first3sBps},")
            sb.append("\"last3sBps\":${r.last3sBps},")
            sb.append("\"burstRatio\":${"%.3f".format(r.burstRatio)},")
            sb.append("\"urlCount\":${r.urlCount},")
            sb.append("\"warmupProtocol\":\"${r.warmupProtocol ?: ""}\",")
            sb.append("\"verdict\":\"${r.verdict.name}\"")
            sb.append("}")
        }
        sb.append("]}")
        return sb.toString()
    }
}
