package io.github.romanvht.byedpi.diagnostic

import android.content.Context
import io.github.romanvht.byedpi.data.DiagnosticConfig
import io.github.romanvht.byedpi.data.DiagnosticRow
import io.github.romanvht.byedpi.data.DiagnosticState
import io.github.romanvht.byedpi.utility.getPreferences
import io.github.romanvht.byedpi.utility.getProxyIpAndPort
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Orchestrates a diagnostic run: resolves the proxy endpoint, dispatches the
 * selected tests sequentially, and publishes state through [onState].
 *
 * Safety rails required by the spec:
 *  - hard ceiling of [TOTAL_CAP_MS] (5 minutes) for the whole run
 *  - sequential execution (concurrency 1) so we do not trip rate limits
 *  - cancellable at any point; in-flight work is torn down on cancel
 *
 * The tests read the *local* byedpi SOCKS endpoint from preferences, so a row
 * marked VIA_ENGINE only means anything while the engine is actually up —
 * [engineLikelyUp] is reported so the UI can badge it honestly.
 */
class DiagnosticRunner(
    private val context: Context,
    private val onState: (DiagnosticState) -> Unit,
) {
    companion object {
        /** Whole-run ceiling: never let diagnostics run longer than 5 minutes. */
        const val TOTAL_CAP_MS = 5 * 60 * 1000L
    }

    /** Built-in registry. Pass 1 only registers Test 1; add tests here later. */
    private val tests: Map<Int, DiagnosticTest> = mapOf(
        1 to FingerprintMatrixTest(),
    )

    suspend fun run(config: DiagnosticConfig, previousRunId: Long) {
        val runId = previousRunId + 1
        val selected = config.tests.sorted().mapNotNull { tests[it] }
        val proxyHost: String
        val proxyPort: Int
        withContext(Dispatchers.IO) {
            val (h, p) = context.getPreferences().getProxyIpAndPort()
            proxyHost = h
            proxyPort = p.toIntOrNull() ?: 1080
        }

        val log = ArrayDeque<String>()
        val rows = mutableListOf<DiagnosticRow>()

        fun publish(
            isRunning: Boolean,
            isStopping: Boolean = false,
            currentTest: Int = 0,
            failed: Boolean = false,
            wasInterrupted: Boolean = false,
        ) {
            onState(
                DiagnosticState(
                    runId = runId,
                    isRunning = isRunning,
                    isStopping = isStopping,
                    currentTest = currentTest,
                    totalTests = selected.size,
                    log = log.toList(),
                    rows = rows.toList(),
                    failed = failed,
                    wasInterrupted = wasInterrupted,
                )
            )
        }

        publish(isRunning = true)
        log.addLast(
            "diagnostic start: url=${config.url} timeout=${config.timeoutMs}ms " +
                "abort=${config.abortBps}B/s after ${config.abortAfterMs}ms " +
                "proxy=$proxyHost:$proxyPort engineUp=${engineLikelyUp()}"
        )
        publish(isRunning = true)

        var failed = false
        try {
            val transport = DiagnosticTransport(context)
            // Hard ceiling over the whole run, not per test.
            val finished = withTimeoutOrNull(TOTAL_CAP_MS) {
                selected.forEachIndexed { index, test ->
                    // Throws CancellationException if the caller cancelled.
                    currentCoroutineContext().ensureActive()
                    publish(isRunning = true, currentTest = index + 1)
                    test.run(
                        config = config,
                        transport = transport,
                        proxyHost = proxyHost,
                        proxyPort = proxyPort,
                        emit = { line ->
                            // Publishing on every line keeps the live view in
                            // lockstep with the external script output.
                            log.addLast(line)
                            while (log.size > 500) log.removeFirst()
                            publish(isRunning = true, currentTest = index + 1)
                        },
                        onRow = { row ->
                            rows.add(row)
                            publish(isRunning = true, currentTest = index + 1)
                        },
                        isCancelled = { false },
                    )
                }
                true
            }
            if (finished == null) {
                log.addLast("aborted: total run exceeded ${TOTAL_CAP_MS / 1000}s cap")
                failed = true
            }
        } catch (e: CancellationException) {
            log.addLast("cancelled by user")
            withContext(NonCancellable) {
                publish(isRunning = false, wasInterrupted = true)
            }
            throw e
        } catch (e: Exception) {
            log.addLast("error: ${e.message ?: e.javaClass.simpleName}")
            failed = true
        }

        withContext(NonCancellable) {
            log.addLast(
                if (failed) "diagnostic finished with errors"
                else "diagnostic finished: ${rows.size} row(s)"
            )
            publish(isRunning = false, failed = failed)
        }
    }

    /**
     * Best-effort check that a local SOCKS endpoint is accepting connections, so
     * the run header can say whether VIA_ENGINE rows are meaningful. Never
     * throws — this is diagnostics, not a gate.
     */
    private fun engineLikelyUp(): Boolean = try {
        val (h, p) = context.getPreferences().getProxyIpAndPort()
        java.net.Socket().use { s ->
            s.connect(java.net.InetSocketAddress(h, p.toIntOrNull() ?: 1080), 300)
        }
        true
    } catch (_: Exception) {
        false
    }
}
