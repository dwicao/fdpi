package io.github.romanvht.byedpi.diagnostic

import io.github.romanvht.byedpi.data.DiagnosticConfig
import io.github.romanvht.byedpi.data.DiagnosticRoute
import io.github.romanvht.byedpi.data.DiagnosticRow
import io.github.romanvht.byedpi.data.DiagnosticStack
import io.github.romanvht.byedpi.data.DiagnosticVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.coroutineContext

/**
 * One selectable diagnostic. Test 1 (fingerprint matrix) ships in Pass 1;
 * Tests 2-5 are added later by implementing this interface — no changes to the
 * runner or service are needed.
 */
interface DiagnosticTest {
    val id: Int
    val title: String

    /**
     * Runs the test, emitting progress lines via [emit] and reporting each
     * finished row via [onRow]. Returns when done or when [isCancelled] flips.
     */
    suspend fun run(
        config: DiagnosticConfig,
        transport: DiagnosticTransport,
        proxyHost: String,
        proxyPort: Int,
        emit: (String) -> Unit,
        onRow: (DiagnosticRow) -> Unit,
        isCancelled: () -> Boolean,
    )
}

/**
 * Pass 1 — the fingerprint matrix. Five rows, each isolating one variable:
 *
 *  1. Cronet / direct / QUIC hinted  → Maps-like reference (BoringSSL + QUIC)
 *  2. Cronet / direct / QUIC off     → same fingerprint, TCP only
 *  3. OkHttp / direct / h2           → different fingerprint, same TCP+h2
 *  4. OkHttp / direct / h1.1         → protocol lever (OkHttp never does QUIC)
 *  5. OkHttp / via engine / h2       → does the byedpi bypass help at all
 *
 * Reading the result: (1 fast, 2/3 slow) ⇒ protocol is the cause. (5 fast,
 * 3 slow) ⇒ bypass helps. (3 slow, 2 fast) ⇒ fingerprint matters.
 *
 * The negotiated protocol is always read back from the stack, so a row is
 * attributed to what actually happened rather than what we hoped would.
 */
class FingerprintMatrixTest : DiagnosticTest {
    override val id = 1
    override val title = "TLS fingerprint matrix"

    /** One cell of the matrix. */
    private data class RowSpec(
        val stack: DiagnosticStack,
        val route: DiagnosticRoute,
        val http2: Boolean,
        val quicHint: Boolean,
        val label: String,
    )

    private val specs = listOf(
        RowSpec(DiagnosticStack.CRONET, DiagnosticRoute.DIRECT, http2 = true, quicHint = true, "cronet/quic"),
        RowSpec(DiagnosticStack.CRONET, DiagnosticRoute.DIRECT, http2 = true, quicHint = false, "cronet/tcp"),
        RowSpec(DiagnosticStack.OKHTTP, DiagnosticRoute.DIRECT, http2 = true, quicHint = false, "okhttp/h2"),
        RowSpec(DiagnosticStack.OKHTTP, DiagnosticRoute.DIRECT, http2 = false, quicHint = false, "okhttp/h1.1"),
        RowSpec(DiagnosticStack.OKHTTP, DiagnosticRoute.VIA_ENGINE, http2 = true, quicHint = false, "okhttp/h2 via engine"),
    )

    override suspend fun run(
        config: DiagnosticConfig,
        transport: DiagnosticTransport,
        proxyHost: String,
        proxyPort: Int,
        emit: (String) -> Unit,
        onRow: (DiagnosticRow) -> Unit,
        isCancelled: () -> Boolean,
    ) {
        specs.forEachIndexed { index, spec ->
            if (isCancelled()) return
            emit("[${index + 1}/${specs.size}] ${spec.label} …")
            val row = executeRow(spec, config, transport, proxyHost, proxyPort, emit, isCancelled)
            if (isCancelled()) return
            onRow(row)
            emit(
                "  → ${row.protocol} | avg ${SpeedAccumulator.human(row.avgBps)} | " +
                    "peak ${SpeedAccumulator.human(row.peakBps)} | " +
                    "${SpeedAccumulator.humanBytes(row.bytes)} | ${row.verdict}"
            )
        }
    }

    /**
     * Runs one cell: streams bytes through a [SpeedAccumulator], emits a log
     * line every second, and enforces both the early-abort floor (below
     * [DiagnosticConfig.abortBps] after [DiagnosticConfig.abortAfterMs]) and the
     * hard per-row ceiling ([DiagnosticConfig.timeoutMs]).
     */
    private suspend fun executeRow(
        spec: RowSpec,
        config: DiagnosticConfig,
        transport: DiagnosticTransport,
        proxyHost: String,
        proxyPort: Int,
        emit: (String) -> Unit,
        isCancelled: () -> Boolean,
    ): DiagnosticRow = coroutineScope {
        val acc = SpeedAccumulator()
        val aborted = AtomicBoolean(false)
        val throttled = AtomicBoolean(false)
        val prefix = "  ${spec.label} | "

        val fetch = async(Dispatchers.IO) {
            val onBytes: (Int) -> Unit = { acc.onBytes(it) }
            val cancelled: () -> Boolean = { aborted.get() || isCancelled() }
            when (spec.stack) {
                DiagnosticStack.CRONET -> transport.fetchCronet(
                    url = config.url,
                    headers = emptyMap(), // Test 1 is a pure fingerprint test.
                    quicHint = spec.quicHint,
                    onBytes = onBytes,
                    isCancelled = cancelled,
                )
                else -> transport.fetchOkHttp(
                    url = config.url,
                    headers = emptyMap(),
                    route = spec.route,
                    http2 = spec.http2,
                    proxyHost = proxyHost,
                    proxyPort = proxyPort,
                    timeoutMs = config.timeoutMs,
                    onBytes = onBytes,
                    isCancelled = cancelled,
                )
            }
        }

        // Watchdog: rolls the window once a second (drives the log line and the
        // first/last-3s verdict), then cuts the row short if it is crawling or
        // has run past the hard ceiling.
        val watchdog = launch {
            while (true) {
                delay(1_000)
                emit(prefix + acc.line())
                val elapsed = acc.elapsedMillis()
                if (elapsed >= config.abortAfterMs && acc.nowBps in 1 until config.abortBps) {
                    throttled.set(true)
                    aborted.set(true)
                    fetch.cancel()
                    return@launch
                }
                if (elapsed >= config.timeoutMs) {
                    aborted.set(true)
                    fetch.cancel()
                    return@launch
                }
            }
        }

        var error: String? = null
        var protocol = "unknown"
        try {
            val outcome = fetch.await()
            protocol = normalize(outcome.protocol)
            error = outcome.error
        } catch (e: CancellationException) {
            // Aborted by the watchdog or by the user; still report what we saw.
            error = if (throttled.get()) null else (e.message ?: "cancelled")
        } catch (e: Exception) {
            error = e.message ?: e.javaClass.simpleName
        } finally {
            watchdog.cancel()
            // Final roll so the tail seconds count toward avg/first/last-3s.
            acc.rollWindow()
            coroutineContext.ensureActive()
        }

        val verdict = when {
            throttled.get() -> DiagnosticVerdict.THROTTLED
            error != null && error != "cancelled" -> DiagnosticVerdict.FAILED
            else -> acc.verdict(config.abortBps)
        }

        DiagnosticRow(
            stack = spec.stack,
            route = spec.route,
            url = config.url,
            protocol = protocol,
            avgBps = acc.avgBps(),
            peakBps = acc.peakBps,
            bytes = acc.bytes,
            millis = acc.elapsedMillis(),
            first3sBps = acc.firstSecsBps(),
            last3sBps = acc.lastSecsBps(),
            verdict = verdict,
            error = error,
        )
    }

    /**
     * Normalizes protocol labels so Cronet ("h2", "h3", "http/1.1") and OkHttp
     * ("http/1.1", "h2"/"http/2.0") end up in the same vocabulary.
     */
    private fun normalize(raw: String): String = when {
        raw.contains("h3", ignoreCase = true) -> "h3"
        raw == "h2" || raw.startsWith("http/2") -> "h2"
        raw.startsWith("http/1.1") -> "http/1.1"
        raw.startsWith("http/1.0") -> "http/1.0"
        else -> raw.ifBlank { "unknown" }
    }
}
