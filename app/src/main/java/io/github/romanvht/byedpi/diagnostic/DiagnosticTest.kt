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
 * Pass 1 (v3) — sustained multi-URL test against REAL Google endpoints.
 * Four rows = protocol (h3/h2) × endpoint:
 *
 *  1. cronet/h3-mt0  → 36 map tiles (x/y 9659..9664 / 12317..12322, z=15)
 *  2. cronet/h3-lh3  → 20 Maps photos on lh3.googleusercontent.com
 *  3. cronet/h2-mt0  → same tiles, QUIC disabled
 *  4. cronet/h2-lh3  → same photos, QUIC disabled
 *
 * Each row downloads its URL list sequentially on ONE Cronet engine until
 * max_time (20s) or max_bytes (10MB), so the HTTP/3 connection and Alt-Svc
 * cache survive across URLs. OkHttp is dropped from this run (FIX 3): the
 * comparison that matters is Cronet/h3 vs Cronet/h2 on real Google hosts.
 *
 * Reading the result: h3 fast but h2 slow ⇒ throttle keys on protocol;
 * lh3 unthrottled on QUIC but throttled on TCP ⇒ QUIC+Google is the bypass.
 * The warmup readback (`warmup=h3 -> measured=h3`) proves Alt-Svc discovery.
 */
class FingerprintMatrixTest : DiagnosticTest {
    override val id = 1
    override val title = "Sustained multi-URL fingerprint matrix"

    /** One cell of the matrix. */
    private data class RowSpec(
        val label: String,
        val quicHint: Boolean,
        val urls: List<String>,
        val headers: Map<String, String>,
    )

    private val specs = listOf(
        RowSpec("cronet/h3-mt0", quicHint = true, urls = tileUrls(), headers = emptyMap()),
        RowSpec("cronet/h3-lh3", quicHint = true, urls = lh3Urls(), headers = MAPS_HEADERS),
        RowSpec("cronet/h2-mt0", quicHint = false, urls = tileUrls(), headers = emptyMap()),
        RowSpec("cronet/h2-lh3", quicHint = false, urls = lh3Urls(), headers = MAPS_HEADERS),
    )

    /**
     * 36 Google Maps tiles around New York at z=15, alternating satellite/map.
     * Coordinates are verified to return 200 for BOTH lyrs=s and lyrs=m — the
     * spec's original x/y 999..1004 range sits over imagery-less arctic water
     * and 404s, and lyrs=s has coverage gaps at z=15 in many regions.
     */
    private fun tileUrls(): List<String> {
        val urls = mutableListOf<String>()
        var i = 0
        for (x in 9659..9664) {
            for (y in 12317..12322) {
                val lyr = if (i % 2 == 0) "s" else "m"
                urls += "https://mt0.google.com/vt/lyrs=$lyr&hl=en&x=$x&y=$y&z=15"
                i++
            }
        }
        return urls
    }

    /**
     * 20 lh3 Maps photos with cache-busting query params. The photo id is a
     * verified-live one (the spec's example returns 400/expired); at
     * =w1600-h1200 each is ~425 KB, so 20× ≈ 8.5 MB — fits the 10 MB budget.
     */
    private fun lh3Urls(): List<String> {
        val base = "https://lh3.googleusercontent.com/p/" +
            "AF1QipMPYp_acWrBa6fa2F0TsosyYI-wDt_rL9wFVcvC=w1600-h1200"
        return (1..20).map { "$base?v=$it" }
    }

    private companion object {
        val MAPS_HEADERS: Map<String, String> = DiagnosticTransport.MAPS_HEADERS
    }

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
            val row = executeRow(spec, config, transport, emit, isCancelled)
            if (isCancelled()) return
            onRow(row)
            // Result line per v3 spec:
            // [x/4] label | warmup=W -> measured=P → P | N URLs | avg | first3s | last3s | ratio | VERDICT
            val warm = row.warmupProtocol?.let { normalize(it) } ?: "?"
            emit(
                "[${index + 1}/${specs.size}] ${spec.label} | " +
                    "warmup=$warm -> measured=${row.protocol} → ${row.protocol} | " +
                    "${row.urlCount} URLs | " +
                    "avg ${SpeedAccumulator.human(row.avgBps)} | " +
                    "first3s=${SpeedAccumulator.human(row.first3sBps)} | " +
                    "last3s=${SpeedAccumulator.human(row.last3sBps)} | " +
                    "ratio=${"%.2f".format(row.burstRatio)} | " +
                    "${row.verdict}"
            )
        }
    }

    /**
     * Runs one cell: streams bytes from the row's URL sequence through a
     * [SpeedAccumulator], emits a log line every second, and stops at the hard
     * per-row ceiling ([DiagnosticConfig.timeoutMs]) or [DiagnosticConfig.maxBytes].
     *
     * The early-abort floor is deliberately gone: cutting a throttled row at
     * 10s would destroy the first-3s/last-3s window this test exists to measure.
     * [DiagnosticConfig.abortBps] still classifies a finished row as THROTTLED.
     *
     * The transport self-stops (via the isCancelled lambda) so it RETURNS a
     * normal outcome with urlCount/warmup intact even at the 20s ceiling. The
     * watchdog only cancels as a safety net for a genuine hang, well after the
     * self-stop, so a normal timeout never loses the counters.
     */
    private suspend fun executeRow(
        spec: RowSpec,
        config: DiagnosticConfig,
        transport: DiagnosticTransport,
        emit: (String) -> Unit,
        isCancelled: () -> Boolean,
    ): DiagnosticRow = coroutineScope {
        val acc = SpeedAccumulator()
        val aborted = AtomicBoolean(false)
        val prefix = "  ${spec.label} | "

        // Self-stop on the time ceiling (max_bytes is checked inside the
        // transport), so the outcome comes back normally instead of throwing.
        val shouldStop: () -> Boolean = {
            aborted.get() || isCancelled() || acc.elapsedMillis() >= config.timeoutMs
        }

        val fetch = async(Dispatchers.IO) {
            transport.fetchCronetSequence(
                urls = spec.urls,
                headers = spec.headers,
                quicHint = spec.quicHint,
                onBytes = { acc.onBytes(it) },
                isCancelled = shouldStop,
                maxBytes = config.maxBytes,
            )
        }

        // Watchdog: rolls the window once a second (drives the log line and
        // the first/last-3s verdict). Cancels only as a safety net for a hang
        // (well past the 20s self-stop) so the counters are never lost.
        val watchdog = launch {
            while (true) {
                delay(1_000)
                emit(prefix + acc.line())
                if (acc.elapsedMillis() >= config.timeoutMs + 8_000) {
                    aborted.set(true)
                    fetch.cancel()
                    return@launch
                }
            }
        }

        var error: String? = null
        var protocol = "unknown"
        var warmup: String? = null
        var urlCount = 0
        try {
            val outcome = fetch.await()
            protocol = normalize(outcome.protocol)
            error = outcome.error
            warmup = outcome.warmupProtocol
            urlCount = outcome.urlCount
        } catch (e: CancellationException) {
            // Safety-net cancel or user stop; accumulated data still yields a
            // verdict through acc.verdict below.
            error = e.message ?: "cancelled"
        } catch (e: Exception) {
            error = e.message ?: e.javaClass.simpleName
        } finally {
            watchdog.cancel()
            // Final roll so the tail seconds count toward avg/first/last-3s.
            acc.rollWindow()
            coroutineContext.ensureActive()
        }

        // Timeout/cancel is a legitimate stop condition, not a failure.
        val verdict = when {
            error != null && error != "cancelled" -> DiagnosticVerdict.FAILED
            else -> acc.verdict(config.abortBps)
        }

        DiagnosticRow(
            stack = DiagnosticStack.CRONET,
            route = DiagnosticRoute.DIRECT,
            url = spec.urls.firstOrNull() ?: "",
            protocol = protocol,
            avgBps = acc.avgBps(),
            peakBps = acc.peakBps,
            bytes = acc.bytes,
            millis = acc.elapsedMillis(),
            first3sBps = acc.firstSecsBps(),
            last3sBps = acc.lastSecsBps(),
            verdict = verdict,
            error = error,
            urlCount = urlCount,
            warmupProtocol = warmup,
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
