package io.github.romanvht.byedpi.data

/**
 * Root state for the diagnostic test suite. Mirrors [TestState] so the Activity
 * can collect it the same way (StateFlow + repeatOnLifecycle).
 */
data class DiagnosticState(
    val runId: Long = 0,
    val isRunning: Boolean = false,
    val isStopping: Boolean = false,
    /** Currently executing test index, 1-based; 0 when nothing selected yet. */
    val currentTest: Int = 0,
    /** Total tests in this run. */
    val totalTests: Int = 0,
    /** Log lines emitted so far, newest last. Plain text to match pasted chat logs. */
    val log: List<String> = emptyList(),
    /** Completed rows, in completion order. */
    val rows: List<DiagnosticRow> = emptyList(),
    val failed: Boolean = false,
    val wasInterrupted: Boolean = false,
)

/**
 * Which TLS/network stack produced a result. This is the "fingerprint" axis of
 * the matrix — Cronet is BoringSSL (Maps-like), OkHttp is Conscrypt.
 */
enum class DiagnosticStack(val label: String) {
    CRONET("Cronet"),
    OKHTTP("OkHttp"),
    HTTPURLCONNECTION("HttpURLConnection"),
}

/**
 * Whether the request was made directly or through the running byedpi SOCKS
 * proxy. The app excludes itself from the VPN tunnel, so "via engine" can only
 * mean "via the local SOCKS proxy", never "through the tunnel".
 */
enum class DiagnosticRoute(val label: String) {
    DIRECT("direct"),
    VIA_ENGINE("via engine"),
}

/** Coarse verdict so the table can be scanned without reading numbers. */
enum class DiagnosticVerdict {
    SUSTAINED,  // kept a healthy speed for the whole transfer
    BURST,      // started fast, collapsed late (throttle kicking in)
    THROTTLED,  // slow from the start
    FAILED,     // request errored / timed out
    RUNNING,    // in progress
}

/**
 * One measured row of the matrix, e.g. "Cronet / via engine / h2".
 *
 * [protocol] is filled from the negotiated protocol when the stack reports it
 * ("h3", "h2", "http/1.1"); "unknown" when it does not. This is what lets us
 * tell a fingerprint win apart from a QUIC win.
 */
data class DiagnosticRow(
    val stack: DiagnosticStack,
    val route: DiagnosticRoute,
    val url: String,
    val protocol: String = "unknown",
    val avgBps: Long = 0,
    val peakBps: Long = 0,
    val bytes: Long = 0,
    val millis: Long = 0,
    /** First-3s average in bytes/sec; 0 if the run was too short. */
    val first3sBps: Long = 0,
    /** Last-3s average in bytes/sec; 0 if the run was too short. */
    val last3sBps: Long = 0,
    val verdict: DiagnosticVerdict = DiagnosticVerdict.FAILED,
    val error: String? = null,
    /** How many URLs in this row's list were actually fetched before the stop. */
    val urlCount: Int = 0,
    /**
     * Protocol of the discarded QUIC warmup request, folded into the result
     * line as "warmup=X -> measured=Y" so Alt-Svc discovery is visible.
     */
    val warmupProtocol: String? = null,
) {
    /** < 0.3 means the tail collapsed relative to the head → BURST. */
    val burstRatio: Float
        get() = if (first3sBps > 0) last3sBps.toFloat() / first3sBps else 0f
}

/**
 * Inputs for a run, all editable from the UI.
 *
 * @param abortBps early-abort floor in bytes/sec used by [SpeedAccumulator]
 *   only to classify a finished row as THROTTLED — no longer cuts a row short,
 *   because the sustained measurement needs the full window.
 * @param timeoutMs hard ceiling per row (max_time; 20s per v3 spec).
 * @param maxBytes cumulative byte ceiling per row (max_bytes; 10MB per v3
 *   spec). Checked between URLs in the sequence.
 */
data class DiagnosticConfig(
    val url: String = DEFAULT_URL,
    val timeoutMs: Long = 20_000L,
    val abortBps: Long = 30L * 1024,
    val abortAfterMs: Long = 10_000L,
    val maxBytes: Long = 10L * 1024 * 1024,
    /** Pass 1 only runs the fingerprint matrix; extended later. */
    val tests: Set<Int> = setOf(1),
) {
    companion object {
        const val DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes=1048576"
    }
}
