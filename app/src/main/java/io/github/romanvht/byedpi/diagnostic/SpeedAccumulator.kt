package io.github.romanvht.byedpi.diagnostic

import io.github.romanvht.byedpi.data.DiagnosticVerdict

/**
 * Tracks throughput of a single download over time and produces the per-second
 * log lines plus the aggregates a row needs (avg, peak, first/last-3s).
 *
 * Feed it bytes as they arrive via [onBytes]; call [line] once per second to
 * get the log line in the exact shape used by the external scripts:
 *
 *     t=5.0s | now: 15.3 KB/s | cum: 14.8 KB/s | tiles: 42 | total: 12.1 KB
 *
 * The `tiles` segment is only included when [tiles] is set (Test 3); other
 * tests omit it so the line stays focused on speed.
 */
class SpeedAccumulator(
    private val startNanos: Long = System.nanoTime(),
) {
    private var totalBytes = 0L
    private var windowBytes = 0L
    private var windowStartNanos = System.nanoTime()

    /** bytes/sec sampled over the most recent window (the "now" value). */
    var nowBps: Long = 0
        private set

    /** bytes/sec averaged since the start (the "cum" value). */
    var cumBps: Long = 0
        private set

    var peakBps: Long = 0
        private set

    /** Per-second samples, used for first/last-3s and the bar chart. */
    val samples = mutableListOf<Long>()

    /** Optional counter rendered into the log line (e.g. tiles downloaded). */
    var tiles: Int? = null

    /** Elapsed time since construction, in nanoseconds. */
    fun elapsedNanos(): Long = System.nanoTime() - startNanos

    fun elapsedMillis(): Long = elapsedNanos() / 1_000_000

    val bytes: Long get() = totalBytes

    fun onBytes(count: Int) {
        if (count <= 0) return
        totalBytes += count
        windowBytes += count
    }

    /**
     * Rolls the current sampling window into [samples] and recomputes
     * now/cum/peak. Call this about once per second, or before reading the
     * final aggregates so the tail is counted.
     */
    fun rollWindow() {
        val now = System.nanoTime()
        val windowNanos = now - windowStartNanos
        if (windowNanos > 0) {
            val bps = (windowBytes * 1_000_000_000L) / windowNanos
            samples.add(bps)
            nowBps = bps
            if (bps > peakBps) peakBps = bps
        }
        windowBytes = 0
        windowStartNanos = now
        cumBps = if (elapsedNanos() > 0) (totalBytes * 1_000_000_000L) / elapsedNanos() else 0
    }

    fun avgBps(): Long =
        if (elapsedNanos() > 0) (totalBytes * 1_000_000_000L) / elapsedNanos() else 0

    /**
     * Average of the first [n] one-second samples, or 0 if fewer than [n]
     * exist. Used for the BURST detector (first-3s vs last-3s).
     */
    fun firstSecsBps(n: Int = 3): Long {
        if (samples.size < n) return 0
        return samples.take(n).average().toLong()
    }

    /**
     * Average of the last [n] one-second samples, or 0 if fewer than [n]
     * exist. Needs at least [n] samples so a short run isn't misreported.
     */
    fun lastSecsBps(n: Int = 3): Long {
        if (samples.size < n) return 0
        return samples.takeLast(n).average().toLong()
    }

    /**
     * Builds one log line at the current timestamp. Call once per second while
     * the transfer runs so the live view matches the external script output.
     */
    fun line(): String {
        rollWindow()
        val secs = elapsedMillis() / 1000.0
        val tileSeg = tiles?.let { " | tiles: $it" } ?: ""
        return "t=%.1fs | now: %s | cum: %s%s | total: %s".format(
            secs, human(nowBps), human(cumBps), tileSeg, humanBytes(totalBytes),
        )
    }

    /**
     * Classifies the finished sample set. Needs at least 6 one-second samples
     * to compare first-3s vs last-3s; shorter runs fall back to the average so
     * a quick success isn't wrongly called FAILED.
     */
    fun verdict(abortBps: Long): DiagnosticVerdict {
        val avg = avgBps()
        if (samples.size >= 6) {
            val first = firstSecsBps()
            val last = lastSecsBps()
            // Tail collapsed to under 30% of the head → throttle kicked in.
            if (last in 1 until (first * 0.3).toLong()) return DiagnosticVerdict.BURST
        }
        return when {
            avg < abortBps -> DiagnosticVerdict.THROTTLED
            else -> DiagnosticVerdict.SUSTAINED
        }
    }

    companion object {
        /**
         * Formats bytes/sec (or plain bytes for the `total` field) using the
         * same units the external logs used, so pasted output stays diffable.
         */
        fun human(value: Long): String {
            val units = arrayOf("B/s", "KB/s", "MB/s", "GB/s")
            var v = value.toDouble()
            var i = 0
            while (v >= 1024 && i < units.size - 1) {
                v /= 1024
                i++
            }
            return if (i == 0) "${v.toLong()} ${units[i]}" else "%.1f %s".format(v, units[i])
        }

        /** Same as [human] but with plain byte units (no "/s") for totals. */
        fun humanBytes(value: Long): String {
            val units = arrayOf("B", "KB", "MB", "GB")
            var v = value.toDouble()
            var i = 0
            while (v >= 1024 && i < units.size - 1) {
                v /= 1024
                i++
            }
            return if (i == 0) "${v.toLong()} ${units[i]}" else "%.1f %s".format(v, units[i])
        }
    }
}
