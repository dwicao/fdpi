package io.github.romanvht.byedpi.utility

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.coroutines.coroutineContext

/**
 * Fail-safe for the Google Maps masquerade.
 *
 * The `--maps` preset injects a fake Cronet ClientHello with a Google Maps
 * SNI. On some carriers that anomaly triggers a hard block of the whole data
 * session (even ICMP dies). Per the project constraint — "lebih baik throttle
 * daripada mati" — this watchdog probes the real outbound path through the
 * local byedpi SOCKS proxy and, after [FAIL_THRESHOLD] consecutive failures
 * while masquerade is enabled, trips once to let the caller disable the
 * feature and restart.
 *
 * It is deliberately self-limiting: the caller turns the masquerade pref off
 * before restarting, which disarms this guard, so it can never enter a
 * restart loop. It runs entirely in-process, so it keeps detecting even when
 * the carrier has cut connectivity.
 */
object MapsMasqueradeGuard {
    private const val TAG = "MapsMasqueradeGuard"

    /** Consecutive failed probes before tripping. */
    private const val FAIL_THRESHOLD = 3

    /** Delay between probes. */
    private const val PROBE_INTERVAL_MS = 5_000L

    /** Socket connect/read timeout per probe. */
    private const val PROBE_TIMEOUT_MS = 3_000

    /** Ignore the first window after start to avoid transient startup blips. */
    private const val GRACE_PERIOD_MS = 15_000L

    /** Reliable, always-on outbound target used to prove the path works. */
    private val TARGET_IP = byteArrayOf(1, 1, 1, 1)
    private const val TARGET_PORT = 443

    /**
     * Probe loop. Returns normally only when cancelled by the caller (session
     * stopped). Invokes [onTrip] exactly once if the path stays dead while the
     * masquerade is still enabled.
     *
     * [stillEligible] is re-checked every cycle so the loop disarms as soon as
     * the feature is turned off or the session is no longer running.
     */
    suspend fun watch(
        proxyHost: String,
        proxyPort: Int,
        stillEligible: () -> Boolean,
        onTrip: suspend () -> Unit,
    ) {
        delay(GRACE_PERIOD_MS)
        var failures = 0
        while (coroutineContext.isActive) {
            if (!stillEligible()) return
            val ok = probe(proxyHost, proxyPort)
            if (!stillEligible()) return
            if (ok) {
                if (failures != 0) Log.d(TAG, "probe recovered")
                failures = 0
            } else {
                failures++
                Log.w(TAG, "probe failed $failures/$FAIL_THRESHOLD (proxy=$proxyHost:$proxyPort)")
                if (failures >= FAIL_THRESHOLD) {
                    Log.e(TAG, "hard block suspected; disabling masquerade")
                    onTrip()
                    return
                }
            }
            delay(PROBE_INTERVAL_MS)
        }
    }

    /**
     * SOCKS5 CONNECT to a fixed target through the local byedpi proxy. Success
     * means byedpi established a real outbound TCP connection, i.e. the user's
     * data path works end to end. Any handshake or connect failure counts as a
     * failed probe.
     */
    private suspend fun probe(host: String, port: Int): Boolean =
        withContext(Dispatchers.IO) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), PROBE_TIMEOUT_MS)
                    socket.soTimeout = PROBE_TIMEOUT_MS
                    val out = socket.getOutputStream()
                    val input = socket.getInputStream()

                    // SOCKS5 greeting: offer no-auth.
                    out.write(byteArrayOf(0x05, 0x01, 0x00))
                    out.flush()
                    if (input.read() != 0x05 || input.read() != 0x00) return@use false

                    // SOCKS5 CONNECT to TARGET_IP:TARGET_PORT.
                    val req = byteArrayOf(
                        0x05, 0x01, 0x00, 0x01,
                        TARGET_IP[0], TARGET_IP[1], TARGET_IP[2], TARGET_IP[3],
                        ((TARGET_PORT shr 8) and 0xff).toByte(),
                        (TARGET_PORT and 0xff).toByte(),
                    )
                    out.write(req)
                    out.flush()

                    val header = ByteArray(4)
                    var read = 0
                    while (read < 4) {
                        val n = input.read(header, read, 4 - read)
                        if (n < 0) return@use false
                        read += n
                    }
                    // header[1] == 0 means "succeeded".
                    header[1].toInt() == 0
                }
            } catch (e: IOException) {
                Log.d(TAG, "probe error: ${e.message}")
                false
            }
        }
}
