package io.github.romanvht.byedpi.diagnostic

import android.content.Context
import android.util.Log
import io.github.romanvht.byedpi.data.DiagnosticRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Protocol
import org.chromium.net.CronetEngine
import org.chromium.net.CronetException
import org.chromium.net.UrlRequest
import org.chromium.net.UrlResponseInfo
import java.net.InetSocketAddress
import java.net.Proxy
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/**
 * Performs a single GET with a chosen TLS stack and route, streaming bytes back
 * through [onBytes] so the caller can measure throughput.
 *
 * Two stacks are supported (this is the fingerprint axis of the matrix):
 *  - Cronet  → BoringSSL, i.e. the stack Google Maps uses. Direct only: Cronet
 *    has no public SOCKS proxy support, so [DiagnosticRoute.VIA_ENGINE] is not
 *    available for it.
 *  - OkHttp  → Conscrypt. Supports both direct and via the local byedpi SOCKS
 *    proxy, and can pin HTTP/1.1 vs HTTP/2 (OkHttp never speaks QUIC), which
 *    gives a deterministic protocol lever.
 *
 * The negotiated protocol is always returned so a "fast" row can be attributed
 * to a fingerprint or to QUIC/h2 rather than guessed.
 */
class DiagnosticTransport(context: Context) {

    private val appContext = context.applicationContext

    data class FetchOutcome(
        /** Negotiated protocol as reported by the stack ("h3", "h2", "http/1.1"). */
        val protocol: String = "unknown",
        val bytes: Long = 0,
        /** Non-null when the request failed; the row should be marked FAILED. */
        val error: String? = null,
        /**
         * Protocol of the discarded QUIC warmup request, if one ran. Cronet
         * discovers QUIC via Alt-Svc: the first request to a host is TCP, only
         * later ones can be h3. Warmup populates that cache so the measured
         * request can actually reach h3; logging both proves discovery worked.
         */
        val warmupProtocol: String? = null,
        /**
         * How many URLs of the sequence were actually fetched. Used by the
         * multi-URL rows so the result shows "N URLs" even when max_time or
         * max_bytes stopped the run early.
         */
        val urlCount: Int = 0,
    )

    /**
     * Cronet fetch of a LIST of URLs, sequentially, on ONE engine.
     *
     * Reusing a single engine across the whole sequence is essential: it keeps
     * the HTTP/3 connection and the Alt-Svc cache alive, so URL #2..#N can stay
     * on QUIC. Building an engine per URL would reset discovery and force every
     * request back to TCP.
     *
     * [quicHint] controls QUIC at the engine level: false → `enableQuic(false)`
     * (forced HTTP/2), true → QUIC enabled + host hint so Cronet may attempt
     * HTTP/3. A single warmup request populates Alt-Svc before measuring.
     *
     * Stops when: all URLs done, cumulative bytes reach [maxBytes], or
     * [isCancelled]. Each stop (except cancel) returns a normal outcome with
     * [FetchOutcome.urlCount] reflecting how far it got.
     */
    suspend fun fetchCronetSequence(
        urls: List<String>,
        headers: Map<String, String>,
        quicHint: Boolean,
        onBytes: (Int) -> Unit,
        isCancelled: () -> Boolean,
        maxBytes: Long,
    ): FetchOutcome {
        if (urls.isEmpty()) return FetchOutcome(error = "no urls")
        // FIX 2: log the real stack trace so build failures are distinguishable
        // from callback-dispatch failures.
        val engine = try {
            CronetEngine.Builder(appContext).apply {
                enableQuic(quicHint)
                enableHttp2(true)
                if (quicHint) {
                    val host = hostOf(urls.first())
                    if (host != null) addQuicHint(host, 443, 443)
                }
            }.build()
        } catch (e: Throwable) {
            Log.e(TAG, "cronet engine build failed (quicHint=$quicHint)", e)
            return FetchOutcome(
                error = "cronet build failed: ${e.message ?: e.javaClass.simpleName}",
            )
        }

        // FIX 1: dedicated single-thread executor per run, shut down AFTER the
        // engine so queued callbacks drain first.
        val executor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "cronet-callback").apply { isDaemon = true }
        }

        var warmupProto: String? = null
        var lastProtocol = "unknown"
        var urlCount = 0
        var grandTotal = 0L
        var firstError: String? = null
        try {
            // FIX 3 (v3): one warmup against the first URL's host, shrunk by
            // warmupUrlOf so it is tiny (tile / 64px thumbnail). Headers arrive
            // before the body, so Alt-Svc is cached even if we cut it short.
            val warm = withDeadline(8_000L) {
                runCronetRequest(engine, executor, warmupUrlOf(urls.first()), emptyMap(), { }, it)
            }
            warmupProto = warm.protocol
            Log.i(TAG, "cronet warmup ${warmupUrlOf(urls.first())} -> ${warm.protocol} err=${warm.error}")

            for (u in urls) {
                if (isCancelled()) break
                if (grandTotal >= maxBytes) {
                    Log.i(TAG, "cronet max_bytes reached ($grandTotal >= $maxBytes), stopping")
                    break
                }
                // Per-request cancel also fires when the byte budget is hit
                // mid-download, so one oversized URL can't blow past maxBytes.
                val req = runCronetRequest(
                    engine, executor, u, headers,
                    { n -> grandTotal += n; onBytes(n) },
                    { isCancelled() || grandTotal >= maxBytes },
                )
                if (req.protocol != "unknown") lastProtocol = req.protocol
                // A URL counts as fetched if it completed or delivered bytes.
                if (req.error == null || req.bytes > 0) urlCount++
                if (req.error != null && req.error != "cancelled" && firstError == null) {
                    firstError = req.error
                }
                Log.i(TAG, "cronet[$urlCount] ${req.protocol} err=${req.error} $u")
            }

            // Only fail the row if NOTHING was fetched; partial success (some
            // 404s among good tiles) still yields a usable measurement.
            val error = if (urlCount == 0) (firstError ?: "no urls fetched") else null
            return FetchOutcome(lastProtocol, grandTotal, error, warmupProto, urlCount)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "cronet sequence failed (quicHint=$quicHint)", e)
            return FetchOutcome(
                protocol = lastProtocol,
                bytes = grandTotal,
                error = e.message ?: e.javaClass.simpleName,
                warmupProtocol = warmupProto,
                urlCount = urlCount,
            )
        } finally {
            engine.shutdown()
            executor.shutdown()
        }
    }

    /**
     * Runs one Cronet GET against an already-built [engine] + [executor].
     * Never throws for request-level failures — they come back as
     * [FetchOutcome.error] with the stack trace logged — so cancellation stays
     * the only exceptional path out.
     */
    private suspend fun runCronetRequest(
        engine: CronetEngine,
        executor: java.util.concurrent.Executor,
        url: String,
        headers: Map<String, String>,
        onBytes: (Int) -> Unit,
        isCancelled: () -> Boolean,
    ): FetchOutcome = try {
        suspendCancellableCoroutine { cont ->
            var protocol = "unknown"
            var total = 0L
            val buffer = ByteBuffer.allocateDirect(32 * 1024)

            val callback = object : UrlRequest.Callback() {
                override fun onRedirectReceived(
                    request: UrlRequest,
                    info: UrlResponseInfo,
                    newUrl: String,
                ) {
                    request.followRedirect()
                }

                override fun onResponseStarted(request: UrlRequest, info: UrlResponseInfo) {
                    protocol = info.negotiatedProtocol ?: "unknown"
                    buffer.clear()
                    request.read(buffer)
                }

                override fun onReadCompleted(
                    request: UrlRequest,
                    info: UrlResponseInfo,
                    byteBuffer: ByteBuffer,
                ) {
                    val n = byteBuffer.position()
                    if (n > 0) {
                        total += n
                        onBytes(n)
                    }
                    if (isCancelled()) {
                        request.cancel()
                        return
                    }
                    byteBuffer.clear()
                    request.read(byteBuffer)
                }

                override fun onSucceeded(request: UrlRequest, info: UrlResponseInfo) {
                    if (cont.isActive) cont.resume(FetchOutcome(protocol, total))
                }

                override fun onFailed(request: UrlRequest, info: UrlResponseInfo?, error: CronetException) {
                    // FIX 4: if we got far enough for the stack to negotiate a
                    // protocol but then failed, keep it — otherwise a late
                    // failure would report "unknown" and hide a real h2/h3.
                    val negotiated = info?.negotiatedProtocol
                    if (!negotiated.isNullOrEmpty()) protocol = negotiated
                    Log.w(TAG, "cronet onFailed ($protocol): ${error.message}", error)
                    if (cont.isActive) cont.resume(FetchOutcome(protocol, total, error.message ?: "cronet failed"))
                }

                override fun onCanceled(request: UrlRequest, info: UrlResponseInfo?) {
                    if (cont.isActive) cont.resume(FetchOutcome(protocol, total, "cancelled"))
                }
            }

            val builder = engine.newUrlRequestBuilder(url, callback, executor)
            builder.setPriority(UrlRequest.Builder.REQUEST_PRIORITY_HIGHEST)
            headers.forEach { (k, v) -> builder.addHeader(k, v) }
            val request = builder.build()
            cont.invokeOnCancellation { request.cancel() }
            request.start()
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.e(TAG, "cronet request error: $url", e)
        FetchOutcome(error = e.message ?: e.javaClass.simpleName)
    }

    /**
     * Warmup URL: shrink the payload so the discarded request stays tiny.
     *  - cloudflare `bytes=` → 1024 (default target 1 MiB → 1 KiB)
     *  - lh3 size suffix `=WxH` → `=w64-h64` thumbnail (~3 KB instead of
     *    ~425 KB); Google lh3 honours arbitrary sizes and still returns 200.
     *  - tile URLs have neither and pass through unchanged (tiles are small).
     */
    private fun warmupUrlOf(url: String): String {
        if (url.contains("bytes=")) return url.replace(Regex("bytes=\\d+"), "bytes=1024")
        return url.replace(Regex("=w\\d+-h\\d+"), "=w64-h64")
    }

    /**
     * Runs [block] but forces it to give up after [deadlineMs] by flipping the
     * cancellation flag, so a slow warmup cannot consume the row's whole
     * timeout budget. Used only for warmup.
     */
    private suspend fun withDeadline(
        deadlineMs: Long,
        block: suspend (isCancelled: () -> Boolean) -> FetchOutcome,
    ): FetchOutcome {
        val start = System.currentTimeMillis()
        return block({ (System.currentTimeMillis() - start) >= deadlineMs })
    }

    /**
     * OkHttp fetch. [route] selects direct vs the local byedpi SOCKS proxy;
     * [http2] pins HTTP/2 (true) or forces HTTP/1.1 (false). OkHttp does not
     * speak QUIC, so this is the reliable protocol lever regardless of Cronet's
     * QUIC behaviour.
     */
    suspend fun fetchOkHttp(
        url: String,
        headers: Map<String, String>,
        route: DiagnosticRoute,
        http2: Boolean,
        proxyHost: String,
        proxyPort: Int,
        timeoutMs: Long,
        onBytes: (Int) -> Unit,
        isCancelled: () -> Boolean,
    ): FetchOutcome {
        val client = OkHttpClient.Builder().apply {
            if (route == DiagnosticRoute.VIA_ENGINE) {
                // Same mechanism SiteCheckUtils uses, so "via engine" means
                // exactly what the existing site check means by it.
                proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxyHost, proxyPort)))
            }
            protocols(
                if (http2) listOf(Protocol.HTTP_2, Protocol.HTTP_1_1)
                else listOf(Protocol.HTTP_1_1)
            )
            connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            callTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            // One connection per row keeps measurements independent.
            connectionPool(okhttp3.ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
        }.build()

        try {
            val request = Request.Builder().url(url).apply {
                headers.forEach { (k, v) -> addHeader(k, v) }
            }.build()
            // FIX 3: OkHttp canonicalizes through HttpUrl. Log the exact URL it
            // will request so a 404 can be traced to input-vs-request mutation.
            Log.i(TAG, "okhttp requesting: ${request.url} (input: $url)")

            return client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return@use FetchOutcome(
                        protocol = response.protocol.toString(),
                        error = "http ${response.code}",
                    )
                }
                val body = response.body ?: return@use FetchOutcome(
                    protocol = response.protocol.toString(),
                    error = "empty body",
                )
                val source = body.byteStream()
                val buf = ByteArray(16 * 1024)
                var total = 0L
                while (!isCancelled()) {
                    val n = source.read(buf)
                    if (n < 0) break
                    total += n
                    onBytes(n)
                }
                FetchOutcome(response.protocol.toString(), total)
            }
        } catch (e: Exception) {
            return FetchOutcome(error = e.message ?: e.javaClass.simpleName)
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }

    private fun hostOf(url: String): String? = try {
        java.net.URI(url).host
    } catch (_: Exception) {
        null
    }

    companion object {
        private const val TAG = "DiagnosticTransport"

        /** Google Maps Android headers, applied by Test 2 (URL diversity). */
        val MAPS_HEADERS: Map<String, String> = mapOf(
            "User-Agent" to "Google Maps/11.120.0 (Linux; U; Android 14; en_US; " +
                "SM-F946B; Build/UP1A.231005.007; Cronet/120.0.6099.43)",
            "X-Android-Package" to "com.google.android.apps.maps",
            "X-Android-Cert" to "38918A453D07199354F8B19AF05EC6562CED5788",
            "Accept" to "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
            "Accept-Language" to "en-US,en;q=0.9",
        )
    }
}
