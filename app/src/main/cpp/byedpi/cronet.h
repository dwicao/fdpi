#ifndef CRONET_H
#define CRONET_H

#include <sys/types.h>

/* Base (minimum) size of the generated Cronet-like ClientHello record,
 * matching Chrome's 512-byte padded hello. */
#define CRONET_CH_BASE 512

/*
 * Build a Cronet (Chrome/BoringSSL)-style TLS ClientHello into out.
 *   sni    - server name to place in the hello (may be rotated by caller)
 *   target - desired record size; the hello is padded with the padding
 *            extension (0x0015) up to max(target, CRONET_CH_BASE), which
 *            mimics Chrome's fixed-size hello and gives change_tls_sni
 *            room to resize the name later.
 * Returns record size in bytes, or -1 on error.
 *
 * The generated hello is syntactically valid but the key_share holds
 * random bytes: it is meant to be sent only as a low-TTL fake packet that
 * never completes a handshake. */
ssize_t build_cronet_chello(char *out, size_t cap,
        const char *sni, ssize_t target);

#endif
