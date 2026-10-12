#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cronet.h"

/* Minimal byte writer with overflow guard. */
struct cw {
    unsigned char *p;
    size_t len;
    size_t cap;
    int err;
};

static void cw_bytes(struct cw *w, const void *d, size_t n)
{
    if (w->err || (w->len + n) > w->cap) {
        w->err = 1;
        return;
    }
    memcpy(w->p + w->len, d, n);
    w->len += n;
}

static void cw_u8(struct cw *w, uint8_t v)
{
    cw_bytes(w, &v, 1);
}

static void cw_u16(struct cw *w, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    cw_bytes(w, b, 2);
}

static void cw_u24(struct cw *w, uint32_t v)
{
    uint8_t b[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    cw_bytes(w, b, 3);
}

static void cw_patch16(struct cw *w, size_t off, size_t v)
{
    if ((off + 2) > w->len) {
        return;
    }
    w->p[off] = (uint8_t)(v >> 8);
    w->p[off + 1] = (uint8_t)v;
}

static void cw_patch24(struct cw *w, size_t off, size_t v)
{
    if ((off + 3) > w->len) {
        return;
    }
    w->p[off] = (uint8_t)(v >> 16);
    w->p[off + 1] = (uint8_t)(v >> 8);
    w->p[off + 2] = (uint8_t)v;
}

static void cw_rand(struct cw *w, size_t n)
{
    for (; n; n--) {
        cw_u8(w, (uint8_t)(rand() % 256));
    }
}

ssize_t build_cronet_chello(char *out, size_t cap,
        const char *sni, ssize_t target)
{
    /* Chrome/Cronet (BoringSSL) cipher order, GREASE first. */
    static const uint16_t ciphers[] = {
        0x0a0a,
        0x1301, 0x1302, 0x1303,
        0xc02b, 0xc02f, 0xcca9, 0xcca8,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
    };
    static const uint16_t groups[] = { 0x001d, 0x0017, 0x0018 };
    static const uint16_t sigalgs[] = {
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601, 0x0807, 0x0808, 0x0809,
        0x080a, 0x080b
    };
    if (!sni) {
        sni = "mt0.google.com";
    }
    size_t sl = strlen(sni);
    if (sl > 255 || sl < 1) {
        return -1;
    }
    struct cw w = {
        .p = (unsigned char *)out, .len = 0, .cap = cap, .err = 0
    };
    
    cw_u8(&w, 0x16);                    /* record: handshake */
    cw_u16(&w, 0x0301);
    size_t rec_off = w.len;
    cw_u16(&w, 0);                      /* patched below */
    
    cw_u8(&w, 0x01);                    /* handshake: client_hello */
    size_t hs_off = w.len;
    cw_u24(&w, 0);                      /* patched below */
    
    cw_u16(&w, 0x0303);                 /* client version TLS 1.2 */
    cw_rand(&w, 32);                    /* random */
    cw_u8(&w, 32);                      /* legacy session id length */
    cw_rand(&w, 32);                    /* legacy session id (compat mode) */
    
    cw_u16(&w, sizeof(ciphers));
    for (size_t i = 0; i < sizeof(ciphers) / sizeof(*ciphers); i++) {
        cw_u16(&w, ciphers[i]);
    }
    cw_u8(&w, 1);                       /* compression: null */
    cw_u8(&w, 0);
    
    size_t ext_off = w.len;
    cw_u16(&w, 0);                      /* patched below */
    
    cw_u16(&w, 0x0a0a);                 /* GREASE */
    cw_u16(&w, 0);
    
    cw_u16(&w, 0x0000);                 /* server_name */
    cw_u16(&w, (uint16_t)(sl + 5));
    cw_u16(&w, (uint16_t)(sl + 3));
    cw_u8(&w, 0x00);
    cw_u16(&w, (uint16_t)sl);
    cw_bytes(&w, sni, sl);
    
    cw_u16(&w, 0x0017);                 /* extended_master_secret */
    cw_u16(&w, 0);
    
    cw_u16(&w, 0xff01);                 /* renegotiation_info */
    cw_u16(&w, 2);
    cw_u8(&w, 0x01);
    cw_u8(&w, 0x00);
    
    cw_u16(&w, 0x000a);                 /* supported_groups */
    cw_u16(&w, (uint16_t)(2 + sizeof(groups)));
    cw_u16(&w, (uint16_t)sizeof(groups));
    for (size_t i = 0; i < sizeof(groups) / sizeof(*groups); i++) {
        cw_u16(&w, groups[i]);
    }
    
    cw_u16(&w, 0x000b);                 /* ec_point_formats */
    cw_u16(&w, 2);
    cw_u8(&w, 0x01);
    cw_u8(&w, 0x00);
    
    cw_u16(&w, 0x0023);                 /* session_ticket */
    cw_u16(&w, 0);
    
    cw_u16(&w, 0x0010);                 /* ALPN: h2, http/1.1 */
    cw_u16(&w, 2 + 3 + 9);
    cw_u16(&w, 3 + 9);
    cw_u8(&w, 2);
    cw_bytes(&w, "h2", 2);
    cw_u8(&w, 8);
    cw_bytes(&w, "http/1.1", 8);
    
    cw_u16(&w, 0x0005);                 /* status_request (OCSP) */
    cw_u16(&w, 0);
    
    cw_u16(&w, 0x002b);                 /* supported_versions */
    cw_u16(&w, 7);
    cw_u8(&w, 6);
    cw_u16(&w, 0x0a0a);                 /* GREASE */
    cw_u16(&w, 0x0304);                 /* TLS 1.3 */
    cw_u16(&w, 0x0303);                 /* TLS 1.2 */
    
    cw_u16(&w, 0x0033);                 /* key_share */
    cw_u16(&w, 43);
    cw_u16(&w, 41);
    cw_u16(&w, 0x0a0a);                 /* GREASE share, 1 byte */
    cw_u16(&w, 1);
    cw_u8(&w, 0x00);
    cw_u16(&w, 0x001d);                 /* x25519 */
    cw_u16(&w, 32);
    cw_rand(&w, 32);
    
    cw_u16(&w, 0x000d);                 /* signature_algorithms */
    cw_u16(&w, (uint16_t)(2 + sizeof(sigalgs)));
    cw_u16(&w, (uint16_t)sizeof(sigalgs));
    for (size_t i = 0; i < sizeof(sigalgs) / sizeof(*sigalgs); i++) {
        cw_u16(&w, sigalgs[i]);
    }
    
    cw_u16(&w, 0x002d);                 /* psk_key_exchange_modes */
    cw_u16(&w, 3);
    cw_u8(&w, 2);
    cw_u8(&w, 0x00);
    cw_u8(&w, 0x01);
    
    cw_u16(&w, 0x0a0a);                 /* GREASE */
    cw_u16(&w, 0);
    
    /* Padding extension up to the target record size: mimics Chrome's
     * fixed 512-byte hello (or the size of the real ClientHello) and
     * leaves room for change_tls_sni to resize the name. */
    ssize_t want = target;
    if (want < CRONET_CH_BASE) {
        want = CRONET_CH_BASE;
    }
    ssize_t pad = want - (ssize_t)w.len - 4;
    if (pad >= 0 && pad <= 0xffff && !w.err) {
        cw_u16(&w, 0x0015);
        cw_u16(&w, (uint16_t)pad);
        for (ssize_t i = 0; i < pad; i++) {
            cw_u8(&w, 0x00);
        }
    }
    if (w.err) {
        return -1;
    }
    cw_patch16(&w, ext_off, w.len - (ext_off + 2));
    cw_patch24(&w, hs_off, w.len - (hs_off + 3));
    cw_patch16(&w, rec_off, w.len - (rec_off + 2));
    return (ssize_t)w.len;
}
