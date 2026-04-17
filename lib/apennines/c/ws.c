#include "apennines/ws.h"
#include "apennines/base.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ================================================================
 *  Minimal SHA-1 (FIPS 180-4) — local to this translation unit.
 *  WebSocket handshake (RFC 6455 Section 4.2.2) requires SHA-1
 *  specifically for the Sec-WebSocket-Accept computation.
 * ================================================================ */

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    u32 h[5];
    u8  buf[SHA1_BLOCK_SIZE];
    u64 total;
    u32 buf_len;
} sha1_ctx;

static u32 sha1_rotl(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_compress(sha1_ctx *ctx, const u8 block[SHA1_BLOCK_SIZE]) {
    u32 w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((u32)block[i * 4 + 0] << 24)
             | ((u32)block[i * 4 + 1] << 16)
             | ((u32)block[i * 4 + 2] <<  8)
             | ((u32)block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    u32 a = ctx->h[0], b = ctx->h[1], c = ctx->h[2],
        d = ctx->h[3], e = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        u32 temp = sha1_rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = sha1_rotl(b, 30);
        b = a;
        a = temp;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

static void sha1_init(sha1_ctx *ctx) {
    ctx->h[0] = 0x67452301U;
    ctx->h[1] = 0xEFCDAB89U;
    ctx->h[2] = 0x98BADCFEU;
    ctx->h[3] = 0x10325476U;
    ctx->h[4] = 0xC3D2E1F0U;
    ctx->total   = 0;
    ctx->buf_len = 0;
}

static void sha1_update(sha1_ctx *ctx, const u8 *data, u64 len) {
    ctx->total += len;
    while (len > 0) {
        u32 space = SHA1_BLOCK_SIZE - ctx->buf_len;
        u32 chunk = (len < space) ? (u32)len : space;
        memcpy(ctx->buf + ctx->buf_len, data, chunk);
        ctx->buf_len += chunk;
        data += chunk;
        len  -= chunk;
        if (ctx->buf_len == SHA1_BLOCK_SIZE) {
            sha1_compress(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, u8 digest[SHA1_DIGEST_SIZE]) {
    u64 bits = ctx->total * 8;

    /* append 0x80 */
    u8 pad = 0x80;
    sha1_update(ctx, &pad, 1);

    /* pad with zeros until 56 mod 64 */
    u8 zero = 0x00;
    while (ctx->buf_len != 56) {
        sha1_update(ctx, &zero, 1);
    }

    /* append 64-bit big-endian bit count */
    u8 len_be[8];
    for (int i = 7; i >= 0; i--) {
        len_be[i] = (u8)(bits & 0xFF);
        bits >>= 8;
    }
    sha1_update(ctx, len_be, 8);

    /* write digest in big-endian */
    for (int i = 0; i < 5; i++) {
        digest[i * 4 + 0] = (u8)(ctx->h[i] >> 24);
        digest[i * 4 + 1] = (u8)(ctx->h[i] >> 16);
        digest[i * 4 + 2] = (u8)(ctx->h[i] >>  8);
        digest[i * 4 + 3] = (u8)(ctx->h[i]);
    }
}

static void sha1_digest(u8 digest[SHA1_DIGEST_SIZE], const u8 *data, u64 len) {
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

/* ================================================================
 *  WebSocket GUID (RFC 6455 Section 4.2.2)
 * ================================================================ */

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-5AB5DC11650B";

/* ================================================================
 *  Helpers
 * ================================================================ */

/* Find a header value in an HTTP response (case-insensitive header name).
 * Returns pointer to value start, sets *val_len to length.
 * Returns NULL if not found. */
static const char *find_header(const char *response, u64 response_len,
                               const char *name, u64 *val_len) {
    const char *end = response + response_len;
    const char *p = response;
    u64 name_len = strlen(name);

    /* Skip status line */
    while (p < end && *p != '\n') p++;
    if (p < end) p++; /* skip '\n' */

    while (p < end) {
        /* End of headers? */
        if (*p == '\r' || *p == '\n') break;

        /* Check if header name matches */
        const char *line_start = p;
        const char *colon = NULL;
        while (p < end && *p != '\n') {
            if (!colon && *p == ':') colon = p;
            p++;
        }
        if (p < end) p++; /* skip '\n' */

        if (!colon) continue;

        u64 hdr_len = (u64)(colon - line_start);
        if (hdr_len != name_len) continue;

        /* Case-insensitive compare of header name */
        int match = 1;
        for (u64 i = 0; i < hdr_len; i++) {
            if (tolower((unsigned char)line_start[i]) !=
                tolower((unsigned char)name[i])) {
                match = 0;
                break;
            }
        }
        if (!match) continue;

        /* Skip ": " and leading whitespace */
        const char *val = colon + 1;
        while (val < end && (*val == ' ' || *val == '\t')) val++;

        /* Value extends to end of line (strip trailing \r\n) */
        const char *val_end = p - 1; /* points at '\n' */
        if (val_end > val && *(val_end - 1) == '\r') val_end--; /* skip '\r' */

        *val_len = (u64)(val_end - val);
        return val;
    }

    return NULL;
}

/* Compute the Sec-WebSocket-Accept value:
 *   base64(SHA-1(client_key_b64 + WS_GUID))
 * Writes into accept_buf which must hold the result.
 * Returns 0 on success, non-zero on failure. */
static unsigned long compute_accept(buf *accept_buf, const char *key_b64) {
    u64 key_len = strlen(key_b64);
    u64 guid_len = strlen(WS_GUID);
    u64 concat_len = key_len + guid_len;

    u8 *concat = (u8 *)malloc(concat_len);
    if (!concat) return 1;

    memcpy(concat, key_b64, key_len);
    memcpy(concat + key_len, WS_GUID, guid_len);

    u8 hash[SHA1_DIGEST_SIZE];
    sha1_digest(hash, concat, concat_len);
    free(concat);

    return base64_encode(accept_buf, hash, SHA1_DIGEST_SIZE);
}

/* ================================================================
 *  Frame operations
 * ================================================================ */

unsigned long ws_mask(u8 *data, u64 len, const u8 mask_key[4]) {
    if (!data || !mask_key) return 0;
    for (u64 i = 0; i < len; i++) {
        data[i] ^= mask_key[i % 4];
    }
    return 0;
}

unsigned long ws_frame_encode(u8 **out, u64 *out_len,
                                             u8 opcode,
                                             const u8 *payload, u64 len,
                                             int masked, const u8 mask_key[4]) {
    if (!out)     return 1;
    if (!out_len) return 2;

    /* Calculate header size */
    u64 header_size = 2; /* byte 0 (FIN+opcode) + byte 1 (MASK+len) */
    if (len >= 126 && len <= 0xFFFF) {
        header_size += 2; /* 16-bit extended length */
    } else if (len > 0xFFFF) {
        header_size += 8; /* 64-bit extended length */
    }
    if (masked) {
        header_size += 4; /* masking key */
    }

    u64 total = header_size + len;
    u8 *frame = (u8 *)malloc(total);
    if (!frame) return 3;

    u64 pos = 0;

    /* Byte 0: FIN=1, RSV=000, opcode */
    frame[pos++] = 0x80 | (opcode & 0x0F);

    /* Byte 1: MASK bit + payload length */
    u8 mask_bit = masked ? 0x80 : 0x00;
    if (len < 126) {
        frame[pos++] = mask_bit | (u8)len;
    } else if (len <= 0xFFFF) {
        frame[pos++] = mask_bit | 126;
        frame[pos++] = (u8)(len >> 8);
        frame[pos++] = (u8)(len & 0xFF);
    } else {
        frame[pos++] = mask_bit | 127;
        for (int i = 7; i >= 0; i--) {
            frame[pos++] = (u8)((len >> (i * 8)) & 0xFF);
        }
    }

    /* Masking key */
    if (masked && mask_key) {
        memcpy(frame + pos, mask_key, 4);
        pos += 4;
    } else if (masked) {
        /* No key provided but masked requested — zero key */
        memset(frame + pos, 0, 4);
        pos += 4;
    }

    /* Payload */
    if (payload && len > 0) {
        memcpy(frame + pos, payload, len);
        if (masked) {
            /* mask_key is in the frame at (pos - 4) */
            ws_mask(frame + pos, len, frame + pos - 4);
        }
    }

    *out = frame;
    *out_len = total;
    return 0;
}

unsigned long ws_frame_decode(ws_frame *out, u64 *bytes_consumed,
                                             const u8 *data, u64 data_len) {
    if (!out)            return 1;
    if (!bytes_consumed) return 2;
    if (!data)           return 3;

    /* Need at least 2 bytes for minimal header */
    if (data_len < 2) return 4;

    u64 pos = 0;

    /* Byte 0 */
    u8 byte0 = data[pos++];
    int fin    = (byte0 >> 7) & 1;
    u8 opcode  = byte0 & 0x0F;

    /* Byte 1 */
    u8 byte1 = data[pos++];
    int masked     = (byte1 >> 7) & 1;
    u8 len_field   = byte1 & 0x7F;

    u64 payload_len = 0;

    if (len_field < 126) {
        payload_len = len_field;
    } else if (len_field == 126) {
        if (data_len < pos + 2) return 4;
        payload_len = ((u64)data[pos] << 8) | (u64)data[pos + 1];
        pos += 2;
    } else { /* 127 */
        if (data_len < pos + 8) return 4;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | (u64)data[pos + i];
        }
        pos += 8;
    }

    u8 mk[4] = {0};
    if (masked) {
        if (data_len < pos + 4) return 4;
        memcpy(mk, data + pos, 4);
        pos += 4;
    }

    /* Check we have the full payload */
    if (data_len < pos + payload_len) return 4;

    /* Allocate and copy payload */
    u8 *payload = NULL;
    if (payload_len > 0) {
        payload = (u8 *)malloc(payload_len);
        if (!payload) return 5;
        memcpy(payload, data + pos, payload_len);

        /* Unmask if needed */
        if (masked) {
            ws_mask(payload, payload_len, mk);
        }
    }

    out->fin         = fin;
    out->opcode      = opcode;
    out->payload     = payload;
    out->payload_len = payload_len;
    out->masked      = masked;
    memcpy(out->mask_key, mk, 4);

    *bytes_consumed = pos + payload_len;
    return 0;
}

unsigned long ws_frame_free(ws_frame *f) {
    if (!f) return 0;
    if (f->payload) {
        free(f->payload);
        f->payload = NULL;
    }
    f->payload_len = 0;
    return 0;
}

/* ================================================================
 *  Handshake
 * ================================================================ */

unsigned long ws_handshake_build_request(u8 **out, u64 *out_len,
                                                        const char *host,
                                                        const char *path,
                                                        const u8 key[16]) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!host)    return 3;
    if (!path)    return 4;
    if (!key)     return 5;

    /* Base64-encode the 16-byte key */
    buf key_b64;
    memset(&key_b64, 0, sizeof(key_b64));
    unsigned long rc = base64_encode(&key_b64, (u8 *)key, 16);
    if (rc != 0) return 6;

    /* Build the request string.
     * Template:
     *   GET {path} HTTP/1.1\r\n
     *   Host: {host}\r\n
     *   Upgrade: websocket\r\n
     *   Connection: Upgrade\r\n
     *   Sec-WebSocket-Key: {base64_key}\r\n
     *   Sec-WebSocket-Version: 13\r\n
     *   \r\n
     */
    u64 host_len = strlen(host);
    u64 path_len = strlen(path);

    /* Generous size estimate */
    u64 est = 4 + path_len + 11       /* GET {path} HTTP/1.1\r\n */
            + 6 + host_len + 2        /* Host: {host}\r\n */
            + 22                       /* Upgrade: websocket\r\n */
            + 21                       /* Connection: Upgrade\r\n */
            + 22 + key_b64.len + 2    /* Sec-WebSocket-Key: ...\r\n */
            + 27                       /* Sec-WebSocket-Version: 13\r\n */
            + 2                        /* \r\n */
            + 1;                       /* NUL safety */

    u8 *req = (u8 *)malloc(est);
    if (!req) {
        buf_destroy(&key_b64);
        return 6;
    }

    int written = snprintf((char *)req, est,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %.*s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, (int)key_b64.len, (char *)key_b64.data);

    buf_destroy(&key_b64);

    if (written < 0) {
        free(req);
        return 6;
    }

    *out = req;
    *out_len = (u64)written;
    return 0;
}

unsigned long ws_handshake_validate_response(int *out_valid,
                                                            const u8 *response,
                                                            u64 response_len,
                                                            const u8 expected_key[16]) {
    if (!out_valid)    return 1;
    if (!response)     return 2;
    if (!expected_key) return 3;

    *out_valid = 0;

    /* Check for "101" status in the first line */
    const char *resp = (const char *)response;
    const char *first_space = NULL;
    for (u64 i = 0; i < response_len; i++) {
        if (resp[i] == ' ') {
            first_space = resp + i;
            break;
        }
    }
    if (!first_space) return 4;

    /* Status code follows the first space */
    if (first_space + 4 > resp + response_len) return 4;
    if (first_space[1] != '1' || first_space[2] != '0' || first_space[3] != '1') return 4;

    /* Find Sec-WebSocket-Accept header */
    u64 accept_val_len = 0;
    const char *accept_val = find_header(resp, response_len,
                                          "Sec-WebSocket-Accept", &accept_val_len);
    if (!accept_val) return 5;

    /* Compute expected accept value:
     *   base64(SHA-1(base64(expected_key) + WS_GUID)) */
    buf key_b64;
    memset(&key_b64, 0, sizeof(key_b64));
    unsigned long rc = base64_encode(&key_b64, (u8 *)expected_key, 16);
    if (rc != 0) return 5;

    /* Null-terminate the key for compute_accept */
    u8 *key_str = (u8 *)malloc(key_b64.len + 1);
    if (!key_str) {
        buf_destroy(&key_b64);
        return 5;
    }
    memcpy(key_str, key_b64.data, key_b64.len);
    key_str[key_b64.len] = '\0';
    buf_destroy(&key_b64);

    buf accept_expected;
    memset(&accept_expected, 0, sizeof(accept_expected));
    rc = compute_accept(&accept_expected, (const char *)key_str);
    free(key_str);
    if (rc != 0) return 5;

    /* Compare */
    if (accept_expected.len != accept_val_len ||
        memcmp(accept_expected.data, accept_val, accept_val_len) != 0) {
        buf_destroy(&accept_expected);
        return 6;
    }

    buf_destroy(&accept_expected);
    *out_valid = 1;
    return 0;
}

unsigned long ws_handshake_build_response(u8 **out, u64 *out_len,
                                                         const char *client_key) {
    if (!out)        return 1;
    if (!out_len)    return 2;
    if (!client_key) return 3;

    /* Compute accept = base64(SHA-1(client_key + WS_GUID)) */
    buf accept_val;
    memset(&accept_val, 0, sizeof(accept_val));
    unsigned long rc = compute_accept(&accept_val, client_key);
    if (rc != 0) return 4;

    /* Build response:
     *   HTTP/1.1 101 Switching Protocols\r\n
     *   Upgrade: websocket\r\n
     *   Connection: Upgrade\r\n
     *   Sec-WebSocket-Accept: {accept}\r\n
     *   \r\n
     */
    u64 est = 34                        /* HTTP/1.1 101 Switching Protocols\r\n */
            + 22                        /* Upgrade: websocket\r\n */
            + 21                        /* Connection: Upgrade\r\n */
            + 22 + accept_val.len + 2   /* Sec-WebSocket-Accept: ...\r\n */
            + 2                         /* \r\n */
            + 1;                        /* NUL safety */

    u8 *resp = (u8 *)malloc(est);
    if (!resp) {
        buf_destroy(&accept_val);
        return 4;
    }

    int written = snprintf((char *)resp, est,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %.*s\r\n"
        "\r\n",
        (int)accept_val.len, (char *)accept_val.data);

    buf_destroy(&accept_val);

    if (written < 0) {
        free(resp);
        return 4;
    }

    *out = resp;
    *out_len = (u64)written;
    return 0;
}
unsigned long ws_conn_create_client(void) { return 0; }
unsigned long ws_conn_create_server(void) { return 0; }
unsigned long ws_conn_destroy(void) { return 0; }
unsigned long ws_conn_recv(void) { return 0; }
unsigned long ws_conn_send_binary(void) { return 0; }
unsigned long ws_conn_send_close(void) { return 0; }
unsigned long ws_conn_send_ping(void) { return 0; }
unsigned long ws_conn_send_pong(void) { return 0; }
unsigned long ws_conn_send_text(void) { return 0; }
