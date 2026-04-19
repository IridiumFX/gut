#include "apennines/ssh.h"
#include "apennines/tcp.h"
#include "apennines/uds.h"
#include "apennines/addr.h"
#include "apennines/hash.h"
#include "apennines/ec.h"
#include "apennines/cipher.h"
#include "apennines/entropy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* ================================================================
 *  Diagnostic tracing — gated on APENNINES_SSH_DEBUG env var.
 *
 *  Set once at first use; fprintf's stderr when non-NULL/non-"0". Cheap
 *  enough to leave compiled-in (env lookup happens once). Each trace
 *  point names the KEX/auth/channel stage and the relevant byte counts
 *  / message types so a consumer (gut, cookbook) can send us a
 *  transcript when a handshake fails against a specific server.
 * ================================================================ */

static int ssh_dbg_enabled(void) {
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("APENNINES_SSH_DEBUG");
        cached = (v && *v && v[0] != '0') ? 1 : 0;
    }
    return cached;
}

#define SSH_DBG(...)                                     \
    do {                                                  \
        if (ssh_dbg_enabled()) {                          \
            fprintf(stderr, "[apennines_ssh] " __VA_ARGS__); \
            fflush(stderr);                               \
        }                                                 \
    } while (0)

/* ================================================================
 *  SSH Transport — RFC 4253/4252 client implementation
 * ================================================================ */

/* ---- SSH message types ---- */
#define SSH_MSG_DISCONNECT           1
#define SSH_MSG_SERVICE_REQUEST      5
#define SSH_MSG_SERVICE_ACCEPT       6
#define SSH_MSG_KEXINIT             20
#define SSH_MSG_NEWKEYS             21
#define SSH_MSG_KEX_ECDH_INIT      30
#define SSH_MSG_KEX_ECDH_REPLY     31
#define SSH_MSG_USERAUTH_REQUEST   50
#define SSH_MSG_USERAUTH_FAILURE   51
#define SSH_MSG_USERAUTH_SUCCESS   52
#define SSH_MSG_USERAUTH_BANNER    53
#define SSH_MSG_GLOBAL_REQUEST     80
#define SSH_MSG_REQUEST_SUCCESS    81
#define SSH_MSG_REQUEST_FAILURE    82
#define SSH_MSG_CHANNEL_OPEN       90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM 91
#define SSH_MSG_CHANNEL_OPEN_FAIL  92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA       94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF        96
#define SSH_MSG_CHANNEL_CLOSE      97
#define SSH_MSG_CHANNEL_REQUEST    98
#define SSH_MSG_CHANNEL_SUCCESS    99
#define SSH_MSG_CHANNEL_FAILURE   100

#define SSH_MAX_PACKET      35000
#define SSH_VERSION_STRING  "SSH-2.0-apennines_1.0\r\n"
#define SSH_INITIAL_WINDOW  0x200000   /* 2 MB */
#define SSH_MAX_PACKET_SIZE 0x8000

/* ---- Internal structs ---- */

struct ssh_channel {
    u32       local_id;
    u32       remote_id;
    u32       remote_window;
    int       closed;
    u8       *recv_buf;
    u64       recv_len;
    u64       recv_cap;

    /* Separate stderr ring for SSH_MSG_CHANNEL_EXTENDED_DATA with
     * data_type_code = SSH_EXTENDED_DATA_STDERR (1). For the
     * git-over-ssh flow this carries `git-upload-pack`'s error output.
     * Drain via ssh_channel_read_stderr. */
    u8       *err_recv_buf;
    u64       err_recv_len;
    u64       err_recv_cap;

    ssh_conn *conn;     /* back-pointer for I/O */
};

struct ssh_conn {
    tcp_conn    tcp;
    int         connected;

    /* Transport keys */
    u8   enc_key_c2s[32], enc_key_s2c[32];
    u8   mac_key_c2s[32], mac_key_s2c[32];
    u8   iv_c2s[12], iv_s2c[12];
    u64  seq_c2s, seq_s2c;
    int  encrypted;

    aes_ctx  aes_c2s;
    aes_ctx  aes_s2c;

    u8   session_id[32];
    u64  session_id_len;

    /* Version strings (CR/LF stripped) — captured during version
     * exchange, used by ssh_key_exchange when computing the proper
     * RFC 4253 §8 exchange hash (V_C, V_S). */
    u8   client_version[256];
    u64  client_version_len;
    u8   server_version[256];
    u64  server_version_len;

    /* Channel tracking */
    ssh_channel **channels;
    u64           channel_count;
    u64           channel_cap;
    u32           next_channel_id;

    /* Userauth service state — set once the server ACCEPTs our
     * SSH_MSG_SERVICE_REQUEST "ssh-userauth" (RFC 4253 §10). Guards
     * every auth method from re-requesting the service. */
    int           service_accepted;

    /* AES-GCM invocation counter (RFC 5647 §7.1). At NEWKEYS these
     * are seeded from iv_c2s[4..11] / iv_s2c[4..11] as big-endian
     * u64. The nonce for each packet is iv[0..3] || BE64(counter);
     * the counter increments by 1 after each use. Separate from the
     * protocol sequence number seq_c2s/seq_s2c which is unused for
     * aes256-gcm@openssh.com (it has no separate MAC — AEAD tag
     * replaces HMAC). */
    u64           gcm_ctr_c2s;
    u64           gcm_ctr_s2c;

    /* Host-key verifier (set by ssh_conn_create_ex; NULL means TOFU
     * accept). Called inside KEX after sig verification succeeds but
     * before we commit transport keys. Return non-zero to reject. */
    ssh_hostkey_verifier_fn verifier_fn;
    void                   *verifier_ctx;
    /* Copy of the host string passed to create_ex — needed because
     * the verifier is invoked inside ssh_key_exchange, long after the
     * caller's pointer may have been freed. */
    char                    verify_host[256];
    u16                     verify_port;
};

/* ================================================================
 *  Helpers: big-endian encoding
 * ================================================================ */

static void put_u32(u8 *dst, u32 v) {
    dst[0] = (u8)(v >> 24);
    dst[1] = (u8)(v >> 16);
    dst[2] = (u8)(v >> 8);
    dst[3] = (u8)(v);
}

static u32 get_u32(const u8 *src) {
    return ((u32)src[0] << 24) | ((u32)src[1] << 16) |
           ((u32)src[2] << 8)  | (u32)src[3];
}

static void put_u64(u8 *dst, u64 v) {
    dst[0] = (u8)(v >> 56);
    dst[1] = (u8)(v >> 48);
    dst[2] = (u8)(v >> 40);
    dst[3] = (u8)(v >> 32);
    dst[4] = (u8)(v >> 24);
    dst[5] = (u8)(v >> 16);
    dst[6] = (u8)(v >> 8);
    dst[7] = (u8)(v);
}

static u64 get_u64(const u8 *src) {
    return ((u64)src[0] << 56) | ((u64)src[1] << 48) |
           ((u64)src[2] << 40) | ((u64)src[3] << 32) |
           ((u64)src[4] << 24) | ((u64)src[5] << 16) |
           ((u64)src[6] << 8)  | (u64)src[7];
}

/* ================================================================
 *  Low-level TCP send/recv helpers
 * ================================================================ */

static unsigned long tcp_recv_exact(tcp_conn *tcp, u8 *buf, u64 len) {
    u64 total = 0;
    while (total < len) {
        u64 got = 0;
        unsigned long rc = tcp_conn_read(&got, tcp, buf + total, len - total);
        if (rc != 0) return 1;
        if (got == 0) return 1;  /* connection closed */
        total += got;
    }
    return 0;
}

static unsigned long tcp_send_all(tcp_conn *tcp, const u8 *data, u64 len) {
    u64 sent = 0;
    return tcp_conn_write_all(&sent, tcp, data, len);
}

/* ================================================================
 *  SSH binary packet: send / receive
 * ================================================================ */

/* Build and send a packet. payload is the SSH message (type byte + data).
 * If encrypted, encrypts with AES-256-GCM. */
static unsigned long ssh_send_packet(ssh_conn *conn, const u8 *payload, u64 payload_len) {
    u8 pkt[SSH_MAX_PACKET];
    u8 pad_len;
    u64 block_size = conn->encrypted ? 16 : 8;
    u64 unpadded, total_len;
    u64 wr;

    /* RFC 4253 §6: "the total length of the packet (not counting the
     * 'mac' or the length field) is a multiple of the block size."
     * The "encrypted portion" is padding_length(1) + payload + padding.
     * The 4-byte length field is NOT counted. For AES-GCM the block
     * size is 16; previous code mistakenly aligned 4+1+payload+pad to
     * 16, giving an encrypted portion ≡ 12 mod 16, which strict
     * servers (e.g. GitHub's babeld) silently drop. */
    unpadded = 1 + payload_len;
    pad_len = (u8)(block_size - (unpadded % block_size));
    if (pad_len < 4) pad_len += (u8)block_size;

    total_len = 4 + 1 + payload_len + pad_len;
    if (total_len > SSH_MAX_PACKET) return 1;

    /* packet_length = 1 + payload_len + pad_len (excludes the length field itself) */
    put_u32(pkt, (u32)(1 + payload_len + pad_len));
    pkt[4] = pad_len;
    memcpy(pkt + 5, payload, payload_len);
    /* random padding — fill with zeros for simplicity (a real impl uses CSPRNG) */
    memset(pkt + 5 + payload_len, 0, pad_len);

    if (conn->encrypted) {
        u8 enc_buf[SSH_MAX_PACKET];
        u8 tag[16];
        u8 nonce[12];
        u64 enc_len = total_len - 4;  /* encrypt everything after length field */

        /* RFC 5647 §7.1 nonce: first 4 bytes from iv_c2s[0..3] (fixed),
         * last 8 bytes are the big-endian invocation counter. The counter
         * starts at iv_c2s[4..11] as BE64 at NEWKEYS, and increments by 1
         * per packet. This is NOT the XOR-with-seq-num used by some SSH
         * AEAD constructions — aes*-gcm@openssh.com uses RFC 5647. */
        memcpy(nonce, conn->iv_c2s, 4);
        put_u64(nonce + 4, conn->gcm_ctr_c2s);

        if (ssh_dbg_enabled()) {
            u32 i;
            fprintf(stderr, "[apennines_ssh] enc send seq=%llu ctr=%llu nonce=",
                    (unsigned long long)conn->seq_c2s,
                    (unsigned long long)conn->gcm_ctr_c2s);
            for (i = 0; i < 12; i++) fprintf(stderr, "%02x", nonce[i]);
            fprintf(stderr, " aad_len=4 pt_len=%llu\n", (unsigned long long)enc_len);
            fflush(stderr);
        }

        /* AAD = packet_length (first 4 bytes, unencrypted on wire). */
        if (aes256_gcm_encrypt(enc_buf, tag, &conn->aes_c2s,
                               nonce, pkt, 4,
                               pkt + 4, enc_len) != 0) return 2;

        /* Advance the invocation counter now that this nonce was consumed. */
        conn->gcm_ctr_c2s++;

        /* Send: length(4) + encrypted_body + tag(16) */
        if (ssh_dbg_enabled()) {
            u32 i;
            u32 n = (u32)(enc_len > 16 ? 16 : enc_len);
            fprintf(stderr, "[apennines_ssh] enc send wire first4=%02x%02x%02x%02x ct_first16=",
                    pkt[0], pkt[1], pkt[2], pkt[3]);
            for (i = 0; i < n; i++) fprintf(stderr, "%02x", enc_buf[i]);
            fprintf(stderr, " tag=");
            for (i = 0; i < 16; i++) fprintf(stderr, "%02x", tag[i]);
            fprintf(stderr, " (enc_len=%llu total_wire=%llu)\n",
                    (unsigned long long)enc_len,
                    (unsigned long long)(4 + enc_len + 16));
            fflush(stderr);
        }
        if (tcp_send_all(&conn->tcp, pkt, 4) != 0) return 3;
        if (tcp_send_all(&conn->tcp, enc_buf, enc_len) != 0) return 3;
        if (tcp_send_all(&conn->tcp, tag, 16) != 0) return 3;
    } else {
        if (tcp_conn_write_all(&wr, &conn->tcp, pkt, total_len) != 0) return 3;
    }

    conn->seq_c2s++;
    return 0;
}

/* Receive one SSH packet. payload_out receives just the message (type + data).
 * Caller provides buffer. Returns payload length in *payload_len_out. */
static unsigned long ssh_recv_packet(ssh_conn *conn,
                                     u8 *payload_out, u64 payload_cap,
                                     u64 *payload_len_out) {
    u8 hdr[4];
    u32 packet_length;
    u8 body[SSH_MAX_PACKET];
    u8 pad_len;
    u64 plen;

    if (tcp_recv_exact(&conn->tcp, hdr, 4) != 0) return 1;
    packet_length = get_u32(hdr);
    if (packet_length < 2 || packet_length > SSH_MAX_PACKET - 4) return 2;

    if (conn->encrypted) {
        u8 enc_body[SSH_MAX_PACKET];
        u8 tag[16];
        u8 nonce[12];

        if (tcp_recv_exact(&conn->tcp, enc_body, packet_length) != 0) return 1;
        if (tcp_recv_exact(&conn->tcp, tag, 16) != 0) return 1;

        /* RFC 5647 §7.1 nonce for s2c direction. */
        memcpy(nonce, conn->iv_s2c, 4);
        put_u64(nonce + 4, conn->gcm_ctr_s2c);

        if (ssh_dbg_enabled()) {
            u32 i;
            fprintf(stderr, "[apennines_ssh] enc recv seq=%llu ctr=%llu nonce=",
                    (unsigned long long)conn->seq_s2c,
                    (unsigned long long)conn->gcm_ctr_s2c);
            for (i = 0; i < 12; i++) fprintf(stderr, "%02x", nonce[i]);
            fprintf(stderr, " aad_len=4 ct_len=%llu\n",
                    (unsigned long long)packet_length);
            fflush(stderr);
        }

        if (aes256_gcm_decrypt(body, &conn->aes_s2c,
                               nonce, hdr, 4,
                               enc_body, packet_length,
                               tag) != 0) return 3;

        /* Advance the invocation counter after successful decrypt. */
        conn->gcm_ctr_s2c++;
    } else {
        if (tcp_recv_exact(&conn->tcp, body, packet_length) != 0) return 1;
    }

    conn->seq_s2c++;

    pad_len = body[0];
    plen = packet_length - 1 - pad_len;
    if (plen > payload_cap) return 4;

    memcpy(payload_out, body + 1, plen);
    *payload_len_out = plen;
    return 0;
}

/* Forward declarations — pr_init / pr_u8 / pr_string are defined
 * below in the payload-reader block but we need them here to parse
 * GLOBAL_REQUEST bodies inside the noise filter. */
typedef struct { const u8 *data; u64 len; u64 pos; } pkt_reader;
static void pr_init(pkt_reader *pr, const u8 *data, u64 len);
static int  pr_u8(pkt_reader *pr, u8 *out);
static int  pr_string(pkt_reader *pr, const u8 **out, u64 *out_len);

/* ssh_recv_packet_filtered — recv + transparently drop unsolicited
 * informational / control messages that callers shouldn't see.
 *
 * Filtered types:
 *   SSH_MSG_IGNORE (2)          RFC 4253 §11.2
 *   SSH_MSG_UNIMPLEMENTED (3)   RFC 4253 §11.4
 *   SSH_MSG_DEBUG (4)           RFC 4253 §11.3
 *   SSH_MSG_USERAUTH_BANNER (53) RFC 4252 §5.4 (informational login notice)
 *   SSH_MSG_GLOBAL_REQUEST (80) RFC 4254 §4 (e.g. GitHub's
 *                                hostkeys-00@openssh.com announcement
 *                                sent between CHANNEL_OPEN and
 *                                CHANNEL_OPEN_CONFIRMATION). If
 *                                want_reply=TRUE, we MUST reply with
 *                                REQUEST_FAILURE per §4; we don't
 *                                implement any extension so we always
 *                                refuse.
 *   SSH_MSG_REQUEST_SUCCESS/FAILURE (81/82) — defensive, never
 *                                expected unsolicited.
 *
 * Without this filter a server that sends any of these between our
 * CHANNEL_OPEN and its CHANNEL_OPEN_CONFIRMATION would cause us to
 * treat the interleaved message as the confirmation — exactly what
 * gut hit against github.com in the 03:30 trace.
 */
static unsigned long ssh_recv_packet_filtered(ssh_conn *conn,
                                               u8 *payload_out, u64 payload_cap,
                                               u64 *payload_len_out) {
    for (;;) {
        unsigned long rc = ssh_recv_packet(conn, payload_out, payload_cap, payload_len_out);
        if (rc != 0) {
            SSH_DBG("recv_packet rc=%lu\n", rc);
            return rc;
        }
        if (*payload_len_out >= 1) {
            u8 t = payload_out[0];
            SSH_DBG("recv msg_type=%u len=%llu\n", (unsigned)t,
                    (unsigned long long)*payload_len_out);
            if (t == 2 /* SSH_MSG_IGNORE */ ||
                t == 3 /* SSH_MSG_UNIMPLEMENTED */ ||
                t == 4 /* SSH_MSG_DEBUG */ ||
                t == SSH_MSG_USERAUTH_BANNER /* 53 */ ||
                t == SSH_MSG_REQUEST_SUCCESS  /* 81 — defensive */ ||
                t == SSH_MSG_REQUEST_FAILURE  /* 82 — defensive */) {
                continue;
            }
            if (t == SSH_MSG_GLOBAL_REQUEST) {
                /* Parse: string request_name || bool want_reply || <data>
                 * We don't implement any global-request extension, so if
                 * the server wants a reply, refuse with REQUEST_FAILURE. */
                pkt_reader gr;
                u8 msg_type;
                const u8 *name = NULL;
                u64 name_len = 0;
                u8 want_reply = 0;

                pr_init(&gr, payload_out, *payload_len_out);
                (void)pr_u8(&gr, &msg_type);
                (void)pr_string(&gr, &name, &name_len);
                (void)pr_u8(&gr, &want_reply);

                SSH_DBG("filter: dropped GLOBAL_REQUEST name='%.*s' want_reply=%u\n",
                        (int)name_len, (const char *)(name ? name : (const u8 *)""),
                        (unsigned)want_reply);

                if (want_reply) {
                    u8 resp = SSH_MSG_REQUEST_FAILURE;
                    (void)ssh_send_packet(conn, &resp, 1);
                }
                continue;
            }
        }
        return 0;
    }
}

/* ================================================================
 *  Payload builder helpers
 * ================================================================ */

typedef struct {
    u8  *buf;
    u64  len;
    u64  cap;
} pkt_buf;

static void pb_init(pkt_buf *pb, u8 *buf, u64 cap) {
    pb->buf = buf;
    pb->len = 0;
    pb->cap = cap;
}

static void pb_u8(pkt_buf *pb, u8 v) {
    if (pb->len + 1 <= pb->cap) pb->buf[pb->len++] = v;
}

static void pb_u32(pkt_buf *pb, u32 v) {
    if (pb->len + 4 <= pb->cap) {
        put_u32(pb->buf + pb->len, v);
        pb->len += 4;
    }
}

static void pb_string(pkt_buf *pb, const u8 *data, u64 data_len) {
    pb_u32(pb, (u32)data_len);
    if (pb->len + data_len <= pb->cap) {
        memcpy(pb->buf + pb->len, data, data_len);
        pb->len += data_len;
    }
}

static void pb_cstring(pkt_buf *pb, const char *s) {
    pb_string(pb, (const u8 *)s, (u64)strlen(s));
}

static void pb_bool(pkt_buf *pb, int v) {
    pb_u8(pb, v ? 1 : 0);
}

static void pb_raw(pkt_buf *pb, const u8 *data, u64 len) {
    if (pb->len + len <= pb->cap) {
        memcpy(pb->buf + pb->len, data, len);
        pb->len += len;
    }
}

/* Read helpers for received payloads. (pkt_reader typedef is forward-
 * declared earlier so the noise filter can use it.) */

static void pr_init(pkt_reader *pr, const u8 *data, u64 len) {
    pr->data = data;
    pr->len  = len;
    pr->pos  = 0;
}

static int pr_u8(pkt_reader *pr, u8 *out) {
    if (pr->pos + 1 > pr->len) return -1;
    *out = pr->data[pr->pos++];
    return 0;
}

static int pr_u32(pkt_reader *pr, u32 *out) {
    if (pr->pos + 4 > pr->len) return -1;
    *out = get_u32(pr->data + pr->pos);
    pr->pos += 4;
    return 0;
}

static int pr_string(pkt_reader *pr, const u8 **out, u64 *out_len) {
    u32 slen;
    if (pr_u32(pr, &slen) != 0) return -1;
    if (pr->pos + slen > pr->len) return -1;
    *out = pr->data + pr->pos;
    *out_len = slen;
    pr->pos += slen;
    return 0;
}

static int pr_skip(pkt_reader *pr, u64 n) {
    if (pr->pos + n > pr->len) return -1;
    pr->pos += n;
    return 0;
}

/* ================================================================
 *  Version exchange
 * ================================================================ */

static unsigned long ssh_version_exchange(ssh_conn *conn) {
    u8 buf[256];
    u64 pos = 0;
    u64 rd;
    const char *ver = SSH_VERSION_STRING;
    u64 ver_len = (u64)strlen(ver);
    u64 vlen_no_crlf;

    /* Send our version */
    if (tcp_send_all(&conn->tcp, (const u8 *)ver, ver_len) != 0) return 1;

    /* Store V_C with CR/LF stripped — RFC 4253 §8 hashes the version
     * line without the trailing CR LF. SSH_VERSION_STRING is
     * "SSH-2.0-apennines_1.0\r\n", so we drop the last 2 bytes. */
    vlen_no_crlf = ver_len;
    while (vlen_no_crlf > 0 &&
           (ver[vlen_no_crlf - 1] == '\r' || ver[vlen_no_crlf - 1] == '\n')) {
        vlen_no_crlf--;
    }
    if (vlen_no_crlf > sizeof(conn->client_version)) return 4;
    memcpy(conn->client_version, ver, (size_t)vlen_no_crlf);
    conn->client_version_len = vlen_no_crlf;

    /* Read server version line (ends with \r\n or \n). OpenSSH and
     * some servers may send banner lines *before* the version line —
     * the spec (RFC 4253 §4.2) allows arbitrary lines before the one
     * that starts with "SSH-2.0-" / "SSH-1.99-". Loop until we see
     * one we recognise. */
    for (;;) {
        pos = 0;
        while (pos < sizeof(buf) - 1) {
            if (tcp_conn_read(&rd, &conn->tcp, buf + pos, 1) != 0) return 2;
            if (rd == 0) return 2;
            if (buf[pos] == '\n') break;
            pos++;
        }
        /* pos points at '\n'; trim CR if present */
        {
            u64 line_len = pos;
            if (line_len > 0 && buf[line_len - 1] == '\r') line_len--;
            if (line_len >= 8 && memcmp(buf, "SSH-2.0-", 8) == 0) {
                if (line_len > sizeof(conn->server_version)) return 3;
                memcpy(conn->server_version, buf, (size_t)line_len);
                conn->server_version_len = line_len;
                return 0;
            }
            if (line_len >= 9 && memcmp(buf, "SSH-1.99-", 9) == 0) {
                if (line_len > sizeof(conn->server_version)) return 3;
                memcpy(conn->server_version, buf, (size_t)line_len);
                conn->server_version_len = line_len;
                return 0;
            }
            /* Else: treat as a pre-version banner line and keep reading. */
        }
    }
}

/* ================================================================
 *  KEXINIT construction
 * ================================================================ */

static void build_kexinit(pkt_buf *pb) {
    u8 cookie[16];

    /* RFC 4253 §7.1 requires a random cookie. Some forges check it; we
     * had a constant 0x42... which at best loses anti-replay, at worst
     * trips server-side heuristics. Fall back to an all-zero cookie if
     * entropy isn't available — better than crashing. */
    if (entropy_get_system(cookie, 16) != 0) {
        memset(cookie, 0, 16);
    }

    pb_u8(pb, SSH_MSG_KEXINIT);
    pb_raw(pb, cookie, 16);

    /* kex_algorithms */
    pb_cstring(pb, "curve25519-sha256");
    /* server_host_key_algorithms */
    pb_cstring(pb, "ssh-ed25519");
    /* encryption_algorithms_client_to_server */
    pb_cstring(pb, "aes256-gcm@openssh.com");
    /* encryption_algorithms_server_to_client */
    pb_cstring(pb, "aes256-gcm@openssh.com");
    /* mac_algorithms_client_to_server */
    pb_cstring(pb, "hmac-sha2-256");
    /* mac_algorithms_server_to_client */
    pb_cstring(pb, "hmac-sha2-256");
    /* compression_algorithms_client_to_server */
    pb_cstring(pb, "none");
    /* compression_algorithms_server_to_client */
    pb_cstring(pb, "none");
    /* languages_client_to_server */
    pb_cstring(pb, "");
    /* languages_server_to_client */
    pb_cstring(pb, "");
    /* first_kex_packet_follows */
    pb_bool(pb, 0);
    /* reserved */
    pb_u32(pb, 0);
}

/* ================================================================
 *  SSH mpint encoding (RFC 4251 §5)
 *
 *  Multi-precision integer:
 *    - Positive numbers with MSB set must be prefixed with 0x00 so
 *      they don't look negative in two's complement.
 *    - Leading zero bytes must be stripped (except when needed to
 *      keep the number positive per the above rule).
 *    - The result is length-prefixed as an SSH string.
 *  Zero is a 4-byte length prefix of 0 followed by nothing.
 *
 *  Used for encoding K (the X25519 shared secret) in the exchange hash.
 * ================================================================ */

static void pb_mpint(pkt_buf *pb, const u8 *bytes, u64 len) {
    u64 i = 0;

    /* Strip leading zero bytes */
    while (i < len && bytes[i] == 0) i++;

    if (i == len) {
        /* All zeros → empty mpint */
        pb_u32(pb, 0);
        return;
    }

    /* If the leading byte has MSB set, prepend 0x00 to mark positive. */
    if (bytes[i] & 0x80) {
        pb_u32(pb, (u32)(len - i + 1));
        pb_u8(pb, 0);
        if (pb->len + (len - i) <= pb->cap) {
            memcpy(pb->buf + pb->len, bytes + i, (size_t)(len - i));
            pb->len += (len - i);
        }
    } else {
        pb_u32(pb, (u32)(len - i));
        if (pb->len + (len - i) <= pb->cap) {
            memcpy(pb->buf + pb->len, bytes + i, (size_t)(len - i));
            pb->len += (len - i);
        }
    }
}

/* ================================================================
 *  Key derivation (RFC 4253 section 7.2)
 * ================================================================ */

static unsigned long derive_key(u8 *out, u64 out_len,
                                const u8 *shared_secret, u64 ss_len,
                                const u8 *exchange_hash,
                                u8 letter,
                                const u8 *session_id, u64 sid_len) {
    sha256_ctx ctx;
    u8 hash[32];
    u8 ss_buf[64];
    pkt_buf sb;

    /* Encode shared secret K as SSH mpint (RFC 4253 §7.2). Old code
     * used pb_string (raw length-prefix), which mis-encodes negative-
     * looking values (MSB set) and wouldn't match a peer's derivation. */
    pb_init(&sb, ss_buf, sizeof(ss_buf));
    pb_mpint(&sb, shared_secret, ss_len);

    if (sha256_init(&ctx) != 0) return 1;
    if (sha256_update(&ctx, sb.buf, sb.len) != 0) return 1;
    if (sha256_update(&ctx, exchange_hash, 32) != 0) return 1;
    if (sha256_update(&ctx, &letter, 1) != 0) return 1;
    if (sha256_update(&ctx, session_id, sid_len) != 0) return 1;
    if (sha256_final(hash, &ctx) != 0) return 1;

    /* For 32 bytes or less, one round suffices */
    if (out_len <= 32) {
        memcpy(out, hash, out_len);
    } else {
        /* Need multiple rounds (unlikely for our 32-byte keys) */
        memcpy(out, hash, 32);
    }

    return 0;
}

/* ================================================================
 *  Key exchange (curve25519-sha256)
 *
 *  The inner function returns a detailed sub-hatch (1..12). The outer
 *  wrapper captures that into `g_last_kex_sub_hatch` so a caller whose
 *  ssh_conn_create hit hatch 5 can call `ssh_last_kex_sub_hatch()` to
 *  see whether it was field-parse (5) vs sig-verify (8) etc. Poor-man's
 *  errno — not thread-safe but fine for the current single-caller flow,
 *  and saves changing the public hatch contract. (NOTE: replace with
 *  thread-local or a per-conn field when multi-conn concurrency lands.)
 * ================================================================ */

static unsigned long g_last_kex_sub_hatch = 0;

unsigned long ssh_last_kex_sub_hatch(unsigned long *out);

unsigned long ssh_last_kex_sub_hatch(unsigned long *out) {
    if (!out) return 1;
    *out = g_last_kex_sub_hatch;
    return 0;
}

static unsigned long ssh_key_exchange_impl(ssh_conn *conn);

static unsigned long ssh_key_exchange(ssh_conn *conn) {
    unsigned long rc = ssh_key_exchange_impl(conn);
    g_last_kex_sub_hatch = rc;
    SSH_DBG("KEX: key_exchange returning sub-hatch %lu\n", rc);
    return rc;
}

static unsigned long ssh_key_exchange_impl(ssh_conn *conn) {
    u8 payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf pb;
    x25519_keypair ephemeral;
    u8 shared_secret[X25519_SHARED_LEN];
    u8 exchange_hash[32];
    sha256_ctx hctx;

    /* Saved copies for the exchange-hash computation (RFC 4253 §8).
     * I_C = our KEXINIT payload, I_S = server KEXINIT payload.
     * Must survive the two recv_packet calls that follow — the shared
     * `payload` buffer gets overwritten on the next recv. */
    u8  ic_buf[SSH_MAX_PACKET];  u64 ic_len = 0;
    u8  is_buf[SSH_MAX_PACKET];  u64 is_len = 0;

    /* 1. Send our KEXINIT */
    SSH_DBG("KEX: sending KEXINIT\n");
    pb_init(&pb, payload, sizeof(payload));
    build_kexinit(&pb);
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 1;
    /* Save I_C — the full KEXINIT payload (including the type byte). */
    if (pb.len > sizeof(ic_buf)) return 1;
    memcpy(ic_buf, pb.buf, (size_t)pb.len);
    ic_len = pb.len;

    /* 2. Receive server KEXINIT */
    SSH_DBG("KEX: awaiting server KEXINIT\n");
    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 2;
    if (payload_len < 1 || payload[0] != SSH_MSG_KEXINIT) {
        SSH_DBG("KEX: expected SSH_MSG_KEXINIT(20) got %u\n",
                payload_len >= 1 ? (unsigned)payload[0] : 0);
        return 2;
    }
    /* Save I_S before the next recv clobbers payload. */
    if (payload_len > sizeof(is_buf)) return 2;
    memcpy(is_buf, payload, (size_t)payload_len);
    is_len = payload_len;

    /* 3. Generate ephemeral X25519 keypair */
    if (x25519_keygen(&ephemeral) != 0) return 3;

    /* 4. Send KEX_ECDH_INIT with our public key */
    SSH_DBG("KEX: sending KEX_ECDH_INIT (Q_C len=%d)\n", (int)X25519_KEY_LEN);
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_KEX_ECDH_INIT);
    pb_string(&pb, ephemeral.pub.data, X25519_KEY_LEN);
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 4;

    /* 5. Receive KEX_ECDH_REPLY */
    SSH_DBG("KEX: awaiting KEX_ECDH_REPLY\n");
    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 5;
    if (payload_len >= 1) {
        SSH_DBG("KEX: recv msg_type=%u (expect 31 = KEX_ECDH_REPLY)\n",
                (unsigned)payload[0]);
    }
    {
        pkt_reader pr;
        u8 msg_type;
        const u8 *host_key_blob, *server_pub_raw, *sig_blob;
        u64 hk_len, sp_len, sig_len;
        x25519_pubkey server_pub;

        pr_init(&pr, payload, payload_len);
        if (pr_u8(&pr, &msg_type) != 0 || msg_type != SSH_MSG_KEX_ECDH_REPLY) return 5;

        /* K_S (host key blob) */
        if (pr_string(&pr, &host_key_blob, &hk_len) != 0) return 5;
        /* Q_S (server ephemeral public) */
        if (pr_string(&pr, &server_pub_raw, &sp_len) != 0) return 5;
        if (sp_len != X25519_KEY_LEN) return 5;
        memcpy(server_pub.data, server_pub_raw, X25519_KEY_LEN);
        /* signature */
        if (pr_string(&pr, &sig_blob, &sig_len) != 0) return 5;

        /* 6. Compute shared secret K */
        if (x25519_dh(shared_secret, &ephemeral.priv, &server_pub) != 0) return 6;

        /* 7. Compute exchange hash H per RFC 4253 §8:
         *     H = HASH( string(V_C) || string(V_S) || string(I_C) ||
         *               string(I_S) || string(K_S) || string(Q_C) ||
         *               string(Q_S) || mpint(K) )
         *
         * Every field is length-prefixed as an SSH string; K uses mpint
         * encoding (strip leading zeros, prepend 0x00 if MSB set).
         * The server signs this exact hash, so our computation must match
         * byte-for-byte or sig verification (step 8) fails. */
        SSH_DBG("KEX: computing exchange hash (V_C=%llu V_S=%llu I_C=%llu I_S=%llu K_S=%llu)\n",
                (unsigned long long)conn->client_version_len,
                (unsigned long long)conn->server_version_len,
                (unsigned long long)ic_len,
                (unsigned long long)is_len,
                (unsigned long long)hk_len);
        if (sha256_init(&hctx) != 0) return 7;
        {
            u8 hdr[4];

            put_u32(hdr, (u32)conn->client_version_len);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, conn->client_version, conn->client_version_len) != 0) return 7;

            put_u32(hdr, (u32)conn->server_version_len);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, conn->server_version, conn->server_version_len) != 0) return 7;

            put_u32(hdr, (u32)ic_len);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, ic_buf, ic_len) != 0) return 7;

            put_u32(hdr, (u32)is_len);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, is_buf, is_len) != 0) return 7;

            put_u32(hdr, (u32)hk_len);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, host_key_blob, hk_len) != 0) return 7;

            put_u32(hdr, X25519_KEY_LEN);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, ephemeral.pub.data, X25519_KEY_LEN) != 0) return 7;

            put_u32(hdr, X25519_KEY_LEN);
            if (sha256_update(&hctx, hdr, 4) != 0) return 7;
            if (sha256_update(&hctx, server_pub.data, X25519_KEY_LEN) != 0) return 7;
        }
        /* mpint(K) */
        {
            u8 k_buf[64];
            pkt_buf kb;
            pb_init(&kb, k_buf, sizeof(k_buf));
            pb_mpint(&kb, shared_secret, X25519_SHARED_LEN);
            if (sha256_update(&hctx, kb.buf, kb.len) != 0) return 7;
        }
        if (sha256_final(exchange_hash, &hctx) != 0) return 7;

        /* Session ID = first exchange hash */
        memcpy(conn->session_id, exchange_hash, 32);
        conn->session_id_len = 32;

        if (ssh_dbg_enabled()) {
            u32 i;
            fprintf(stderr, "[apennines_ssh] KEX: exchange_hash H=");
            for (i = 0; i < 32; i++) fprintf(stderr, "%02x", exchange_hash[i]);
            fprintf(stderr, "\n");
            fflush(stderr);
        }

        /* 8. Verify host key signature (Ed25519) */
        SSH_DBG("KEX: parsing host key blob (hk_len=%llu)\n", (unsigned long long)hk_len);
        {
            pkt_reader skr;
            const u8 *key_type_str, *ed_pub_raw;
            u64 kt_len, ep_len;
            ed25519_pubkey host_pub;
            unsigned long valid = 0;

            /* Parse host key blob: string "ssh-ed25519" + string pubkey(32) */
            pr_init(&skr, host_key_blob, hk_len);
            if (pr_string(&skr, &key_type_str, &kt_len) != 0) {
                SSH_DBG("KEX: host key kt parse failed\n");
                return 5;
            }
            SSH_DBG("KEX: host key kt='%.*s' (len=%llu)\n",
                    (int)kt_len, (const char *)key_type_str,
                    (unsigned long long)kt_len);

            if (pr_string(&skr, &ed_pub_raw, &ep_len) != 0) {
                SSH_DBG("KEX: host key pub parse failed\n");
                return 5;
            }
            if (ep_len != ED25519_PUBKEY_LEN) {
                SSH_DBG("KEX: host key pub_len=%llu (expect 32)\n",
                        (unsigned long long)ep_len);
                return 5;
            }
            memcpy(host_pub.data, ed_pub_raw, ED25519_PUBKEY_LEN);

            if (ssh_dbg_enabled()) {
                u32 i;
                fprintf(stderr, "[apennines_ssh] KEX: host pub=");
                for (i = 0; i < 32; i++) fprintf(stderr, "%02x", host_pub.data[i]);
                fprintf(stderr, "\n");
                fflush(stderr);
            }

            /* Parse signature blob: string "ssh-ed25519" + string sig(64) */
            SSH_DBG("KEX: parsing sig blob (sig_len=%llu)\n", (unsigned long long)sig_len);
            {
                pkt_reader sigr;
                const u8 *sig_type_str, *sig_raw;
                u64 st_len, sr_len;

                pr_init(&sigr, sig_blob, sig_len);
                if (pr_string(&sigr, &sig_type_str, &st_len) != 0) {
                    SSH_DBG("KEX: sig kt parse failed\n");
                    return 5;
                }
                SSH_DBG("KEX: sig kt='%.*s' (len=%llu)\n",
                        (int)st_len, (const char *)sig_type_str,
                        (unsigned long long)st_len);

                if (pr_string(&sigr, &sig_raw, &sr_len) != 0) {
                    SSH_DBG("KEX: sig raw parse failed\n");
                    return 5;
                }
                if (sr_len != ED25519_SIG_LEN) {
                    SSH_DBG("KEX: sig raw_len=%llu (expect 64)\n",
                            (unsigned long long)sr_len);
                    return 5;
                }

                if (ssh_dbg_enabled()) {
                    u32 i;
                    fprintf(stderr, "[apennines_ssh] KEX: sig_raw=");
                    for (i = 0; i < 64; i++) fprintf(stderr, "%02x", sig_raw[i]);
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }

                {
                    unsigned long vrc = ed25519_verify(&valid, &host_pub, sig_raw,
                                                       exchange_hash, 32);
                    SSH_DBG("KEX: ed25519_verify rc=%lu valid=%lu\n", vrc, valid);
                    if (vrc != 0) return 8;
                    if (!valid)   return 8;
                }

                /* Host-key verifier hook. Runs here — after sig verify
                 * confirms the server owns K_S, but BEFORE we derive
                 * transport keys or send NEWKEYS. A rejection aborts
                 * the handshake with no encrypted data leaked. */
                if (conn->verifier_fn) {
                    unsigned long vok = conn->verifier_fn(conn->verifier_ctx,
                                                           conn->verify_host,
                                                           conn->verify_port,
                                                           host_key_blob,
                                                           hk_len);
                    SSH_DBG("KEX: hostkey_verifier rc=%lu\n", vok);
                    if (vok != 0) return 8;
                }
            }
        }
    }

    /* 9. Derive transport keys (RFC 4253 s7.2):
     *    A = IV c2s, B = IV s2c, C = enc c2s, D = enc s2c, E = mac c2s, F = mac s2c */
    if (derive_key(conn->iv_c2s,      12, shared_secret, X25519_SHARED_LEN,
                   exchange_hash, 'A', conn->session_id, conn->session_id_len) != 0) return 9;
    if (derive_key(conn->iv_s2c,      12, shared_secret, X25519_SHARED_LEN,
                   exchange_hash, 'B', conn->session_id, conn->session_id_len) != 0) return 9;
    if (derive_key(conn->enc_key_c2s, 32, shared_secret, X25519_SHARED_LEN,
                   exchange_hash, 'C', conn->session_id, conn->session_id_len) != 0) return 9;
    if (derive_key(conn->enc_key_s2c, 32, shared_secret, X25519_SHARED_LEN,
                   exchange_hash, 'D', conn->session_id, conn->session_id_len) != 0) return 9;
    if (derive_key(conn->mac_key_c2s, 32, shared_secret, X25519_SHARED_LEN,
                   exchange_hash, 'E', conn->session_id, conn->session_id_len) != 0) return 9;
    if (derive_key(conn->mac_key_s2c, 32, shared_secret, X25519_SHARED_LEN,
                   exchange_hash, 'F', conn->session_id, conn->session_id_len) != 0) return 9;

    /* 10. Send NEWKEYS */
    {
        u8 nk = SSH_MSG_NEWKEYS;
        if (ssh_send_packet(conn, &nk, 1) != 0) return 10;
    }

    /* 11. Receive NEWKEYS */
    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 11;
    if (payload_len < 1 || payload[0] != SSH_MSG_NEWKEYS) return 11;

    /* 12. Initialize AES-256-GCM contexts and switch to encrypted mode */
    if (aes256_init(&conn->aes_c2s, conn->enc_key_c2s) != 0) return 12;
    if (aes256_init(&conn->aes_s2c, conn->enc_key_s2c) != 0) return 12;

    /* Seed AES-GCM invocation counters from iv[4..11] per RFC 5647 §7.1.
     * These increment per packet; nonce = iv[0..3] || BE64(counter). */
    conn->gcm_ctr_c2s = get_u64(conn->iv_c2s + 4);
    conn->gcm_ctr_s2c = get_u64(conn->iv_s2c + 4);
    SSH_DBG("KEX: gcm counters seeded c2s=%llu s2c=%llu (fixed c2s=%02x%02x%02x%02x s2c=%02x%02x%02x%02x)\n",
            (unsigned long long)conn->gcm_ctr_c2s,
            (unsigned long long)conn->gcm_ctr_s2c,
            conn->iv_c2s[0], conn->iv_c2s[1], conn->iv_c2s[2], conn->iv_c2s[3],
            conn->iv_s2c[0], conn->iv_s2c[1], conn->iv_s2c[2], conn->iv_s2c[3]);

    conn->encrypted = 1;

    /* Scrub shared secret from stack */
    memset(shared_secret, 0, sizeof(shared_secret));

    return 0;
}

/* ================================================================
 *  ssh_conn_create
 * ================================================================ */

unsigned long ssh_conn_create_ex(ssh_conn **out,
                                                const char *host, u16 port,
                                                ssh_hostkey_verifier_fn verifier,
                                                void *verifier_ctx) {
    ssh_conn *conn;
    net_sock_addr addr;
    unsigned long rc;

    if (!out)  return 1;
    if (!host) return 2;

    conn = (ssh_conn *)calloc(1, sizeof(ssh_conn));
    if (!conn) return 6;

    /* Stash verifier + host/port for the KEX hook. Host is copied (the
     * caller's string could be freed before KEX runs — unlikely in
     * practice but the copy is cheap and the rule is clear). */
    conn->verifier_fn  = verifier;
    conn->verifier_ctx = verifier_ctx;
    strncpy(conn->verify_host, host, sizeof(conn->verify_host) - 1);
    conn->verify_host[sizeof(conn->verify_host) - 1] = '\0';
    conn->verify_port = port;

    /* Resolve host to an IP and connect via TCP. addr_sockaddr_create only
     * accepts literal IPv4/IPv6, so if that fails (hostname was passed),
     * fall back to addr_resolve and use the first address. This lets
     * callers hand us "github.com" directly instead of pre-resolving. */
    rc = addr_sockaddr_create(&addr, host, port);
    if (rc != 0) {
        ipv4_addr *ips = NULL;
        u64 n_ips = 0;
        char ip_str[64];  /* enough for IPv4 ("255.255.255.255") + slack */

        SSH_DBG("host %s is not an IP literal, resolving via DNS\n", host);
        if (addr_resolve(&ips, &n_ips, host) != 0 || n_ips == 0) {
            free(ips);
            free(conn);
            return 3;
        }
        if (addr_ipv4_format(ip_str, sizeof(ip_str), &ips[0]) != 0) {
            free(ips);
            free(conn);
            return 3;
        }
        free(ips);
        SSH_DBG("resolved %s -> %s\n", host, ip_str);
        if (addr_sockaddr_create(&addr, ip_str, port) != 0) {
            free(conn);
            return 3;
        }
    }

    rc = tcp_conn_create(&conn->tcp, &addr);
    if (rc != 0) { free(conn); return 3; }

    conn->connected = 1;

    /* Version exchange */
    rc = ssh_version_exchange(conn);
    if (rc != 0) {
        tcp_conn_destroy(&conn->tcp);
        free(conn);
        return 4;
    }

    /* Key exchange (invokes the host-key verifier internally if set) */
    rc = ssh_key_exchange(conn);
    if (rc != 0) {
        tcp_conn_destroy(&conn->tcp);
        free(conn);
        return 5;
    }

    /* Allocate channel table */
    conn->channel_cap = 8;
    conn->channels = (ssh_channel **)calloc(conn->channel_cap, sizeof(ssh_channel *));
    if (!conn->channels) {
        tcp_conn_destroy(&conn->tcp);
        free(conn);
        return 6;
    }

    *out = conn;
    return 0;
}

unsigned long ssh_conn_create(ssh_conn **out,
                                             const char *host, u16 port) {
    return ssh_conn_create_ex(out, host, port, NULL, NULL);
}

/* ================================================================
 *  Userauth service negotiation (RFC 4253 §10).
 *
 *  Between the end of KEX and the start of any USERAUTH_REQUEST, the
 *  client MUST send SSH_MSG_SERVICE_REQUEST with service name
 *  "ssh-userauth", and wait for SSH_MSG_SERVICE_ACCEPT. Without this,
 *  some servers (notably github.com's babeld) silently drop or buffer
 *  USERAUTH_REQUEST messages and the client hangs forever.
 *
 *  Once per connection. `conn->service_accepted` short-circuits the
 *  second caller so multiple auth method attempts don't re-negotiate.
 * ================================================================ */

static unsigned long ssh_request_userauth_service(ssh_conn *conn) {
    u8  payload[256];
    u64 payload_len;
    pkt_buf pb;

    if (conn->service_accepted) {
        SSH_DBG("userauth: service already accepted, skipping\n");
        return 0;
    }

    SSH_DBG("userauth: requesting ssh-userauth service\n");
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_SERVICE_REQUEST);
    pb_cstring(&pb, "ssh-userauth");
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 1;

    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 2;
    if (payload_len < 1 || payload[0] != SSH_MSG_SERVICE_ACCEPT) {
        SSH_DBG("userauth: expected SERVICE_ACCEPT(6) got %u\n",
                payload_len >= 1 ? (unsigned)payload[0] : 0);
        return 3;
    }
    SSH_DBG("userauth: service accepted\n");
    conn->service_accepted = 1;
    return 0;
}

/* ================================================================
 *  ssh_conn_auth_password
 * ================================================================ */

unsigned long ssh_conn_auth_password(ssh_conn *conn,
                                                    const char *username,
                                                    const char *password) {
    u8 payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf pb;

    if (!conn)     return 1;
    if (!username) return 2;
    if (!password) return 3;

    /* RFC 4253 §10 — negotiate ssh-userauth service before any
     * USERAUTH_REQUEST. Idempotent via conn->service_accepted flag. */
    if (ssh_request_userauth_service(conn) != 0) return 5;

    SSH_DBG("userauth: sending USERAUTH_REQUEST method=password user=%s\n", username);

    /* Build SSH_MSG_USERAUTH_REQUEST (password) */
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_USERAUTH_REQUEST);
    pb_cstring(&pb, username);
    pb_cstring(&pb, "ssh-connection");   /* service name */
    pb_cstring(&pb, "password");
    pb_bool(&pb, 0);                     /* FALSE = no old password */
    pb_cstring(&pb, password);

    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 5;

    /* Receive response */
    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 5;
    if (payload_len < 1) return 5;
    SSH_DBG("userauth: recv msg_type=%u\n", (unsigned)payload[0]);

    if (payload[0] == SSH_MSG_USERAUTH_SUCCESS) return 0;
    if (payload[0] == SSH_MSG_USERAUTH_FAILURE) return 4;

    return 5;
}

/* ================================================================
 *  ssh_conn_auth_pubkey
 * ================================================================ */

unsigned long ssh_conn_auth_pubkey(ssh_conn *conn,
                                                  const char *username,
                                                  const u8 *privkey, u64 privkey_len) {
    u8 payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf pb;
    ed25519_privkey epriv;
    ed25519_pubkey epub;
    u8 pubkey_blob[SSH_MAX_PACKET];
    pkt_buf pkb;
    u8 sig_data[SSH_MAX_PACKET];
    pkt_buf sdb;
    u8 sig[ED25519_SIG_LEN];
    u8 sig_blob[SSH_MAX_PACKET];
    pkt_buf sgb;

    if (!conn)    return 1;
    if (!username) return 2;
    if (!privkey)  return 3;
    /* Accept either 32-byte raw seed (we expand internally) or 64-byte
     * pre-expanded ed25519 private key. Most users have raw seeds from
     * OpenSSH-format private keys; making them call ed25519_keygen_from_seed
     * first was a needless integration step. */
    if (privkey_len != ED25519_SEED_LEN &&
        privkey_len != ED25519_PRIVKEY_LEN) return 3;

    /* RFC 4253 §10 — ssh-userauth service negotiation. */
    if (ssh_request_userauth_service(conn) != 0) return 6;

    if (privkey_len == ED25519_SEED_LEN) {
        ed25519_seed    seed;
        ed25519_keypair kp;
        memcpy(seed.data, privkey, ED25519_SEED_LEN);
        if (ed25519_keygen_from_seed(&kp, &seed) != 0) {
            memset(seed.data, 0, ED25519_SEED_LEN);
            return 5;
        }
        memcpy(epriv.data, kp.priv.data, ED25519_PRIVKEY_LEN);
        memcpy(epub.data,  kp.pub.data,  ED25519_PUBKEY_LEN);
        memset(seed.data, 0, ED25519_SEED_LEN);
        memset(&kp, 0, sizeof(kp));
    } else {
        memcpy(epriv.data, privkey, ED25519_PRIVKEY_LEN);
        if (ed25519_pubkey_from_privkey(&epub, &epriv) != 0) return 5;
    }

    /* Build public key blob: "ssh-ed25519" + raw pubkey */
    pb_init(&pkb, pubkey_blob, sizeof(pubkey_blob));
    pb_cstring(&pkb, "ssh-ed25519");
    pb_string(&pkb, epub.data, ED25519_PUBKEY_LEN);

    /* Build data to sign: session_id + USERAUTH_REQUEST message */
    pb_init(&sdb, sig_data, sizeof(sig_data));
    pb_string(&sdb, conn->session_id, conn->session_id_len);
    pb_u8(&sdb, SSH_MSG_USERAUTH_REQUEST);
    pb_cstring(&sdb, username);
    pb_cstring(&sdb, "ssh-connection");
    pb_cstring(&sdb, "publickey");
    pb_bool(&sdb, 1);   /* TRUE = real authentication */
    pb_cstring(&sdb, "ssh-ed25519");
    pb_string(&sdb, pkb.buf, pkb.len);

    /* Sign */
    if (ed25519_sign(sig, &epriv, &epub, sdb.buf, sdb.len) != 0) return 5;

    /* Build signature blob: "ssh-ed25519" + raw signature */
    pb_init(&sgb, sig_blob, sizeof(sig_blob));
    pb_cstring(&sgb, "ssh-ed25519");
    pb_string(&sgb, sig, ED25519_SIG_LEN);

    /* Build the actual packet */
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_USERAUTH_REQUEST);
    pb_cstring(&pb, username);
    pb_cstring(&pb, "ssh-connection");
    pb_cstring(&pb, "publickey");
    pb_bool(&pb, 1);
    pb_cstring(&pb, "ssh-ed25519");
    pb_string(&pb, pkb.buf, pkb.len);
    pb_string(&pb, sgb.buf, sgb.len);

    SSH_DBG("userauth: sending USERAUTH_REQUEST method=publickey user=%s\n", username);
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 6;

    /* Receive response */
    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 6;
    if (payload_len < 1) return 6;
    SSH_DBG("userauth: recv msg_type=%u\n", (unsigned)payload[0]);

    if (payload[0] == SSH_MSG_USERAUTH_SUCCESS) {
        memset(epriv.data, 0, ED25519_PRIVKEY_LEN);
        memset(sig, 0, ED25519_SIG_LEN);
        return 0;
    }
    if (payload[0] == SSH_MSG_USERAUTH_FAILURE) {
        memset(epriv.data, 0, ED25519_PRIVKEY_LEN);
        memset(sig, 0, ED25519_SIG_LEN);
        return 4;
    }

    /* Scrub private key material */
    memset(epriv.data, 0, ED25519_PRIVKEY_LEN);
    memset(sig, 0, ED25519_SIG_LEN);

    return 6;
}

/* ================================================================
 *  ssh-agent client (RFC-draft-miller-ssh-agent / OpenSSH PROTOCOL.agent)
 *
 *  Needed because real-world users keep their `~/.ssh/id_ed25519`
 *  passphrase-encrypted (aes256-ctr + bcrypt-pbkdf). We can't
 *  practically decrypt it without implementing OpenSSH's KDF; the
 *  canonical solution is to delegate signing to the running ssh-agent,
 *  which holds the decrypted key in memory for the session. Gut's
 *  `git clone git@github.com:...` flow requires this.
 *
 *  Transport endpoint:
 *    POSIX:   Unix domain socket at $SSH_AUTH_SOCK
 *    Windows: named pipe \\.\pipe\openssh-ssh-agent
 *
 *  Wire format: u32 big-endian length prefix + body.
 *  Messages used here:
 *    SSH_AGENTC_REQUEST_IDENTITIES  (11)  — list keys
 *    SSH_AGENT_IDENTITIES_ANSWER    (12)  — reply: u32 nkeys + per key
 *                                           (string pubkey_blob, string comment)
 *    SSH_AGENTC_SIGN_REQUEST        (13)  — ask agent to sign
 *                                           (string pubkey_blob, string data, u32 flags)
 *    SSH_AGENT_SIGN_RESPONSE        (14)  — reply: string sig_blob
 *    SSH_AGENT_FAILURE              (5)
 * ================================================================ */

#define SSH_AGENTC_REQUEST_IDENTITIES  11
#define SSH_AGENT_IDENTITIES_ANSWER    12
#define SSH_AGENTC_SIGN_REQUEST        13
#define SSH_AGENT_SIGN_RESPONSE        14
#define SSH_AGENT_FAILURE               5

typedef struct {
#ifdef _WIN32
    HANDLE   pipe;
    int      is_pipe;   /* 1 on Windows when using named pipe */
    uds_conn uds;       /* fallback on Windows 10+ if SSH_AUTH_SOCK is set */
#else
    uds_conn uds;
#endif
    int      opened;
} ssh_agent_conn;

static unsigned long agent_open(ssh_agent_conn *a) {
    const char *sock;

    memset(a, 0, sizeof(*a));

    /* Prefer SSH_AUTH_SOCK if the env var is set (works on both POSIX
     * and Windows 10+ when the agent is exposed via AF_UNIX). */
    sock = getenv("SSH_AUTH_SOCK");
    if (sock && *sock) {
        if (uds_conn_create(&a->uds, sock) == 0) {
            a->opened = 1;
            return 0;
        }
        /* fall through to named-pipe on Windows */
    }

#ifdef _WIN32
    /* Windows: OpenSSH-for-Windows exposes the agent at
     * \\.\pipe\openssh-ssh-agent. CreateFileA + ReadFile/WriteFile
     * treat it as a message-mode pipe. */
    {
        HANDLE h = CreateFileA(
            "\\\\.\\pipe\\openssh-ssh-agent",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (h != INVALID_HANDLE_VALUE) {
            a->pipe    = h;
            a->is_pipe = 1;
            a->opened  = 1;
            return 0;
        }
    }
#endif

    return 1;
}

static unsigned long agent_write_all(ssh_agent_conn *a, const u8 *buf, u64 len) {
#ifdef _WIN32
    if (a->is_pipe) {
        u64 total = 0;
        while (total < len) {
            DWORD written = 0;
            DWORD chunk = (DWORD)(len - total > 0x40000000u ? 0x40000000u : len - total);
            if (!WriteFile(a->pipe, buf + total, chunk, &written, NULL)) return 1;
            if (written == 0) return 1;
            total += written;
        }
        return 0;
    }
#endif
    {
        u64 written = 0;
        return uds_conn_write_all(&written, &a->uds, buf, len);
    }
}

static unsigned long agent_read_exact(ssh_agent_conn *a, u8 *buf, u64 len) {
    u64 total = 0;
    while (total < len) {
#ifdef _WIN32
        if (a->is_pipe) {
            DWORD got = 0;
            DWORD chunk = (DWORD)(len - total > 0x40000000u ? 0x40000000u : len - total);
            if (!ReadFile(a->pipe, buf + total, chunk, &got, NULL)) return 1;
            if (got == 0) return 1;
            total += got;
            continue;
        }
#endif
        {
            u64 got = 0;
            if (uds_conn_read(&got, &a->uds, buf + total, len - total) != 0) return 1;
            if (got == 0) return 1;
            total += got;
        }
    }
    return 0;
}

static void agent_close(ssh_agent_conn *a) {
    if (!a->opened) return;
#ifdef _WIN32
    if (a->is_pipe) {
        if (a->pipe != INVALID_HANDLE_VALUE) CloseHandle(a->pipe);
        a->pipe = INVALID_HANDLE_VALUE;
        a->is_pipe = 0;
        a->opened = 0;
        return;
    }
#endif
    uds_conn_destroy(&a->uds);
    a->opened = 0;
}

/* Send one agent request: u32 length + u8 type + body. */
static unsigned long agent_send(ssh_agent_conn *a, u8 type,
                                const u8 *body, u64 body_len) {
    u8 hdr[5];
    u32 total_len = (u32)(1 + body_len);
    put_u32(hdr, total_len);
    hdr[4] = type;
    if (agent_write_all(a, hdr, 5) != 0) return 1;
    if (body_len > 0) {
        if (agent_write_all(a, body, body_len) != 0) return 1;
    }
    return 0;
}

/* Read one agent reply. Caller supplies a buffer; on success *out_len
 * is the reply body length (excluding the length prefix, excluding the
 * leading type byte — out[0] is the type byte, out[1..*out_len] is the
 * body proper). Returns 0 on success. */
static unsigned long agent_recv(ssh_agent_conn *a, u8 *out, u64 cap, u64 *out_len) {
    u8 lenbuf[4];
    u32 mlen;

    if (agent_read_exact(a, lenbuf, 4) != 0) return 1;
    mlen = get_u32(lenbuf);
    if (mlen == 0 || mlen > cap) return 2;
    if (agent_read_exact(a, out, mlen) != 0) return 1;
    *out_len = mlen;
    return 0;
}

/* Pick the first ed25519 identity from an IDENTITIES_ANSWER reply.
 * On success, *pub_out receives a pointer into `reply` to the 32-byte
 * public key, and the full pubkey_blob (for the SIGN_REQUEST) is copied
 * into blob_out/blob_out_len. Returns 0 on success, non-zero if no
 * ed25519 key is present. */
static unsigned long agent_pick_ed25519(const u8 *reply, u64 reply_len,
                                         u8 *blob_out, u64 blob_cap,
                                         u64 *blob_out_len,
                                         const u8 **pub_out) {
    pkt_reader pr;
    u8         msg_type;
    u32        nkeys, i;

    pr_init(&pr, reply, reply_len);
    if (pr_u8(&pr, &msg_type) != 0)      return 1;
    if (msg_type != SSH_AGENT_IDENTITIES_ANSWER) return 1;
    if (pr_u32(&pr, &nkeys) != 0)        return 1;

    for (i = 0; i < nkeys; i++) {
        const u8 *blob, *comment;
        u64       blob_len, comment_len;
        pkt_reader inner;
        const u8 *keytype, *pub;
        u64       keytype_len, pub_len;

        if (pr_string(&pr, &blob, &blob_len) != 0)      return 1;
        if (pr_string(&pr, &comment, &comment_len) != 0) return 1;
        (void)comment;

        /* Parse the pubkey blob: string(keytype) + string(pubkey_data) */
        pr_init(&inner, blob, blob_len);
        if (pr_string(&inner, &keytype, &keytype_len) != 0) continue;
        if (pr_string(&inner, &pub,     &pub_len)     != 0) continue;

        if (keytype_len == 11 && memcmp(keytype, "ssh-ed25519", 11) == 0
            && pub_len == 32) {
            if (blob_len > blob_cap) return 2;
            memcpy(blob_out, blob, blob_len);
            *blob_out_len = blob_len;
            *pub_out = blob + 4 + 11 + 4;  /* skip keytype string + len-prefix of pubkey */
            (void)pub;  /* alternatively *pub_out = pub; but `pub` refs inner reader */
            *pub_out = pub;
            return 0;
        }
    }
    return 3;
}

unsigned long ssh_conn_auth_agent(ssh_conn *conn,
                                                 const char *username) {
    ssh_agent_conn agent;
    u8  reply[4096];
    u64 reply_len;
    u8  pubkey_blob[512];
    u64 pubkey_blob_len;
    const u8 *pub_raw = NULL;
    u8  sig_data[SSH_MAX_PACKET];
    pkt_buf  sdb;
    u8  sign_req[1024];
    pkt_buf  srb;
    u8  sign_reply[1024];
    u64 sign_reply_len;
    pkt_reader pr;
    u8  sr_type;
    const u8 *sig_blob;
    u64 sig_blob_len;
    u8  payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf  pb;
    unsigned long rc;

    if (!conn)     return 1;
    if (!username) return 2;

    /* RFC 4253 §10 — ssh-userauth service negotiation. Must happen
     * before any USERAUTH_REQUEST regardless of auth method. */
    if (ssh_request_userauth_service(conn) != 0) return 6;

    if (agent_open(&agent) != 0) return 3;

    /* 1. Request identities. Body is empty. */
    if (agent_send(&agent, SSH_AGENTC_REQUEST_IDENTITIES, NULL, 0) != 0) {
        agent_close(&agent); return 3;
    }

    if (agent_recv(&agent, reply, sizeof(reply), &reply_len) != 0) {
        agent_close(&agent); return 3;
    }

    if (agent_pick_ed25519(reply, reply_len,
                            pubkey_blob, sizeof(pubkey_blob),
                            &pubkey_blob_len, &pub_raw) != 0) {
        agent_close(&agent); return 4;
    }

    /* 2. Build the userauth data-to-sign blob, identical to the shape
     *    ssh_conn_auth_pubkey constructs. Agent signs this blob. */
    pb_init(&sdb, sig_data, sizeof(sig_data));
    pb_string(&sdb, conn->session_id, conn->session_id_len);
    pb_u8(&sdb, SSH_MSG_USERAUTH_REQUEST);
    pb_cstring(&sdb, username);
    pb_cstring(&sdb, "ssh-connection");
    pb_cstring(&sdb, "publickey");
    pb_bool(&sdb, 1);  /* TRUE: real auth, not just probe */
    pb_cstring(&sdb, "ssh-ed25519");
    pb_string(&sdb, pubkey_blob, pubkey_blob_len);

    /* 3. Ask the agent to sign. SIGN_REQUEST body:
     *      string pubkey_blob, string data, u32 flags */
    pb_init(&srb, sign_req, sizeof(sign_req));
    pb_string(&srb, pubkey_blob, pubkey_blob_len);
    pb_string(&srb, sdb.buf, sdb.len);
    pb_u32(&srb, 0);   /* flags=0 — no SHA-2 preference for ed25519 */

    if (agent_send(&agent, SSH_AGENTC_SIGN_REQUEST, srb.buf, srb.len) != 0) {
        agent_close(&agent); return 5;
    }

    if (agent_recv(&agent, sign_reply, sizeof(sign_reply), &sign_reply_len) != 0) {
        agent_close(&agent); return 5;
    }
    agent_close(&agent);

    pr_init(&pr, sign_reply, sign_reply_len);
    if (pr_u8(&pr, &sr_type) != 0)             return 5;
    if (sr_type == SSH_AGENT_FAILURE)          return 5;
    if (sr_type != SSH_AGENT_SIGN_RESPONSE)    return 5;
    if (pr_string(&pr, &sig_blob, &sig_blob_len) != 0) return 5;

    /* 4. Assemble the userauth request packet with the agent's signature.
     *    Server accepts this exactly like any other ssh-ed25519 sig. */
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_USERAUTH_REQUEST);
    pb_cstring(&pb, username);
    pb_cstring(&pb, "ssh-connection");
    pb_cstring(&pb, "publickey");
    pb_bool(&pb, 1);
    pb_cstring(&pb, "ssh-ed25519");
    pb_string(&pb, pubkey_blob, pubkey_blob_len);
    pb_string(&pb, sig_blob, sig_blob_len);

    SSH_DBG("userauth: sending USERAUTH_REQUEST method=publickey (agent-signed) user=%s\n", username);
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 6;

    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) return 6;
    if (payload_len < 1) return 6;
    SSH_DBG("userauth: recv msg_type=%u\n", (unsigned)payload[0]);

    if (payload[0] == SSH_MSG_USERAUTH_SUCCESS) { rc = 0; }
    else if (payload[0] == SSH_MSG_USERAUTH_FAILURE) { rc = 6; }
    else { rc = 6; }

    /* pub_raw is only used to suppress an unused-variable warning in
     * case future callers want the raw pubkey bytes. */
    (void)pub_raw;

    return rc;
}

/* ================================================================
 *  ssh_conn_open_channel
 * ================================================================ */

static unsigned long ssh_add_channel(ssh_conn *conn, ssh_channel *ch) {
    if (conn->channel_count >= conn->channel_cap) {
        u64 new_cap = conn->channel_cap * 2;
        ssh_channel **new_arr = (ssh_channel **)realloc(
            conn->channels, new_cap * sizeof(ssh_channel *));
        if (!new_arr) return 1;
        conn->channels = new_arr;
        conn->channel_cap = new_cap;
    }
    conn->channels[conn->channel_count++] = ch;
    return 0;
}

unsigned long ssh_conn_open_channel(ssh_channel **out,
                                                   ssh_conn *conn) {
    u8 payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf pb;
    ssh_channel *ch;

    if (!out)  return 1;
    if (!conn) return 2;

    ch = (ssh_channel *)calloc(1, sizeof(ssh_channel));
    if (!ch) return 4;

    ch->local_id = conn->next_channel_id++;
    ch->conn = conn;

    /* Build CHANNEL_OPEN */
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_CHANNEL_OPEN);
    pb_cstring(&pb, "session");
    pb_u32(&pb, ch->local_id);
    pb_u32(&pb, SSH_INITIAL_WINDOW);
    pb_u32(&pb, SSH_MAX_PACKET_SIZE);

    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) {
        free(ch);
        return 3;
    }

    /* Receive CHANNEL_OPEN_CONFIRMATION or FAILURE */
    if (ssh_recv_packet_filtered(conn, payload, sizeof(payload), &payload_len) != 0) {
        free(ch);
        return 3;
    }

    if (payload_len < 1) { free(ch); return 3; }

    if (payload[0] == SSH_MSG_CHANNEL_OPEN_CONFIRM) {
        pkt_reader pr;
        u8 msg_type;
        u32 recipient, sender, window, max_pkt;

        pr_init(&pr, payload, payload_len);
        if (pr_u8(&pr, &msg_type) != 0)    { free(ch); return 3; }
        if (pr_u32(&pr, &recipient) != 0)   { free(ch); return 3; }
        if (pr_u32(&pr, &sender) != 0)      { free(ch); return 3; }
        if (pr_u32(&pr, &window) != 0)      { free(ch); return 3; }
        if (pr_u32(&pr, &max_pkt) != 0)     { free(ch); return 3; }

        ch->remote_id = sender;
        ch->remote_window = window;
        ch->closed = 0;

        /* Allocate receive buffer */
        ch->recv_cap = 4096;
        ch->recv_buf = (u8 *)malloc(ch->recv_cap);
        if (!ch->recv_buf) { free(ch); return 4; }
        ch->recv_len = 0;

        if (ssh_add_channel(conn, ch) != 0) {
            free(ch->recv_buf);
            free(ch);
            return 4;
        }

        *out = ch;
        return 0;
    }

    if (payload[0] == SSH_MSG_CHANNEL_OPEN_FAIL) {
        free(ch);
        return 3;
    }

    free(ch);
    return 3;
}

/* ================================================================
 *  ssh_channel_write
 * ================================================================ */

unsigned long ssh_channel_write(u64 *bytes_written, ssh_channel *ch,
                                               const u8 *data, u64 len) {
    u8 payload[SSH_MAX_PACKET];
    pkt_buf pb;
    u64 total = 0;

    if (!bytes_written) return 1;
    if (!ch)            return 2;
    if (!data && len)   return 3;
    if (ch->closed)     return 4;

    *bytes_written = 0;

    while (total < len) {
        u64 chunk = len - total;

        /* Respect remote window */
        if (ch->remote_window == 0) {
            /* Wait for WINDOW_ADJUST — try reading one packet */
            u8 rxbuf[SSH_MAX_PACKET];
            u64 rxlen;
            if (ssh_recv_packet_filtered(ch->conn, rxbuf, sizeof(rxbuf), &rxlen) != 0) return 5;
            if (rxlen >= 9 && rxbuf[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
                u32 adjust = get_u32(rxbuf + 5);
                ch->remote_window += adjust;
            }
            continue;
        }

        if (chunk > ch->remote_window) chunk = ch->remote_window;
        if (chunk > SSH_MAX_PACKET_SIZE - 9) chunk = SSH_MAX_PACKET_SIZE - 9;

        pb_init(&pb, payload, sizeof(payload));
        pb_u8(&pb, SSH_MSG_CHANNEL_DATA);
        pb_u32(&pb, ch->remote_id);
        pb_string(&pb, data + total, chunk);

        if (ssh_send_packet(ch->conn, pb.buf, pb.len) != 0) {
            *bytes_written = total;
            return 5;
        }

        ch->remote_window -= (u32)chunk;
        total += chunk;
    }

    *bytes_written = total;
    return 0;
}

/* ================================================================
 *  ssh_channel_read
 * ================================================================ */

/* Dispatch a received packet to the appropriate channel buffer. */
static void ssh_dispatch_channel_packet(ssh_conn *conn, const u8 *payload, u64 payload_len) {
    u8 msg_type;
    u32 ch_id;
    u64 i;
    ssh_channel *ch = NULL;

    if (payload_len < 5) return;
    msg_type = payload[0];
    ch_id = get_u32(payload + 1);

    /* Find the channel */
    for (i = 0; i < conn->channel_count; i++) {
        if (conn->channels[i]->local_id == ch_id) {
            ch = conn->channels[i];
            break;
        }
    }
    if (!ch) return;

    if (msg_type == SSH_MSG_CHANNEL_DATA && payload_len >= 9) {
        u32 data_len = get_u32(payload + 5);
        const u8 *data_ptr = payload + 9;

        if (9 + (u64)data_len > payload_len) return;

        /* Grow buffer if needed */
        while (ch->recv_len + data_len > ch->recv_cap) {
            u64 new_cap = ch->recv_cap * 2;
            u8 *new_buf = (u8 *)realloc(ch->recv_buf, new_cap);
            if (!new_buf) return;
            ch->recv_buf = new_buf;
            ch->recv_cap = new_cap;
        }
        memcpy(ch->recv_buf + ch->recv_len, data_ptr, data_len);
        ch->recv_len += data_len;
    } else if (msg_type == SSH_MSG_CHANNEL_EXTENDED_DATA && payload_len >= 13) {
        /* RFC 4254 §5.2: byte msg_type || u32 channel || u32 data_type_code
         * || string data. data_type_code=1 is SSH_EXTENDED_DATA_STDERR.
         * We only route stderr to the err ring; other data_type_codes are
         * undefined for session channels and we drop them. */
        u32 type_code = get_u32(payload + 5);
        u32 data_len  = get_u32(payload + 9);
        const u8 *data_ptr = payload + 13;

        if (13 + (u64)data_len > payload_len) return;

        if (ssh_dbg_enabled()) {
            /* Surface the first 256 bytes of stderr inline so consumers
             * without an ssh_channel_read_stderr call still see errors in
             * diagnostic traces. Primary reason this was added: gut's
             * clone was getting 7 bytes of stderr from git-upload-pack
             * and silently dropping them, producing "empty repository"
             * instead of the real error. */
            u32 n = data_len > 256 ? 256 : data_len;
            fprintf(stderr,
                    "[apennines_ssh] CHANNEL_EXTENDED_DATA ch=%u type=%u len=%u data=<%.*s>\n",
                    ch_id, type_code, data_len, (int)n, (const char *)data_ptr);
            fflush(stderr);
        }

        if (type_code == 1 /* SSH_EXTENDED_DATA_STDERR */) {
            u64 needed = ch->err_recv_len + data_len;
            if (needed > ch->err_recv_cap) {
                u64 new_cap = ch->err_recv_cap > 0 ? ch->err_recv_cap : 256;
                while (new_cap < needed) new_cap *= 2;
                {
                    u8 *new_buf = (u8 *)realloc(ch->err_recv_buf, new_cap);
                    if (!new_buf) return;
                    ch->err_recv_buf = new_buf;
                    ch->err_recv_cap = new_cap;
                }
            }
            memcpy(ch->err_recv_buf + ch->err_recv_len, data_ptr, data_len);
            ch->err_recv_len += data_len;
        }
        /* NOTE: do NOT set ch->closed here — extended_data is just
         * out-of-band bytes, not a channel-state change. */
    } else if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST && payload_len >= 9) {
        u32 adjust = get_u32(payload + 5);
        ch->remote_window += adjust;
    } else if (msg_type == SSH_MSG_CHANNEL_EOF || msg_type == SSH_MSG_CHANNEL_CLOSE) {
        ch->closed = 1;
    }
}

unsigned long ssh_channel_read(u64 *bytes_read, ssh_channel *ch,
                                              u8 *buf, u64 len) {
    if (!bytes_read) return 1;
    if (!ch)         return 2;
    if (!buf)        return 3;

    *bytes_read = 0;

    /* If data already buffered, return it */
    if (ch->recv_len > 0) {
        u64 copy = (ch->recv_len < len) ? ch->recv_len : len;
        memcpy(buf, ch->recv_buf, copy);
        /* Shift remaining data */
        if (copy < ch->recv_len) {
            memmove(ch->recv_buf, ch->recv_buf + copy, ch->recv_len - copy);
        }
        ch->recv_len -= copy;
        *bytes_read = copy;

        /* Send window adjust to keep flow going */
        {
            u8 payload[16];
            pkt_buf pb;
            pb_init(&pb, payload, sizeof(payload));
            pb_u8(&pb, SSH_MSG_CHANNEL_WINDOW_ADJUST);
            pb_u32(&pb, ch->remote_id);
            pb_u32(&pb, (u32)copy);
            ssh_send_packet(ch->conn, pb.buf, pb.len);
        }

        return 0;
    }

    if (ch->closed) {
        *bytes_read = 0;
        return 0;
    }

    /* Need to receive packets until we get channel data */
    {
        u8 pkt[SSH_MAX_PACKET];
        u64 pkt_len;

        if (ssh_recv_packet_filtered(ch->conn, pkt, sizeof(pkt), &pkt_len) != 0) return 4;
        ssh_dispatch_channel_packet(ch->conn, pkt, pkt_len);

        /* Try again from buffer */
        if (ch->recv_len > 0) {
            u64 copy = (ch->recv_len < len) ? ch->recv_len : len;
            memcpy(buf, ch->recv_buf, copy);
            if (copy < ch->recv_len) {
                memmove(ch->recv_buf, ch->recv_buf + copy, ch->recv_len - copy);
            }
            ch->recv_len -= copy;
            *bytes_read = copy;

            /* Window adjust */
            {
                u8 wa[16];
                pkt_buf wpb;
                pb_init(&wpb, wa, sizeof(wa));
                pb_u8(&wpb, SSH_MSG_CHANNEL_WINDOW_ADJUST);
                pb_u32(&wpb, ch->remote_id);
                pb_u32(&wpb, (u32)copy);
                ssh_send_packet(ch->conn, wpb.buf, wpb.len);
            }
        }
    }

    return 0;
}

/* ================================================================
 *  ssh_channel_read_stderr — drain bytes that arrived via
 *  SSH_MSG_CHANNEL_EXTENDED_DATA with data_type_code = 1 (stderr).
 *
 *  Non-blocking: returns whatever's already been buffered by earlier
 *  dispatch calls. If the buffer is empty, returns 0 with *bytes_read=0
 *  (does NOT try to pull a new packet — that would steal stdout bytes
 *  from ssh_channel_read). Typical use: call after the main read loop
 *  observes an EOF or error to surface the server's diagnostic output.
 * ================================================================ */

unsigned long ssh_channel_read_stderr(u64 *bytes_read,
                                                     ssh_channel *ch,
                                                     u8 *buf, u64 len) {
    if (!bytes_read) return 1;
    if (!ch)         return 2;
    if (!buf)        return 3;

    *bytes_read = 0;

    if (ch->err_recv_len > 0) {
        u64 copy = (ch->err_recv_len < len) ? ch->err_recv_len : len;
        memcpy(buf, ch->err_recv_buf, copy);
        if (copy < ch->err_recv_len) {
            memmove(ch->err_recv_buf, ch->err_recv_buf + copy,
                    ch->err_recv_len - copy);
        }
        ch->err_recv_len -= copy;
        *bytes_read = copy;
    }

    return 0;
}

/* ================================================================
 *  ssh_channel_is_closed — non-blocking accessor for the channel's
 *  close state. True (1) once we've received CHANNEL_EOF (96) or
 *  CHANNEL_CLOSE (97) from the server, or sent our own CHANNEL_CLOSE.
 *
 *  Lets a drain loop return as soon as the server signals EOF,
 *  without a consecutive-empty-reads heuristic.
 * ================================================================ */

unsigned long ssh_channel_is_closed(int *out, ssh_channel *ch) {
    if (!out) return 1;
    if (!ch)  return 2;
    *out = ch->closed;
    return 0;
}

/* ================================================================
 *  ssh_channel_exec — run a remote command on an open session channel.
 *
 *  RFC 4254 §6.5: client sends SSH_MSG_CHANNEL_REQUEST with
 *    request_type = "exec", want_reply = 1, command = <string>.
 *  Server responds with SSH_MSG_CHANNEL_SUCCESS (accepted) or
 *    SSH_MSG_CHANNEL_FAILURE (rejected).
 *
 *  After a successful exec, the channel's read/write streams are the
 *  command's stdout/stdin. This is the mechanism git uses over SSH:
 *    exec "git-upload-pack '/path/to/repo.git'"  on the server,
 *  then pack protocol flows over the channel.
 *
 *  Between the request and the reply, the server may interleave
 *  SSH_MSG_CHANNEL_WINDOW_ADJUST packets — we handle those and keep
 *  reading until the success/failure reply arrives.
 * ================================================================ */

unsigned long ssh_channel_exec(ssh_channel *ch, const char *command) {
    u8 payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf pb;
    u64 cmd_len;
    int tries;

    if (!ch)      return 1;
    if (!command) return 2;
    if (ch->closed) return 3;

    cmd_len = (u64)strlen(command);

    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_CHANNEL_REQUEST);
    pb_u32(&pb, ch->remote_id);
    pb_cstring(&pb, "exec");
    pb_u8(&pb, 1);                          /* want_reply */
    pb_string(&pb, (const u8 *)command, cmd_len);

    if (ssh_send_packet(ch->conn, pb.buf, pb.len) != 0) return 4;

    /* Read until we see the request's success/failure reply. Drop any
     * interleaved WINDOW_ADJUST packets (server commonly sends one). */
    for (tries = 0; tries < 8; tries++) {
        if (ssh_recv_packet_filtered(ch->conn, payload, sizeof(payload), &payload_len) != 0)
            return 4;
        if (payload_len < 1) return 4;

        if (payload[0] == SSH_MSG_CHANNEL_SUCCESS) return 0;
        if (payload[0] == SSH_MSG_CHANNEL_FAILURE) return 5;

        if (payload[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST && payload_len >= 9) {
            u32 adjust = get_u32(payload + 5);
            ch->remote_window += adjust;
            continue;
        }

        /* Any other packet here (unexpected) — ignore and keep waiting
         * for the reply to our request. */
    }
    return 4;
}

/* ================================================================
 *  ssh_channel_close
 * ================================================================ */

unsigned long ssh_channel_close(ssh_channel *ch) {
    u8 payload[16];
    pkt_buf pb;

    if (!ch) return 1;

    if (!ch->closed) {
        /* Send CHANNEL_CLOSE */
        pb_init(&pb, payload, sizeof(payload));
        pb_u8(&pb, SSH_MSG_CHANNEL_CLOSE);
        pb_u32(&pb, ch->remote_id);
        ssh_send_packet(ch->conn, pb.buf, pb.len);
        ch->closed = 1;
    }

    free(ch->recv_buf);
    ch->recv_buf = NULL;
    ch->recv_len = 0;
    ch->recv_cap = 0;

    free(ch->err_recv_buf);
    ch->err_recv_buf = NULL;
    ch->err_recv_len = 0;
    ch->err_recv_cap = 0;

    return 0;
}

/* ================================================================
 *  ssh_conn_destroy
 * ================================================================ */

unsigned long ssh_conn_destroy(ssh_conn *conn) {
    u64 i;

    if (!conn) return 1;

    /* Send disconnect if still connected */
    if (conn->connected) {
        u8 payload[64];
        pkt_buf pb;
        pb_init(&pb, payload, sizeof(payload));
        pb_u8(&pb, SSH_MSG_DISCONNECT);
        pb_u32(&pb, 11);                  /* SSH_DISCONNECT_BY_APPLICATION */
        pb_cstring(&pb, "closing");        /* description */
        pb_cstring(&pb, "");               /* language tag */
        ssh_send_packet(conn, pb.buf, pb.len);
    }

    /* Free channels */
    for (i = 0; i < conn->channel_count; i++) {
        if (conn->channels[i]) {
            free(conn->channels[i]->recv_buf);
            free(conn->channels[i]->err_recv_buf);
            free(conn->channels[i]);
        }
    }
    free(conn->channels);

    /* Close TCP */
    tcp_conn_destroy(&conn->tcp);

    /* Scrub keying material */
    memset(conn->enc_key_c2s, 0, 32);
    memset(conn->enc_key_s2c, 0, 32);
    memset(conn->mac_key_c2s, 0, 32);
    memset(conn->mac_key_s2c, 0, 32);
    memset(conn->iv_c2s, 0, 12);
    memset(conn->iv_s2c, 0, 12);

    free(conn);
    return 0;
}

/* ================================================================
 *  Test-only hook: expose pb_mpint to the test suite. The mpint
 *  encoding is load-bearing for the RFC 4253 §8 exchange hash — a
 *  single off-by-one in the MSB-prefix / leading-zero logic makes
 *  every handshake fail sig verification against a real server.
 *  Not part of the public API; `_dbg` suffix warns callers.
 * ================================================================ */

unsigned long ssh_dbg_encode_mpint(u8 *out, u64 out_cap,
                                                  u64 *out_len,
                                                  const u8 *bytes, u64 len);

unsigned long ssh_dbg_encode_mpint(u8 *out, u64 out_cap, u64 *out_len,
                                    const u8 *bytes, u64 len) {
    pkt_buf pb;
    if (!out || !out_len) return 1;
    if (len > 0 && !bytes) return 2;
    pb_init(&pb, out, out_cap);
    pb_mpint(&pb, bytes, len);
    *out_len = pb.len;
    return 0;
}
