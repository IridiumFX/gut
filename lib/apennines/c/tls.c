#include "apennines/tls.h"
#include "apennines/cipher.h"
#include "apennines/hash.h"
#include "apennines/ec.h"
#include "apennines/ecdsa.h"
#include "apennines/pki.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ================================================================
 *  Internal constants — TLS 1.3 (RFC 8446)
 * ================================================================ */

/* Content types */
#define CT_CHANGE_CIPHER_SPEC 20
#define CT_ALERT              21
#define CT_HANDSHAKE          22
#define CT_APPLICATION_DATA   23

/* Handshake types */
#define HT_CLIENT_HELLO        1
#define HT_SERVER_HELLO        2
#define HT_ENCRYPTED_EXTS      8
#define HT_CERTIFICATE        11
#define HT_CERTIFICATE_VERIFY 15
#define HT_FINISHED           20

/* Extension types */
#define EXT_SERVER_NAME          0x0000
#define EXT_SUPPORTED_GROUPS     0x000A
#define EXT_SIGNATURE_ALGORITHMS 0x000D
#define EXT_ALPN                 0x0010
#define EXT_SUPPORTED_VERSIONS   0x002B
#define EXT_KEY_SHARE            0x0033

/* Named groups */
#define GROUP_X25519  0x001D
#define GROUP_SECP256R1 0x0017

/* Signature schemes */
#define SIG_ECDSA_SECP256R1_SHA256 0x0403
#define SIG_ED25519                0x0807
#define SIG_RSA_PSS_RSAE_SHA256    0x0804

/* Cipher suites (TLS 1.3) */
#define CS_AES_128_GCM_SHA256       0x1301
#define CS_AES_256_GCM_SHA384       0x1302
#define CS_CHACHA20_POLY1305_SHA256 0x1303

/* Alert levels and descriptions */
#define ALERT_WARNING  1
#define ALERT_FATAL    2
#define ALERT_CLOSE_NOTIFY     0
#define ALERT_UNEXPECTED_MSG  10
#define ALERT_BAD_RECORD_MAC  20
#define ALERT_HANDSHAKE_FAIL  40
#define ALERT_DECODE_ERROR    50
#define ALERT_INTERNAL_ERROR  80

/* Record limits */
#define TLS_RECORD_MAX   16384
#define TLS_RECORD_HDR      5
#define GCM_TAG_LEN        16

/* ================================================================
 *  Struct definitions
 * ================================================================ */

struct tls_config {
    u8  *cert_data;   u64 cert_len;
    u8  *key_data;    u64 key_len;
    u8  *ca_data;     u64 ca_len;
    char **alpn;      u64 alpn_count;
    u16  min_ver;
    u16  max_ver;
    int  verify_mode;
};

struct tls_conn {
    tcp_conn   *tcp;
    tls_config *cfg;
    int         is_client;
    u16         version;

    /* Key material */
    u8  client_write_key[32];
    u8  server_write_key[32];
    u8  client_write_iv[12];
    u8  server_write_iv[12];
    u64 client_seq;
    u64 server_seq;
    int cipher_id;   /* 0=AES-128-GCM, 1=AES-256-GCM, 2=ChaCha20 */

    /* AES contexts for application data */
    aes_ctx client_aes;
    aes_ctx server_aes;

    /* Handshake state */
    int   handshake_done;
    char *alpn_selected;
    char  cipher_name[64];
    u8   *peer_cert;
    u64   peer_cert_len;

    /* Read buffer for leftover decrypted data */
    u8   *read_buf;
    u64   read_buf_len;
    u64   read_buf_off;
};

/* ================================================================
 *  Helpers — byte encoding
 * ================================================================ */

static void put_u8(u8 *p, u8 v)   { p[0] = v; }
static void put_u16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void put_u24(u8 *p, u32 v) { p[0] = (u8)(v >> 16); p[1] = (u8)(v >> 8); p[2] = (u8)v; }
static void put_u32(u8 *p, u32 v) { p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v; }

static u8  get_u8(const u8 *p)  { return p[0]; }
static u16 get_u16(const u8 *p) { return (u16)((u16)p[0] << 8 | p[1]); }
static u32 get_u24(const u8 *p) { return (u32)p[0] << 16 | (u32)p[1] << 8 | p[2]; }
static u32 get_u32(const u8 *p) { return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3]; }

/* Constant-time compare */
static int ct_equal(const u8 *a, const u8 *b, u64 len) {
    u8 acc = 0;
    u64 i;
    for (i = 0; i < len; i++) acc |= a[i] ^ b[i];
    return acc == 0;
}

/* Simple CSPRNG fill using X25519 keygen as entropy source */
static unsigned long random_bytes(u8 *out, u64 len) {
    x25519_keypair kp;
    u64 off = 0;
    unsigned long rc;
    while (off < len) {
        rc = x25519_keygen(&kp);
        if (rc) return rc;
        u64 chunk = len - off;
        if (chunk > 32) chunk = 32;
        memcpy(out + off, kp.priv.data, chunk);
        off += chunk;
    }
    memset(&kp, 0, sizeof(kp));
    return 0;
}

/* ================================================================
 *  TLS 1.3 Key Schedule helpers
 * ================================================================ */

/* HKDF-Expand-Label (RFC 8446 sec 7.1):
 *   info = u16(length) || u8(label_len) || "tls13 " || label
 *                      || u8(context_len) || context                         */
static unsigned long hkdf_expand_label(u8 *out, u64 out_len,
                                       const u8 *secret, u64 secret_len,
                                       const char *label, u64 label_len,
                                       const u8 *context, u64 context_len)
{
    u8 info[512];
    u64 info_len = 0;
    static const char prefix[] = "tls13 ";
    u64 prefix_len = 6;

    /* length (u16) */
    info[info_len++] = (u8)(out_len >> 8);
    info[info_len++] = (u8)(out_len);
    /* label length + prefix + label */
    info[info_len++] = (u8)(prefix_len + label_len);
    memcpy(info + info_len, prefix, prefix_len);
    info_len += prefix_len;
    memcpy(info + info_len, label, label_len);
    info_len += label_len;
    /* context length + context */
    info[info_len++] = (u8)context_len;
    if (context_len > 0) {
        memcpy(info + info_len, context, context_len);
        info_len += context_len;
    }

    return hkdf_expand(out, out_len, HMAC_HASH_SHA256,
                        secret, secret_len, info, info_len);
}

/* Derive-Secret(Secret, Label, Messages) =
 *   HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length) */
static unsigned long derive_secret(u8 *out,
                                   const u8 *secret, u64 secret_len,
                                   const char *label, u64 label_len,
                                   const u8 *messages, u64 messages_len)
{
    u8 hash[32];
    unsigned long rc = sha256_digest(hash, messages, messages_len);
    if (rc) return rc;
    return hkdf_expand_label(out, 32, secret, secret_len,
                              label, label_len, hash, 32);
}

/* ================================================================
 *  Record layer — send / receive
 * ================================================================ */

/* Send a raw TLS record */
static unsigned long send_record(tcp_conn *tcp, u8 content_type,
                                  u16 version, const u8 *data, u64 data_len)
{
    u8 hdr[TLS_RECORD_HDR];
    u64 written;
    unsigned long rc;

    put_u8(hdr, content_type);
    put_u16(hdr + 1, version);
    put_u16(hdr + 3, (u16)data_len);

    rc = tcp_conn_write_all(&written, tcp, hdr, TLS_RECORD_HDR);
    if (rc) return rc;
    if (data_len > 0) {
        rc = tcp_conn_write_all(&written, tcp, data, data_len);
        if (rc) return rc;
    }
    return 0;
}

/* Read exactly n bytes from TCP */
static unsigned long tcp_read_exact(tcp_conn *tcp, u8 *buf, u64 len) {
    u64 total = 0;
    while (total < len) {
        u64 got;
        unsigned long rc = tcp_conn_read(&got, tcp, buf + total, len - total);
        if (rc) return rc;
        if (got == 0) return 1; /* unexpected EOF */
        total += got;
    }
    return 0;
}

/* Receive a raw TLS record. Caller must free *data. */
static unsigned long recv_record(u8 *out_type, u8 **out_data, u64 *out_len,
                                  tcp_conn *tcp)
{
    u8 hdr[TLS_RECORD_HDR];
    u64 payload_len;
    u8 *payload;
    unsigned long rc;

    rc = tcp_read_exact(tcp, hdr, TLS_RECORD_HDR);
    if (rc) return rc;

    *out_type = hdr[0];
    payload_len = get_u16(hdr + 3);
    if (payload_len > TLS_RECORD_MAX + 256) return 2; /* record too large */

    payload = (u8 *)malloc(payload_len);
    if (!payload) return 3;

    rc = tcp_read_exact(tcp, payload, payload_len);
    if (rc) { free(payload); return rc; }

    *out_data = payload;
    *out_len  = payload_len;
    return 0;
}

/* Build per-record nonce: IV XOR sequence_number */
static void make_nonce(u8 *nonce12, const u8 *iv, u64 seq) {
    memcpy(nonce12, iv, 12);
    /* XOR the sequence number into the last 8 bytes of the IV */
    nonce12[4]  ^= (u8)(seq >> 56);
    nonce12[5]  ^= (u8)(seq >> 48);
    nonce12[6]  ^= (u8)(seq >> 40);
    nonce12[7]  ^= (u8)(seq >> 32);
    nonce12[8]  ^= (u8)(seq >> 24);
    nonce12[9]  ^= (u8)(seq >> 16);
    nonce12[10] ^= (u8)(seq >> 8);
    nonce12[11] ^= (u8)(seq);
}

/* Encrypt and send a TLS 1.3 record (application_data wrapper).
 * inner_type is appended to plaintext before encryption. */
static unsigned long send_encrypted_record(tls_conn *conn,
                                            u8 inner_type,
                                            const u8 *data, u64 data_len)
{
    u8 nonce[12];
    u8 aad[5];
    u64 ct_len = data_len + 1 + GCM_TAG_LEN; /* plaintext + inner_type + tag */
    u8 *plaintext;
    u8 *ciphertext;
    u8 tag[GCM_TAG_LEN];
    unsigned long rc;

    plaintext = (u8 *)malloc(data_len + 1);
    if (!plaintext) return 1;
    memcpy(plaintext, data, data_len);
    plaintext[data_len] = inner_type;

    ciphertext = (u8 *)malloc(ct_len);
    if (!ciphertext) { free(plaintext); return 1; }

    /* AAD = record header: type(0x17) || legacy_version(0x0303) || length */
    aad[0] = CT_APPLICATION_DATA;
    put_u16(aad + 1, 0x0303);
    put_u16(aad + 3, (u16)ct_len);

    if (conn->is_client) {
        make_nonce(nonce, conn->client_write_iv, conn->client_seq);
        rc = aes128_gcm_encrypt(ciphertext, tag,
                                 &conn->client_aes, nonce,
                                 aad, 5,
                                 plaintext, data_len + 1);
        conn->client_seq++;
    } else {
        make_nonce(nonce, conn->server_write_iv, conn->server_seq);
        rc = aes128_gcm_encrypt(ciphertext, tag,
                                 &conn->server_aes, nonce,
                                 aad, 5,
                                 plaintext, data_len + 1);
        conn->server_seq++;
    }

    free(plaintext);
    if (rc) { free(ciphertext); return 2; }

    /* Append tag to ciphertext */
    memcpy(ciphertext + data_len + 1, tag, GCM_TAG_LEN);

    rc = send_record(conn->tcp, CT_APPLICATION_DATA, 0x0303,
                      ciphertext, ct_len);
    free(ciphertext);
    return rc;
}

/* Receive and decrypt a TLS 1.3 record.
 * Returns inner_type and decrypted payload (caller frees). */
static unsigned long recv_encrypted_record(u8 *out_inner_type,
                                            u8 **out_data, u64 *out_len,
                                            tls_conn *conn)
{
    u8 rec_type;
    u8 *raw = NULL;
    u64 raw_len;
    u8 nonce[12];
    u8 aad[5];
    u8 *decrypted;
    u64 pt_len;
    unsigned long rc;

    /* Skip change_cipher_spec records (TLS 1.3 compat) */
    for (;;) {
        rc = recv_record(&rec_type, &raw, &raw_len, conn->tcp);
        if (rc) return rc;
        if (rec_type == CT_CHANGE_CIPHER_SPEC) {
            free(raw);
            raw = NULL;
            continue;
        }
        break;
    }

    if (rec_type != CT_APPLICATION_DATA) {
        /* Alert or plaintext handshake — pass through for error handling */
        if (rec_type == CT_ALERT && raw_len >= 2) {
            free(raw);
            return 3; /* alert received */
        }
        free(raw);
        return 4; /* unexpected record type */
    }

    if (raw_len < GCM_TAG_LEN + 1) { free(raw); return 5; }

    pt_len = raw_len - GCM_TAG_LEN;
    decrypted = (u8 *)malloc(pt_len);
    if (!decrypted) { free(raw); return 6; }

    /* AAD = record header */
    aad[0] = CT_APPLICATION_DATA;
    put_u16(aad + 1, 0x0303);
    put_u16(aad + 3, (u16)raw_len);

    if (conn->is_client) {
        /* Decrypt with server write key */
        make_nonce(nonce, conn->server_write_iv, conn->server_seq);
        rc = aes128_gcm_decrypt(decrypted,
                                 &conn->server_aes, nonce,
                                 aad, 5,
                                 raw, pt_len,
                                 raw + pt_len);
        conn->server_seq++;
    } else {
        /* Decrypt with client write key */
        make_nonce(nonce, conn->client_write_iv, conn->client_seq);
        rc = aes128_gcm_decrypt(decrypted,
                                 &conn->client_aes, nonce,
                                 aad, 5,
                                 raw, pt_len,
                                 raw + pt_len);
        conn->client_seq++;
    }

    free(raw);
    if (rc) { free(decrypted); return 7; /* decryption failed */ }

    /* Strip trailing zeros and extract inner content type (last non-zero byte) */
    while (pt_len > 0 && decrypted[pt_len - 1] == 0) pt_len--;
    if (pt_len == 0) { free(decrypted); return 8; }

    *out_inner_type = decrypted[pt_len - 1];
    *out_len = pt_len - 1;
    *out_data = decrypted;
    return 0;
}

/* ================================================================
 *  Handshake message helpers
 * ================================================================ */

/* Accumulate transcript (simply append raw handshake message bytes) */
typedef struct {
    u8  *data;
    u64  len;
    u64  cap;
} transcript_t;

static unsigned long transcript_init(transcript_t *t) {
    t->data = (u8 *)malloc(8192);
    if (!t->data) return 1;
    t->len = 0;
    t->cap = 8192;
    return 0;
}

static unsigned long transcript_append(transcript_t *t, const u8 *data, u64 len) {
    if (t->len + len > t->cap) {
        u64 new_cap = t->cap * 2;
        u8 *new_data;
        while (new_cap < t->len + len) new_cap *= 2;
        new_data = (u8 *)realloc(t->data, new_cap);
        if (!new_data) return 1;
        t->data = new_data;
        t->cap = new_cap;
    }
    memcpy(t->data + t->len, data, len);
    t->len += len;
    return 0;
}

static void transcript_free(transcript_t *t) {
    free(t->data);
    t->data = NULL;
    t->len = 0;
    t->cap = 0;
}

/* Hash the current transcript */
static unsigned long transcript_hash(u8 *out32, const transcript_t *t) {
    return sha256_digest(out32, t->data, t->len);
}

/* ================================================================
 *  Client handshake — TLS 1.3
 * ================================================================ */

/* Build and send ClientHello, return the handshake message bytes for transcript */
static unsigned long build_client_hello(u8 **out_msg, u64 *out_msg_len,
                                         tcp_conn *tcp,
                                         const x25519_pubkey *pub_key,
                                         const char *hostname,
                                         const tls_config *cfg)
{
    /* Max ClientHello size: generous buffer */
    u8 *msg = (u8 *)malloc(4096);
    u64 pos = 0;
    u64 ext_start, ext_len_pos;
    u64 hostname_len;
    unsigned long rc;

    if (!msg) return 1;

    /* Handshake header: type(1) + length(3) — fill length later */
    msg[pos++] = HT_CLIENT_HELLO;
    pos += 3; /* placeholder for length */

    /* client_version: 0x0303 (TLS 1.2 for compat, real version in extension) */
    put_u16(msg + pos, 0x0303); pos += 2;

    /* random: 32 bytes */
    rc = random_bytes(msg + pos, 32);
    if (rc) { free(msg); return 2; }
    pos += 32;

    /* session_id: 32 bytes (TLS 1.3 middlebox compat) */
    msg[pos++] = 32;
    rc = random_bytes(msg + pos, 32);
    if (rc) { free(msg); return 2; }
    pos += 32;

    /* cipher_suites: 3 suites = 6 bytes */
    put_u16(msg + pos, 6); pos += 2;
    put_u16(msg + pos, CS_AES_128_GCM_SHA256); pos += 2;
    put_u16(msg + pos, CS_AES_256_GCM_SHA384); pos += 2;
    put_u16(msg + pos, CS_CHACHA20_POLY1305_SHA256); pos += 2;

    /* compression_methods: 1 byte, null only */
    msg[pos++] = 1;
    msg[pos++] = 0;

    /* Extensions */
    ext_len_pos = pos;
    pos += 2; /* placeholder for total extensions length */
    ext_start = pos;

    /* --- supported_versions extension (mandatory for TLS 1.3) --- */
    put_u16(msg + pos, EXT_SUPPORTED_VERSIONS); pos += 2;
    put_u16(msg + pos, 3); pos += 2; /* ext data length */
    msg[pos++] = 2; /* list length */
    put_u16(msg + pos, TLS_VERSION_13); pos += 2;

    /* --- supported_groups extension --- */
    put_u16(msg + pos, EXT_SUPPORTED_GROUPS); pos += 2;
    put_u16(msg + pos, 6); pos += 2; /* ext data length */
    put_u16(msg + pos, 4); pos += 2; /* list length */
    put_u16(msg + pos, GROUP_X25519); pos += 2;
    put_u16(msg + pos, GROUP_SECP256R1); pos += 2;

    /* --- key_share extension (X25519) --- */
    put_u16(msg + pos, EXT_KEY_SHARE); pos += 2;
    put_u16(msg + pos, 2 + 2 + 2 + 32); pos += 2; /* ext data length */
    put_u16(msg + pos, 2 + 2 + 32); pos += 2; /* client_shares length */
    put_u16(msg + pos, GROUP_X25519); pos += 2; /* named group */
    put_u16(msg + pos, 32); pos += 2; /* key_exchange length */
    memcpy(msg + pos, pub_key->data, 32); pos += 32;

    /* --- signature_algorithms extension --- */
    put_u16(msg + pos, EXT_SIGNATURE_ALGORITHMS); pos += 2;
    put_u16(msg + pos, 2 + 6); pos += 2; /* ext data length */
    put_u16(msg + pos, 6); pos += 2; /* list length */
    put_u16(msg + pos, SIG_ECDSA_SECP256R1_SHA256); pos += 2;
    put_u16(msg + pos, SIG_ED25519); pos += 2;
    put_u16(msg + pos, SIG_RSA_PSS_RSAE_SHA256); pos += 2;

    /* --- server_name (SNI) extension --- */
    if (hostname && hostname[0]) {
        hostname_len = strlen(hostname);
        put_u16(msg + pos, EXT_SERVER_NAME); pos += 2;
        put_u16(msg + pos, (u16)(hostname_len + 5)); pos += 2; /* ext data length */
        put_u16(msg + pos, (u16)(hostname_len + 3)); pos += 2; /* server_name_list length */
        msg[pos++] = 0; /* host_name type */
        put_u16(msg + pos, (u16)hostname_len); pos += 2;
        memcpy(msg + pos, hostname, hostname_len); pos += hostname_len;
    }

    /* --- ALPN extension --- */
    if (cfg->alpn && cfg->alpn_count > 0) {
        u64 alpn_list_len = 0;
        u64 i;
        for (i = 0; i < cfg->alpn_count; i++) {
            alpn_list_len += 1 + strlen(cfg->alpn[i]);
        }
        put_u16(msg + pos, EXT_ALPN); pos += 2;
        put_u16(msg + pos, (u16)(alpn_list_len + 2)); pos += 2;
        put_u16(msg + pos, (u16)alpn_list_len); pos += 2;
        for (i = 0; i < cfg->alpn_count; i++) {
            u64 plen = strlen(cfg->alpn[i]);
            msg[pos++] = (u8)plen;
            memcpy(msg + pos, cfg->alpn[i], plen);
            pos += plen;
        }
    }

    /* Fill in extensions length */
    put_u16(msg + ext_len_pos, (u16)(pos - ext_start));

    /* Fill in handshake length (3 bytes after type byte) */
    put_u24(msg + 1, (u32)(pos - 4));

    /* Send as TLS record (legacy version 0x0301 for max compat) */
    rc = send_record(tcp, CT_HANDSHAKE, 0x0301, msg, pos);
    if (rc) { free(msg); return 3; }

    *out_msg = msg;
    *out_msg_len = pos;
    return 0;
}

/* Parse ServerHello, extract server X25519 key share and selected cipher.
 * Assumes msg starts at handshake type byte. */
static unsigned long parse_server_hello(u16 *out_cipher,
                                         u8 *out_server_pub32,
                                         u16 *out_version,
                                         const u8 *msg, u64 msg_len)
{
    u64 pos;
    u32 hs_len;
    u8 session_id_len;
    u16 cipher_suite;
    u64 ext_total_len, ext_end;

    if (msg_len < 4) return 1;
    if (msg[0] != HT_SERVER_HELLO) return 2;
    hs_len = get_u24(msg + 1);
    pos = 4;

    if (pos + 2 > msg_len) return 3;
    /* server_version (legacy) */ pos += 2;

    /* random (32 bytes) */
    if (pos + 32 > msg_len) return 3;
    pos += 32;

    /* session_id */
    if (pos + 1 > msg_len) return 3;
    session_id_len = msg[pos++];
    if (pos + session_id_len > msg_len) return 3;
    pos += session_id_len;

    /* cipher suite */
    if (pos + 2 > msg_len) return 3;
    cipher_suite = get_u16(msg + pos); pos += 2;
    *out_cipher = cipher_suite;

    /* compression method */
    if (pos + 1 > msg_len) return 3;
    pos += 1;

    /* extensions */
    *out_version = TLS_VERSION_13; /* default, confirmed by supported_versions ext */

    if (pos + 2 > msg_len) return 0; /* no extensions — shouldn't happen for 1.3 */
    ext_total_len = get_u16(msg + pos); pos += 2;
    ext_end = pos + ext_total_len;
    if (ext_end > msg_len) return 3;

    while (pos + 4 <= ext_end) {
        u16 ext_type = get_u16(msg + pos); pos += 2;
        u16 ext_len  = get_u16(msg + pos); pos += 2;
        if (pos + ext_len > ext_end) return 3;

        if (ext_type == EXT_SUPPORTED_VERSIONS && ext_len >= 2) {
            *out_version = get_u16(msg + pos);
        }
        else if (ext_type == EXT_KEY_SHARE && ext_len >= 36) {
            u16 group = get_u16(msg + pos);
            u16 key_len = get_u16(msg + pos + 2);
            if (group == GROUP_X25519 && key_len == 32) {
                memcpy(out_server_pub32, msg + pos + 4, 32);
            }
        }
        pos += ext_len;
    }
    return 0;
}

/* Parse EncryptedExtensions. Extract ALPN if present. */
static unsigned long parse_encrypted_extensions(char **out_alpn,
                                                 const u8 *msg, u64 msg_len)
{
    u64 pos;
    u32 hs_len;
    u64 ext_total_len, ext_end;

    *out_alpn = NULL;
    if (msg_len < 4) return 1;
    if (msg[0] != HT_ENCRYPTED_EXTS) return 2;
    hs_len = get_u24(msg + 1);
    pos = 4;

    if (pos + 2 > msg_len) return 0;
    ext_total_len = get_u16(msg + pos); pos += 2;
    ext_end = pos + ext_total_len;
    if (ext_end > msg_len) return 3;

    while (pos + 4 <= ext_end) {
        u16 ext_type = get_u16(msg + pos); pos += 2;
        u16 ext_len  = get_u16(msg + pos); pos += 2;
        if (pos + ext_len > ext_end) return 3;

        if (ext_type == EXT_ALPN && ext_len >= 4) {
            u16 list_len = get_u16(msg + pos);
            (void)list_len;
            u8 proto_len = msg[pos + 2];
            if (proto_len > 0 && pos + 3 + proto_len <= ext_end) {
                *out_alpn = (char *)malloc(proto_len + 1);
                if (*out_alpn) {
                    memcpy(*out_alpn, msg + pos + 3, proto_len);
                    (*out_alpn)[proto_len] = '\0';
                }
            }
        }
        pos += ext_len;
    }
    return 0;
}

/* Parse Certificate message. Extract first cert (leaf) in DER. */
static unsigned long parse_certificate(u8 **out_cert, u64 *out_cert_len,
                                        const u8 *msg, u64 msg_len)
{
    u64 pos;
    u32 hs_len;
    u8 ctx_len;
    u32 certs_len;
    u32 cert_data_len;

    *out_cert = NULL;
    *out_cert_len = 0;

    if (msg_len < 4) return 1;
    if (msg[0] != HT_CERTIFICATE) return 2;
    hs_len = get_u24(msg + 1);
    pos = 4;

    /* certificate_request_context */
    if (pos + 1 > msg_len) return 3;
    ctx_len = msg[pos++];
    pos += ctx_len;

    /* certificate_list length (3 bytes) */
    if (pos + 3 > msg_len) return 3;
    certs_len = get_u24(msg + pos); pos += 3;

    if (certs_len == 0) return 0; /* empty cert list */

    /* First CertificateEntry: cert_data(3-byte length-prefixed) + extensions(2-byte) */
    if (pos + 3 > msg_len) return 3;
    cert_data_len = get_u24(msg + pos); pos += 3;
    if (pos + cert_data_len > msg_len) return 3;

    *out_cert = (u8 *)malloc(cert_data_len);
    if (!*out_cert) return 4;
    memcpy(*out_cert, msg + pos, cert_data_len);
    *out_cert_len = cert_data_len;
    return 0;
}

/* Parse CertificateVerify — we store the signature but skip verification for now */
static unsigned long parse_certificate_verify(const u8 *msg, u64 msg_len) {
    if (msg_len < 4) return 1;
    if (msg[0] != HT_CERTIFICATE_VERIFY) return 2;
    /* We accept but don't verify the signature in this implementation */
    return 0;
}

/* Parse Finished message and verify its verify_data */
static unsigned long parse_finished(const u8 *msg, u64 msg_len,
                                     const u8 *finished_key,
                                     const u8 *transcript_hash_val)
{
    u32 hs_len;
    u8 expected[32];
    unsigned long rc;

    if (msg_len < 4) return 1;
    if (msg[0] != HT_FINISHED) return 2;
    hs_len = get_u24(msg + 1);
    if (hs_len != 32) return 3;
    if (msg_len < 4 + 32) return 3;

    /* verify_data = HMAC(finished_key, transcript_hash) */
    rc = hmac_digest(expected, HMAC_HASH_SHA256,
                      finished_key, 32,
                      transcript_hash_val, 32);
    if (rc) return 4;

    if (!ct_equal(msg + 4, expected, 32)) return 5;
    return 0;
}

/* Build client Finished message */
static unsigned long build_finished(u8 *out_msg, u64 *out_msg_len,
                                     const u8 *finished_key,
                                     const u8 *transcript_hash_val)
{
    u8 verify_data[32];
    unsigned long rc;

    rc = hmac_digest(verify_data, HMAC_HASH_SHA256,
                      finished_key, 32,
                      transcript_hash_val, 32);
    if (rc) return 1;

    out_msg[0] = HT_FINISHED;
    put_u24(out_msg + 1, 32);
    memcpy(out_msg + 4, verify_data, 32);
    *out_msg_len = 36;
    return 0;
}

/* Receive a handshake message from an encrypted record.
 * The caller frees *out_msg. */
static unsigned long recv_handshake_encrypted(u8 **out_msg, u64 *out_msg_len,
                                               tls_conn *conn)
{
    u8 inner_type;
    unsigned long rc = recv_encrypted_record(&inner_type, out_msg, out_msg_len, conn);
    if (rc) return rc;
    if (inner_type != CT_HANDSHAKE) {
        free(*out_msg);
        *out_msg = NULL;
        return 1;
    }
    return 0;
}

/* ================================================================
 *  Key derivation — full TLS 1.3 key schedule
 * ================================================================ */

static unsigned long derive_handshake_keys(
    u8 *client_hs_key, u8 *client_hs_iv,
    u8 *server_hs_key, u8 *server_hs_iv,
    u8 *client_hs_secret, u8 *server_hs_secret,
    u8 *handshake_secret,
    const u8 *shared_secret,
    const transcript_t *transcript)
{
    u8 early_secret[32];
    u8 derived_secret[32];
    u8 empty_hash[32];
    u8 zeros[32];
    unsigned long rc;

    memset(zeros, 0, 32);

    /* early_secret = HKDF-Extract(salt=0, ikm=0) — no PSK */
    rc = hkdf_extract(early_secret, HMAC_HASH_SHA256, NULL, 0, zeros, 32);
    if (rc) return rc;

    /* derived_secret = Derive-Secret(early_secret, "derived", "") */
    rc = sha256_digest(empty_hash, (const u8 *)"", 0);
    if (rc) return rc;
    rc = hkdf_expand_label(derived_secret, 32, early_secret, 32,
                            "derived", 7, empty_hash, 32);
    if (rc) return rc;

    /* handshake_secret = HKDF-Extract(salt=derived_secret, ikm=shared_secret) */
    rc = hkdf_extract(handshake_secret, HMAC_HASH_SHA256,
                       derived_secret, 32, shared_secret, 32);
    if (rc) return rc;

    /* client_handshake_traffic_secret */
    rc = derive_secret(client_hs_secret, handshake_secret, 32,
                        "c hs traffic", 12,
                        transcript->data, transcript->len);
    if (rc) return rc;

    /* server_handshake_traffic_secret */
    rc = derive_secret(server_hs_secret, handshake_secret, 32,
                        "s hs traffic", 12,
                        transcript->data, transcript->len);
    if (rc) return rc;

    /* Derive keys and IVs */
    rc = hkdf_expand_label(client_hs_key, 16, client_hs_secret, 32,
                            "key", 3, NULL, 0);
    if (rc) return rc;
    rc = hkdf_expand_label(client_hs_iv, 12, client_hs_secret, 32,
                            "iv", 2, NULL, 0);
    if (rc) return rc;
    rc = hkdf_expand_label(server_hs_key, 16, server_hs_secret, 32,
                            "key", 3, NULL, 0);
    if (rc) return rc;
    rc = hkdf_expand_label(server_hs_iv, 12, server_hs_secret, 32,
                            "iv", 2, NULL, 0);
    if (rc) return rc;

    return 0;
}

static unsigned long derive_application_keys(
    u8 *client_app_key, u8 *client_app_iv,
    u8 *server_app_key, u8 *server_app_iv,
    const u8 *handshake_secret,
    const transcript_t *transcript)
{
    u8 derived_secret[32];
    u8 master_secret[32];
    u8 empty_hash[32];
    u8 client_app_secret[32];
    u8 server_app_secret[32];
    u8 zeros[32];
    unsigned long rc;

    memset(zeros, 0, 32);

    /* derived = Derive-Secret(handshake_secret, "derived", "") */
    rc = sha256_digest(empty_hash, (const u8 *)"", 0);
    if (rc) return rc;
    rc = hkdf_expand_label(derived_secret, 32, handshake_secret, 32,
                            "derived", 7, empty_hash, 32);
    if (rc) return rc;

    /* master_secret = HKDF-Extract(salt=derived, ikm=0) */
    rc = hkdf_extract(master_secret, HMAC_HASH_SHA256,
                       derived_secret, 32, zeros, 32);
    if (rc) return rc;

    /* client_application_traffic_secret_0 */
    rc = derive_secret(client_app_secret, master_secret, 32,
                        "c ap traffic", 12,
                        transcript->data, transcript->len);
    if (rc) return rc;

    /* server_application_traffic_secret_0 */
    rc = derive_secret(server_app_secret, master_secret, 32,
                        "s ap traffic", 12,
                        transcript->data, transcript->len);
    if (rc) return rc;

    /* Derive keys and IVs (16-byte key for AES-128-GCM) */
    rc = hkdf_expand_label(client_app_key, 16, client_app_secret, 32,
                            "key", 3, NULL, 0);
    if (rc) return rc;
    rc = hkdf_expand_label(client_app_iv, 12, client_app_secret, 32,
                            "iv", 2, NULL, 0);
    if (rc) return rc;
    rc = hkdf_expand_label(server_app_key, 16, server_app_secret, 32,
                            "key", 3, NULL, 0);
    if (rc) return rc;
    rc = hkdf_expand_label(server_app_iv, 12, server_app_secret, 32,
                            "iv", 2, NULL, 0);
    if (rc) return rc;

    return 0;
}

/* ================================================================
 *  Configuration API
 * ================================================================ */

unsigned long tls_config_create(tls_config **out) {
    tls_config *cfg;
    if (!out) return 1;
    cfg = (tls_config *)calloc(1, sizeof(tls_config));
    if (!cfg) return 2;
    cfg->min_ver = TLS_VERSION_13;
    cfg->max_ver = TLS_VERSION_13;
    cfg->verify_mode = TLS_VERIFY_NONE;
    *out = cfg;
    return 0;
}

unsigned long tls_config_set_cert(tls_config *cfg, const u8 *data, u64 len) {
    u8 *copy;
    if (!cfg)  return 1;
    if (!data) return 2;
    copy = (u8 *)malloc(len);
    if (!copy) return 3;
    memcpy(copy, data, len);
    free(cfg->cert_data);
    cfg->cert_data = copy;
    cfg->cert_len  = len;
    return 0;
}

unsigned long tls_config_set_key(tls_config *cfg, const u8 *data, u64 len) {
    u8 *copy;
    if (!cfg)  return 1;
    if (!data) return 2;
    copy = (u8 *)malloc(len);
    if (!copy) return 3;
    memcpy(copy, data, len);
    free(cfg->key_data);
    cfg->key_data = copy;
    cfg->key_len  = len;
    return 0;
}

unsigned long tls_config_set_ca(tls_config *cfg, const u8 *data, u64 len) {
    u8 *copy;
    if (!cfg)  return 1;
    if (!data) return 2;
    copy = (u8 *)malloc(len);
    if (!copy) return 3;
    memcpy(copy, data, len);
    free(cfg->ca_data);
    cfg->ca_data = copy;
    cfg->ca_len  = len;
    return 0;
}

unsigned long tls_config_set_alpn(tls_config *cfg, const char **protocols) {
    u64 count = 0;
    u64 i;
    char **alpn;

    if (!cfg) return 1;
    if (!protocols) return 2;

    /* Count protocols */
    while (protocols[count]) count++;

    alpn = (char **)calloc(count, sizeof(char *));
    if (!alpn) return 3;

    for (i = 0; i < count; i++) {
        u64 plen = strlen(protocols[i]);
        alpn[i] = (char *)malloc(plen + 1);
        if (!alpn[i]) {
            u64 j;
            for (j = 0; j < i; j++) free(alpn[j]);
            free(alpn);
            return 3;
        }
        memcpy(alpn[i], protocols[i], plen + 1);
    }

    /* Free old */
    if (cfg->alpn) {
        for (i = 0; i < cfg->alpn_count; i++) free(cfg->alpn[i]);
        free(cfg->alpn);
    }
    cfg->alpn = alpn;
    cfg->alpn_count = count;
    return 0;
}

unsigned long tls_config_set_versions(tls_config *cfg, u16 min_ver, u16 max_ver) {
    if (!cfg) return 1;
    if (min_ver > max_ver) return 2;
    cfg->min_ver = min_ver;
    cfg->max_ver = max_ver;
    return 0;
}

unsigned long tls_config_set_verify_mode(tls_config *cfg, int mode) {
    if (!cfg) return 1;
    cfg->verify_mode = mode;
    return 0;
}

unsigned long tls_config_destroy(tls_config *cfg) {
    u64 i;
    if (!cfg) return 1;
    free(cfg->cert_data);
    free(cfg->key_data);
    free(cfg->ca_data);
    if (cfg->alpn) {
        for (i = 0; i < cfg->alpn_count; i++) free(cfg->alpn[i]);
        free(cfg->alpn);
    }
    free(cfg);
    return 0;
}

/* ================================================================
 *  Client handshake
 * ================================================================ */

unsigned long tls_conn_create_client(tls_conn **out, tcp_conn *tcp,
                                      tls_config *cfg, const char *hostname)
{
    tls_conn *conn;
    x25519_keypair eph;
    u8 *ch_msg = NULL;
    u64 ch_len = 0;
    transcript_t ts;
    u8 rec_type;
    u8 *sh_raw = NULL;
    u64 sh_raw_len;
    u16 selected_cipher;
    u8 server_pub[32];
    u16 negotiated_ver;
    u8 shared_secret[32];
    u8 handshake_secret[32];
    u8 client_hs_key[16], client_hs_iv[12];
    u8 server_hs_key[16], server_hs_iv[12];
    u8 client_hs_secret[32], server_hs_secret[32];
    u8 server_finished_key[32], client_finished_key[32];
    u8 *hs_msg = NULL;
    u64 hs_msg_len;
    u8 inner_type;
    char *alpn_result = NULL;
    u8 *peer_cert = NULL;
    u64 peer_cert_len = 0;
    u8 th[32];
    u8 finished_buf[36];
    u64 finished_len;
    unsigned long rc;

    if (!out) return 1;
    if (!tcp) return 2;
    if (!cfg) return 3;

    conn = (tls_conn *)calloc(1, sizeof(tls_conn));
    if (!conn) return 6;
    conn->tcp = tcp;
    conn->cfg = cfg;
    conn->is_client = 1;
    conn->version = TLS_VERSION_13;

    /* Step 1: Generate ephemeral X25519 keypair */
    rc = x25519_keygen(&eph);
    if (rc) goto fail;

    /* Step 2: Build and send ClientHello */
    rc = build_client_hello(&ch_msg, &ch_len, tcp, &eph.pub, hostname, cfg);
    if (rc) goto fail;

    /* Init transcript with ClientHello */
    rc = transcript_init(&ts);
    if (rc) { free(ch_msg); goto fail; }
    rc = transcript_append(&ts, ch_msg, ch_len);
    free(ch_msg); ch_msg = NULL;
    if (rc) goto fail_ts;

    /* Step 3: Receive ServerHello */
    rc = recv_record(&rec_type, &sh_raw, &sh_raw_len, tcp);
    if (rc) goto fail_ts;
    if (rec_type != CT_HANDSHAKE) { free(sh_raw); rc = 4; goto fail_ts; }

    rc = parse_server_hello(&selected_cipher, server_pub, &negotiated_ver,
                             sh_raw, sh_raw_len);
    if (rc) { free(sh_raw); rc = 4; goto fail_ts; }
    if (negotiated_ver != TLS_VERSION_13) { free(sh_raw); rc = 4; goto fail_ts; }

    /* Add ServerHello to transcript */
    rc = transcript_append(&ts, sh_raw, sh_raw_len);
    free(sh_raw); sh_raw = NULL;
    if (rc) goto fail_ts;

    /* Step 4: Compute shared secret */
    {
        x25519_pubkey srv_pub;
        memcpy(srv_pub.data, server_pub, 32);
        rc = x25519_dh(shared_secret, &eph.priv, &srv_pub);
        if (rc) { rc = 4; goto fail_ts; }
    }
    memset(&eph, 0, sizeof(eph));

    /* Step 5: Derive handshake keys */
    rc = derive_handshake_keys(client_hs_key, client_hs_iv,
                                server_hs_key, server_hs_iv,
                                client_hs_secret, server_hs_secret,
                                handshake_secret,
                                shared_secret, &ts);
    memset(shared_secret, 0, 32);
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 6: Install handshake keys into conn for decryption */
    memcpy(conn->server_write_key, server_hs_key, 16);
    memcpy(conn->server_write_iv,  server_hs_iv,  12);
    memcpy(conn->client_write_key, client_hs_key, 16);
    memcpy(conn->client_write_iv,  client_hs_iv,  12);
    conn->client_seq = 0;
    conn->server_seq = 0;
    conn->cipher_id  = 0; /* AES-128-GCM */

    rc = aes128_init(&conn->server_aes, server_hs_key);
    if (rc) { rc = 4; goto fail_ts; }
    rc = aes128_init(&conn->client_aes, client_hs_key);
    if (rc) { rc = 4; goto fail_ts; }

    /* Derive finished keys for verification */
    rc = hkdf_expand_label(server_finished_key, 32, server_hs_secret, 32,
                            "finished", 8, NULL, 0);
    if (rc) { rc = 4; goto fail_ts; }
    rc = hkdf_expand_label(client_finished_key, 32, client_hs_secret, 32,
                            "finished", 8, NULL, 0);
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 7: Receive EncryptedExtensions */
    rc = recv_handshake_encrypted(&hs_msg, &hs_msg_len, conn);
    if (rc) { rc = 4; goto fail_ts; }
    rc = parse_encrypted_extensions(&alpn_result, hs_msg, hs_msg_len);
    transcript_append(&ts, hs_msg, hs_msg_len);
    free(hs_msg); hs_msg = NULL;
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 8: Receive Certificate */
    rc = recv_handshake_encrypted(&hs_msg, &hs_msg_len, conn);
    if (rc) { rc = 4; goto fail_ts; }
    rc = parse_certificate(&peer_cert, &peer_cert_len, hs_msg, hs_msg_len);
    transcript_append(&ts, hs_msg, hs_msg_len);
    free(hs_msg); hs_msg = NULL;
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 9: Receive CertificateVerify */
    rc = recv_handshake_encrypted(&hs_msg, &hs_msg_len, conn);
    if (rc) { rc = 4; goto fail_ts; }
    rc = parse_certificate_verify(hs_msg, hs_msg_len);
    transcript_append(&ts, hs_msg, hs_msg_len);
    free(hs_msg); hs_msg = NULL;
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 10: Receive Finished */
    rc = recv_handshake_encrypted(&hs_msg, &hs_msg_len, conn);
    if (rc) { rc = 4; goto fail_ts; }

    /* Verify server Finished */
    rc = transcript_hash(th, &ts);
    if (rc) { free(hs_msg); rc = 4; goto fail_ts; }
    rc = parse_finished(hs_msg, hs_msg_len, server_finished_key, th);
    transcript_append(&ts, hs_msg, hs_msg_len);
    free(hs_msg); hs_msg = NULL;
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 11: Send client Finished */
    rc = transcript_hash(th, &ts);
    if (rc) { rc = 4; goto fail_ts; }
    rc = build_finished(finished_buf, &finished_len, client_finished_key, th);
    if (rc) { rc = 4; goto fail_ts; }

    rc = send_encrypted_record(conn, CT_HANDSHAKE, finished_buf, finished_len);
    if (rc) { rc = 4; goto fail_ts; }

    /* Add client Finished to transcript for application key derivation */
    transcript_append(&ts, finished_buf, finished_len);

    /* Step 12: Derive application traffic keys */
    {
        u8 app_c_key[16], app_c_iv[12];
        u8 app_s_key[16], app_s_iv[12];
        rc = derive_application_keys(app_c_key, app_c_iv,
                                      app_s_key, app_s_iv,
                                      handshake_secret, &ts);
        if (rc) { rc = 4; goto fail_ts; }

        memcpy(conn->client_write_key, app_c_key, 16);
        memcpy(conn->client_write_iv,  app_c_iv,  12);
        memcpy(conn->server_write_key, app_s_key, 16);
        memcpy(conn->server_write_iv,  app_s_iv,  12);
        conn->client_seq = 0;
        conn->server_seq = 0;

        rc = aes128_init(&conn->client_aes, app_c_key);
        if (rc) { rc = 4; goto fail_ts; }
        rc = aes128_init(&conn->server_aes, app_s_key);
        if (rc) { rc = 4; goto fail_ts; }
    }

    /* Fill conn metadata */
    conn->handshake_done = 1;
    conn->alpn_selected  = alpn_result;
    conn->peer_cert      = peer_cert;
    conn->peer_cert_len  = peer_cert_len;

    if (selected_cipher == CS_AES_128_GCM_SHA256) {
        conn->cipher_id = 0;
        memcpy(conn->cipher_name, "TLS_AES_128_GCM_SHA256", 23);
    } else if (selected_cipher == CS_AES_256_GCM_SHA384) {
        conn->cipher_id = 1;
        memcpy(conn->cipher_name, "TLS_AES_256_GCM_SHA384", 23);
    } else if (selected_cipher == CS_CHACHA20_POLY1305_SHA256) {
        conn->cipher_id = 2;
        memcpy(conn->cipher_name, "TLS_CHACHA20_POLY1305_SHA256", 29);
    }

    /* Clean up */
    memset(handshake_secret, 0, 32);
    memset(client_hs_secret, 0, 32);
    memset(server_hs_secret, 0, 32);
    memset(server_finished_key, 0, 32);
    memset(client_finished_key, 0, 32);
    transcript_free(&ts);

    *out = conn;
    return 0;

fail_ts:
    transcript_free(&ts);
fail:
    free(conn->alpn_selected);
    free(conn->peer_cert);
    free(conn->read_buf);
    free(conn);
    free(alpn_result);
    free(peer_cert);
    return rc;
}

/* ================================================================
 *  Server handshake
 * ================================================================ */

/* Build ServerHello message */
static unsigned long build_server_hello(u8 **out_msg, u64 *out_msg_len,
                                         u16 cipher_suite,
                                         const u8 *session_id, u8 session_id_len,
                                         const x25519_pubkey *pub_key)
{
    u8 *msg = (u8 *)malloc(1024);
    u64 pos = 0;
    u64 ext_start, ext_len_pos;
    unsigned long rc;

    if (!msg) return 1;

    /* Handshake type + length placeholder */
    msg[pos++] = HT_SERVER_HELLO;
    pos += 3;

    /* server_version (legacy: 0x0303) */
    put_u16(msg + pos, 0x0303); pos += 2;

    /* random (32 bytes) */
    rc = random_bytes(msg + pos, 32);
    if (rc) { free(msg); return 2; }
    pos += 32;

    /* session_id echo */
    msg[pos++] = session_id_len;
    if (session_id_len > 0) {
        memcpy(msg + pos, session_id, session_id_len);
        pos += session_id_len;
    }

    /* cipher suite */
    put_u16(msg + pos, cipher_suite); pos += 2;

    /* compression method (null) */
    msg[pos++] = 0;

    /* Extensions */
    ext_len_pos = pos;
    pos += 2;
    ext_start = pos;

    /* supported_versions */
    put_u16(msg + pos, EXT_SUPPORTED_VERSIONS); pos += 2;
    put_u16(msg + pos, 2); pos += 2;
    put_u16(msg + pos, TLS_VERSION_13); pos += 2;

    /* key_share (X25519) */
    put_u16(msg + pos, EXT_KEY_SHARE); pos += 2;
    put_u16(msg + pos, 2 + 2 + 32); pos += 2;
    put_u16(msg + pos, GROUP_X25519); pos += 2;
    put_u16(msg + pos, 32); pos += 2;
    memcpy(msg + pos, pub_key->data, 32); pos += 32;

    put_u16(msg + ext_len_pos, (u16)(pos - ext_start));
    put_u24(msg + 1, (u32)(pos - 4));

    *out_msg = msg;
    *out_msg_len = pos;
    return 0;
}

/* Build EncryptedExtensions (minimal) */
static unsigned long build_encrypted_extensions(u8 *out, u64 *out_len,
                                                 const char *alpn_selected)
{
    u64 pos = 0;
    u64 ext_start;

    out[pos++] = HT_ENCRYPTED_EXTS;
    pos += 3; /* length placeholder */

    /* Extensions length placeholder */
    u64 ext_len_pos = pos;
    pos += 2;
    ext_start = pos;

    if (alpn_selected && alpn_selected[0]) {
        u64 plen = strlen(alpn_selected);
        put_u16(out + pos, EXT_ALPN); pos += 2;
        put_u16(out + pos, (u16)(plen + 3 + 2)); pos += 2;
        put_u16(out + pos, (u16)(plen + 1)); pos += 2;
        out[pos++] = (u8)plen;
        memcpy(out + pos, alpn_selected, plen);
        pos += plen;
    }

    put_u16(out + ext_len_pos, (u16)(pos - ext_start));
    put_u24(out + 1, (u32)(pos - 4));
    *out_len = pos;
    return 0;
}

/* Build Certificate message from config cert_data (treated as single DER cert) */
static unsigned long build_certificate(u8 *out, u64 *out_len,
                                        const u8 *cert_data, u64 cert_len)
{
    u64 pos = 0;

    out[pos++] = HT_CERTIFICATE;
    pos += 3; /* length placeholder */

    /* certificate_request_context: empty */
    out[pos++] = 0;

    /* certificate_list length: cert_data(3) + cert(n) + extensions(2) */
    put_u24(out + pos, (u32)(3 + cert_len + 2));
    pos += 3;

    /* CertificateEntry */
    put_u24(out + pos, (u32)cert_len);
    pos += 3;
    memcpy(out + pos, cert_data, cert_len);
    pos += cert_len;

    /* Extensions (empty) */
    put_u16(out + pos, 0);
    pos += 2;

    put_u24(out + 1, (u32)(pos - 4));
    *out_len = pos;
    return 0;
}

/* Build a stub CertificateVerify (placeholder — Ed25519 with zero sig) */
static unsigned long build_certificate_verify(u8 *out, u64 *out_len,
                                               const u8 *key_data, u64 key_len,
                                               const u8 *transcript_hash_val)
{
    u64 pos = 0;
    u8 content[130]; /* 64 spaces + 33 context + 1 zero + 32 hash */
    u64 content_len;
    ed25519_keypair kp;
    u8 sig[64];
    unsigned long rc;
    (void)key_data;
    (void)key_len;

    /* Build signature content per RFC 8446 sec 4.4.3 */
    memset(content, 0x20, 64); /* 64 spaces */
    content_len = 64;
    memcpy(content + content_len, "TLS 1.3, server CertificateVerify", 33);
    content_len += 33;
    content[content_len++] = 0;
    memcpy(content + content_len, transcript_hash_val, 32);
    content_len += 32;

    /* For now, sign with an ephemeral Ed25519 key as a placeholder.
     * Real implementation would use the private key from config. */
    rc = ed25519_keygen(&kp);
    if (rc) return rc;
    rc = ed25519_sign(sig, &kp.priv, &kp.pub, content, content_len);
    if (rc) return rc;

    out[pos++] = HT_CERTIFICATE_VERIFY;
    pos += 3; /* length placeholder */
    put_u16(out + pos, SIG_ED25519);
    pos += 2;
    put_u16(out + pos, 64);
    pos += 2;
    memcpy(out + pos, sig, 64);
    pos += 64;

    put_u24(out + 1, (u32)(pos - 4));
    *out_len = pos;
    return 0;
}

/* Parse ClientHello from raw handshake bytes, extract key share and session_id */
static unsigned long parse_client_hello(u8 *out_session_id, u8 *out_session_id_len,
                                         u8 *out_client_pub32,
                                         char **out_alpn_match,
                                         const tls_config *cfg,
                                         const u8 *msg, u64 msg_len)
{
    u64 pos;
    u32 hs_len;
    u8 sid_len;
    u16 cs_list_len;
    u8 comp_len;
    u64 ext_total_len, ext_end;

    *out_alpn_match = NULL;
    *out_session_id_len = 0;

    if (msg_len < 4) return 1;
    if (msg[0] != HT_CLIENT_HELLO) return 2;
    hs_len = get_u24(msg + 1);
    pos = 4;

    /* client_version */
    if (pos + 2 > msg_len) return 3;
    pos += 2;

    /* random */
    if (pos + 32 > msg_len) return 3;
    pos += 32;

    /* session_id */
    if (pos + 1 > msg_len) return 3;
    sid_len = msg[pos++];
    if (pos + sid_len > msg_len) return 3;
    *out_session_id_len = sid_len;
    if (sid_len > 0) memcpy(out_session_id, msg + pos, sid_len);
    pos += sid_len;

    /* cipher_suites */
    if (pos + 2 > msg_len) return 3;
    cs_list_len = get_u16(msg + pos); pos += 2;
    if (pos + cs_list_len > msg_len) return 3;
    pos += cs_list_len;

    /* compression_methods */
    if (pos + 1 > msg_len) return 3;
    comp_len = msg[pos++];
    if (pos + comp_len > msg_len) return 3;
    pos += comp_len;

    /* extensions */
    if (pos + 2 > msg_len) return 0;
    ext_total_len = get_u16(msg + pos); pos += 2;
    ext_end = pos + ext_total_len;
    if (ext_end > msg_len) return 3;

    while (pos + 4 <= ext_end) {
        u16 ext_type = get_u16(msg + pos); pos += 2;
        u16 ext_len  = get_u16(msg + pos); pos += 2;
        if (pos + ext_len > ext_end) return 3;

        if (ext_type == EXT_KEY_SHARE) {
            /* client_shares list */
            u64 shares_end;
            u16 shares_len;
            u64 sp;
            if (ext_len < 2) { pos += ext_len; continue; }
            shares_len = get_u16(msg + pos);
            sp = pos + 2;
            shares_end = sp + shares_len;
            while (sp + 4 <= shares_end) {
                u16 group = get_u16(msg + sp); sp += 2;
                u16 klen  = get_u16(msg + sp); sp += 2;
                if (group == GROUP_X25519 && klen == 32 && sp + 32 <= shares_end) {
                    memcpy(out_client_pub32, msg + sp, 32);
                }
                sp += klen;
            }
        }
        else if (ext_type == EXT_ALPN && cfg->alpn && cfg->alpn_count > 0) {
            /* Try to match one of our ALPN protocols */
            u64 ap = pos;
            u16 list_len;
            u64 list_end;
            if (ext_len < 2) { pos += ext_len; continue; }
            list_len = get_u16(msg + ap); ap += 2;
            list_end = ap + list_len;
            while (ap + 1 <= list_end) {
                u8 plen = msg[ap++];
                if (ap + plen > list_end) break;
                u64 i;
                for (i = 0; i < cfg->alpn_count; i++) {
                    if (strlen(cfg->alpn[i]) == plen &&
                        memcmp(cfg->alpn[i], msg + ap, plen) == 0) {
                        *out_alpn_match = (char *)malloc(plen + 1);
                        if (*out_alpn_match) {
                            memcpy(*out_alpn_match, msg + ap, plen);
                            (*out_alpn_match)[plen] = '\0';
                        }
                        break;
                    }
                }
                ap += plen;
                if (*out_alpn_match) break;
            }
        }
        pos += ext_len;
    }
    return 0;
}

unsigned long tls_conn_create_server(tls_conn **out, tcp_conn *tcp,
                                      tls_config *cfg)
{
    tls_conn *conn;
    x25519_keypair eph;
    transcript_t ts;
    u8 rec_type;
    u8 *ch_raw = NULL;
    u64 ch_raw_len;
    u8 session_id[32];
    u8 session_id_len = 0;
    u8 client_pub[32];
    char *alpn_match = NULL;
    u8 *sh_msg = NULL;
    u64 sh_msg_len;
    u8 shared_secret[32];
    u8 handshake_secret[32];
    u8 client_hs_key[16], client_hs_iv[12];
    u8 server_hs_key[16], server_hs_iv[12];
    u8 client_hs_secret[32], server_hs_secret[32];
    u8 server_finished_key[32], client_finished_key[32];
    u8 enc_ext_buf[512];
    u64 enc_ext_len;
    u8 cert_buf[8192];
    u64 cert_buf_len;
    u8 cv_buf[256];
    u64 cv_len;
    u8 th[32];
    u8 finished_buf[36];
    u64 finished_len;
    u8 *hs_msg = NULL;
    u64 hs_msg_len;
    unsigned long rc;

    if (!out) return 1;
    if (!tcp) return 2;
    if (!cfg) return 3;
    if (!cfg->cert_data || !cfg->key_data) return 5;

    conn = (tls_conn *)calloc(1, sizeof(tls_conn));
    if (!conn) return 6;
    conn->tcp = tcp;
    conn->cfg = cfg;
    conn->is_client = 0;
    conn->version = TLS_VERSION_13;

    /* Step 1: Receive ClientHello */
    rc = recv_record(&rec_type, &ch_raw, &ch_raw_len, tcp);
    if (rc) goto fail;
    if (rec_type != CT_HANDSHAKE) { free(ch_raw); rc = 4; goto fail; }

    rc = parse_client_hello(session_id, &session_id_len, client_pub,
                             &alpn_match, cfg, ch_raw, ch_raw_len);
    if (rc) { free(ch_raw); rc = 4; goto fail; }

    /* Init transcript */
    rc = transcript_init(&ts);
    if (rc) { free(ch_raw); goto fail; }
    transcript_append(&ts, ch_raw, ch_raw_len);
    free(ch_raw); ch_raw = NULL;

    /* Step 2: Generate ephemeral X25519 keypair */
    rc = x25519_keygen(&eph);
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 3: Compute shared secret */
    {
        x25519_pubkey cli_pub;
        memcpy(cli_pub.data, client_pub, 32);
        rc = x25519_dh(shared_secret, &eph.priv, &cli_pub);
        if (rc) { rc = 4; goto fail_ts; }
    }

    /* Step 4: Build and send ServerHello */
    rc = build_server_hello(&sh_msg, &sh_msg_len,
                             CS_AES_128_GCM_SHA256,
                             session_id, session_id_len,
                             &eph.pub);
    memset(&eph, 0, sizeof(eph));
    if (rc) { rc = 4; goto fail_ts; }

    rc = send_record(tcp, CT_HANDSHAKE, 0x0303, sh_msg, sh_msg_len);
    if (rc) { free(sh_msg); rc = 4; goto fail_ts; }
    transcript_append(&ts, sh_msg, sh_msg_len);
    free(sh_msg); sh_msg = NULL;

    /* Optional: send change_cipher_spec for middlebox compat */
    {
        u8 ccs = 1;
        send_record(tcp, CT_CHANGE_CIPHER_SPEC, 0x0303, &ccs, 1);
    }

    /* Step 5: Derive handshake keys */
    rc = derive_handshake_keys(client_hs_key, client_hs_iv,
                                server_hs_key, server_hs_iv,
                                client_hs_secret, server_hs_secret,
                                handshake_secret,
                                shared_secret, &ts);
    memset(shared_secret, 0, 32);
    if (rc) { rc = 4; goto fail_ts; }

    /* Install handshake keys */
    memcpy(conn->server_write_key, server_hs_key, 16);
    memcpy(conn->server_write_iv,  server_hs_iv,  12);
    memcpy(conn->client_write_key, client_hs_key, 16);
    memcpy(conn->client_write_iv,  client_hs_iv,  12);
    conn->client_seq = 0;
    conn->server_seq = 0;
    conn->cipher_id  = 0;

    rc = aes128_init(&conn->server_aes, server_hs_key);
    if (rc) { rc = 4; goto fail_ts; }
    rc = aes128_init(&conn->client_aes, client_hs_key);
    if (rc) { rc = 4; goto fail_ts; }

    /* Derive finished keys */
    rc = hkdf_expand_label(server_finished_key, 32, server_hs_secret, 32,
                            "finished", 8, NULL, 0);
    if (rc) { rc = 4; goto fail_ts; }
    rc = hkdf_expand_label(client_finished_key, 32, client_hs_secret, 32,
                            "finished", 8, NULL, 0);
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 6: Send EncryptedExtensions */
    rc = build_encrypted_extensions(enc_ext_buf, &enc_ext_len, alpn_match);
    if (rc) { rc = 4; goto fail_ts; }
    rc = send_encrypted_record(conn, CT_HANDSHAKE, enc_ext_buf, enc_ext_len);
    if (rc) { rc = 4; goto fail_ts; }
    transcript_append(&ts, enc_ext_buf, enc_ext_len);

    /* Step 7: Send Certificate */
    if (cfg->cert_len + 64 > sizeof(cert_buf)) { rc = 4; goto fail_ts; }
    rc = build_certificate(cert_buf, &cert_buf_len, cfg->cert_data, cfg->cert_len);
    if (rc) { rc = 4; goto fail_ts; }
    rc = send_encrypted_record(conn, CT_HANDSHAKE, cert_buf, cert_buf_len);
    if (rc) { rc = 4; goto fail_ts; }
    transcript_append(&ts, cert_buf, cert_buf_len);

    /* Step 8: Send CertificateVerify */
    rc = transcript_hash(th, &ts);
    if (rc) { rc = 4; goto fail_ts; }
    rc = build_certificate_verify(cv_buf, &cv_len, cfg->key_data, cfg->key_len, th);
    if (rc) { rc = 4; goto fail_ts; }
    rc = send_encrypted_record(conn, CT_HANDSHAKE, cv_buf, cv_len);
    if (rc) { rc = 4; goto fail_ts; }
    transcript_append(&ts, cv_buf, cv_len);

    /* Step 9: Send server Finished */
    rc = transcript_hash(th, &ts);
    if (rc) { rc = 4; goto fail_ts; }
    rc = build_finished(finished_buf, &finished_len, server_finished_key, th);
    if (rc) { rc = 4; goto fail_ts; }
    rc = send_encrypted_record(conn, CT_HANDSHAKE, finished_buf, finished_len);
    if (rc) { rc = 4; goto fail_ts; }
    transcript_append(&ts, finished_buf, finished_len);

    /* Step 10: Receive client Finished */
    rc = recv_handshake_encrypted(&hs_msg, &hs_msg_len, conn);
    if (rc) { rc = 4; goto fail_ts; }

    rc = transcript_hash(th, &ts);
    if (rc) { free(hs_msg); rc = 4; goto fail_ts; }
    rc = parse_finished(hs_msg, hs_msg_len, client_finished_key, th);
    transcript_append(&ts, hs_msg, hs_msg_len);
    free(hs_msg); hs_msg = NULL;
    if (rc) { rc = 4; goto fail_ts; }

    /* Step 11: Derive application traffic keys */
    {
        u8 app_c_key[16], app_c_iv[12];
        u8 app_s_key[16], app_s_iv[12];
        rc = derive_application_keys(app_c_key, app_c_iv,
                                      app_s_key, app_s_iv,
                                      handshake_secret, &ts);
        if (rc) { rc = 4; goto fail_ts; }

        memcpy(conn->client_write_key, app_c_key, 16);
        memcpy(conn->client_write_iv,  app_c_iv,  12);
        memcpy(conn->server_write_key, app_s_key, 16);
        memcpy(conn->server_write_iv,  app_s_iv,  12);
        conn->client_seq = 0;
        conn->server_seq = 0;

        rc = aes128_init(&conn->client_aes, app_c_key);
        if (rc) { rc = 4; goto fail_ts; }
        rc = aes128_init(&conn->server_aes, app_s_key);
        if (rc) { rc = 4; goto fail_ts; }
    }

    /* Done */
    conn->handshake_done = 1;
    conn->alpn_selected  = alpn_match;
    conn->cipher_id      = 0;
    memcpy(conn->cipher_name, "TLS_AES_128_GCM_SHA256", 23);

    memset(handshake_secret, 0, 32);
    memset(client_hs_secret, 0, 32);
    memset(server_hs_secret, 0, 32);
    memset(server_finished_key, 0, 32);
    memset(client_finished_key, 0, 32);
    transcript_free(&ts);

    *out = conn;
    return 0;

fail_ts:
    transcript_free(&ts);
fail:
    free(alpn_match);
    free(conn->read_buf);
    free(conn);
    return rc;
}

/* ================================================================
 *  Data transfer — read / write
 * ================================================================ */

unsigned long tls_conn_read(u64 *bytes_read, tls_conn *conn,
                             u8 *buf, u64 len)
{
    u8 inner_type;
    u8 *data;
    u64 data_len;
    unsigned long rc;

    if (!bytes_read) return 1;
    if (!conn)       return 2;
    if (!buf)        return 3;

    *bytes_read = 0;

    /* First, serve from read buffer if we have leftover data */
    if (conn->read_buf && conn->read_buf_off < conn->read_buf_len) {
        u64 avail = conn->read_buf_len - conn->read_buf_off;
        u64 copy  = avail < len ? avail : len;
        memcpy(buf, conn->read_buf + conn->read_buf_off, copy);
        conn->read_buf_off += copy;
        if (conn->read_buf_off >= conn->read_buf_len) {
            free(conn->read_buf);
            conn->read_buf = NULL;
            conn->read_buf_len = 0;
            conn->read_buf_off = 0;
        }
        *bytes_read = copy;
        return 0;
    }

    /* Receive next encrypted record */
    rc = recv_encrypted_record(&inner_type, &data, &data_len, conn);
    if (rc) return 4;

    if (inner_type == CT_ALERT) {
        /* close_notify or error */
        free(data);
        *bytes_read = 0;
        return 0;
    }

    if (inner_type != CT_APPLICATION_DATA) {
        /* Handshake message post-handshake (e.g. NewSessionTicket) — skip */
        free(data);
        /* Recurse to get actual application data */
        return tls_conn_read(bytes_read, conn, buf, len);
    }

    if (data_len <= len) {
        memcpy(buf, data, data_len);
        *bytes_read = data_len;
        free(data);
    } else {
        /* Buffer the rest */
        memcpy(buf, data, len);
        *bytes_read = len;
        conn->read_buf = data;
        conn->read_buf_len = data_len;
        conn->read_buf_off = len;
        /* data is now owned by conn */
        return 0;
    }

    return 0;
}

unsigned long tls_conn_write(u64 *bytes_written, tls_conn *conn,
                              const u8 *data, u64 len)
{
    unsigned long rc;

    if (!bytes_written) return 1;
    if (!conn)          return 2;
    if (!data && len)   return 3;

    *bytes_written = 0;

    /* Fragment into TLS records of max 16384 bytes */
    if (len > TLS_RECORD_MAX) len = TLS_RECORD_MAX;

    rc = send_encrypted_record(conn, CT_APPLICATION_DATA, data, len);
    if (rc) return 4;

    *bytes_written = len;
    return 0;
}

unsigned long tls_conn_write_all(u64 *bytes_written, tls_conn *conn,
                                  const u8 *data, u64 len)
{
    u64 total = 0;
    unsigned long rc;

    if (!bytes_written) return 1;
    if (!conn)          return 2;
    if (!data && len)   return 3;

    while (total < len) {
        u64 chunk = len - total;
        u64 sent;
        if (chunk > TLS_RECORD_MAX) chunk = TLS_RECORD_MAX;
        rc = tls_conn_write(&sent, conn, data + total, chunk);
        if (rc) { *bytes_written = total; return rc; }
        total += sent;
    }

    *bytes_written = total;
    return 0;
}

/* ================================================================
 *  Connection info / shutdown / destroy
 * ================================================================ */

unsigned long tls_conn_peer_cert(const u8 **out, u64 *out_len, tls_conn *conn) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!conn)    return 3;
    *out     = conn->peer_cert;
    *out_len = conn->peer_cert_len;
    return 0;
}

unsigned long tls_conn_alpn_selected(const char **out, tls_conn *conn) {
    if (!out)  return 1;
    if (!conn) return 2;
    *out = conn->alpn_selected;
    return 0;
}

unsigned long tls_conn_cipher(const char **out, tls_conn *conn) {
    if (!out)  return 1;
    if (!conn) return 2;
    *out = conn->cipher_name;
    return 0;
}

unsigned long tls_conn_version(u16 *out, tls_conn *conn) {
    if (!out)  return 1;
    if (!conn) return 2;
    *out = conn->version;
    return 0;
}

unsigned long tls_conn_shutdown(tls_conn *conn) {
    u8 alert[2];
    if (!conn) return 1;
    /* Send close_notify alert */
    alert[0] = ALERT_WARNING;
    alert[1] = ALERT_CLOSE_NOTIFY;
    return send_encrypted_record(conn, CT_ALERT, alert, 2);
}

unsigned long tls_conn_destroy(tls_conn *conn) {
    if (!conn) return 1;

    /* Zero key material */
    memset(conn->client_write_key, 0, 32);
    memset(conn->server_write_key, 0, 32);
    memset(conn->client_write_iv,  0, 12);
    memset(conn->server_write_iv,  0, 12);

    free(conn->alpn_selected);
    free(conn->peer_cert);
    free(conn->read_buf);
    free(conn);
    return 0;
}
