#include "apennines/ssh.h"
#include "apennines/tcp.h"
#include "apennines/addr.h"
#include "apennines/hash.h"
#include "apennines/ec.h"
#include "apennines/cipher.h"
#include <stdlib.h>
#include <string.h>

/* ================================================================
 *  SSH Transport — RFC 4253/4252 client implementation
 * ================================================================ */

/* ---- SSH message types ---- */
#define SSH_MSG_DISCONNECT           1
#define SSH_MSG_KEXINIT             20
#define SSH_MSG_NEWKEYS             21
#define SSH_MSG_KEX_ECDH_INIT      30
#define SSH_MSG_KEX_ECDH_REPLY     31
#define SSH_MSG_USERAUTH_REQUEST   50
#define SSH_MSG_USERAUTH_FAILURE   51
#define SSH_MSG_USERAUTH_SUCCESS   52
#define SSH_MSG_CHANNEL_OPEN       90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM 91
#define SSH_MSG_CHANNEL_OPEN_FAIL  92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA       94
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

    /* Channel tracking */
    ssh_channel **channels;
    u64           channel_count;
    u64           channel_cap;
    u32           next_channel_id;
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

    /* minimum 4 bytes padding, total (4+1+payload+pad) must be multiple of block_size */
    unpadded = 4 + 1 + payload_len;
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
        u8 seq_buf[4];
        u64 enc_len = total_len - 4;  /* encrypt everything after length field */

        /* Build nonce: IV XOR sequence number (in big-endian, zero-padded to 12 bytes) */
        memcpy(nonce, conn->iv_c2s, 12);
        put_u32(seq_buf, (u32)conn->seq_c2s);
        nonce[8]  ^= seq_buf[0];
        nonce[9]  ^= seq_buf[1];
        nonce[10] ^= seq_buf[2];
        nonce[11] ^= seq_buf[3];

        /* AAD = packet_length (first 4 bytes, unencrypted) */
        if (aes256_gcm_encrypt(enc_buf, tag, &conn->aes_c2s,
                               nonce, pkt, 4,
                               pkt + 4, enc_len) != 0) return 2;

        /* Send: length(4) + encrypted_body + tag(16) */
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
        u8 seq_buf[4];

        if (tcp_recv_exact(&conn->tcp, enc_body, packet_length) != 0) return 1;
        if (tcp_recv_exact(&conn->tcp, tag, 16) != 0) return 1;

        memcpy(nonce, conn->iv_s2c, 12);
        put_u32(seq_buf, (u32)conn->seq_s2c);
        nonce[8]  ^= seq_buf[0];
        nonce[9]  ^= seq_buf[1];
        nonce[10] ^= seq_buf[2];
        nonce[11] ^= seq_buf[3];

        if (aes256_gcm_decrypt(body, &conn->aes_s2c,
                               nonce, hdr, 4,
                               enc_body, packet_length,
                               tag) != 0) return 3;
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

/* Read helpers for received payloads */
typedef struct {
    const u8 *data;
    u64       len;
    u64       pos;
} pkt_reader;

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

    /* Send our version */
    if (tcp_send_all(&conn->tcp, (const u8 *)ver, (u64)strlen(ver)) != 0) return 1;

    /* Read server version line (ends with \r\n or \n) */
    while (pos < sizeof(buf) - 1) {
        if (tcp_conn_read(&rd, &conn->tcp, buf + pos, 1) != 0) return 2;
        if (rd == 0) return 2;
        if (buf[pos] == '\n') {
            buf[pos + 1] = '\0';
            break;
        }
        pos++;
    }

    /* Verify it starts with "SSH-2.0-" */
    if (pos < 8) return 3;
    if (memcmp(buf, "SSH-2.0-", 8) != 0) return 3;

    return 0;
}

/* ================================================================
 *  KEXINIT construction
 * ================================================================ */

static void build_kexinit(pkt_buf *pb) {
    u8 cookie[16];
    memset(cookie, 0x42, 16);  /* non-random cookie for simplicity */

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
 *  Key derivation (RFC 4253 section 7.2)
 * ================================================================ */

static unsigned long derive_key(u8 *out, u64 out_len,
                                const u8 *shared_secret, u64 ss_len,
                                const u8 *exchange_hash,
                                u8 letter,
                                const u8 *session_id, u64 sid_len) {
    sha256_ctx ctx;
    u8 hash[32];
    u8 ss_buf[SSH_MAX_PACKET];
    pkt_buf sb;

    /* Encode shared secret as SSH mpint */
    pb_init(&sb, ss_buf, sizeof(ss_buf));
    pb_string(&sb, shared_secret, ss_len);

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
 * ================================================================ */

static unsigned long ssh_key_exchange(ssh_conn *conn) {
    u8 payload[SSH_MAX_PACKET];
    u64 payload_len;
    pkt_buf pb;
    x25519_keypair ephemeral;
    u8 shared_secret[X25519_SHARED_LEN];
    u8 exchange_hash[32];
    sha256_ctx hctx;

    /* 1. Send our KEXINIT */
    pb_init(&pb, payload, sizeof(payload));
    build_kexinit(&pb);
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 1;

    /* 2. Receive server KEXINIT */
    if (ssh_recv_packet(conn, payload, sizeof(payload), &payload_len) != 0) return 2;
    if (payload_len < 1 || payload[0] != SSH_MSG_KEXINIT) return 2;

    /* 3. Generate ephemeral X25519 keypair */
    if (x25519_keygen(&ephemeral) != 0) return 3;

    /* 4. Send KEX_ECDH_INIT with our public key */
    pb_init(&pb, payload, sizeof(payload));
    pb_u8(&pb, SSH_MSG_KEX_ECDH_INIT);
    pb_string(&pb, ephemeral.pub.data, X25519_KEY_LEN);
    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 4;

    /* 5. Receive KEX_ECDH_REPLY */
    if (ssh_recv_packet(conn, payload, sizeof(payload), &payload_len) != 0) return 5;
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

        /* 7. Compute exchange hash H = SHA-256(...) — simplified:
         *    hash(shared_secret || server_pub || client_pub || host_key)
         *    A real implementation hashes the full transcript per RFC 4253 s8. */
        if (sha256_init(&hctx) != 0) return 7;
        if (sha256_update(&hctx, shared_secret, X25519_SHARED_LEN) != 0) return 7;
        if (sha256_update(&hctx, server_pub.data, X25519_KEY_LEN) != 0) return 7;
        if (sha256_update(&hctx, ephemeral.pub.data, X25519_KEY_LEN) != 0) return 7;
        if (sha256_update(&hctx, host_key_blob, hk_len) != 0) return 7;
        if (sha256_final(exchange_hash, &hctx) != 0) return 7;

        /* Session ID = first exchange hash */
        memcpy(conn->session_id, exchange_hash, 32);
        conn->session_id_len = 32;

        /* 8. Verify host key signature (Ed25519) */
        {
            pkt_reader skr;
            const u8 *key_type_str, *ed_pub_raw;
            u64 kt_len, ep_len;
            ed25519_pubkey host_pub;
            unsigned long valid = 0;

            /* Parse host key blob: string "ssh-ed25519" + string pubkey(32) */
            pr_init(&skr, host_key_blob, hk_len);
            if (pr_string(&skr, &key_type_str, &kt_len) != 0) return 5;
            if (pr_string(&skr, &ed_pub_raw, &ep_len) != 0) return 5;
            if (ep_len != ED25519_PUBKEY_LEN) return 5;
            memcpy(host_pub.data, ed_pub_raw, ED25519_PUBKEY_LEN);

            /* Parse signature blob: string "ssh-ed25519" + string sig(64) */
            {
                pkt_reader sigr;
                const u8 *sig_type_str, *sig_raw;
                u64 st_len, sr_len;

                pr_init(&sigr, sig_blob, sig_len);
                if (pr_string(&sigr, &sig_type_str, &st_len) != 0) return 5;
                if (pr_string(&sigr, &sig_raw, &sr_len) != 0) return 5;
                if (sr_len != ED25519_SIG_LEN) return 5;

                if (ed25519_verify(&valid, &host_pub, sig_raw,
                                   exchange_hash, 32) != 0) return 8;
                if (!valid) return 8;
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
    if (ssh_recv_packet(conn, payload, sizeof(payload), &payload_len) != 0) return 11;
    if (payload_len < 1 || payload[0] != SSH_MSG_NEWKEYS) return 11;

    /* 12. Initialize AES-256-GCM contexts and switch to encrypted mode */
    if (aes256_init(&conn->aes_c2s, conn->enc_key_c2s) != 0) return 12;
    if (aes256_init(&conn->aes_s2c, conn->enc_key_s2c) != 0) return 12;
    conn->encrypted = 1;

    /* Scrub shared secret from stack */
    memset(shared_secret, 0, sizeof(shared_secret));

    return 0;
}

/* ================================================================
 *  ssh_conn_create
 * ================================================================ */

unsigned long ssh_conn_create(ssh_conn **out,
                                             const char *host, u16 port) {
    ssh_conn *conn;
    net_sock_addr addr;
    unsigned long rc;

    if (!out)  return 1;
    if (!host) return 2;

    conn = (ssh_conn *)calloc(1, sizeof(ssh_conn));
    if (!conn) return 6;

    /* Resolve and connect via TCP */
    rc = addr_sockaddr_create(&addr, host, port);
    if (rc != 0) { free(conn); return 3; }

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

    /* Key exchange */
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
    if (ssh_recv_packet(conn, payload, sizeof(payload), &payload_len) != 0) return 5;
    if (payload_len < 1) return 5;

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
    if (privkey_len != ED25519_PRIVKEY_LEN) return 3;

    memcpy(epriv.data, privkey, ED25519_PRIVKEY_LEN);
    if (ed25519_pubkey_from_privkey(&epub, &epriv) != 0) return 5;

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

    if (ssh_send_packet(conn, pb.buf, pb.len) != 0) return 6;

    /* Receive response */
    if (ssh_recv_packet(conn, payload, sizeof(payload), &payload_len) != 0) return 6;
    if (payload_len < 1) return 6;

    if (payload[0] == SSH_MSG_USERAUTH_SUCCESS) return 0;
    if (payload[0] == SSH_MSG_USERAUTH_FAILURE) return 4;

    /* Scrub private key material */
    memset(epriv.data, 0, ED25519_PRIVKEY_LEN);
    memset(sig, 0, ED25519_SIG_LEN);

    return 6;
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
    if (ssh_recv_packet(conn, payload, sizeof(payload), &payload_len) != 0) {
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
            if (ssh_recv_packet(ch->conn, rxbuf, sizeof(rxbuf), &rxlen) != 0) return 5;
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

        if (ssh_recv_packet(ch->conn, pkt, sizeof(pkt), &pkt_len) != 0) return 4;
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
        if (ssh_recv_packet(ch->conn, payload, sizeof(payload), &payload_len) != 0)
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
