/*
 * Git over SSH transport (RFC 4253/4252/4254 + git-upload-pack /
 * git-receive-pack). Mirrors remote.c's HTTP smart-protocol code
 * path for path — same pkt-line framing, same want/have/done dance,
 * same sideband-64k pack extraction.
 *
 * URL forms:
 *   git@host:path              (scp-like; path not absolute)
 *   ssh://user@host/path       (URL form)
 *   ssh://user@host:port/path  (URL form with non-default port)
 *
 * Key source priority (ed25519 seed — 32 raw bytes):
 *   1. GUT_SSH_PRIVKEY_HEX  env — 64 hex chars of seed
 *   2. GUT_SSH_PRIVKEY_FILE env — path to raw 32-byte file OR OpenSSH PEM
 *   3. ~/.ssh/id_ed25519          — standard OpenSSH location
 */

#include "gut/remote.h"
#include "apennines/ssh_known_hosts.h"
#include "apennines/ssh.h"
#include "apennines/buf.h"
#include "apennines/pem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

/* ====================================================================
 *  URL parsing
 * ==================================================================== */

typedef struct {
    char user[256];
    char host[256];
    char path[1024];
    u16  port;
} ssh_url_parts;

/* Return non-zero if `url` looks like an SSH URL (either scp-like
 * "user@host:path" or "ssh://..."). */
int url_is_ssh(const char *url) {
    const char *at, *slash, *colon;
    if (!url) return 0;
    if (strncmp(url, "ssh://", 6) == 0) return 1;
    /* scp-like: "<user>@<host>:<path>". The colon must come before any
     * slash (otherwise a path like http://example.com:8080/ would
     * match). */
    at    = strchr(url, '@');
    slash = strchr(url, '/');
    colon = strchr(url, ':');
    if (!at || !colon || colon <= at) return 0;
    if (slash && slash < colon) return 0;
    /* Protect http:// / https:// from matching — the colon there is
     * in the scheme, before the '@' (which rules it out above), but
     * defensive. */
    return 1;
}

/* Parse either URL form into parts. Returns 0 on success. */
static unsigned long url_parse_ssh(ssh_url_parts *out, const char *url) {
    if (!out || !url) return __LINE__;
    out->user[0] = '\0';
    out->host[0] = '\0';
    out->path[0] = '\0';
    out->port = 22;

    if (strncmp(url, "ssh://", 6) == 0) {
        /* ssh://[user@]host[:port]/path */
        const char *p = url + 6;
        const char *at = strchr(p, '@');
        const char *host_start;
        const char *slash;
        const char *colon;

        if (at) {
            u64 ulen = (u64)(at - p);
            if (ulen >= sizeof(out->user)) return __LINE__;
            memcpy(out->user, p, ulen);
            out->user[ulen] = '\0';
            host_start = at + 1;
        } else {
            host_start = p;
            snprintf(out->user, sizeof(out->user), "git");
        }

        slash = strchr(host_start, '/');
        if (!slash) return __LINE__;

        /* host[:port] is host_start..slash */
        colon = NULL;
        {
            const char *c;
            for (c = host_start; c < slash; c++) {
                if (*c == ':') { colon = c; break; }
            }
        }
        {
            u64 hlen;
            if (colon) {
                hlen = (u64)(colon - host_start);
                out->port = (u16)atoi(colon + 1);
                if (out->port == 0) out->port = 22;
            } else {
                hlen = (u64)(slash - host_start);
            }
            if (hlen >= sizeof(out->host)) return __LINE__;
            memcpy(out->host, host_start, hlen);
            out->host[hlen] = '\0';
        }
        /* Path: keep the leading slash — servers like github expect it. */
        if (strlen(slash) >= sizeof(out->path)) return __LINE__;
        snprintf(out->path, sizeof(out->path), "%s", slash);
        return 0;
    }

    /* scp-like: user@host:path */
    {
        const char *at = strchr(url, '@');
        const char *colon = strchr(url, ':');
        u64 ulen, hlen;
        if (!at || !colon || colon <= at) return __LINE__;

        ulen = (u64)(at - url);
        if (ulen >= sizeof(out->user)) return __LINE__;
        memcpy(out->user, url, ulen);
        out->user[ulen] = '\0';

        hlen = (u64)(colon - (at + 1));
        if (hlen >= sizeof(out->host)) return __LINE__;
        memcpy(out->host, at + 1, hlen);
        out->host[hlen] = '\0';

        /* scp-like path is relative; we don't inject a leading slash.
         * GitHub/Gitea accept both "user/repo.git" and "/user/repo.git"
         * when the exec command quotes them. */
        if (strlen(colon + 1) >= sizeof(out->path)) return __LINE__;
        snprintf(out->path, sizeof(out->path), "%s", colon + 1);
        return 0;
    }
}

/* ====================================================================
 *  ed25519 seed loader
 * ==================================================================== */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static unsigned long seed_from_hex(u8 *out32, const char *hex) {
    int i;
    if (!hex) return __LINE__;
    if (strlen(hex) != 64) return __LINE__;
    for (i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return __LINE__;
        out32[i] = (u8)((hi << 4) | lo);
    }
    return 0;
}

/* Read uint32 big-endian from `p`, advance `*p` past it. */
static u32 read_u32_be(const u8 **p, const u8 *end) {
    u32 v;
    if (end - *p < 4) return 0;
    v = ((u32)(*p)[0] << 24) | ((u32)(*p)[1] << 16) |
        ((u32)(*p)[2] <<  8) | ((u32)(*p)[3]);
    *p += 4;
    return v;
}

/* Read a length-prefixed SSH string, point `*str` at its bytes and
 * write its length into `*len`. Advances `*p`. Returns 0 on success. */
static int read_ssh_string(const u8 **str, u32 *len,
                           const u8 **p, const u8 *end) {
    u32 L;
    if (end - *p < 4) return -1;
    L = read_u32_be(p, end);
    if ((u64)L > (u64)(end - *p)) return -1;
    *str = *p;
    *len = L;
    *p += L;
    return 0;
}

/* Parse OpenSSH ed25519 private key (unencrypted only) and return the
 * 32-byte seed. See PROTOCOL.key in the OpenSSH source:
 *
 *   magic:            "openssh-key-v1\0"        (15 bytes)
 *   string ciphername                           "none" for unencrypted
 *   string kdfname                              "none" for unencrypted
 *   string kdfoptions                           "" for unencrypted
 *   uint32 numkeys                              always 1 in practice
 *   string publickeyblob
 *   string privatekeypayload                    (encrypted if cipher != "none")
 *     within:
 *       uint32 checkint
 *       uint32 checkint                         (must equal prev)
 *       string keytype                          "ssh-ed25519"
 *       string pubkey                           32 bytes
 *       string privkey                          64 bytes = seed(32) || pubkey(32)
 *       string comment
 *       padding
 */
static unsigned long parse_openssh_ed25519(u8 *out32,
                                           const u8 *raw, u64 raw_len) {
    const u8 *p = raw;
    const u8 *end = raw + raw_len;
    const u8 *s;
    u32 L;
    u32 numkeys;
    u32 c1, c2;
    static const char MAGIC[] = "openssh-key-v1";
    const u64 mlen = sizeof(MAGIC); /* 15 — includes trailing NUL */

    if (raw_len < mlen) return __LINE__;
    if (memcmp(raw, MAGIC, mlen) != 0) return __LINE__;
    p += mlen;

    /* ciphername */
    if (read_ssh_string(&s, &L, &p, end)) return __LINE__;
    if (L != 4 || memcmp(s, "none", 4) != 0) {
        /* Encrypted key — would need passphrase + bcrypt-pbkdf. */
        return __LINE__;
    }
    /* kdfname */
    if (read_ssh_string(&s, &L, &p, end)) return __LINE__;
    if (L != 4 || memcmp(s, "none", 4) != 0) return __LINE__;
    /* kdfoptions */
    if (read_ssh_string(&s, &L, &p, end)) return __LINE__;
    /* numkeys */
    if (end - p < 4) return __LINE__;
    numkeys = read_u32_be(&p, end);
    if (numkeys != 1) return __LINE__;
    /* public key blob — skip */
    if (read_ssh_string(&s, &L, &p, end)) return __LINE__;
    /* private key payload — re-enter to read its internal fields */
    if (read_ssh_string(&s, &L, &p, end)) return __LINE__;
    {
        const u8 *pp = s;
        const u8 *pe = s + L;
        const u8 *priv_blob;
        u32 priv_len;

        if (pe - pp < 8) return __LINE__;
        c1 = read_u32_be(&pp, pe);
        c2 = read_u32_be(&pp, pe);
        if (c1 != c2) return __LINE__;   /* decryption sanity check */
        /* key type */
        if (read_ssh_string(&s, &L, &pp, pe)) return __LINE__;
        if (L != 11 || memcmp(s, "ssh-ed25519", 11) != 0) return __LINE__;
        /* pubkey — skip */
        if (read_ssh_string(&s, &L, &pp, pe)) return __LINE__;
        if (L != 32) return __LINE__;
        /* privkey — first 32 bytes are the seed, last 32 the pubkey */
        if (read_ssh_string(&priv_blob, &priv_len, &pp, pe)) return __LINE__;
        if (priv_len != 64) return __LINE__;
        memcpy(out32, priv_blob, 32);
    }
    return 0;
}

/* Read file bytes into a freshly-allocated buffer. Caller frees. */
static unsigned long slurp_file(u8 **out, u64 *out_len, const char *path) {
    FILE *fp;
    long sz;
    u8 *bytes;
    size_t got;

    fp = fopen(path, "rb");
    if (!fp) return __LINE__;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return __LINE__; }
    sz = ftell(fp);
    if (sz < 0) { fclose(fp); return __LINE__; }
    rewind(fp);
    bytes = (u8 *)malloc((size_t)sz + 1);
    if (!bytes) { fclose(fp); return __LINE__; }
    got = fread(bytes, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) { free(bytes); return __LINE__; }
    bytes[sz] = '\0';
    *out = bytes;
    *out_len = (u64)sz;
    return 0;
}

static unsigned long load_from_file(u8 *out32, const char *path) {
    u8 *bytes = NULL;
    u64 len = 0;
    unsigned long rc;
    int verbose = getenv("GUT_SSH_DEBUG") != NULL;

    rc = slurp_file(&bytes, &len, path);
    if (verbose) fprintf(stderr, "[ssh] slurp_file(%s) rc=%lu len=%llu\n",
                         path, rc, (unsigned long long)len);
    if (rc) return __LINE__;

    /* Raw 32-byte file? */
    if (len == 32) {
        memcpy(out32, bytes, 32);
        free(bytes);
        return 0;
    }

    /* OpenSSH PEM? */
    {
        char label[64];
        buf decoded;
        if (buf_create(&decoded, len)) { free(bytes); return __LINE__; }
        rc = pem_decode(&decoded, label, sizeof(label), bytes, len);
        free(bytes);
        if (verbose) fprintf(stderr, "[ssh] pem_decode rc=%lu label=%s\n",
                             rc, rc == 0 ? label : "?");
        if (rc) { buf_destroy(&decoded); return __LINE__; }
        if (strcmp(label, "OPENSSH PRIVATE KEY") != 0) {
            buf_destroy(&decoded);
            return __LINE__;
        }
        rc = parse_openssh_ed25519(out32, decoded.data, decoded.len);
        if (verbose) fprintf(stderr, "[ssh] parse_openssh_ed25519 rc=%lu decoded_len=%llu\n",
                             rc, (unsigned long long)decoded.len);
        buf_destroy(&decoded);
        if (rc) return __LINE__;
    }
    return 0;
}

static unsigned long resolve_home_ssh_path(char *out, u64 out_size,
                                           const char *basename) {
    const char *home = getenv("HOME");
#ifdef _WIN32
    const char *up, *hp;
    char home_buf[1024];
    if (!home) {
        up = getenv("USERPROFILE");
        if (up) {
            snprintf(home_buf, sizeof(home_buf), "%s", up);
            home = home_buf;
        } else {
            hp = getenv("HOMEDRIVE");
            if (hp) {
                const char *hpath = getenv("HOMEPATH");
                if (hpath) {
                    snprintf(home_buf, sizeof(home_buf), "%s%s", hp, hpath);
                    home = home_buf;
                }
            }
        }
    }
#endif
    if (!home) return __LINE__;
    if ((u64)snprintf(out, (size_t)out_size, "%s/.ssh/%s", home, basename)
        >= out_size) return __LINE__;
    return 0;
}

static unsigned long load_ed25519_seed(u8 *out32) {
    const char *e;
    char home_path[1024];
    unsigned long rc;
    int verbose = getenv("GUT_SSH_DEBUG") != NULL;

    e = getenv("GUT_SSH_PRIVKEY_HEX");
    if (e && *e) {
        rc = seed_from_hex(out32, e);
        if (verbose) fprintf(stderr, "[ssh] seed_from_hex rc=%lu\n", rc);
        return rc;
    }
    e = getenv("GUT_SSH_PRIVKEY_FILE");
    if (e && *e) {
        rc = load_from_file(out32, e);
        if (verbose) fprintf(stderr, "[ssh] load_from_file(%s) rc=%lu\n", e, rc);
        return rc;
    }
    rc = resolve_home_ssh_path(home_path, sizeof(home_path), "id_ed25519");
    if (verbose) fprintf(stderr, "[ssh] resolve_home rc=%lu path=%s\n", rc, home_path);
    if (rc) return __LINE__;
    rc = load_from_file(out32, home_path);
    if (verbose) fprintf(stderr, "[ssh] load_from_file(%s) rc=%lu\n", home_path, rc);
    return rc;
}

/* ====================================================================
 *  Pkt-line helpers (local to the SSH path — remote.c has its own
 *  but they're static). Kept tiny and in sync with that file.
 * ==================================================================== */

static u32 pktline_len(const u8 *data) {
    u32 val = 0;
    int i;
    for (i = 0; i < 4; i++) {
        u8 c = data[i];
        val <<= 4;
        if (c >= '0' && c <= '9') val |= (c - '0');
        else if (c >= 'a' && c <= 'f') val |= (10 + c - 'a');
        else if (c >= 'A' && c <= 'F') val |= (10 + c - 'A');
        else return 0;
    }
    return val;
}

static unsigned long pktline_write_ch(ssh_channel *ch, const char *line) {
    u64 len = strlen(line);
    u64 pkt_len = len + 5;
    char hdr[5];
    u64 w;
    snprintf(hdr, sizeof(hdr), "%04x", (unsigned)pkt_len);
    if (ssh_channel_write(&w, ch, (const u8 *)hdr, 4)) return __LINE__;
    if (ssh_channel_write(&w, ch, (const u8 *)line, len)) return __LINE__;
    if (ssh_channel_write(&w, ch, (const u8 *)"\n", 1)) return __LINE__;
    return 0;
}

static unsigned long pktline_flush_ch(ssh_channel *ch) {
    u64 w;
    if (ssh_channel_write(&w, ch, (const u8 *)"0000", 4)) return __LINE__;
    return 0;
}

/* ====================================================================
 *  Channel reader that accumulates everything the remote sends until
 *  EOF. Cleaner than mixing reads with pkt-line parsing, and matches
 *  the HTTP path which already works on a full response buffer.
 * ==================================================================== */

/* Scan a pkt-line stream starting at offset 0 for a flush packet
 * (length "0000"). Returns 1 if a flush is present AND the walk up to
 * it is consistent (each pkt-line's length points at the next valid
 * pkt-line). Returns 0 if no flush yet OR the walk is still
 * incomplete (needs more bytes). This is how we know an SSH
 * git-upload-pack refs advertisement is fully received — the
 * advertisement always ends with a flush. */
static int has_pktline_flush(const u8 *buf_data, u64 len) {
    u64 pos = 0;
    while (pos + 4 <= len) {
        u32 plen = pktline_len(buf_data + pos);
        if (plen == 0) return 1;
        if (plen < 4) return 0;
        if (pos + plen > len) return 0;
        pos += plen;
    }
    return 0;
}

/* Drain a channel until one of:
 *   mode = DRAIN_UNTIL_PKTLINE_FLUSH — stop when a pkt-line flush
 *     packet (0000) is found in the accumulated stdout buffer (used
 *     for the refs advertisement phase)
 *   mode = DRAIN_UNTIL_CLOSED — stop when ssh_channel_is_closed
 *     reports 1 (CHANNEL_EOF or CHANNEL_CLOSE arrived), used for the
 *     pack data phase
 * stderr is always polled and written to the user's stderr, so
 * git-upload-pack error messages aren't lost. */
#define DRAIN_UNTIL_PKTLINE_FLUSH  1
#define DRAIN_UNTIL_CLOSED         2

static unsigned long drain_channel_until(u8 **out, u64 *out_len,
                                         ssh_channel *ch, int mode) {
    buf b;
    u8 chunk[8192];
    u64 n;
    unsigned long rc;

    if (buf_create(&b, 8192)) return __LINE__;

    for (;;) {
        rc = ssh_channel_read(&n, ch, chunk, sizeof(chunk));
        if (rc) break;
        if (n > 0) {
            if (buf_append(&b, chunk, n)) { buf_destroy(&b); return __LINE__; }
        }

        {
            u64 en;
            u8 echunk[1024];
            if (ssh_channel_read_stderr(&en, ch, echunk, sizeof(echunk)) == 0 &&
                en > 0) {
                fwrite(echunk, 1, (size_t)en, stderr);
            }
        }

        if (mode == DRAIN_UNTIL_PKTLINE_FLUSH) {
            /* As soon as we see a complete pkt-line flush in the
             * accumulated buffer, we're done with this phase — the
             * server is now waiting for our wants/haves/done. */
            if (has_pktline_flush(b.data, b.len)) break;
        } else /* DRAIN_UNTIL_CLOSED */ {
            int closed = 0;
            if (ssh_channel_is_closed(&closed, ch) == 0 && closed) break;
        }
    }

    *out = b.data;
    *out_len = b.len;
    return 0;
}

/* Back-compat wrapper used by the legacy code paths. New call sites
 * should pass a mode explicitly. */
static unsigned long drain_channel(u8 **out, u64 *out_len, ssh_channel *ch) {
    return drain_channel_until(out, out_len, ch, DRAIN_UNTIL_CLOSED);
}

/* ====================================================================
 *  Low-level: open ssh conn, auth, channel, exec <command>
 * ==================================================================== */

/* Verifier context — passed through ssh_conn_create_ex to our
 * host-key-pinning callback. Carries the parsed known_hosts plus an
 * opt-in TOFU flag (when set, unknown hosts are accepted on first
 * use and appended to the known_hosts file). */
typedef struct {
    ssh_khosts *khosts;
    char        path[1024];   /* known_hosts path we loaded from */
    int         tofu_accept;  /* non-zero → accept UNKNOWN and append */
    int         verbose;
} verify_ctx_t;

/* Verifier called by apennines during KEX, after the server's sig
 * is verified and before transport keys derive. Returning non-zero
 * aborts ssh_conn_create_ex with hatch 5 sub 8.
 *
 * hostkey_blob is the SSH wire blob: string("ssh-ed25519") + string(pub).
 * We only support ed25519 here — other key types are treated as
 * UNKNOWN (equivalent to TOFU). */
static unsigned long gut_ssh_verifier(void *ctx, const char *host, u16 port,
                                      const u8 *hostkey_blob, u64 blob_len) {
    verify_ctx_t *v = (verify_ctx_t *)ctx;
    ssh_khosts_match m;
    const u8 *pub;

    if (!v || !v->khosts) return 0;  /* no pinning configured → accept */

    /* Crack the blob: 4B len(11) "ssh-ed25519" 4B len(32) 32B pub */
    if (blob_len != 4 + 11 + 4 + 32) {
        if (v->verbose) fprintf(stderr,
            "[ssh] host key is not ssh-ed25519 (blob_len=%llu) — accepting under TOFU\n",
            (unsigned long long)blob_len);
        return 0;
    }
    {
        u32 tlen = ((u32)hostkey_blob[0] << 24) |
                   ((u32)hostkey_blob[1] << 16) |
                   ((u32)hostkey_blob[2] << 8)  | (u32)hostkey_blob[3];
        if (tlen != 11 || memcmp(hostkey_blob + 4, "ssh-ed25519", 11) != 0) {
            if (v->verbose) fprintf(stderr,
                "[ssh] host key type not ssh-ed25519 — accepting under TOFU\n");
            return 0;
        }
    }
    pub = hostkey_blob + 4 + 11 + 4;

    if (ssh_khosts_lookup_ed25519(&m, v->khosts, host, port, pub) != 0) {
        fprintf(stderr, "error: ssh_khosts_lookup_ed25519 failed\n");
        return 1;
    }

    switch (m) {
        case SSH_KHOSTS_MATCH_PINNED:
            if (v->verbose)
                fprintf(stderr, "[ssh] host key PINNED for %s:%u\n", host, port);
            return 0;
        case SSH_KHOSTS_MATCH_MISMATCH:
            fprintf(stderr,
                "error: host key mismatch for %s:%u — possible MITM, "
                "refusing connection\n", host, port);
            fprintf(stderr,
                "  if the remote legitimately rotated its key, remove the "
                "old entry from %s first\n", v->path);
            return 2;
        case SSH_KHOSTS_MATCH_REVOKED:
            fprintf(stderr,
                "error: host key for %s:%u is @revoked — refusing connection\n",
                host, port);
            return 3;
        case SSH_KHOSTS_MATCH_UNKNOWN:
        default:
            if (v->tofu_accept) {
                if (v->verbose || 1)
                    fprintf(stderr,
                        "warning: unknown host %s:%u — pinning key on first use\n",
                        host, port);
                (void)ssh_khosts_append_ed25519(v->path, host, port, pub);
                return 0;
            }
            fprintf(stderr,
                "error: unknown host %s:%u — refusing (set GUT_SSH_TOFU=1 to "
                "accept-and-pin on first use)\n", host, port);
            return 4;
    }
}

static unsigned long ssh_exec_open(ssh_conn **conn_out, ssh_channel **ch_out,
                                   const ssh_url_parts *u, const char *cmd) {
    u8 seed[32];
    int have_seed = 0;
    int have_explicit_key = (getenv("GUT_SSH_PRIVKEY_HEX") ||
                             getenv("GUT_SSH_PRIVKEY_FILE"));
    int force_agent = (getenv("GUT_SSH_USE_AGENT") != NULL);
    int verbose = getenv("GUT_SSH_DEBUG") != NULL;
    int no_pin = (getenv("GUT_SSH_NO_PIN") != NULL);
    int tofu = (getenv("GUT_SSH_TOFU") != NULL);
    ssh_conn *c = NULL;
    ssh_channel *ch = NULL;
    unsigned long rc;
    verify_ctx_t vctx;
    ssh_khosts *k = NULL;

    /* Key-file path is opt-in for testing: only try to load a seed
     * from disk if the caller explicitly pointed us at one. Otherwise
     * go straight to ssh-agent, which is the production path for
     * encrypted keys (OpenSSH's default). */
    if (have_explicit_key && !force_agent) {
        if (load_ed25519_seed(seed) == 0) have_seed = 1;
        else {
            fprintf(stderr,
                    "error: GUT_SSH_PRIVKEY_* set but the key could not be "
                    "loaded (encrypted keys require ssh-agent — unset the "
                    "env var and run `ssh-add` first)\n");
            return __LINE__;
        }
    }

    /* Host-key pinning via known_hosts + apennines' verifier callback.
     * Opt out via GUT_SSH_NO_PIN=1 (back to pure TOFU from apennines). */
    memset(&vctx, 0, sizeof(vctx));
    vctx.verbose = verbose;
    vctx.tofu_accept = tofu;
    if (!no_pin) {
        const char *override = getenv("GUT_KHOSTS_FILE");
        if (override) {
            snprintf(vctx.path, sizeof(vctx.path), "%s", override);
        } else if (ssh_khosts_default_path(vctx.path, sizeof(vctx.path)) != 0) {
            vctx.path[0] = '\0';
        }
        if (vctx.path[0]) {
            if (ssh_khosts_open(&k, vctx.path) == 0) {
                vctx.khosts = k;
                if (verbose)
                    fprintf(stderr, "[ssh] loaded known_hosts from %s\n", vctx.path);
            }
        }
    }

    /* ssh_conn_create_ex handles DNS internally since apennines 000121
     * and runs our verifier callback after the server's hostkey sig
     * is verified — if the verifier returns non-zero, the connection
     * is torn down before any encrypted data flows. Passing NULL
     * verifier = TOFU (apennines 000128 behavior). */
    rc = ssh_conn_create_ex(&c, u->host, u->port,
                            vctx.khosts ? gut_ssh_verifier : NULL,
                            vctx.khosts ? &vctx : NULL);
    if (rc) {
        unsigned long sub = 0;
        const char *where = "(unknown)";
        if (rc == 5 && ssh_last_kex_sub_hatch(&sub) == 0) {
            switch (sub) {
                case 1: where = "kex: send KEXINIT"; break;
                case 2: where = "kex: recv server KEXINIT"; break;
                case 3: where = "kex: x25519 keygen"; break;
                case 4: where = "kex: send ECDH_INIT"; break;
                case 5: where = "kex: recv/parse ECDH_REPLY"; break;
                case 6: where = "kex: x25519 DH"; break;
                case 7: where = "kex: exchange-hash sha256"; break;
                case 8: where = "kex: host-key verifier rejected"; break;
                case 9: where = "kex: derive transport keys"; break;
                case 10: where = "kex: send NEWKEYS"; break;
                case 11: where = "kex: recv NEWKEYS"; break;
                case 12: where = "kex: init AES-256-GCM"; break;
                default: break;
            }
        }
        if (rc != 5 || sub != 8) {  /* sub=8 already printed its own message */
            fprintf(stderr, "error: ssh_conn_create failed (rc=%lu sub=%lu) — "
                    "%s — host=%s port=%u\n",
                    rc, sub, where, u->host, u->port);
        }
        ssh_khosts_close(k);
        return __LINE__;
    }
    ssh_khosts_close(k);
    vctx.khosts = NULL;
    if (have_seed) {
        /* Since apennines 000129, ssh_conn_auth_pubkey accepts either
         * the 32-byte raw seed or the 64-byte expanded form; we pass
         * the seed directly and let it expand internally. */
        if (verbose) fprintf(stderr, "[ssh] auth: pubkey (env-provided seed)\n");
        rc = ssh_conn_auth_pubkey(c, u->user, seed, 32);
    } else {
        if (verbose) fprintf(stderr, "[ssh] auth: ssh-agent\n");
        rc = ssh_conn_auth_agent(c, u->user);
    }
    if (rc) {
        if (have_seed) {
            fprintf(stderr, "error: ssh pubkey auth rejected (line %lu) — "
                    "user=%s host=%s (is the key registered with the remote?)\n",
                    rc, u->user, u->host);
        } else {
            const char *hint =
                (rc == 3) ? "no ssh-agent reachable — is it running? "
                            "(check SSH_AUTH_SOCK or the Windows named pipe)"
              : (rc == 4) ? "no ed25519 key loaded in agent — run `ssh-add ~/.ssh/id_ed25519`"
              : (rc == 5) ? "ssh-agent sign request failed"
              : (rc == 6) ? "remote rejected the userauth request "
                            "(is the pubkey registered with the remote?)"
                          : "(unknown)";
            fprintf(stderr, "error: ssh-agent auth failed (line %lu) — %s\n",
                    rc, hint);
        }
        ssh_conn_destroy(c);
        return __LINE__;
    }
    rc = ssh_conn_open_channel(&ch, c);
    if (rc) {
        fprintf(stderr, "error: ssh channel open failed (line %lu)\n", rc);
        ssh_conn_destroy(c);
        return __LINE__;
    }
    rc = ssh_channel_exec(ch, cmd);
    if (rc) {
        fprintf(stderr, "error: ssh exec failed (line %lu) — cmd=%s\n", rc, cmd);
        ssh_channel_close(ch);
        ssh_conn_destroy(c);
        return __LINE__;
    }
    *conn_out = c;
    *ch_out = ch;
    return 0;
}

/* Build the quoted exec command git-upload-pack/receive-pack expects:
 *   git-upload-pack '<path>'
 * The single quotes let the remote shell pass paths with spaces. */
static void build_git_cmd(char *out, u64 out_sz, const char *service,
                          const char *path) {
    snprintf(out, (size_t)out_sz, "%s '%s'", service, path);
}

/* ====================================================================
 *  Refs advertisement parser (shared between discover_refs and
 *  fetch_pack — both need to consume and discard it first).
 * ==================================================================== */

/* Parse advertisement bytes starting at `body[*pos]` into `out`. On
 * return, `*pos` points at the byte after the flush that terminates
 * the advertisement (i.e. the start of the caller's next protocol
 * phase). */
static unsigned long parse_ref_advertisement(gut_remote_refs *out,
                                             const u8 *body, u64 body_len,
                                             u64 *pos_inout) {
    u64 pos = *pos_inout;

    out->count = 0;
    out->capabilities[0] = '\0';
    out->hash_algo = GUT_HASH_SHA1;

    while (pos + 4 <= body_len) {
        u32 pkt_len = pktline_len(body + pos);

        if (pkt_len == 0) {
            /* Flush = end of advertisement. */
            pos += 4;
            break;
        }
        if (pkt_len < 4 || pos + pkt_len > body_len) break;

        {
            const char *line = (const char *)(body + pos + 4);
            u64 line_len = pkt_len - 4;
            unsigned hex_len;
            u64 sp;

            while (line_len > 0 &&
                   (line[line_len - 1] == '\n' || line[line_len - 1] == '\r'))
                line_len--;

            if (line[0] == '#') { pos += pkt_len; continue; }

            sp = 0;
            while (sp < line_len && line[sp] != ' ') sp++;
            if (sp != 40 && sp != 64) { pos += pkt_len; continue; }
            hex_len = (unsigned)sp;
            if (out->count == 0)
                out->hash_algo = (hex_len == 64) ? GUT_HASH_SHA256 : GUT_HASH_SHA1;

            if (line_len >= hex_len + 1 && out->count < GUT_REMOTE_MAX_REFS) {
                gut_remote_ref *ref = &out->refs[out->count];
                if (oid_from_hex_n(&ref->oid, line, hex_len) == 0) {
                    const char *name_start = line + hex_len + 1;
                    const char *name_end = name_start;
                    const char *caps = NULL;
                    while (name_end < line + line_len && *name_end != '\0')
                        name_end++;
                    if (name_end < line + line_len && *name_end == '\0')
                        caps = name_end + 1;
                    {
                        u64 nlen = (u64)(name_end - name_start);
                        if (nlen >= sizeof(ref->name)) nlen = sizeof(ref->name) - 1;
                        memcpy(ref->name, name_start, nlen);
                        ref->name[nlen] = '\0';
                    }
                    if (caps && out->count == 0) {
                        u64 clen = (u64)(line + line_len - caps);
                        if (clen >= sizeof(out->capabilities))
                            clen = sizeof(out->capabilities) - 1;
                        memcpy(out->capabilities, caps, clen);
                        out->capabilities[clen] = '\0';
                        if (strstr(out->capabilities, "object-format=sha256"))
                            out->hash_algo = GUT_HASH_SHA256;
                    }
                    out->count++;
                }
            }
        }
        pos += pkt_len;
    }

    *pos_inout = pos;
    return 0;
}

/* ====================================================================
 *  Public entry points: called from remote.c via the dispatch branch
 * ==================================================================== */

unsigned long ssh_discover_refs(gut_remote_refs *out, const char *url) {
    ssh_url_parts u;
    ssh_conn *c = NULL;
    ssh_channel *ch = NULL;
    char cmd[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos = 0;
    unsigned long rc;

    if (!out || !url) return __LINE__;

    rc = url_parse_ssh(&u, url);
    if (rc) return __LINE__;

    build_git_cmd(cmd, sizeof(cmd), "git-upload-pack", u.path);
    rc = ssh_exec_open(&c, &ch, &u, cmd);
    if (rc) return __LINE__;

    /* Read until we see the flush that terminates the refs
     * advertisement. git-upload-pack then waits for our wants/haves
     * — which ssh_fetch_pack_algo will send on a fresh channel. */
    rc = drain_channel_until(&body, &body_len, ch,
                             DRAIN_UNTIL_PKTLINE_FLUSH);
    if (rc == 0) rc = parse_ref_advertisement(out, body, body_len, &pos);
    free(body);

    ssh_channel_close(ch);
    ssh_conn_destroy(c);
    return rc;
}

unsigned long ssh_fetch_pack_algo(const char *url,
                                  gut_oid *want_oids, u64 want_count,
                                  gut_oid *have_oids, u64 have_count,
                                  const char *pack_path,
                                  int depth,
                                  gut_oid **shallow_out,
                                  u64     *shallow_count_out,
                                  gut_hash_algo algo) {
    ssh_url_parts u;
    ssh_conn *c = NULL;
    ssh_channel *ch = NULL;
    char cmd[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos = 0;
    gut_remote_refs adv;
    unsigned long rc;
    u64 i;
    unsigned hex_len = gut_oid_hex_size(algo);
    gut_oid *shallows = NULL;
    u64 n_shallows = 0;
    FILE *fp;

    if (shallow_out) *shallow_out = NULL;
    if (shallow_count_out) *shallow_count_out = 0;

    if (!url || !want_oids || want_count == 0 || !pack_path) return __LINE__;

    rc = url_parse_ssh(&u, url);
    if (rc) return __LINE__;

    build_git_cmd(cmd, sizeof(cmd), "git-upload-pack", u.path);
    rc = ssh_exec_open(&c, &ch, &u, cmd);
    if (rc) return __LINE__;

    /* Send wants + flush + haves + done immediately; server will then
     * respond with its own advertisement interleaved, or (depending on
     * stateful/stateless behavior) reply to the wants. The standard
     * flow actually is: server first writes refs advertisement, then
     * client writes wants. But since the channel is bidirectional and
     * we already know from remote_discover_refs what the refs are
     * (cmd_clone called that first), we write wants optimistically.
     *
     * Technically we should parse the advertisement before sending
     * wants — git-upload-pack will read wants even after its own
     * advertisement arrives. Writing early is safe because SSH
     * channels buffer.
     *
     * Wait — actually no. git-upload-pack reads the client's wants
     * *after* sending the advertisement and its terminating flush.
     * If we send wants first, they land in the kernel buffer and
     * upload-pack picks them up after it's done writing its
     * advertisement. Works in practice.
     */
    for (i = 0; i < want_count; i++) {
        char line[256];
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        oid_to_hex_n(hex, &want_oids[i], hex_len);
        if (i == 0) {
            const char *fmt_cap = (algo == GUT_HASH_SHA256)
                ? " object-format=sha256" : "";
            snprintf(line, sizeof(line),
                     "want %s multi_ack_detailed side-band-64k ofs-delta shallow%s",
                     hex, fmt_cap);
        } else {
            snprintf(line, sizeof(line), "want %s", hex);
        }
        rc = pktline_write_ch(ch, line);
        if (rc) goto out;
    }

    if (depth > 0) {
        char line[32];
        snprintf(line, sizeof(line), "deepen %d", depth);
        rc = pktline_write_ch(ch, line);
        if (rc) goto out;
    }
    rc = pktline_flush_ch(ch);
    if (rc) goto out;

    for (i = 0; i < have_count; i++) {
        char line[160];
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        oid_to_hex_n(hex, &have_oids[i], hex_len);
        snprintf(line, sizeof(line), "have %s", hex);
        rc = pktline_write_ch(ch, line);
        if (rc) goto out;
    }
    rc = pktline_write_ch(ch, "done");
    if (rc) goto out;

    /* Read the whole server response — advertisement, possibly ACK
     * lines, then NAK + sideband-muxed pack. The pack data phase ends
     * when the server closes its side of the channel. */
    rc = drain_channel_until(&body, &body_len, ch, DRAIN_UNTIL_CLOSED);
    if (rc) goto out;

    /* Skip the refs advertisement (ends at the first flush packet). */
    (void)parse_ref_advertisement(&adv, body, body_len, &pos);

    /* Now parse the rest: shallow/unshallow lines, NAK, sideband pack. */
    {
        u8 *pack_stream = (u8 *)malloc((size_t)body_len);
        u64 pack_stream_len = 0;
        int saw_nak = 0;

        if (!pack_stream) { rc = __LINE__; goto out; }

        while (pos + 4 <= body_len) {
            u32 plen = pktline_len(body + pos);
            if (plen == 0) { pos += 4; continue; }
            if (plen < 4 || pos + plen > body_len) break;
            {
                const u8 *payload = body + pos + 4;
                u64 payload_len = plen - 4;

                if (!saw_nak && payload_len >= 8 + (u64)hex_len &&
                    memcmp(payload, "shallow ", 8) == 0) {
                    gut_oid s_oid;
                    char hex[GUT_OID_MAX_HEX_SIZE + 1];
                    memcpy(hex, payload + 8, hex_len);
                    hex[hex_len] = 0;
                    if (oid_from_hex_n(&s_oid, hex, hex_len) == 0) {
                        gut_oid *tmp = (gut_oid *)realloc(
                            shallows, (n_shallows + 1) * sizeof(gut_oid));
                        if (tmp) { shallows = tmp; shallows[n_shallows++] = s_oid; }
                    }
                    pos += plen;
                    continue;
                }

                if (!saw_nak && payload_len >= 3 &&
                    payload[0] == 'N' && payload[1] == 'A' && payload[2] == 'K') {
                    saw_nak = 1;
                    pos += plen;
                    continue;
                }

                if (payload_len >= 1) {
                    u8 band = payload[0];
                    if (band == 1) {
                        memcpy(pack_stream + pack_stream_len,
                               payload + 1, (size_t)(payload_len - 1));
                        pack_stream_len += payload_len - 1;
                    }
                    /* band 2 (progress) / band 3 (error) — ignore. */
                }
            }
            pos += plen;
        }

        /* Write pack to file. If sideband produced nothing, try the
         * raw body (non-sideband servers).  */
        if (pack_stream_len > 0) {
            fp = fopen(pack_path, "wb");
            if (!fp) { free(pack_stream); rc = __LINE__; goto out; }
            fwrite(pack_stream, 1, (size_t)pack_stream_len, fp);
            fclose(fp);
        } else {
            u64 k;
            u64 pack_start = body_len; /* sentinel = not found */
            for (k = pos; k + 4 <= body_len; k++) {
                if (body[k] == 'P' && body[k + 1] == 'A' &&
                    body[k + 2] == 'C' && body[k + 3] == 'K') {
                    pack_start = k;
                    break;
                }
            }
            if (pack_start >= body_len) {
                free(pack_stream);
                rc = __LINE__;
                goto out;
            }
            fp = fopen(pack_path, "wb");
            if (!fp) { free(pack_stream); rc = __LINE__; goto out; }
            fwrite(body + pack_start, 1,
                   (size_t)(body_len - pack_start), fp);
            fclose(fp);
        }
        free(pack_stream);
    }

    if (shallow_out && n_shallows > 0) {
        *shallow_out = shallows;
        shallows = NULL;
        if (shallow_count_out) *shallow_count_out = n_shallows;
    }
    rc = 0;

out:
    free(shallows);
    free(body);
    if (ch) ssh_channel_close(ch);
    if (c) ssh_conn_destroy(c);
    return rc;
}

unsigned long ssh_discover_refs_for_push(gut_remote_refs *out, const char *url) {
    ssh_url_parts u;
    ssh_conn *c = NULL;
    ssh_channel *ch = NULL;
    char cmd[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos = 0;
    unsigned long rc;

    if (!out || !url) return __LINE__;
    rc = url_parse_ssh(&u, url);
    if (rc) return __LINE__;

    build_git_cmd(cmd, sizeof(cmd), "git-receive-pack", u.path);
    rc = ssh_exec_open(&c, &ch, &u, cmd);
    if (rc) return __LINE__;

    rc = drain_channel_until(&body, &body_len, ch,
                             DRAIN_UNTIL_PKTLINE_FLUSH);
    if (rc == 0) rc = parse_ref_advertisement(out, body, body_len, &pos);
    free(body);

    ssh_channel_close(ch);
    ssh_conn_destroy(c);
    return rc;
}

unsigned long ssh_send_pack_algo(char **server_msg, const char *url,
                                 gut_remote_update *updates, u64 update_count,
                                 u8 *pack_data, u64 pack_len,
                                 gut_hash_algo algo) {
    ssh_url_parts u;
    ssh_conn *c = NULL;
    ssh_channel *ch = NULL;
    char cmd[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos = 0;
    gut_remote_refs adv;
    unsigned long rc;
    u64 i;
    u64 w;
    unsigned hex_len = gut_oid_hex_size(algo);

    if (server_msg) *server_msg = NULL;
    if (!url || !updates || update_count == 0 || !pack_data) return __LINE__;

    rc = url_parse_ssh(&u, url);
    if (rc) return __LINE__;

    build_git_cmd(cmd, sizeof(cmd), "git-receive-pack", u.path);
    rc = ssh_exec_open(&c, &ch, &u, cmd);
    if (rc) return __LINE__;

    /* Send update commands + pack. Server will first advertise its
     * refs on stdout; we optimistically send updates, they land after
     * the server finishes writing. Same trick as fetch. */
    for (i = 0; i < update_count; i++) {
        char line[512];
        char old_hex[GUT_OID_MAX_HEX_SIZE + 1];
        char new_hex[GUT_OID_MAX_HEX_SIZE + 1];
        oid_to_hex_n(old_hex, &updates[i].old_oid, hex_len);
        oid_to_hex_n(new_hex, &updates[i].new_oid, hex_len);
        old_hex[hex_len] = '\0';
        new_hex[hex_len] = '\0';
        if (i == 0) {
            const char *fmt_cap = (algo == GUT_HASH_SHA256)
                ? " object-format=sha256" : "";
            snprintf(line, sizeof(line), "%s %s %s\0report-status%s",
                     old_hex, new_hex, updates[i].ref_name, fmt_cap);
            /* snprintf stops at the \0; need an explicit write with
             * a NUL + capabilities suffix. Build it by parts. */
            {
                char head[512];
                int hn = snprintf(head, sizeof(head), "%s %s %s",
                                  old_hex, new_hex, updates[i].ref_name);
                const char caps[] = "\0report-status";
                const int cl = (int)sizeof(caps) - 1;
                const char *fmt = fmt_cap;
                const int fl = (int)strlen(fmt);
                int total = hn + cl + fl + 1;  /* + trailing \n */
                char hdr[5];
                snprintf(hdr, sizeof(hdr), "%04x", total + 4);
                if (ssh_channel_write(&w, ch, (const u8 *)hdr, 4)) { rc = __LINE__; goto out; }
                if (ssh_channel_write(&w, ch, (const u8 *)head, (u64)hn)) { rc = __LINE__; goto out; }
                if (ssh_channel_write(&w, ch, (const u8 *)caps, (u64)cl)) { rc = __LINE__; goto out; }
                if (ssh_channel_write(&w, ch, (const u8 *)fmt, (u64)fl)) { rc = __LINE__; goto out; }
                if (ssh_channel_write(&w, ch, (const u8 *)"\n", 1)) { rc = __LINE__; goto out; }
                (void)line;
            }
        } else {
            snprintf(line, sizeof(line), "%s %s %s",
                     old_hex, new_hex, updates[i].ref_name);
            rc = pktline_write_ch(ch, line);
            if (rc) goto out;
        }
    }
    rc = pktline_flush_ch(ch);
    if (rc) goto out;

    /* Pack */
    if (ssh_channel_write(&w, ch, pack_data, pack_len)) { rc = __LINE__; goto out; }

    /* Read response — skip advertisement, collect report-status. */
    rc = drain_channel(&body, &body_len, ch);
    if (rc) goto out;

    (void)parse_ref_advertisement(&adv, body, body_len, &pos);

    {
        buf msg;
        if (buf_create(&msg, 256)) { rc = __LINE__; goto out; }
        while (pos + 4 <= body_len) {
            u32 plen = pktline_len(body + pos);
            if (plen == 0) { pos += 4; continue; }
            if (plen < 4 || pos + plen > body_len) break;
            buf_append(&msg, body + pos + 4, plen - 4);
            pos += plen;
        }
        if (server_msg) {
            char *s = (char *)malloc((size_t)msg.len + 1);
            if (s) {
                memcpy(s, msg.data, (size_t)msg.len);
                s[msg.len] = '\0';
                *server_msg = s;
            }
        }
        buf_destroy(&msg);
    }
    rc = 0;

out:
    free(body);
    if (ch) ssh_channel_close(ch);
    if (c) ssh_conn_destroy(c);
    return rc;
}
