/*
 * OpenSSH known_hosts parser + host-key pinning.
 *
 * Absorbed from gut (commit f77598e) — see mailbox `gut-for-apennines/`
 * entry 2026-04-19 for the original. Renamed gut_khosts → ssh_khosts,
 * dropped the gut/ includes in favour of apennines', switched
 * __LINE__-style debug hatches to sequential numeric hatches.
 *
 * HMAC-SHA1 is implemented inline. Our public hmac_create only
 * exposes SHA-256/512; SHA-1 is needed solely for OpenSSH's
 * HashKnownHosts format (the leading "|1|" pins the hash algorithm),
 * and lives here rather than being promoted to t2/crypto because
 * ws.c and otp.c also keep their own inline SHA-1 copies — the
 * promotion can happen when a 4th consumer shows up.
 */

#include "apennines/ssh_known_hosts.h"
#include "apennines/base.h"
#include "apennines/buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#define khosts_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define khosts_mkdir(p) mkdir(p, 0755)
#endif

/* ====================================================================
 *  Inline SHA-1 (FIPS 180-4 §6.1) + HMAC-SHA1
 * ==================================================================== */

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

typedef struct {
    u32 state[5];
    u8  buf[SHA1_BLOCK_SIZE];
    u32 buf_len;
    u64 total_len;
} sha1_ctx_t;

static u32 sha1_rotl(u32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_compress(sha1_ctx_t *ctx, const u8 block[SHA1_BLOCK_SIZE]) {
    u32 w[80];
    u32 a, b, c, d, e;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((u32)block[i*4] << 24) | ((u32)block[i*4+1] << 16) |
               ((u32)block[i*4+2] << 8) | (u32)block[i*4+3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = sha1_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2];
    d = ctx->state[3]; e = ctx->state[4];
    for (i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6u; }
        {
            u32 temp = sha1_rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = sha1_rotl(b, 30);
            b = a;
            a = temp;
        }
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
    ctx->buf_len  = 0;
    ctx->total_len = 0;
}

static void sha1_update(sha1_ctx_t *ctx, const u8 *data, u64 len) {
    ctx->total_len += len;
    while (len > 0) {
        u32 space = SHA1_BLOCK_SIZE - ctx->buf_len;
        u32 take = (len < space) ? (u32)len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len  -= take;
        if (ctx->buf_len == SHA1_BLOCK_SIZE) {
            sha1_compress(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx_t *ctx, u8 digest[SHA1_DIGEST_SIZE]) {
    u64 bit_len = ctx->total_len * 8;
    u8 pad = 0x80;
    int i;
    sha1_update(ctx, &pad, 1);
    pad = 0x00;
    while (ctx->buf_len != SHA1_BLOCK_SIZE - 8) {
        sha1_update(ctx, &pad, 1);
    }
    for (i = 7; i >= 0; i--) {
        u8 b = (u8)(bit_len >> (i * 8));
        sha1_update(ctx, &b, 1);
    }
    for (i = 0; i < 5; i++) {
        digest[i*4]   = (u8)(ctx->state[i] >> 24);
        digest[i*4+1] = (u8)(ctx->state[i] >> 16);
        digest[i*4+2] = (u8)(ctx->state[i] >> 8);
        digest[i*4+3] = (u8)(ctx->state[i]);
    }
}

static void hmac_sha1(u8 *out,
                      const u8 *key, u64 key_len,
                      const u8 *data, u64 data_len) {
    u8 k_prime[SHA1_BLOCK_SIZE];
    u8 ipad[SHA1_BLOCK_SIZE];
    u8 opad[SHA1_BLOCK_SIZE];
    u8 inner[SHA1_DIGEST_SIZE];
    sha1_ctx_t ctx;
    u64 i;

    memset(k_prime, 0, sizeof(k_prime));
    if (key_len > SHA1_BLOCK_SIZE) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, k_prime);
    } else {
        memcpy(k_prime, key, (size_t)key_len);
    }

    for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
        ipad[i] = (u8)(k_prime[i] ^ 0x36);
        opad[i] = (u8)(k_prime[i] ^ 0x5c);
    }

    sha1_init(&ctx);
    sha1_update(&ctx, ipad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, inner, SHA1_DIGEST_SIZE);
    sha1_final(&ctx, out);
}

/* ====================================================================
 *  Parsed entry representation
 * ==================================================================== */

typedef enum {
    ENTRY_NORMAL         = 0,
    ENTRY_REVOKED        = 1,
    ENTRY_CERT_AUTHORITY = 2
} entry_kind;

typedef enum {
    KEY_ED25519 = 1,
    KEY_OTHER   = 2
} key_kind;

typedef struct {
    char   *pattern;                    /* heap-alloc'd, NUL-terminated */
    int     negated;                    /* 1 if prefixed with '!' */
    int     hashed;                     /* 1 if this is a "|1|salt|hmac" entry */
    u8      salt[64];                   /* HMAC-SHA1 salt; valid if hashed */
    u64     salt_len;
    u8      hmac[SHA1_DIGEST_SIZE];     /* valid if hashed */
} pattern_t;

typedef struct {
    entry_kind  kind;
    key_kind    key;
    pattern_t  *patterns;
    u64         pattern_count;
    u8          ed25519_pub[32];        /* valid if key == KEY_ED25519 */
} entry_t;

struct ssh_khosts {
    entry_t *entries;
    u64      count;
    u64      capacity;
};

/* ====================================================================
 *  Freeing helpers
 * ==================================================================== */

static void pattern_destroy(pattern_t *p) {
    free(p->pattern);
    memset(p, 0, sizeof(*p));
}

static void entry_destroy(entry_t *e) {
    u64 i;
    for (i = 0; i < e->pattern_count; i++) pattern_destroy(&e->patterns[i]);
    free(e->patterns);
    memset(e, 0, sizeof(*e));
}

unsigned long ssh_khosts_close(ssh_khosts *k) {
    u64 i;
    if (!k) return 0;
    for (i = 0; i < k->count; i++) entry_destroy(&k->entries[i]);
    free(k->entries);
    free(k);
    return 0;
}

/* ====================================================================
 *  Parsing utilities
 * ==================================================================== */

static int is_hspace(char c) { return c == ' ' || c == '\t'; }

static const char *skip_hspace(const char *p) {
    while (*p && is_hspace(*p)) p++;
    return p;
}

static const char *read_field(const char **start_out, u64 *len_out,
                              const char *p) {
    const char *start;
    p = skip_hspace(p);
    start = p;
    while (*p && !is_hspace(*p) && *p != '\n' && *p != '\r') p++;
    *start_out = start;
    *len_out = (u64)(p - start);
    return p;
}

static void ascii_lower(char *s, u64 len) {
    u64 i;
    for (i = 0; i < len; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = (char)(s[i] + ('a' - 'A'));
    }
}

/* ====================================================================
 *  Pattern matching
 * ==================================================================== */

/* fnmatch-subset: * matches any run of chars, ? matches one. Hostnames
 * don't contain '/', so the simpler form suffices. */
static int glob_match(const char *pat, const char *s) {
    const char *star = NULL;
    const char *ss = NULL;
    while (*s) {
        if (*pat == '?' || *pat == *s) {
            pat++; s++;
            continue;
        }
        if (*pat == '*') {
            star = pat++;
            ss = s;
            continue;
        }
        if (star) {
            pat = star + 1;
            s = ++ss;
            continue;
        }
        return 0;
    }
    while (*pat == '*') pat++;
    return *pat == 0;
}

static int pattern_matches(const pattern_t *p, const char *name) {
    if (p->hashed) {
        u8 got[SHA1_DIGEST_SIZE];
        hmac_sha1(got, p->salt, p->salt_len,
                  (const u8 *)name, strlen(name));
        return memcmp(got, p->hmac, SHA1_DIGEST_SIZE) == 0;
    }
    return glob_match(p->pattern, name);
}

/* Build the OpenSSH-convention match name for (host, port):
 *   port == 22:  "host"
 *   otherwise:   "[host]:port"
 * OpenSSH hashes the "[host]:port" form when the port is non-default,
 * and the unbracketed "host" form otherwise. */
static void build_match_name(char *out, u64 out_size,
                             const char *host, u16 port) {
    if (port == 22) {
        snprintf(out, (size_t)out_size, "%s", host);
    } else {
        snprintf(out, (size_t)out_size, "[%s]:%u", host, (unsigned)port);
    }
    ascii_lower(out, strlen(out));
}

static int entry_matches_host(const entry_t *e,
                              const char *plain_name,
                              const char *bracketed_name) {
    int any_pos = 0;
    u64 i;
    for (i = 0; i < e->pattern_count; i++) {
        const pattern_t *p = &e->patterns[i];
        int this_hit = 0;
        if (pattern_matches(p, plain_name)) this_hit = 1;
        if (!this_hit && pattern_matches(p, bracketed_name)) this_hit = 1;
        if (!this_hit) continue;
        if (p->negated) return 0;
        any_pos = 1;
    }
    return any_pos;
}

/* ====================================================================
 *  Line parsing
 * ==================================================================== */

static unsigned long parse_pattern(pattern_t *out,
                                   const char *text, u64 text_len) {
    char *pat_str;
    memset(out, 0, sizeof(*out));
    if (text_len == 0) return 1;

    if (text[0] == '!') {
        out->negated = 1;
        text++; text_len--;
        if (text_len == 0) return 2;
    }

    if (text_len >= 3 && text[0] == '|' && text[1] == '1' && text[2] == '|') {
        /* Hashed: |1|<base64 salt>|<base64 hmac> */
        buf salt_buf, hmac_buf;
        const char *p = text + 3;
        const char *end = text + text_len;
        const char *bar = memchr(p, '|', (size_t)(end - p));
        if (!bar) return 3;
        if (buf_create(&salt_buf, 64)) return 4;
        if (base64_decode(&salt_buf, (u8 *)p, (u64)(bar - p))) {
            buf_destroy(&salt_buf);
            return 5;
        }
        if (salt_buf.len > sizeof(out->salt)) {
            buf_destroy(&salt_buf);
            return 6;
        }
        memcpy(out->salt, salt_buf.data, (size_t)salt_buf.len);
        out->salt_len = salt_buf.len;
        buf_destroy(&salt_buf);

        if (buf_create(&hmac_buf, 32)) return 7;
        if (base64_decode(&hmac_buf, (u8 *)(bar + 1),
                          (u64)(end - (bar + 1)))) {
            buf_destroy(&hmac_buf);
            return 8;
        }
        if (hmac_buf.len != SHA1_DIGEST_SIZE) {
            buf_destroy(&hmac_buf);
            return 9;
        }
        memcpy(out->hmac, hmac_buf.data, SHA1_DIGEST_SIZE);
        buf_destroy(&hmac_buf);
        out->hashed = 1;
        return 0;
    }

    pat_str = (char *)malloc((size_t)text_len + 1);
    if (!pat_str) return 10;
    memcpy(pat_str, text, (size_t)text_len);
    pat_str[text_len] = '\0';
    ascii_lower(pat_str, text_len);
    out->pattern = pat_str;
    return 0;
}

static unsigned long parse_pattern_list(pattern_t **out_patterns,
                                        u64 *out_count,
                                        const char *text, u64 text_len) {
    pattern_t *arr = NULL;
    u64 cap = 0, n = 0;
    u64 i = 0;
    *out_patterns = NULL;
    *out_count = 0;

    while (i < text_len) {
        u64 j = i;
        while (j < text_len && text[j] != ',') j++;
        {
            pattern_t p;
            if (parse_pattern(&p, text + i, j - i) == 0) {
                if (n == cap) {
                    u64 new_cap = cap ? cap * 2 : 4;
                    pattern_t *grown =
                        (pattern_t *)realloc(arr, (size_t)new_cap * sizeof(pattern_t));
                    if (!grown) {
                        u64 k;
                        for (k = 0; k < n; k++) pattern_destroy(&arr[k]);
                        free(arr);
                        return 1;
                    }
                    arr = grown;
                    cap = new_cap;
                }
                arr[n++] = p;
            }
            /* bad patterns skipped silently — be liberal in what we accept */
        }
        i = j + 1;
    }
    *out_patterns = arr;
    *out_count = n;
    return 0;
}

static key_kind parse_key_blob(u8 *out32,
                               const char *type_str, u64 type_len,
                               const char *b64_str, u64 b64_len) {
    buf decoded;
    if (type_len != 11 || memcmp(type_str, "ssh-ed25519", 11) != 0) {
        return KEY_OTHER;
    }
    if (buf_create(&decoded, 128)) return KEY_OTHER;
    if (base64_decode(&decoded, (u8 *)b64_str, b64_len)) {
        buf_destroy(&decoded);
        return KEY_OTHER;
    }
    if (decoded.len < 4 + 11 + 4 + 32) {
        buf_destroy(&decoded);
        return KEY_OTHER;
    }
    {
        const u8 *d = decoded.data;
        u32 n = ((u32)d[0] << 24) | ((u32)d[1] << 16) |
                ((u32)d[2] << 8)  | (u32)d[3];
        if (n != 11 || memcmp(d + 4, "ssh-ed25519", 11) != 0) {
            buf_destroy(&decoded);
            return KEY_OTHER;
        }
        d += 4 + 11;
        n = ((u32)d[0] << 24) | ((u32)d[1] << 16) |
            ((u32)d[2] << 8)  | (u32)d[3];
        if (n != 32) {
            buf_destroy(&decoded);
            return KEY_OTHER;
        }
        memcpy(out32, d + 4, 32);
    }
    buf_destroy(&decoded);
    return KEY_ED25519;
}

static unsigned long parse_line(entry_t *out, const char *line, u64 line_len) {
    const char *p = line;
    const char *end;
    const char *field_s;
    u64 field_l;
    entry_kind kind = ENTRY_NORMAL;

    memset(out, 0, sizeof(*out));

    while (line_len > 0 && (line[line_len - 1] == '\n' ||
                            line[line_len - 1] == '\r' ||
                            line[line_len - 1] == ' ' ||
                            line[line_len - 1] == '\t')) {
        line_len--;
    }
    end = line + line_len;
    p = line;
    p = skip_hspace(p);

    if (p >= end || *p == '#' || *p == '\0') return 1;

    if (p < end && *p == '@') {
        const char *start = p;
        while (p < end && !is_hspace(*p)) p++;
        {
            u64 mlen = (u64)(p - start);
            if (mlen == 8 && memcmp(start, "@revoked", 8) == 0) {
                kind = ENTRY_REVOKED;
            } else if (mlen == 15 && memcmp(start, "@cert-authority", 15) == 0) {
                kind = ENTRY_CERT_AUTHORITY;
            } else {
                return 2;
            }
        }
    }

    p = read_field(&field_s, &field_l, p);
    if (field_l == 0) return 3;
    if (parse_pattern_list(&out->patterns, &out->pattern_count,
                           field_s, field_l)) return 4;
    if (out->pattern_count == 0) return 5;

    {
        const char *type_s;
        u64 type_l;
        p = read_field(&type_s, &type_l, p);
        if (type_l == 0) { entry_destroy(out); return 6; }

        {
            const char *b64_s;
            u64 b64_l;
            p = read_field(&b64_s, &b64_l, p);
            if (b64_l == 0) { entry_destroy(out); return 7; }

            out->kind = kind;
            out->key = parse_key_blob(out->ed25519_pub,
                                      type_s, type_l, b64_s, b64_l);
        }
    }

    return 0;
}

/* ====================================================================
 *  File loading
 * ==================================================================== */

static unsigned long append_entry(ssh_khosts *k, entry_t *e) {
    if (k->count == k->capacity) {
        u64 new_cap = k->capacity ? k->capacity * 2 : 32;
        entry_t *grown = (entry_t *)realloc(k->entries,
                                            (size_t)new_cap * sizeof(entry_t));
        if (!grown) return 1;
        k->entries = grown;
        k->capacity = new_cap;
    }
    k->entries[k->count++] = *e;
    return 0;
}

unsigned long ssh_khosts_open(ssh_khosts **out, const char *path) {
    FILE *fp;
    char line[4096];
    ssh_khosts *k;

    if (!out) return 1;
    *out = NULL;

    k = (ssh_khosts *)calloc(1, sizeof(ssh_khosts));
    if (!k) return 2;

    fp = fopen(path, "rb");
    if (!fp) {
        /* Missing file: empty entry set, every lookup returns UNKNOWN. */
        *out = k;
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        entry_t e;
        u64 line_len = strlen(line);
        if (parse_line(&e, line, line_len) == 0) {
            if (append_entry(k, &e) != 0) {
                entry_destroy(&e);
                fclose(fp);
                ssh_khosts_close(k);
                return 3;
            }
        }
        /* malformed / comment / empty — skip */
    }
    fclose(fp);

    *out = k;
    return 0;
}

/* ====================================================================
 *  Lookup
 * ==================================================================== */

unsigned long ssh_khosts_lookup_ed25519(ssh_khosts_match *match_out,
                                                       ssh_khosts *k,
                                                       const char *host,
                                                       u16 port,
                                                       const u8 *server_pub) {
    char plain[512];
    char bracketed[520];
    int pinned_hit = 0;
    int mismatch_hit = 0;
    u64 i;

    if (!match_out) return 1;
    if (!host) return 2;
    if (!server_pub) return 3;
    if (!k) { *match_out = SSH_KHOSTS_MATCH_UNKNOWN; return 0; }

    build_match_name(plain, sizeof(plain), host, 22);
    build_match_name(bracketed, sizeof(bracketed), host, port);

    for (i = 0; i < k->count; i++) {
        entry_t *e = &k->entries[i];
        if (!entry_matches_host(e, plain, bracketed)) continue;

        if (e->kind == ENTRY_REVOKED) {
            *match_out = SSH_KHOSTS_MATCH_REVOKED;
            return 0;
        }

        if (e->kind == ENTRY_CERT_AUTHORITY) continue;
        if (e->key != KEY_ED25519) continue;

        if (memcmp(e->ed25519_pub, server_pub, 32) == 0) {
            pinned_hit = 1;
        } else {
            mismatch_hit = 1;
        }
    }

    if (pinned_hit) { *match_out = SSH_KHOSTS_MATCH_PINNED; return 0; }
    if (mismatch_hit) { *match_out = SSH_KHOSTS_MATCH_MISMATCH; return 0; }
    *match_out = SSH_KHOSTS_MATCH_UNKNOWN;
    return 0;
}

/* ====================================================================
 *  Append (TOFU-on-first-use)
 * ==================================================================== */

static unsigned long mkdirs_for(const char *path) {
    char parent[2048];
    u64 plen;
    const char *slash;

    slash = strrchr(path, '/');
    if (!slash) slash = strrchr(path, '\\');
    if (!slash) return 0;
    plen = (u64)(slash - path);
    if (plen >= sizeof(parent)) return 1;
    memcpy(parent, path, (size_t)plen);
    parent[plen] = '\0';

    {
        u64 i;
        for (i = 1; i < plen; i++) {
            if (parent[i] == '/' || parent[i] == '\\') {
                char saved = parent[i];
                parent[i] = '\0';
                (void)khosts_mkdir(parent);
                parent[i] = saved;
            }
        }
        (void)khosts_mkdir(parent);
    }
    return 0;
}

unsigned long ssh_khosts_append_ed25519(const char *path,
                                                       const char *host,
                                                       u16 port,
                                                       const u8 *server_pub) {
    buf wire;
    buf b64;
    FILE *fp;

    if (!path) return 1;
    if (!host) return 2;
    if (!server_pub) return 3;

    if (mkdirs_for(path) != 0) return 4;

    if (buf_create(&wire, 64)) return 5;
    {
        u8 hdr[4];
        u32 n = 11;  /* strlen("ssh-ed25519") */
        hdr[0] = (u8)(n >> 24); hdr[1] = (u8)(n >> 16);
        hdr[2] = (u8)(n >> 8);  hdr[3] = (u8)n;
        buf_append(&wire, hdr, 4);
        buf_append(&wire, (u8 *)"ssh-ed25519", 11);
        n = 32;
        hdr[0] = (u8)(n >> 24); hdr[1] = (u8)(n >> 16);
        hdr[2] = (u8)(n >> 8);  hdr[3] = (u8)n;
        buf_append(&wire, hdr, 4);
        buf_append(&wire, (u8 *)server_pub, 32);
    }

    if (buf_create(&b64, 128)) { buf_destroy(&wire); return 5; }
    if (base64_encode(&b64, wire.data, wire.len)) {
        buf_destroy(&wire); buf_destroy(&b64);
        return 5;
    }
    buf_destroy(&wire);

    fp = fopen(path, "ab");
    if (!fp) { buf_destroy(&b64); return 4; }
    if (port == 22) {
        fprintf(fp, "%s ssh-ed25519 %.*s\n",
                host, (int)b64.len, (const char *)b64.data);
    } else {
        fprintf(fp, "[%s]:%u ssh-ed25519 %.*s\n",
                host, (unsigned)port, (int)b64.len, (const char *)b64.data);
    }
    fclose(fp);
    buf_destroy(&b64);
    return 0;
}

/* ====================================================================
 *  Default path resolver
 * ==================================================================== */

unsigned long ssh_khosts_default_path(char *out, u64 out_size) {
    const char *home = getenv("HOME");
#ifdef _WIN32
    char home_buf[1024];
    if (!home) {
        const char *up = getenv("USERPROFILE");
        if (up) {
            snprintf(home_buf, sizeof(home_buf), "%s", up);
            home = home_buf;
        } else {
            const char *hd = getenv("HOMEDRIVE");
            const char *hp = getenv("HOMEPATH");
            if (hd && hp) {
                snprintf(home_buf, sizeof(home_buf), "%s%s", hd, hp);
                home = home_buf;
            }
        }
    }
#endif
    if (!out) return 1;
    if (!home) return 2;
    if ((u64)snprintf(out, (size_t)out_size, "%s/.ssh/known_hosts", home)
        >= out_size) return 3;
    {
        char *p;
        for (p = out; *p; p++) if (*p == '\\') *p = '/';
    }
    return 0;
}
