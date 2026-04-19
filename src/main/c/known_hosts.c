/*
 * OpenSSH known_hosts parser + pinning lookup.
 *
 * Designed to run offline against `~/.ssh/known_hosts` without any
 * ssh connection state. Integrates with apennines' SSH client via
 * a verifier hook (once apennines exposes one) or by calling the
 * lookup after a connection's KEX completes and before any userauth
 * message is sent.
 *
 * HMAC-SHA1 is implemented inline on top of gut's own SHA-1 (for git
 * OIDs) because apennines' hash module only exposes HMAC-SHA256/512.
 * OpenSSH's HashKnownHosts format specifically requires SHA-1 (the
 * leading "|1|" in hashed entries is a version marker pinning the
 * hash algorithm). ~50 lines of HMAC on top of existing SHA-1 is
 * cheaper than another round trip with apennines.
 */

#include "gut/known_hosts.h"
#include "gut/sha1.h"
#include "apennines/base.h"
#include "apennines/buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define gut_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define gut_mkdir(p) mkdir(p, 0755)
#endif

/* ====================================================================
 *  HMAC-SHA1 on top of gut/sha1.c
 * ==================================================================== */

#define HMAC_SHA1_BLOCK  GUT_SHA1_BLOCK_SIZE   /* 64 */
#define HMAC_SHA1_DIGEST GUT_SHA1_DIGEST_SIZE  /* 20 */

static unsigned long hmac_sha1(u8 *out,
                               const u8 *key, u64 key_len,
                               const u8 *data, u64 data_len) {
    u8 k_prime[HMAC_SHA1_BLOCK];
    u8 ipad[HMAC_SHA1_BLOCK];
    u8 opad[HMAC_SHA1_BLOCK];
    u8 inner[HMAC_SHA1_DIGEST];
    sha1_ctx ctx;
    u64 i;

    /* Reduce oversized keys via SHA-1, pad short keys with zeros. */
    memset(k_prime, 0, sizeof(k_prime));
    if (key_len > HMAC_SHA1_BLOCK) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(k_prime, &ctx);
    } else {
        memcpy(k_prime, key, (size_t)key_len);
    }

    for (i = 0; i < HMAC_SHA1_BLOCK; i++) {
        ipad[i] = (u8)(k_prime[i] ^ 0x36);
        opad[i] = (u8)(k_prime[i] ^ 0x5c);
    }

    /* inner = SHA1(ipad || data) */
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, HMAC_SHA1_BLOCK);
    sha1_update(&ctx, data, data_len);
    sha1_final(inner, &ctx);

    /* out = SHA1(opad || inner) */
    sha1_init(&ctx);
    sha1_update(&ctx, opad, HMAC_SHA1_BLOCK);
    sha1_update(&ctx, inner, HMAC_SHA1_DIGEST);
    sha1_final(out, &ctx);

    return 0;
}

/* ====================================================================
 *  Parsed entry representation
 * ==================================================================== */

typedef enum {
    ENTRY_NORMAL       = 0,
    ENTRY_REVOKED      = 1,
    ENTRY_CERT_AUTHORITY = 2
} entry_kind;

typedef enum {
    KEY_ED25519 = 1,
    KEY_OTHER   = 2
} key_kind;

/* A single pattern from the comma-separated host list. */
typedef struct {
    char   *pattern;   /* heap-alloc'd, NUL-terminated */
    int     negated;   /* 1 if originally prefixed with '!' */
    int     hashed;    /* 1 if this is a "|1|salt|hmac" entry */
    u8      salt[64];  /* HMAC-SHA1 salt (base64-decoded); valid if hashed */
    u64     salt_len;
    u8      hmac[HMAC_SHA1_DIGEST];   /* valid if hashed */
} pattern_t;

typedef struct {
    entry_kind   kind;
    key_kind     key;
    pattern_t   *patterns;
    u64          pattern_count;
    u8           ed25519_pub[32];   /* valid if key == KEY_ED25519 */
} entry_t;

struct gut_khosts {
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

unsigned long khosts_close(gut_khosts *k) {
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

/* Consume whitespace at p. */
static const char *skip_hspace(const char *p) {
    while (*p && is_hspace(*p)) p++;
    return p;
}

/* Scan a whitespace-delimited field. Returns pointer past the field,
 * writes start/len into out args. */
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

/* ASCII-lowercase a hostname in place (up to len bytes). */
static void ascii_lower(char *s, u64 len) {
    u64 i;
    for (i = 0; i < len; i++) {
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = (char)(s[i] + ('a' - 'A'));
    }
}

/* ====================================================================
 *  Pattern matching
 * ==================================================================== */

/* fnmatch-subset: * matches any run of chars (no /), ? matches one.
 * Hostnames don't contain '/', so the simpler * suffices. */
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

/* Does `name` (already lowercase) match the pattern entry? For hashed
 * patterns, computes HMAC-SHA1(salt, name) and compares against the
 * stored hmac. */
static int pattern_matches(const pattern_t *p, const char *name) {
    if (p->hashed) {
        u8 got[HMAC_SHA1_DIGEST];
        hmac_sha1(got, p->salt, p->salt_len,
                  (const u8 *)name, strlen(name));
        return memcmp(got, p->hmac, HMAC_SHA1_DIGEST) == 0;
    }
    return glob_match(p->pattern, name);
}

/* Build the match key for a host+port pair:
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

/* Check whether the entry as a whole matches the host. Returns 1 if
 * any non-negated pattern matches AND no negated pattern matches. */
static int entry_matches_host(const entry_t *e,
                              const char *plain_name,
                              const char *bracketed_name) {
    int any_pos = 0;
    u64 i;
    for (i = 0; i < e->pattern_count; i++) {
        const pattern_t *p = &e->patterns[i];
        /* For hashed patterns, we always test against bracketed_name
         * (OpenSSH's convention when the port differs) and plain when
         * it matches. We try both, cheap. */
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

/* Parse a single pattern (one element from a comma-separated list)
 * into a pattern_t. The pattern text is `text`, length `text_len`.
 * Handles the leading '!' for negation and the "|1|salt|hmac"
 * hashed form. */
static unsigned long parse_pattern(pattern_t *out,
                                   const char *text, u64 text_len) {
    char *pat_str;
    memset(out, 0, sizeof(*out));
    if (text_len == 0) return __LINE__;

    if (text[0] == '!') {
        out->negated = 1;
        text++; text_len--;
        if (text_len == 0) return __LINE__;
    }

    if (text_len >= 3 && text[0] == '|' && text[1] == '1' && text[2] == '|') {
        /* Hashed: |1|<base64 salt>|<base64 hmac> */
        buf salt_buf, hmac_buf;
        const char *p = text + 3;
        const char *end = text + text_len;
        const char *bar = memchr(p, '|', (size_t)(end - p));
        if (!bar) return __LINE__;
        {
            /* salt = base64-decode(p .. bar) */
            if (buf_create(&salt_buf, 64)) return __LINE__;
            if (base64_decode(&salt_buf, (u8 *)p, (u64)(bar - p))) {
                buf_destroy(&salt_buf);
                return __LINE__;
            }
            if (salt_buf.len > sizeof(out->salt)) {
                buf_destroy(&salt_buf);
                return __LINE__;
            }
            memcpy(out->salt, salt_buf.data, (size_t)salt_buf.len);
            out->salt_len = salt_buf.len;
            buf_destroy(&salt_buf);
        }
        {
            /* hmac = base64-decode(bar+1 .. end) */
            if (buf_create(&hmac_buf, 32)) return __LINE__;
            if (base64_decode(&hmac_buf, (u8 *)(bar + 1),
                              (u64)(end - (bar + 1)))) {
                buf_destroy(&hmac_buf);
                return __LINE__;
            }
            if (hmac_buf.len != HMAC_SHA1_DIGEST) {
                buf_destroy(&hmac_buf);
                return __LINE__;
            }
            memcpy(out->hmac, hmac_buf.data, HMAC_SHA1_DIGEST);
            buf_destroy(&hmac_buf);
        }
        out->hashed = 1;
        /* pattern string kept NULL — hashed entries never use glob */
        return 0;
    }

    /* Plain pattern: copy + lowercase. */
    pat_str = (char *)malloc((size_t)text_len + 1);
    if (!pat_str) return __LINE__;
    memcpy(pat_str, text, (size_t)text_len);
    pat_str[text_len] = '\0';
    ascii_lower(pat_str, text_len);
    out->pattern = pat_str;
    return 0;
}

/* Parse a comma-separated pattern list. Allocates and fills
 * `out_patterns` + `out_count`. */
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
                        return __LINE__;
                    }
                    arr = grown;
                    cap = new_cap;
                }
                arr[n++] = p;
            }
            /* bad patterns skipped silently — be liberal in what we accept */
        }
        i = j + 1;  /* skip the comma or run past end */
    }
    *out_patterns = arr;
    *out_count = n;
    return 0;
}

/* Parse the "ssh-ed25519 <base64>" portion. Writes the 32-byte
 * pubkey into `out32` and returns KEY_ED25519 on success. Other
 * key types return KEY_OTHER (caller stores the entry as KEY_OTHER
 * so it still participates in @revoked matching but is skipped by
 * ed25519 lookups). */
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
    /* Decoded blob: string "ssh-ed25519" (4+11) + string pub(4+32). */
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

/* Parse one non-empty, non-comment line into an entry. Returns 0 on
 * success even for KEY_OTHER entries (they're kept for @revoked
 * matching). Returns non-zero only if the pattern list fails to
 * parse or alloc fails. */
static unsigned long parse_line(entry_t *out, const char *line, u64 line_len) {
    const char *p = line;
    const char *end = line + line_len;
    const char *field_s;
    u64 field_l;
    entry_kind kind = ENTRY_NORMAL;

    memset(out, 0, sizeof(*out));

    /* Strip trailing LF/CR and trailing whitespace first. */
    while (line_len > 0 && (line[line_len - 1] == '\n' ||
                            line[line_len - 1] == '\r' ||
                            line[line_len - 1] == ' ' ||
                            line[line_len - 1] == '\t')) {
        line_len--;
    }
    end = line + line_len;
    p = line;
    p = skip_hspace(p);

    if (p >= end || *p == '#' || *p == '\0') return __LINE__; /* empty/comment */

    /* Optional @marker prefix. */
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
                return __LINE__; /* unknown marker */
            }
        }
    }

    /* patterns */
    p = read_field(&field_s, &field_l, p);
    if (field_l == 0) return __LINE__;
    if (parse_pattern_list(&out->patterns, &out->pattern_count,
                           field_s, field_l)) return __LINE__;
    if (out->pattern_count == 0) return __LINE__;

    /* key type */
    {
        const char *type_s;
        u64 type_l;
        p = read_field(&type_s, &type_l, p);
        if (type_l == 0) goto bad;

        /* key blob (base64) */
        {
            const char *b64_s;
            u64 b64_l;
            p = read_field(&b64_s, &b64_l, p);
            if (b64_l == 0) goto bad;

            out->kind = kind;
            out->key = parse_key_blob(out->ed25519_pub,
                                      type_s, type_l, b64_s, b64_l);
            /* Comment field (if any) ignored. */
        }
    }

    return 0;

bad:
    entry_destroy(out);
    return __LINE__;
}

/* ====================================================================
 *  File loading
 * ==================================================================== */

static unsigned long append_entry(gut_khosts *k, entry_t *e) {
    if (k->count == k->capacity) {
        u64 new_cap = k->capacity ? k->capacity * 2 : 32;
        entry_t *grown = (entry_t *)realloc(k->entries,
                                            (size_t)new_cap * sizeof(entry_t));
        if (!grown) return __LINE__;
        k->entries = grown;
        k->capacity = new_cap;
    }
    k->entries[k->count++] = *e;
    return 0;
}

unsigned long khosts_open(gut_khosts **out, const char *path) {
    FILE *fp;
    char line[4096];
    gut_khosts *k;

    if (!out) return __LINE__;
    *out = NULL;

    k = (gut_khosts *)calloc(1, sizeof(gut_khosts));
    if (!k) return __LINE__;

    fp = fopen(path, "rb");
    if (!fp) {
        /* Missing file is a normal, non-error condition: zero entries,
         * all lookups return UNKNOWN. Users bootstrap known_hosts by
         * pinning on first connect. */
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
                khosts_close(k);
                return __LINE__;
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

unsigned long khosts_lookup_ed25519(gut_khosts_match *match_out,
                                    gut_khosts *k,
                                    const char *host,
                                    u16 port,
                                    const u8 *server_pub) {
    char plain[512];
    char bracketed[520];
    int any_matched_host = 0;
    int pinned_hit = 0;
    int mismatch_hit = 0;
    u64 i;

    if (!match_out) return __LINE__;
    if (!k) { *match_out = KHOSTS_MATCH_UNKNOWN; return 0; }
    if (!host) return __LINE__;
    if (!server_pub) return __LINE__;

    /* Build both forms: plain name matches entries that don't pin
     * a port; "[host]:port" matches port-specific entries. When the
     * port is 22, both forms are the same bare hostname. */
    build_match_name(plain, sizeof(plain), host, 22);
    build_match_name(bracketed, sizeof(bracketed), host, port);

    for (i = 0; i < k->count; i++) {
        entry_t *e = &k->entries[i];
        if (!entry_matches_host(e, plain, bracketed)) continue;
        any_matched_host = 1;

        /* @revoked is terminal: even if the pubkey differs, the host
         * is blacklisted. */
        if (e->kind == ENTRY_REVOKED) {
            *match_out = KHOSTS_MATCH_REVOKED;
            return 0;
        }

        if (e->kind == ENTRY_CERT_AUTHORITY) continue;   /* skip — we don't do SSH certs */

        if (e->key != KEY_ED25519) continue;   /* RSA/ECDSA ignored for ed25519 lookups */

        if (memcmp(e->ed25519_pub, server_pub, 32) == 0) {
            pinned_hit = 1;
        } else {
            mismatch_hit = 1;
        }
    }

    if (pinned_hit) { *match_out = KHOSTS_MATCH_PINNED; return 0; }
    if (mismatch_hit) { *match_out = KHOSTS_MATCH_MISMATCH; return 0; }
    *match_out = any_matched_host ? KHOSTS_MATCH_UNKNOWN
                                  : KHOSTS_MATCH_UNKNOWN;
    return 0;
}

/* ====================================================================
 *  Append (TOFU-on-first-use)
 * ==================================================================== */

static unsigned long mkdirs_for(const char *path) {
    char parent[2048];
    u64 plen;
    const char *slash;
    /* Find the last slash so we know the parent directory. */
    slash = strrchr(path, '/');
    if (!slash) slash = strrchr(path, '\\');
    if (!slash) return 0;  /* no parent to create */
    plen = (u64)(slash - path);
    if (plen >= sizeof(parent)) return __LINE__;
    memcpy(parent, path, (size_t)plen);
    parent[plen] = '\0';

    /* Walk and mkdir each segment. */
    {
        u64 i;
        for (i = 1; i < plen; i++) {
            if (parent[i] == '/' || parent[i] == '\\') {
                char saved = parent[i];
                parent[i] = '\0';
                (void)gut_mkdir(parent);
                parent[i] = saved;
            }
        }
        (void)gut_mkdir(parent);
    }
    return 0;
}

unsigned long khosts_append_ed25519(const char *path,
                                    const char *host,
                                    u16 port,
                                    const u8 *server_pub) {
    buf wire;      /* SSH wire blob: string("ssh-ed25519") || string(pub) */
    buf b64;
    FILE *fp;
    unsigned long rc;

    if (!path || !host || !server_pub) return __LINE__;

    rc = mkdirs_for(path);
    if (rc) return __LINE__;

    if (buf_create(&wire, 64)) return __LINE__;
    {
        u8 hdr[4];
        u32 n = 11;  /* strlen("ssh-ed25519") */
        hdr[0] = (u8)(n >> 24); hdr[1] = (u8)(n >> 16);
        hdr[2] = (u8)(n >> 8);  hdr[3] = (u8)n;
        buf_append(&wire, hdr, 4);
        buf_append(&wire, (const u8 *)"ssh-ed25519", 11);
        n = 32;
        hdr[0] = (u8)(n >> 24); hdr[1] = (u8)(n >> 16);
        hdr[2] = (u8)(n >> 8);  hdr[3] = (u8)n;
        buf_append(&wire, hdr, 4);
        buf_append(&wire, server_pub, 32);
    }

    if (buf_create(&b64, 128)) { buf_destroy(&wire); return __LINE__; }
    if (base64_encode(&b64, wire.data, wire.len)) {
        buf_destroy(&wire); buf_destroy(&b64);
        return __LINE__;
    }
    buf_destroy(&wire);

    fp = fopen(path, "ab");
    if (!fp) { buf_destroy(&b64); return __LINE__; }
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

unsigned long khosts_default_path(char *out, u64 out_size) {
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
    if (!home) return __LINE__;
    if ((u64)snprintf(out, (size_t)out_size, "%s/.ssh/known_hosts", home)
        >= out_size) return __LINE__;
    /* Normalize backslashes. */
    {
        char *p;
        for (p = out; *p; p++) if (*p == '\\') *p = '/';
    }
    return 0;
}
