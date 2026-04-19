#include "gut/remote.h"
#include "gut/cred_helper.h"
#include "apennines/https_client.h"
#include "apennines/http_client.h"
#include "apennines/buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Implemented in remote_ssh.c. Kept out of the public remote.h so
 * HTTP-only callers don't pull in the SSH primitives, but still
 * visible here so remote_* functions can dispatch by URL scheme. */
int           url_is_ssh(const char *url);
unsigned long ssh_discover_refs(gut_remote_refs *out, const char *url);
unsigned long ssh_fetch_pack_algo(const char *url,
                                  gut_oid *want_oids, u64 want_count,
                                  gut_oid *have_oids, u64 have_count,
                                  const char *pack_path,
                                  int depth,
                                  gut_oid **shallow_out,
                                  u64     *shallow_count_out,
                                  gut_hash_algo algo);
unsigned long ssh_discover_refs_for_push(gut_remote_refs *out, const char *url);
unsigned long ssh_send_pack_algo(char **server_msg, const char *url,
                                 gut_remote_update *updates, u64 update_count,
                                 u8 *pack_data, u64 pack_len,
                                 gut_hash_algo algo);

/* ---- pkt-line helpers ---- */

/* Read a pkt-line length from 4 hex chars. Returns 0 for flush packet. */
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

/* Write a pkt-line: 4-hex-length + data + newline */
static unsigned long pktline_write(buf *out, const char *line) {
    u64 len = strlen(line);
    u64 pkt_len = len + 5; /* 4 hex + content + newline */
    char hdr[5];
    unsigned long rc;

    snprintf(hdr, sizeof(hdr), "%04x", (unsigned)(pkt_len));
    rc = buf_append(out, (u8 *)hdr, 4);
    if (rc) return __LINE__;
    rc = buf_append(out, (u8 *)line, len);
    if (rc) return __LINE__;
    rc = buf_append_byte(out, '\n');
    if (rc) return __LINE__;
    return 0;
}

static unsigned long pktline_flush(buf *out) {
    return buf_append(out, (u8 *)"0000", 4);
}

/* ---- HTTP helpers ---- */

/* Determine if URL is HTTPS or HTTP */
static int is_https(const char *url) {
    return (strncmp(url, "https://", 8) == 0);
}

/* Perform GET request, return body. Caller frees *body. */
static unsigned long http_get(u8 **body, u64 *body_len, const char *url) {
    unsigned long rc;

    if (is_https(url)) {
        https_client *c;
        https_response resp;

        rc = https_client_create(&c);
        if (rc) return __LINE__;

        rc = https_client_get(&resp, c, url);
        if (rc) { https_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            https_response_free(&resp);
            https_client_destroy(c);
            return __LINE__;
        }

        *body = (u8 *)malloc((size_t)resp.body_len);
        if (!*body) { https_response_free(&resp); https_client_destroy(c); return __LINE__; }
        memcpy(*body, resp.body, (size_t)resp.body_len);
        *body_len = resp.body_len;

        https_response_free(&resp);
        https_client_destroy(c);
    } else {
        http_client *c;
        http_client_response resp;

        rc = http_client_create(&c);
        if (rc) return __LINE__;

        rc = http_client_get(&resp, c, url);
        if (rc) { http_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            http_client_response_free(&resp);
            http_client_destroy(c);
            return __LINE__;
        }

        *body = (u8 *)malloc((size_t)resp.body_len);
        if (!*body) { http_client_response_free(&resp); http_client_destroy(c); return __LINE__; }
        memcpy(*body, resp.body, (size_t)resp.body_len);
        *body_len = resp.body_len;

        http_client_response_free(&resp);
        http_client_destroy(c);
    }

    return 0;
}

/* Perform POST request with body. Caller frees *resp_body. */
static unsigned long http_post(u8 **resp_body, u64 *resp_body_len,
                               const char *url, const u8 *req_body, u64 req_body_len,
                               const char *content_type) {
    unsigned long rc;

    if (is_https(url)) {
        https_client *c;
        https_response resp;

        rc = https_client_create(&c);
        if (rc) return __LINE__;

        rc = https_client_post(&resp, c, url, req_body, req_body_len, content_type);
        if (rc) { https_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            https_response_free(&resp);
            https_client_destroy(c);
            return __LINE__;
        }

        *resp_body = (u8 *)malloc((size_t)resp.body_len);
        if (!*resp_body) { https_response_free(&resp); https_client_destroy(c); return __LINE__; }
        memcpy(*resp_body, resp.body, (size_t)resp.body_len);
        *resp_body_len = resp.body_len;

        https_response_free(&resp);
        https_client_destroy(c);
    } else {
        http_client *c;
        http_client_response resp;

        rc = http_client_create(&c);
        if (rc) return __LINE__;

        rc = http_client_post(&resp, c, url, req_body, req_body_len, content_type);
        if (rc) { http_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            http_client_response_free(&resp);
            http_client_destroy(c);
            return __LINE__;
        }

        *resp_body = (u8 *)malloc((size_t)resp.body_len);
        if (!*resp_body) { http_client_response_free(&resp); http_client_destroy(c); return __LINE__; }
        memcpy(*resp_body, resp.body, (size_t)resp.body_len);
        *resp_body_len = resp.body_len;

        http_client_response_free(&resp);
        http_client_destroy(c);
    }

    return 0;
}

/* ====================================================================
 *  Credential-helper integration
 *
 *  When an HTTPS smart-protocol call returns 401 Unauthorized, resolve
 *  the configured credential helper (via GUT_CREDENTIAL_HELPER env, a
 *  `credential.helper` config key in the hinted git dir, or nothing),
 *  run `<helper> get` for the URL, and retry the request with HTTP
 *  Basic auth.
 *
 *  A module-local cache keeps the creds once obtained so the next HTTP
 *  call in the same flow (e.g. fetch-pack after discover-refs) doesn't
 *  re-invoke the helper.
 * ==================================================================== */

typedef struct {
    int      valid;
    char     scheme_host[320];   /* "https://github.com" — cache key */
    char     username[256];
    char     password[512];
} cred_cache_t;

static cred_cache_t g_cred_cache = {0};
/* Git dir hint for where to look for `credential.helper`. Set by a
 * repo-aware caller before it makes HTTP calls; NULL for `gut clone`. */
static const char *g_git_dir_hint = NULL;

/* Called by cmd_fetch / cmd_push before issuing HTTP calls; lets us
 * find `credential.helper` in the current repo's .git/config. For
 * `gut clone` the repo doesn't exist yet, so this stays NULL and we
 * fall through to GUT_CREDENTIAL_HELPER only. */
void remote_set_cred_git_dir(const char *git_dir) {
    g_git_dir_hint = git_dir;
}

/* Extract "<scheme>://<host>" from a full URL for cache keying.
 * Ignores port, path, userinfo. */
static void make_cache_key(char *out, u64 out_sz, const char *url) {
    const char *scheme_end;
    const char *authority;
    const char *at;
    const char *p;
    const char *host_end;

    out[0] = '\0';
    scheme_end = strstr(url, "://");
    if (!scheme_end) return;
    authority = scheme_end + 3;
    at = authority;
    p = authority;
    while (*p && *p != '/' && *p != '@') p++;
    authority = (*p == '@') ? p + 1 : at;
    host_end = authority;
    while (*host_end && *host_end != '/' && *host_end != ':') host_end++;
    snprintf(out, (size_t)out_sz, "%.*s://%.*s",
             (int)(scheme_end - url), url,
             (int)(host_end - authority), authority);
}

static unsigned long resolve_cred_helper_name(char *out, u64 out_sz) {
    const char *env = getenv("GUT_CREDENTIAL_HELPER");
    if (env && *env) {
        if (strlen(env) >= out_sz) return __LINE__;
        snprintf(out, (size_t)out_sz, "%s", env);
        return 0;
    }
    if (g_git_dir_hint) {
        return cred_helper_from_config(out, out_sz, g_git_dir_hint);
    }
    return __LINE__;
}

/* Try to fill (user_out, pass_out) from the credential helper for
 * the given URL. Returns 0 on success. Consults the in-flight cache
 * first. */
static unsigned long resolve_credentials_for_url(const char *url,
                                                 char *user_out, u64 user_sz,
                                                 char *pass_out, u64 pass_sz) {
    char helper[256];
    gut_cred_request req;
    gut_cred_response resp;
    char key[320];

    make_cache_key(key, sizeof(key), url);
    if (g_cred_cache.valid &&
        strcmp(g_cred_cache.scheme_host, key) == 0) {
        snprintf(user_out, (size_t)user_sz, "%s", g_cred_cache.username);
        snprintf(pass_out, (size_t)pass_sz, "%s", g_cred_cache.password);
        return 0;
    }

    if (resolve_cred_helper_name(helper, sizeof(helper)) != 0) return __LINE__;
    if (cred_request_from_url(&req, url) != 0) return __LINE__;
    if (cred_helper_get(&resp, helper, &req) != 0) return __LINE__;

    snprintf(user_out, (size_t)user_sz, "%s", resp.username);
    snprintf(pass_out, (size_t)pass_sz, "%s", resp.password);

    /* Cache for subsequent calls in the same flow. */
    g_cred_cache.valid = 1;
    snprintf(g_cred_cache.scheme_host, sizeof(g_cred_cache.scheme_host),
             "%s", key);
    snprintf(g_cred_cache.username, sizeof(g_cred_cache.username),
             "%s", resp.username);
    snprintf(g_cred_cache.password, sizeof(g_cred_cache.password),
             "%s", resp.password);
    return 0;
}

/* HTTPS GET that retries with credential-helper creds on 401.
 * For non-HTTPS URLs, falls through to plain http_get unchanged. */
static unsigned long http_get_auth_aware(u8 **body, u64 *body_len,
                                         const char *url) {
    https_client *c;
    https_response resp;
    unsigned long rc;
    int retried = 0;
    char user[256];
    char pass[512];

    if (!is_https(url)) return http_get(body, body_len, url);

    rc = https_client_create(&c);
    if (rc) return __LINE__;

    /* Preemptively attach cached creds if we have them — saves the
     * 401 roundtrip on the second and subsequent calls of a flow. */
    if (g_cred_cache.valid) {
        char key[320];
        make_cache_key(key, sizeof(key), url);
        if (strcmp(g_cred_cache.scheme_host, key) == 0) {
            https_client_set_auth_basic(c, g_cred_cache.username,
                                        g_cred_cache.password);
            retried = 1;   /* don't loop if the cached creds happen to fail */
        }
    }

    rc = https_client_get(&resp, c, url);
    if (rc) { https_client_destroy(c); return __LINE__; }

    if (resp.status == 401 && !retried) {
        https_response_free(&resp);
        if (resolve_credentials_for_url(url, user, sizeof(user),
                                        pass, sizeof(pass)) != 0) {
            https_client_destroy(c);
            return __LINE__;
        }
        https_client_set_auth_basic(c, user, pass);
        rc = https_client_get(&resp, c, url);
        if (rc) { https_client_destroy(c); return __LINE__; }
    }

    if (resp.status < 200 || resp.status >= 300) {
        fprintf(stderr, "error: HTTP %u from %s\n", (unsigned)resp.status, url);
        https_response_free(&resp);
        https_client_destroy(c);
        return __LINE__;
    }

    *body = (u8 *)malloc((size_t)resp.body_len);
    if (!*body) {
        https_response_free(&resp);
        https_client_destroy(c);
        return __LINE__;
    }
    memcpy(*body, resp.body, (size_t)resp.body_len);
    *body_len = resp.body_len;

    https_response_free(&resp);
    https_client_destroy(c);
    return 0;
}

/* HTTPS POST that retries with credential-helper creds on 401.
 * For non-HTTPS URLs, falls through to plain http_post. */
static unsigned long http_post_auth_aware(u8 **resp_body, u64 *resp_body_len,
                                          const char *url,
                                          const u8 *req_body, u64 req_body_len,
                                          const char *content_type) {
    https_client *c;
    https_response resp;
    unsigned long rc;
    int retried = 0;
    char user[256];
    char pass[512];

    if (!is_https(url)) {
        return http_post(resp_body, resp_body_len, url,
                         req_body, req_body_len, content_type);
    }

    rc = https_client_create(&c);
    if (rc) return __LINE__;

    if (g_cred_cache.valid) {
        char key[320];
        make_cache_key(key, sizeof(key), url);
        if (strcmp(g_cred_cache.scheme_host, key) == 0) {
            https_client_set_auth_basic(c, g_cred_cache.username,
                                        g_cred_cache.password);
            retried = 1;
        }
    }

    rc = https_client_post(&resp, c, url, req_body, req_body_len, content_type);
    if (rc) { https_client_destroy(c); return __LINE__; }

    if (resp.status == 401 && !retried) {
        https_response_free(&resp);
        if (resolve_credentials_for_url(url, user, sizeof(user),
                                        pass, sizeof(pass)) != 0) {
            https_client_destroy(c);
            return __LINE__;
        }
        https_client_set_auth_basic(c, user, pass);
        rc = https_client_post(&resp, c, url, req_body, req_body_len, content_type);
        if (rc) { https_client_destroy(c); return __LINE__; }
    }

    if (resp.status < 200 || resp.status >= 300) {
        fprintf(stderr, "error: HTTP %u from %s\n", (unsigned)resp.status, url);
        https_response_free(&resp);
        https_client_destroy(c);
        return __LINE__;
    }

    *resp_body = (u8 *)malloc((size_t)resp.body_len);
    if (!*resp_body) {
        https_response_free(&resp);
        https_client_destroy(c);
        return __LINE__;
    }
    memcpy(*resp_body, resp.body, (size_t)resp.body_len);
    *resp_body_len = resp.body_len;

    https_response_free(&resp);
    https_client_destroy(c);
    return 0;
}

/* ---- HTTP chunked transfer-encoding dechunker ----
 * If the body is chunked ("1BC\r\n<data>\r\n...0\r\n\r\n"), dechunks in place.
 * If not chunked, leaves body untouched. */
static unsigned long dechunk_if_needed(u8 **body, u64 *body_len) {
    u8 *src = *body;
    u64 src_len = *body_len;
    u64 k, p;
    int is_chunked = 0;
    u8 *dechunked;
    u64 dechunked_len = 0;
    u64 dechunked_cap;

    /* Detect: starts with hex + CRLF */
    k = 0;
    while (k < src_len && ((src[k] >= '0' && src[k] <= '9') ||
           (src[k] >= 'a' && src[k] <= 'f') ||
           (src[k] >= 'A' && src[k] <= 'F'))) k++;
    if (k > 0 && k + 1 < src_len && src[k] == '\r' && src[k + 1] == '\n') {
        is_chunked = 1;
    }
    if (!is_chunked) return 0;

    dechunked_cap = src_len;
    dechunked = (u8 *)malloc((size_t)dechunked_cap);
    if (!dechunked) return __LINE__;

    p = 0;
    while (p < src_len) {
        u64 chunk_size = 0;
        while (p < src_len && src[p] != '\r') {
            u8 c = src[p];
            chunk_size <<= 4;
            if (c >= '0' && c <= '9') chunk_size |= c - '0';
            else if (c >= 'a' && c <= 'f') chunk_size |= 10 + c - 'a';
            else if (c >= 'A' && c <= 'F') chunk_size |= 10 + c - 'A';
            else break;
            p++;
        }
        if (p + 1 >= src_len || src[p] != '\r' || src[p + 1] != '\n') break;
        p += 2;

        if (chunk_size == 0) break;
        if (p + chunk_size > src_len) break;

        if (dechunked_len + chunk_size > dechunked_cap) {
            u8 *tmp;
            dechunked_cap = (dechunked_len + chunk_size) * 2;
            tmp = (u8 *)realloc(dechunked, (size_t)dechunked_cap);
            if (!tmp) { free(dechunked); return __LINE__; }
            dechunked = tmp;
        }

        memcpy(dechunked + dechunked_len, src + p, (size_t)chunk_size);
        dechunked_len += chunk_size;
        p += chunk_size;

        if (p + 1 < src_len && src[p] == '\r' && src[p + 1] == '\n') p += 2;
    }

    free(src);
    *body = dechunked;
    *body_len = dechunked_len;
    return 0;
}

/* ---- Smart HTTP protocol ---- */

unsigned long remote_discover_refs(gut_remote_refs *out, const char *url) {
    char info_url[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!url) return __LINE__;

    if (url_is_ssh(url)) return ssh_discover_refs(out, url);

    out->count = 0;
    out->capabilities[0] = '\0';
    out->hash_algo = GUT_HASH_SHA1;

    /* Strip trailing slash and .git if present */
    {
        char clean_url[2048];
        size_t ulen = strlen(url);
        if (ulen >= sizeof(clean_url)) return __LINE__;
        memcpy(clean_url, url, ulen + 1);
        while (ulen > 0 && clean_url[ulen - 1] == '/') clean_url[--ulen] = '\0';

        snprintf(info_url, sizeof(info_url), "%s/info/refs?service=git-upload-pack", clean_url);
    }

    rc = http_get_auth_aware(&body, &body_len, info_url);
    if (rc) return __LINE__;

    rc = dechunk_if_needed(&body, &body_len);
    if (rc) { free(body); return __LINE__; }

    /* Parse pkt-line response.
     * First line is usually "# service=git-upload-pack\n"
     * Then a flush packet "0000"
     * Then ref lines: "<oid> <refname>\n" or "<oid> <refname>\0<capabilities>\n"
     * OID width is 40 (SHA-1) or 64 (SHA-256) — detected from the position of
     * the first space (or object-format= capability). */
    pos = 0;

    while (pos + 4 <= body_len) {
        u32 pkt_len = pktline_len(body + pos);

        if (pkt_len == 0) {
            /* Flush packet */
            pos += 4;
            continue;
        }

        if (pkt_len < 4 || pos + pkt_len > body_len) break;

        {
            const char *line = (const char *)(body + pos + 4);
            u64 line_len = pkt_len - 4;
            unsigned hex_len;
            u64 sp;

            /* Strip trailing newline */
            while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r'))
                line_len--;

            /* Skip service declaration lines */
            if (line[0] == '#') {
                pos += pkt_len;
                continue;
            }

            /* Detect OID width from first space position (40 or 64). */
            sp = 0;
            while (sp < line_len && line[sp] != ' ') sp++;
            if (sp != 40 && sp != 64) { pos += pkt_len; continue; }
            hex_len = (unsigned)sp;
            if (out->count == 0) {
                out->hash_algo = (hex_len == 64) ? GUT_HASH_SHA256 : GUT_HASH_SHA1;
            }

            if (line_len >= hex_len + 1 && out->count < GUT_REMOTE_MAX_REFS) {
                gut_remote_ref *ref = &out->refs[out->count];
                unsigned long parse_rc;

                parse_rc = oid_from_hex_n(&ref->oid, line, hex_len);
                if (parse_rc == 0) {
                    /* Find ref name (starts after space) */
                    const char *name_start = line + hex_len + 1;
                    const char *name_end = name_start;
                    const char *caps = NULL;

                    /* Name ends at \0 (capabilities follow) or end of line */
                    while (name_end < line + line_len && *name_end != '\0')
                        name_end++;

                    if (name_end < line + line_len && *name_end == '\0') {
                        caps = name_end + 1;
                    }

                    {
                        size_t nlen = (size_t)(name_end - name_start);
                        if (nlen >= sizeof(ref->name)) nlen = sizeof(ref->name) - 1;
                        memcpy(ref->name, name_start, nlen);
                        ref->name[nlen] = '\0';
                    }

                    /* Capture capabilities from first ref */
                    if (caps && out->count == 0) {
                        size_t clen = (size_t)(line + line_len - caps);
                        if (clen >= sizeof(out->capabilities)) clen = sizeof(out->capabilities) - 1;
                        memcpy(out->capabilities, caps, clen);
                        out->capabilities[clen] = '\0';
                        /* Cross-check object-format capability */
                        if (strstr(out->capabilities, "object-format=sha256")) {
                            out->hash_algo = GUT_HASH_SHA256;
                        }
                    }

                    out->count++;
                }
            }
        }

        pos += pkt_len;
    }

    free(body);
    return 0;
}

unsigned long remote_fetch_pack_algo(const char *url,
                                     gut_oid *want_oids, u64 want_count,
                                     gut_oid *have_oids, u64 have_count,
                                     const char *pack_path,
                                     int depth,
                                     gut_oid **shallow_out,
                                     u64     *shallow_count_out,
                                     gut_hash_algo algo) {
    char post_url[2048];
    buf request;
    u8 *resp_body = NULL;
    u64 resp_len = 0;
    unsigned long rc;
    u64 i;
    FILE *fp;
    gut_oid *shallows = NULL;
    u64 n_shallows = 0;
    unsigned hex_len = gut_oid_hex_size(algo);

    if (shallow_out) *shallow_out = NULL;
    if (shallow_count_out) *shallow_count_out = 0;

    if (!url || !want_oids || want_count == 0 || !pack_path) return __LINE__;

    if (url_is_ssh(url)) {
        return ssh_fetch_pack_algo(url, want_oids, want_count,
                                   have_oids, have_count,
                                   pack_path, depth,
                                   shallow_out, shallow_count_out, algo);
    }

    {
        char clean_url[2048];
        size_t ulen = strlen(url);
        if (ulen >= sizeof(clean_url)) return __LINE__;
        memcpy(clean_url, url, ulen + 1);
        while (ulen > 0 && clean_url[ulen - 1] == '/') clean_url[--ulen] = '\0';

        snprintf(post_url, sizeof(post_url), "%s/git-upload-pack", clean_url);
    }

    /* Build request body */
    rc = buf_create(&request, 1024);
    if (rc) return __LINE__;

    /* want lines */
    for (i = 0; i < want_count; i++) {
        char line[256];
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        oid_to_hex_n(hex, &want_oids[i], hex_len);
        if (i == 0) {
            /* First want includes capabilities. Advertise `shallow` so the
             * server knows we can handle shallow/unshallow lines (it will
             * ignore `deepen` if we don't advertise it). */
            const char *fmt_cap = (algo == GUT_HASH_SHA256)
                ? " object-format=sha256" : "";
            snprintf(line, sizeof(line),
                     "want %s multi_ack_detailed side-band-64k ofs-delta shallow%s",
                     hex, fmt_cap);
        } else {
            snprintf(line, sizeof(line), "want %s", hex);
        }
        rc = pktline_write(&request, line);
        if (rc) { buf_destroy(&request); return __LINE__; }
    }

    /* deepen line — must come after wants, before the wants-flush */
    if (depth > 0) {
        char line[32];
        snprintf(line, sizeof(line), "deepen %d", depth);
        rc = pktline_write(&request, line);
        if (rc) { buf_destroy(&request); return __LINE__; }
    }

    rc = pktline_flush(&request);
    if (rc) { buf_destroy(&request); return __LINE__; }

    /* have lines (for fetch, not clone) */
    for (i = 0; i < have_count; i++) {
        char line[160];
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        oid_to_hex_n(hex, &have_oids[i], hex_len);
        snprintf(line, sizeof(line), "have %s", hex);
        rc = pktline_write(&request, line);
        if (rc) { buf_destroy(&request); return __LINE__; }
    }

    /* done */
    rc = pktline_write(&request, "done");
    if (rc) { buf_destroy(&request); return __LINE__; }

    /* POST to git-upload-pack */
    rc = http_post_auth_aware(&resp_body, &resp_len, post_url,
                              request.data, request.len,
                              "application/x-git-upload-pack-request");
    buf_destroy(&request);
    if (rc) return __LINE__;

    rc = dechunk_if_needed(&resp_body, &resp_len);
    if (rc) { free(resp_body); return __LINE__; }

    /* If sideband-64k was negotiated, the pack is wrapped in pkt-lines
     * where each packet's first byte is a band ID (1=pack data, 2=progress, 3=error).
     * Extract only band-1 data into a continuous stream. */
    {
        u8 *pack_stream = NULL;
        u64 pack_stream_len = 0;
        u64 p = 0;
        int saw_nak = 0;

        pack_stream = (u8 *)malloc((size_t)resp_len);
        if (!pack_stream) { free(resp_body); return __LINE__; }

        while (p + 4 <= resp_len) {
            u32 plen = pktline_len(resp_body + p);
            if (plen == 0) {
                /* flush packet */
                p += 4;
                continue;
            }
            if (plen < 4 || p + plen > resp_len) break;

            {
                const u8 *payload = resp_body + p + 4;
                u64 payload_len = plen - 4;

                /* `shallow <oid>` line — appears before NAK, no sideband byte */
                if (!saw_nak && payload_len >= 8 + (u64)hex_len &&
                    memcmp(payload, "shallow ", 8) == 0) {
                    gut_oid s_oid;
                    char hex[GUT_OID_MAX_HEX_SIZE + 1];
                    memcpy(hex, payload + 8, hex_len);
                    hex[hex_len] = 0;
                    if (oid_from_hex_n(&s_oid, hex, hex_len) == 0) {
                        gut_oid *tmp = (gut_oid *)realloc(
                            shallows, (n_shallows + 1) * sizeof(gut_oid));
                        if (tmp) {
                            shallows = tmp;
                            shallows[n_shallows++] = s_oid;
                        }
                    }
                    p += plen;
                    continue;
                }

                /* NAK line: "NAK\n" (no sideband prefix) */
                if (!saw_nak && payload_len >= 3 &&
                    payload[0] == 'N' && payload[1] == 'A' && payload[2] == 'K') {
                    saw_nak = 1;
                    p += plen;
                    continue;
                }

                if (payload_len >= 1) {
                    u8 band = payload[0];
                    if (band == 1) {
                        /* Pack data */
                        memcpy(pack_stream + pack_stream_len,
                               payload + 1, (size_t)(payload_len - 1));
                        pack_stream_len += payload_len - 1;
                    }
                    /* band 2 = progress, band 3 = error — ignore for now */
                }
            }
            p += plen;
        }

        if (pack_stream_len == 0) {
            /* No sideband — scan for PACK signature directly */
            free(pack_stream);
        } else {
            free(resp_body);
            resp_body = pack_stream;
            resp_len = pack_stream_len;
        }
    }

    /* Response: skip pkt-line header (NAK etc), find PACK signature */
    {
        u64 pack_start = 0;
        u64 pos;

        /* Scan for "PACK" signature in response */
        for (pos = 0; pos + 4 <= resp_len; pos++) {
            if (resp_body[pos] == 'P' && resp_body[pos + 1] == 'A' &&
                resp_body[pos + 2] == 'C' && resp_body[pos + 3] == 'K') {
                pack_start = pos;
                break;
            }
        }

        if (pack_start == 0 && resp_len > 4) {
            /* Maybe the whole response is the pack (no sideband) */
            if (resp_body[0] == 'P' && resp_body[1] == 'A' &&
                resp_body[2] == 'C' && resp_body[3] == 'K') {
                pack_start = 0;
            } else {
                free(resp_body);
                free(shallows);
                return __LINE__; /* no pack found */
            }
        }

        /* Write pack to file */
        fp = fopen(pack_path, "wb");
        if (!fp) { free(resp_body); free(shallows); return __LINE__; }

        fwrite(resp_body + pack_start, 1, (size_t)(resp_len - pack_start), fp);
        fclose(fp);
    }

    free(resp_body);

    if (shallow_out && n_shallows > 0) {
        *shallow_out = shallows;
        if (shallow_count_out) *shallow_count_out = n_shallows;
    } else {
        free(shallows);
    }
    return 0;
}

unsigned long remote_fetch_pack(const char *url,
                                gut_oid *want_oids, u64 want_count,
                                gut_oid *have_oids, u64 have_count,
                                const char *pack_path,
                                int depth,
                                gut_oid **shallow_out,
                                u64     *shallow_count_out) {
    return remote_fetch_pack_algo(url, want_oids, want_count,
                                   have_oids, have_count,
                                   pack_path, depth,
                                   shallow_out, shallow_count_out,
                                   GUT_HASH_SHA1);
}

/* ====================================================================
 *  Push: discover refs + send pack
 * ==================================================================== */

/* Same as remote_discover_refs, but uses git-receive-pack service.
 * Optional bearer token via Authorization. */
unsigned long remote_discover_refs_for_push(gut_remote_refs *out, const char *url,
                                             const char *token) {
    char info_url[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos;
    unsigned long rc;

    if (!out || !url) return __LINE__;

    if (url_is_ssh(url)) { (void)token; return ssh_discover_refs_for_push(out, url); }
    out->count = 0;
    out->capabilities[0] = '\0';
    out->hash_algo = GUT_HASH_SHA1;

    {
        char clean_url[2048];
        size_t ulen = strlen(url);
        if (ulen >= sizeof(clean_url)) return __LINE__;
        memcpy(clean_url, url, ulen + 1);
        while (ulen > 0 && clean_url[ulen - 1] == '/') clean_url[--ulen] = '\0';
        snprintf(info_url, sizeof(info_url),
                 "%s/info/refs?service=git-receive-pack", clean_url);
    }

    /* Use authenticated GET if token provided */
    if (token && *token && is_https(info_url)) {
        https_client *c;
        https_response resp;

        rc = https_client_create(&c);
        if (rc) return __LINE__;

        /* Treat token as personal access token: HTTP Basic with x-oauth-basic / token */
        https_client_set_auth_basic(c, "x-oauth-basic", token);

        rc = https_client_get(&resp, c, info_url);
        if (rc) { https_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            fprintf(stderr, "error: server returned status %u\n", (unsigned)resp.status);
            https_response_free(&resp);
            https_client_destroy(c);
            return __LINE__;
        }

        body = (u8 *)malloc((size_t)resp.body_len);
        if (!body) { https_response_free(&resp); https_client_destroy(c); return __LINE__; }
        memcpy(body, resp.body, (size_t)resp.body_len);
        body_len = resp.body_len;

        https_response_free(&resp);
        https_client_destroy(c);
    } else {
        rc = http_get(&body, &body_len, info_url);
        if (rc) return __LINE__;
    }

    rc = dechunk_if_needed(&body, &body_len);
    if (rc) { free(body); return __LINE__; }

    /* Parse pkt-line response (same as discover_refs). Width of OID is
     * detected from the first space in the first ref line. */
    pos = 0;
    while (pos + 4 <= body_len) {
        u32 pkt_len = pktline_len(body + pos);
        if (pkt_len == 0) { pos += 4; continue; }
        if (pkt_len < 4 || pos + pkt_len > body_len) break;

        {
            const char *line = (const char *)(body + pos + 4);
            u64 line_len = pkt_len - 4;
            unsigned hex_len;
            u64 sp;

            while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r'))
                line_len--;
            if (line[0] == '#') { pos += pkt_len; continue; }

            sp = 0;
            while (sp < line_len && line[sp] != ' ') sp++;
            if (sp != 40 && sp != 64) { pos += pkt_len; continue; }
            hex_len = (unsigned)sp;
            if (out->count == 0) {
                out->hash_algo = (hex_len == 64) ? GUT_HASH_SHA256 : GUT_HASH_SHA1;
            }

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
                        size_t nlen = (size_t)(name_end - name_start);
                        if (nlen >= sizeof(ref->name)) nlen = sizeof(ref->name) - 1;
                        memcpy(ref->name, name_start, nlen);
                        ref->name[nlen] = '\0';
                    }
                    if (caps && out->count == 0) {
                        size_t clen = (size_t)(line + line_len - caps);
                        if (clen >= sizeof(out->capabilities)) clen = sizeof(out->capabilities) - 1;
                        memcpy(out->capabilities, caps, clen);
                        out->capabilities[clen] = '\0';
                        if (strstr(out->capabilities, "object-format=sha256")) {
                            out->hash_algo = GUT_HASH_SHA256;
                        }
                    }
                    out->count++;
                }
            }
        }
        pos += pkt_len;
    }

    free(body);
    return 0;
}

unsigned long remote_send_pack_algo(char **server_msg, const char *url,
                                    const char *token,
                                    gut_remote_update *updates, u64 update_count,
                                    u8 *pack_data, u64 pack_len,
                                    gut_hash_algo algo) {
    char post_url[2048];
    buf request;
    u64 i;
    unsigned long rc;
    unsigned hex_len = gut_oid_hex_size(algo);

    if (server_msg) *server_msg = NULL;
    if (!url || !updates || update_count == 0) return __LINE__;

    if (url_is_ssh(url)) {
        (void)token;
        return ssh_send_pack_algo(server_msg, url,
                                  updates, update_count,
                                  pack_data, pack_len, algo);
    }

    {
        char clean_url[2048];
        size_t ulen = strlen(url);
        if (ulen >= sizeof(clean_url)) return __LINE__;
        memcpy(clean_url, url, ulen + 1);
        while (ulen > 0 && clean_url[ulen - 1] == '/') clean_url[--ulen] = '\0';
        snprintf(post_url, sizeof(post_url), "%s/git-receive-pack", clean_url);
    }

    /* Build request body: pkt-line update commands + flush + pack */
    rc = buf_create(&request, pack_len + 1024);
    if (rc) return __LINE__;

    for (i = 0; i < update_count; i++) {
        char old_hex[GUT_OID_MAX_HEX_SIZE + 1];
        char new_hex[GUT_OID_MAX_HEX_SIZE + 1];
        oid_to_hex_n(old_hex, &updates[i].old_oid, hex_len);
        oid_to_hex_n(new_hex, &updates[i].new_oid, hex_len);
        if (i == 0) {
            /* First command line includes capabilities (with object-format
             * when non-default). Manually compose to embed the NUL byte. */
            char caps[128];
            u64 cmd_part_len = (u64)hex_len + 1 + (u64)hex_len + 1
                               + strlen(updates[i].ref_name);
            u64 caps_len;
            u64 total;
            char hdr[5];
            snprintf(caps, sizeof(caps),
                     (algo == GUT_HASH_SHA256)
                         ? "report-status object-format=sha256"
                         : "report-status");
            caps_len = strlen(caps);
            total = cmd_part_len + 1 /*NUL*/ + caps_len + 1 /*\n*/;
            snprintf(hdr, sizeof(hdr), "%04x", (unsigned)(total + 4));
            buf_append(&request, (u8 *)hdr, 4);
            buf_append(&request, (u8 *)old_hex, hex_len);
            buf_append_byte(&request, ' ');
            buf_append(&request, (u8 *)new_hex, hex_len);
            buf_append_byte(&request, ' ');
            buf_append(&request, (u8 *)updates[i].ref_name, strlen(updates[i].ref_name));
            buf_append_byte(&request, '\0');
            buf_append(&request, (u8 *)caps, caps_len);
            buf_append_byte(&request, '\n');
        } else {
            char line[1024];
            int ll;
            char hdr[5];
            ll = snprintf(line, sizeof(line), "%s %s %s\n",
                          old_hex, new_hex, updates[i].ref_name);
            snprintf(hdr, sizeof(hdr), "%04x", (unsigned)(ll + 4));
            buf_append(&request, (u8 *)hdr, 4);
            buf_append(&request, (u8 *)line, (u64)ll);
        }
    }
    pktline_flush(&request);

    /* Append pack bytes */
    buf_append(&request, pack_data, pack_len);

    /* Send authenticated POST */
    {
        u8 *resp_body = NULL;
        u64 resp_len = 0;

        if (token && *token && is_https(post_url)) {
            https_client *c;
            https_response resp;

            rc = https_client_create(&c);
            if (rc) { buf_destroy(&request); return __LINE__; }

            https_client_set_auth_basic(c, "x-oauth-basic", token);

            rc = https_client_post(&resp, c, post_url, request.data, request.len,
                                   "application/x-git-receive-pack-request");
            buf_destroy(&request);
            if (rc) { https_client_destroy(c); return __LINE__; }

            if (resp.status < 200 || resp.status >= 300) {
                fprintf(stderr, "error: push returned status %u\n", (unsigned)resp.status);
                https_response_free(&resp);
                https_client_destroy(c);
                return __LINE__;
            }

            resp_body = (u8 *)malloc((size_t)resp.body_len);
            if (!resp_body) { https_response_free(&resp); https_client_destroy(c); return __LINE__; }
            memcpy(resp_body, resp.body, (size_t)resp.body_len);
            resp_len = resp.body_len;
            https_response_free(&resp);
            https_client_destroy(c);
        } else {
            rc = http_post(&resp_body, &resp_len, post_url, request.data, request.len,
                           "application/x-git-receive-pack-request");
            buf_destroy(&request);
            if (rc) return __LINE__;
        }

        rc = dechunk_if_needed(&resp_body, &resp_len);
        if (rc) { free(resp_body); return __LINE__; }

        if (server_msg) {
            *server_msg = (char *)malloc((size_t)(resp_len + 1));
            if (*server_msg) {
                memcpy(*server_msg, resp_body, (size_t)resp_len);
                (*server_msg)[resp_len] = '\0';
            }
        }
        free(resp_body);
    }

    return 0;
}

unsigned long remote_send_pack(char **server_msg, const char *url, const char *token,
                               gut_remote_update *updates, u64 update_count,
                               u8 *pack_data, u64 pack_len) {
    return remote_send_pack_algo(server_msg, url, token,
                                 updates, update_count,
                                 pack_data, pack_len,
                                 GUT_HASH_SHA1);
}
