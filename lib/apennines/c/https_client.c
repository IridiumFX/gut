#include "apennines/https_client.h"
#include "apennines/tcp.h"
#include "apennines/tls.h"
#include "apennines/dns.h"
#include "apennines/http.h"
#include "apennines/addr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ================================================================
 *  Helpers
 * ================================================================ */

static char *str_dup(const char *s) {
    size_t len;
    char *d;
    if (!s) return NULL;
    len = strlen(s);
    d = (char *)malloc(len + 1);
    if (!d) return NULL;
    memcpy(d, s, len + 1);
    return d;
}

static int ci_equal(const char *a, const char *b) {
    for (; *a && *b; ++a, ++b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

/* ================================================================
 *  Internal structures
 * ================================================================ */

#define HTTPS_DEFAULT_TIMEOUT_MS   30000
#define HTTPS_DEFAULT_MAX_REDIRECT 10
#define HTTPS_READ_BUF_SIZE        8192

typedef struct {
    char *user;
    char *pass;
} basic_auth;

struct https_client {
    tls_config      *tls_cfg;
    http_headers     default_headers;
    u64              timeout_ms;
    u32              max_redirects;
    char            *proxy_url;
    http_cookie_jar *cookie_jar;
    int              cookie_jar_enabled;
    int              compression;

    /* auth — only one active at a time */
    int              auth_type;   /* 0=none, 1=basic, 2=bearer */
    basic_auth       auth_basic;
    char            *auth_bearer;

    /* connection pool stats */
    u64              stat_active;
    u64              stat_idle;
    u64              stat_total;
};

/* ================================================================
 *  base64 mini-encoder (for Basic auth)
 * ================================================================ */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned long base64_encode(char **out, u64 *out_len,
                                   const u8 *data, u64 len) {
    u64 i, o;
    u64 olen;
    char *buf;
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!data && len) return 3;

    olen = 4 * ((len + 2) / 3);
    buf = (char *)malloc(olen + 1);
    if (!buf) return 4;

    o = 0;
    for (i = 0; i < len; i += 3) {
        u32 n = ((u32)data[i]) << 16;
        if (i + 1 < len) n |= ((u32)data[i + 1]) << 8;
        if (i + 2 < len) n |= ((u32)data[i + 2]);
        buf[o++] = b64_table[(n >> 18) & 0x3F];
        buf[o++] = b64_table[(n >> 12) & 0x3F];
        buf[o++] = (i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=';
        buf[o++] = (i + 2 < len) ? b64_table[n & 0x3F] : '=';
    }
    buf[o] = '\0';
    *out = buf;
    *out_len = o;
    return 0;
}

/* ================================================================
 *  Internal: send/receive over raw TCP or TLS
 * ================================================================ */

typedef struct {
    tcp_conn  tcp;
    tls_conn *tls;      /* NULL when plain HTTP */
    int       is_tls;
} conn_handle;

static unsigned long conn_write_all(conn_handle *h,
                                    const u8 *data, u64 len) {
    u64 written = 0;
    if (h->is_tls) {
        return tls_conn_write_all(&written, h->tls, data, len);
    }
    return tcp_conn_write_all(&written, &h->tcp, data, len);
}

static unsigned long conn_read(u64 *bytes_read, conn_handle *h,
                               u8 *buf, u64 len) {
    if (h->is_tls) {
        return tls_conn_read(bytes_read, h->tls, buf, len);
    }
    return tcp_conn_read(bytes_read, &h->tcp, buf, len);
}

static void conn_close(conn_handle *h) {
    if (h->is_tls && h->tls) {
        tls_conn_shutdown(h->tls);
        tls_conn_destroy(h->tls);
        h->tls = NULL;
    }
    tcp_conn_shutdown(&h->tcp, TCP_SHUTDOWN_BOTH);
    tcp_conn_destroy(&h->tcp);
}

/* ================================================================
 *  Internal: read full HTTP response from connection
 * ================================================================ */

static unsigned long read_response_bytes(u8 **out, u64 *out_len,
                                         conn_handle *h) {
    u8 *buf;
    u64 cap, total, nr;
    unsigned long rc;

    if (!out || !out_len) return 1;

    cap = HTTPS_READ_BUF_SIZE;
    buf = (u8 *)malloc(cap);
    if (!buf) return 2;
    total = 0;

    for (;;) {
        if (total + HTTPS_READ_BUF_SIZE > cap) {
            u8 *nb;
            cap *= 2;
            nb = (u8 *)realloc(buf, cap);
            if (!nb) { free(buf); return 2; }
            buf = nb;
        }
        nr = 0;
        rc = conn_read(&nr, h, buf + total, HTTPS_READ_BUF_SIZE);
        if (nr > 0) total += nr;
        if (rc != 0 || nr == 0) break; /* EOF or error */
    }

    *out = buf;
    *out_len = total;
    return 0;
}

/* ================================================================
 *  Internal: apply default/auth headers to a request
 * ================================================================ */

typedef struct {
    http_request *req;
} header_copy_ctx;

static void copy_header_cb(const char *name, const char *value, void *ctx) {
    header_copy_ctx *hc = (header_copy_ctx *)ctx;
    const char *existing = NULL;
    /* don't overwrite headers already set by caller */
    if (http_headers_get(&existing, &hc->req->headers, name) != 0) {
        http_request_set_header(hc->req, name, value);
    }
}

static unsigned long apply_defaults(https_client *c, http_request *req,
                                    const char *host) {
    header_copy_ctx hctx;
    unsigned long rc;

    /* Host header */
    rc = http_request_set_header(req, "Host", host);
    if (rc) return rc;

    /* Default headers */
    hctx.req = req;
    http_headers_iter(&c->default_headers, copy_header_cb, &hctx);

    /* User-Agent if not set */
    {
        const char *ua = NULL;
        if (http_headers_get(&ua, &req->headers, "User-Agent") != 0) {
            http_request_set_header(req, "User-Agent", "apennines/1.0");
        }
    }

    /* Compression */
    if (c->compression) {
        const char *ae = NULL;
        if (http_headers_get(&ae, &req->headers, "Accept-Encoding") != 0) {
            http_request_set_header(req, "Accept-Encoding", "identity");
        }
    }

    /* Auth */
    if (c->auth_type == 1 && c->auth_basic.user) {
        /* Basic auth */
        size_t ulen = strlen(c->auth_basic.user);
        size_t plen = c->auth_basic.pass ? strlen(c->auth_basic.pass) : 0;
        size_t cred_len = ulen + 1 + plen;
        char *cred = (char *)malloc(cred_len + 1);
        if (!cred) return 1;
        memcpy(cred, c->auth_basic.user, ulen);
        cred[ulen] = ':';
        if (plen > 0) memcpy(cred + ulen + 1, c->auth_basic.pass, plen);
        cred[cred_len] = '\0';
        {
            char *b64 = NULL;
            u64 b64_len = 0;
            rc = base64_encode(&b64, &b64_len, (const u8 *)cred, (u64)cred_len);
            free(cred);
            if (rc) return 2;
            {
                size_t hdr_len = 6 + b64_len; /* "Basic " + encoded */
                char *hdr = (char *)malloc(hdr_len + 1);
                if (!hdr) { free(b64); return 3; }
                memcpy(hdr, "Basic ", 6);
                memcpy(hdr + 6, b64, b64_len);
                hdr[hdr_len] = '\0';
                free(b64);
                http_request_set_header(req, "Authorization", hdr);
                free(hdr);
            }
        }
    } else if (c->auth_type == 2 && c->auth_bearer) {
        size_t tlen = strlen(c->auth_bearer);
        size_t hdr_len = 7 + tlen; /* "Bearer " + token */
        char *hdr = (char *)malloc(hdr_len + 1);
        if (!hdr) return 4;
        memcpy(hdr, "Bearer ", 7);
        memcpy(hdr + 7, c->auth_bearer, tlen);
        hdr[hdr_len] = '\0';
        http_request_set_header(req, "Authorization", hdr);
        free(hdr);
    }

    /* Cookies */
    if (c->cookie_jar_enabled && c->cookie_jar) {
        char *cookie_str = NULL;
        u64 cookie_len = 0;
        const char *path = req->url ? req->url : "/";
        rc = http_cookie_build(&cookie_str, &cookie_len,
                               c->cookie_jar, host, path);
        if (rc == 0 && cookie_str && cookie_len > 0) {
            http_request_set_header(req, "Cookie", cookie_str);
            free(cookie_str);
        }
    }

    return 0;
}

/* ================================================================
 *  Internal: store cookies from response
 * ================================================================ */

static void store_cookies(https_client *c, const http_response *resp,
                          const char *host) {
    u64 i;
    if (!c->cookie_jar_enabled || !c->cookie_jar) return;

    for (i = 0; i < resp->headers.count; ++i) {
        if (ci_equal(resp->headers.items[i].name, "Set-Cookie")) {
            http_cookie cookie;
            memset(&cookie, 0, sizeof(cookie));
            if (http_cookie_parse(&cookie,
                                  resp->headers.items[i].value) == 0) {
                /* fill domain if server didn't provide one */
                if (!cookie.domain) {
                    cookie.domain = str_dup(host);
                }
                http_cookie_jar_insert(c->cookie_jar, &cookie);
                http_cookie_free(&cookie);
            }
        }
    }
}

/* ================================================================
 *  Internal: single request/response cycle
 * ================================================================ */

static unsigned long do_single_request(https_response *out,
                                       https_client *c,
                                       int method,
                                       const http_url *url,
                                       const http_headers *extra_hdrs,
                                       const u8 *body, u64 body_len) {
    dns_response dns_resp;
    net_sock_addr addr;
    conn_handle conn;
    http_request req;
    u8 *wire = NULL;
    u64 wire_len = 0;
    u8 *raw = NULL;
    u64 raw_len = 0;
    http_response parsed;
    unsigned long rc;
    u16 port;
    int use_tls;
    char *request_target = NULL;

    memset(&dns_resp, 0, sizeof(dns_resp));
    memset(&conn, 0, sizeof(conn));
    memset(&req, 0, sizeof(req));
    memset(&parsed, 0, sizeof(parsed));
    memset(out, 0, sizeof(*out));

    /* determine scheme */
    use_tls = (url->scheme && ci_equal(url->scheme, "https")) ? 1 : 0;
    port = url->port;
    if (port == 0) port = use_tls ? 443 : 80;

    /* 1. DNS resolve */
    rc = dns_query(&dns_resp, url->host);
    if (rc) return 1;
    if (dns_resp.count == 0) {
        dns_response_free(&dns_resp);
        return 2;
    }

    /* Build address from first A/AAAA record */
    {
        dns_record *rec = &dns_resp.records[0];
        if (rec->type == DNS_TYPE_A && rec->rdata_len == 4) {
            memset(&addr, 0, sizeof(addr));
            addr.family = 4;
            memcpy(addr.addr.v4.octets, rec->rdata, 4);
            addr.port = port;
        } else if (rec->type == DNS_TYPE_AAAA && rec->rdata_len == 16) {
            memset(&addr, 0, sizeof(addr));
            addr.family = 6;
            memcpy(addr.addr.v6.octets, rec->rdata, 16);
            addr.port = port;
        } else {
            dns_response_free(&dns_resp);
            return 3;
        }
    }
    dns_response_free(&dns_resp);

    /* 2. TCP connect */
    rc = tcp_conn_create(&conn.tcp, &addr);
    if (rc) return 4;
    tcp_conn_set_nodelay(&conn.tcp, 1);

    c->stat_active++;
    c->stat_total++;

    /* 3. TLS handshake (if HTTPS) */
    conn.is_tls = use_tls;
    conn.tls = NULL;
    if (use_tls) {
        rc = tls_conn_create_client(&conn.tls, &conn.tcp,
                                    c->tls_cfg, url->host);
        if (rc) {
            c->stat_active--;
            tcp_conn_destroy(&conn.tcp);
            return 5;
        }
    }

    /* 4. Build request target (path + query) */
    {
        const char *path = (url->path && url->path[0]) ? url->path : "/";
        if (url->query) {
            size_t plen = strlen(path);
            size_t qlen = strlen(url->query);
            request_target = (char *)malloc(plen + 1 + qlen + 1);
            if (!request_target) {
                conn_close(&conn);
                c->stat_active--;
                return 6;
            }
            memcpy(request_target, path, plen);
            request_target[plen] = '?';
            memcpy(request_target + plen + 1, url->query, qlen);
            request_target[plen + 1 + qlen] = '\0';
        } else {
            request_target = str_dup(path);
            if (!request_target) {
                conn_close(&conn);
                c->stat_active--;
                return 6;
            }
        }
    }

    /* 5. Build HTTP request */
    rc = http_request_create(&req, method, request_target);
    free(request_target);
    if (rc) {
        conn_close(&conn);
        c->stat_active--;
        return 7;
    }

    /* apply body */
    if (body && body_len > 0) {
        rc = http_request_set_body(&req, body, body_len);
        if (rc) {
            http_request_destroy(&req);
            conn_close(&conn);
            c->stat_active--;
            return 8;
        }
        /* Content-Length */
        {
            char cl_buf[32];
            snprintf(cl_buf, sizeof(cl_buf), "%llu",
                     (unsigned long long)body_len);
            http_request_set_header(&req, "Content-Length", cl_buf);
        }
    }

    /* apply defaults, auth, cookies */
    rc = apply_defaults(c, &req, url->host);
    if (rc) {
        http_request_destroy(&req);
        conn_close(&conn);
        c->stat_active--;
        return 9;
    }

    /* merge caller-supplied extra headers (override defaults) */
    if (extra_hdrs) {
        u64 i;
        for (i = 0; i < extra_hdrs->count; ++i) {
            http_request_set_header(&req,
                                    extra_hdrs->items[i].name,
                                    extra_hdrs->items[i].value);
        }
    }

    /* Connection: close (we don't keep-alive for now) */
    http_request_set_header(&req, "Connection", "close");

    /* 6. Serialize and send */
    rc = http_request_serialize(&wire, &wire_len, &req);
    http_request_destroy(&req);
    if (rc) {
        conn_close(&conn);
        c->stat_active--;
        return 10;
    }

    rc = conn_write_all(&conn, wire, wire_len);
    free(wire);
    if (rc) {
        conn_close(&conn);
        c->stat_active--;
        return 11;
    }

    /* 7. Read response */
    rc = read_response_bytes(&raw, &raw_len, &conn);
    if (rc) {
        conn_close(&conn);
        c->stat_active--;
        return 12;
    }

    /* 8. Parse response */
    rc = http_response_parse(&parsed, raw, raw_len);
    if (rc) {
        free(raw);
        conn_close(&conn);
        c->stat_active--;
        return 13;
    }
    free(raw);

    /* 9. Store cookies */
    store_cookies(c, &parsed, url->host);

    /* 10. Close connection */
    conn_close(&conn);
    c->stat_active--;
    c->stat_idle++;

    /* 11. Build output */
    out->status = parsed.status;
    out->headers = parsed.headers;
    /* transfer body ownership */
    if (parsed.body && parsed.body_len > 0) {
        out->body = (u8 *)malloc(parsed.body_len);
        if (!out->body) {
            http_response_destroy(&parsed);
            return 14;
        }
        memcpy(out->body, parsed.body, parsed.body_len);
        out->body_len = parsed.body_len;
    } else {
        out->body = NULL;
        out->body_len = 0;
    }

    /* free parsed (but headers were moved to out) */
    free(parsed.reason);
    free(parsed.body);
    /* note: headers ownership transferred to out->headers */
    memset(&parsed.headers, 0, sizeof(parsed.headers));

    return 0;
}

/* ================================================================
 *  Internal: extract redirect location
 * ================================================================ */

static int is_redirect(u16 status) {
    return (status == 301 || status == 302 ||
            status == 303 || status == 307 || status == 308);
}

static unsigned long resolve_redirect(http_url *out,
                                      const https_response *resp,
                                      const http_url *original) {
    const char *location = NULL;
    u64 i;
    unsigned long rc;

    for (i = 0; i < resp->headers.count; ++i) {
        if (ci_equal(resp->headers.items[i].name, "Location")) {
            location = resp->headers.items[i].value;
            break;
        }
    }
    if (!location) return 1;

    /* try to parse as absolute URL */
    rc = http_url_parse(out, location);
    if (rc == 0) return 0;

    /* relative URL — build from original */
    {
        size_t needed = strlen(original->scheme) + 3 +
                        strlen(original->host) + 1 +
                        strlen(location) + 8;
        char *abs_url = (char *)malloc(needed);
        if (!abs_url) return 2;

        if (original->port != 0 &&
            !((ci_equal(original->scheme, "https") && original->port == 443) ||
              (ci_equal(original->scheme, "http") && original->port == 80))) {
            snprintf(abs_url, needed, "%s://%s:%u%s%s",
                     original->scheme, original->host,
                     (unsigned)original->port,
                     (location[0] == '/') ? "" : "/",
                     location);
        } else {
            snprintf(abs_url, needed, "%s://%s%s%s",
                     original->scheme, original->host,
                     (location[0] == '/') ? "" : "/",
                     location);
        }

        rc = http_url_parse(out, abs_url);
        free(abs_url);
        return rc;
    }
}

/* ================================================================
 *  Public API
 * ================================================================ */

unsigned long https_client_create(https_client **out) {
    https_client *c;
    unsigned long rc;

    if (!out) return 1;

    c = (https_client *)calloc(1, sizeof(https_client));
    if (!c) return 2;

    /* TLS config with system CAs */
    rc = tls_config_create(&c->tls_cfg);
    if (rc) {
        free(c);
        return 3;
    }
    tls_config_set_verify_mode(c->tls_cfg, TLS_VERIFY_PEER);
    tls_config_set_versions(c->tls_cfg, TLS_VERSION_12, TLS_VERSION_13);

    /* Default headers */
    rc = http_headers_create(&c->default_headers);
    if (rc) {
        tls_config_destroy(c->tls_cfg);
        free(c);
        return 4;
    }

    c->timeout_ms     = HTTPS_DEFAULT_TIMEOUT_MS;
    c->max_redirects  = HTTPS_DEFAULT_MAX_REDIRECT;
    c->compression    = 0;
    c->auth_type      = 0;
    c->cookie_jar_enabled = 0;
    c->cookie_jar     = NULL;

    *out = c;
    return 0;
}

unsigned long https_client_request(https_response *out,
                                   https_client *c,
                                   int method, const char *url,
                                   const http_headers *hdrs,
                                   const u8 *body, u64 body_len) {
    http_url parsed_url;
    unsigned long rc;
    u32 redirects = 0;

    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;

    memset(out, 0, sizeof(*out));

    /* Parse original URL */
    rc = http_url_parse(&parsed_url, url);
    if (rc) return 4;

    /* request + redirect loop */
    for (;;) {
        rc = do_single_request(out, c, method, &parsed_url, hdrs, body, body_len);
        if (rc) {
            http_url_free(&parsed_url);
            return 5;
        }

        /* check for redirect */
        if (is_redirect(out->status) && redirects < c->max_redirects) {
            http_url next_url;
            memset(&next_url, 0, sizeof(next_url));

            rc = resolve_redirect(&next_url, out, &parsed_url);
            if (rc) {
                /* can't follow redirect — return response as-is */
                http_url_free(&parsed_url);
                return 0;
            }

            /* 303 converts to GET, drop body */
            if (out->status == 303) {
                method = HTTP_GET;
                body = NULL;
                body_len = 0;
            }

            /* free current response before retry */
            https_response_free(out);
            memset(out, 0, sizeof(*out));

            http_url_free(&parsed_url);
            parsed_url = next_url;
            redirects++;
            continue;
        }

        break;
    }

    http_url_free(&parsed_url);
    return 0;
}

/* ================================================================
 *  Convenience methods
 * ================================================================ */

unsigned long https_client_get(https_response *out,
                               https_client *c, const char *url) {
    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;
    return https_client_request(out, c, HTTP_GET, url, NULL, NULL, 0);
}

unsigned long https_client_post(https_response *out,
                                https_client *c, const char *url,
                                const u8 *body, u64 body_len,
                                const char *content_type) {
    http_headers hdrs;
    unsigned long rc;

    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;

    if (content_type) {
        rc = http_headers_create(&hdrs);
        if (rc) return 4;
        http_headers_set(&hdrs, "Content-Type", content_type);
        rc = https_client_request(out, c, HTTP_POST, url,
                                  &hdrs, body, body_len);
        http_headers_destroy(&hdrs);
        return rc;
    }
    return https_client_request(out, c, HTTP_POST, url, NULL, body, body_len);
}

unsigned long https_client_put(https_response *out,
                               https_client *c, const char *url,
                               const u8 *body, u64 body_len,
                               const char *content_type) {
    http_headers hdrs;
    unsigned long rc;

    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;

    if (content_type) {
        rc = http_headers_create(&hdrs);
        if (rc) return 4;
        http_headers_set(&hdrs, "Content-Type", content_type);
        rc = https_client_request(out, c, HTTP_PUT, url,
                                  &hdrs, body, body_len);
        http_headers_destroy(&hdrs);
        return rc;
    }
    return https_client_request(out, c, HTTP_PUT, url, NULL, body, body_len);
}

unsigned long https_client_delete(https_response *out,
                                  https_client *c, const char *url) {
    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;
    return https_client_request(out, c, HTTP_DELETE, url, NULL, NULL, 0);
}

unsigned long https_client_patch(https_response *out,
                                 https_client *c, const char *url,
                                 const u8 *body, u64 body_len,
                                 const char *content_type) {
    http_headers hdrs;
    unsigned long rc;

    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;

    if (content_type) {
        rc = http_headers_create(&hdrs);
        if (rc) return 4;
        http_headers_set(&hdrs, "Content-Type", content_type);
        rc = https_client_request(out, c, HTTP_PATCH, url,
                                  &hdrs, body, body_len);
        http_headers_destroy(&hdrs);
        return rc;
    }
    return https_client_request(out, c, HTTP_PATCH, url, NULL, body, body_len);
}

unsigned long https_client_head(https_response *out,
                                https_client *c, const char *url) {
    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;
    return https_client_request(out, c, HTTP_HEAD, url, NULL, NULL, 0);
}

/* ================================================================
 *  Download to file with progress callback
 * ================================================================ */

unsigned long https_client_download(https_client *c, const char *url,
                                    const char *file_path,
                                    https_progress_fn progress,
                                    void *ctx) {
    http_url parsed_url;
    dns_response dns_resp;
    net_sock_addr addr;
    conn_handle conn;
    http_request req;
    u8 *wire = NULL;
    u64 wire_len = 0;
    unsigned long rc;
    u16 port;
    int use_tls;
    FILE *fp;

    if (!c)         return 1;
    if (!url)       return 2;
    if (!file_path) return 3;

    /* parse URL */
    rc = http_url_parse(&parsed_url, url);
    if (rc) return 4;

    use_tls = (parsed_url.scheme && ci_equal(parsed_url.scheme, "https"));
    port = parsed_url.port;
    if (port == 0) port = use_tls ? 443 : 80;

    /* open output file */
    fp = fopen(file_path, "wb");
    if (!fp) {
        http_url_free(&parsed_url);
        return 5;
    }

    /* DNS resolve */
    memset(&dns_resp, 0, sizeof(dns_resp));
    rc = dns_query(&dns_resp, parsed_url.host);
    if (rc) {
        fclose(fp);
        http_url_free(&parsed_url);
        return 6;
    }
    if (dns_resp.count == 0) {
        dns_response_free(&dns_resp);
        fclose(fp);
        http_url_free(&parsed_url);
        return 7;
    }

    /* build address */
    {
        dns_record *rec = &dns_resp.records[0];
        memset(&addr, 0, sizeof(addr));
        if (rec->type == DNS_TYPE_A && rec->rdata_len == 4) {
            addr.family = 4;
            memcpy(addr.addr.v4.octets, rec->rdata, 4);
        } else if (rec->type == DNS_TYPE_AAAA && rec->rdata_len == 16) {
            addr.family = 6;
            memcpy(addr.addr.v6.octets, rec->rdata, 16);
        } else {
            dns_response_free(&dns_resp);
            fclose(fp);
            http_url_free(&parsed_url);
            return 8;
        }
        addr.port = port;
    }
    dns_response_free(&dns_resp);

    /* TCP connect */
    memset(&conn, 0, sizeof(conn));
    rc = tcp_conn_create(&conn.tcp, &addr);
    if (rc) {
        fclose(fp);
        http_url_free(&parsed_url);
        return 9;
    }
    tcp_conn_set_nodelay(&conn.tcp, 1);

    c->stat_active++;
    c->stat_total++;

    /* TLS handshake */
    conn.is_tls = use_tls;
    conn.tls = NULL;
    if (use_tls) {
        rc = tls_conn_create_client(&conn.tls, &conn.tcp,
                                    c->tls_cfg, parsed_url.host);
        if (rc) {
            c->stat_active--;
            tcp_conn_destroy(&conn.tcp);
            fclose(fp);
            http_url_free(&parsed_url);
            return 10;
        }
    }

    /* build request */
    {
        const char *path = (parsed_url.path && parsed_url.path[0])
                            ? parsed_url.path : "/";
        char *target;
        if (parsed_url.query) {
            size_t plen = strlen(path);
            size_t qlen = strlen(parsed_url.query);
            target = (char *)malloc(plen + 1 + qlen + 1);
            if (!target) {
                conn_close(&conn);
                c->stat_active--;
                fclose(fp);
                http_url_free(&parsed_url);
                return 11;
            }
            memcpy(target, path, plen);
            target[plen] = '?';
            memcpy(target + plen + 1, parsed_url.query, qlen);
            target[plen + 1 + qlen] = '\0';
        } else {
            target = str_dup(path);
            if (!target) {
                conn_close(&conn);
                c->stat_active--;
                fclose(fp);
                http_url_free(&parsed_url);
                return 11;
            }
        }

        memset(&req, 0, sizeof(req));
        rc = http_request_create(&req, HTTP_GET, target);
        free(target);
        if (rc) {
            conn_close(&conn);
            c->stat_active--;
            fclose(fp);
            http_url_free(&parsed_url);
            return 12;
        }
    }

    apply_defaults(c, &req, parsed_url.host);
    http_request_set_header(&req, "Connection", "close");

    /* serialize and send */
    rc = http_request_serialize(&wire, &wire_len, &req);
    http_request_destroy(&req);
    if (rc) {
        conn_close(&conn);
        c->stat_active--;
        fclose(fp);
        http_url_free(&parsed_url);
        return 13;
    }

    rc = conn_write_all(&conn, wire, wire_len);
    free(wire);
    if (rc) {
        conn_close(&conn);
        c->stat_active--;
        fclose(fp);
        http_url_free(&parsed_url);
        return 14;
    }

    /* read response headers first, then stream body to file */
    {
        u8 hdr_buf[HTTPS_READ_BUF_SIZE];
        u8 *accum = NULL;
        u64 accum_len = 0, accum_cap = 0;
        u64 nr;
        const char *hdr_end_marker = "\r\n\r\n";
        char *hdr_end = NULL;
        u64 content_length = 0;
        u64 downloaded = 0;
        int have_cl = 0;

        /* accumulate until we see end of headers */
        for (;;) {
            nr = 0;
            rc = conn_read(&nr, &conn, hdr_buf, sizeof(hdr_buf));
            if (nr > 0) {
                u8 *nb;
                if (accum_len + nr > accum_cap) {
                    accum_cap = (accum_cap == 0) ? HTTPS_READ_BUF_SIZE
                                                 : accum_cap * 2;
                    if (accum_len + nr > accum_cap)
                        accum_cap = accum_len + nr;
                    nb = (u8 *)realloc(accum, accum_cap);
                    if (!nb) {
                        free(accum);
                        conn_close(&conn);
                        c->stat_active--;
                        fclose(fp);
                        http_url_free(&parsed_url);
                        return 15;
                    }
                    accum = nb;
                }
                memcpy(accum + accum_len, hdr_buf, nr);
                accum_len += nr;

                /* check for header terminator */
                if (accum_len >= 4) {
                    /* search in accumulated data */
                    u64 search_start = (accum_len - nr > 3)
                                       ? accum_len - nr - 3 : 0;
                    u64 k;
                    for (k = search_start; k + 4 <= accum_len; ++k) {
                        if (accum[k] == '\r' && accum[k+1] == '\n' &&
                            accum[k+2] == '\r' && accum[k+3] == '\n') {
                            hdr_end = (char *)(accum + k + 4);
                            break;
                        }
                    }
                }
            }
            if (hdr_end) break;
            if (rc != 0 || nr == 0) break;
        }

        if (!hdr_end) {
            free(accum);
            conn_close(&conn);
            c->stat_active--;
            fclose(fp);
            http_url_free(&parsed_url);
            return 16;
        }

        /* parse Content-Length from headers */
        {
            const char *cl_hdr = NULL;
            /* quick scan for Content-Length */
            char *h = (char *)accum;
            char *end = hdr_end;
            char *line = h;
            while (line < end) {
                char *nl = strstr(line, "\r\n");
                if (!nl) break;
                if (nl - line > 16 &&
                    tolower((unsigned char)line[0]) == 'c' &&
                    tolower((unsigned char)line[8]) == 'l') {
                    /* rough check for "Content-Length:" */
                    char tmp[32];
                    size_t hlen = (size_t)(nl - line);
                    char *colon = memchr(line, ':', hlen);
                    if (colon) {
                        size_t name_len = (size_t)(colon - line);
                        /* verify it's Content-Length */
                        if (name_len == 14) {
                            char name_buf[15];
                            size_t j;
                            memcpy(name_buf, line, 14);
                            name_buf[14] = '\0';
                            for (j = 0; j < 14; ++j)
                                name_buf[j] = (char)tolower(
                                    (unsigned char)name_buf[j]);
                            if (strcmp(name_buf, "content-length") == 0) {
                                const char *val = colon + 1;
                                while (val < nl && *val == ' ') val++;
                                content_length = (u64)strtoull(val, NULL, 10);
                                have_cl = 1;
                            }
                        }
                    }
                }
                line = nl + 2;
            }
            (void)cl_hdr;
        }

        /* write any body bytes already in accum past headers */
        {
            u64 body_in_accum = accum_len - (u64)(hdr_end - (char *)accum);
            if (body_in_accum > 0) {
                fwrite(hdr_end, 1, (size_t)body_in_accum, fp);
                downloaded += body_in_accum;
                if (progress) {
                    progress(downloaded,
                             have_cl ? content_length : 0, ctx);
                }
            }
        }
        free(accum);

        /* stream remaining body */
        for (;;) {
            u8 buf[HTTPS_READ_BUF_SIZE];
            nr = 0;
            rc = conn_read(&nr, &conn, buf, sizeof(buf));
            if (nr > 0) {
                fwrite(buf, 1, (size_t)nr, fp);
                downloaded += nr;
                if (progress) {
                    progress(downloaded,
                             have_cl ? content_length : 0, ctx);
                }
            }
            if (rc != 0 || nr == 0) break;
        }
    }

    /* cleanup */
    conn_close(&conn);
    c->stat_active--;
    c->stat_idle++;
    fclose(fp);
    http_url_free(&parsed_url);
    return 0;
}

/* ================================================================
 *  Configuration setters
 * ================================================================ */

unsigned long https_client_set_header(https_client *c,
                                      const char *name,
                                      const char *value) {
    if (!c)     return 1;
    if (!name)  return 2;
    if (!value) return 3;
    return http_headers_set(&c->default_headers, name, value);
}

unsigned long https_client_set_timeout(https_client *c, u64 ms) {
    if (!c) return 1;
    c->timeout_ms = ms;
    return 0;
}

unsigned long https_client_set_proxy(https_client *c,
                                     const char *proxy_url) {
    if (!c) return 1;
    free(c->proxy_url);
    c->proxy_url = proxy_url ? str_dup(proxy_url) : NULL;
    if (proxy_url && !c->proxy_url) return 2;
    return 0;
}

unsigned long https_client_set_cookie_jar(https_client *c, int enabled) {
    unsigned long rc;
    if (!c) return 1;
    c->cookie_jar_enabled = enabled;
    if (enabled && !c->cookie_jar) {
        rc = http_cookie_jar_create(&c->cookie_jar);
        if (rc) return 2;
    }
    return 0;
}

unsigned long https_client_set_compression(https_client *c, int enabled) {
    if (!c) return 1;
    c->compression = enabled;
    return 0;
}

unsigned long https_client_set_redirect(https_client *c, u32 max) {
    if (!c) return 1;
    c->max_redirects = max;
    return 0;
}

unsigned long https_client_set_auth_basic(https_client *c,
                                          const char *user,
                                          const char *pass) {
    if (!c)    return 1;
    if (!user) return 2;

    /* clear any previous auth */
    free(c->auth_basic.user);
    free(c->auth_basic.pass);
    free(c->auth_bearer);
    c->auth_bearer = NULL;

    c->auth_basic.user = str_dup(user);
    if (!c->auth_basic.user) return 3;
    c->auth_basic.pass = pass ? str_dup(pass) : NULL;
    if (pass && !c->auth_basic.pass) {
        free(c->auth_basic.user);
        c->auth_basic.user = NULL;
        return 4;
    }
    c->auth_type = 1;
    return 0;
}

unsigned long https_client_set_auth_bearer(https_client *c,
                                           const char *token) {
    if (!c)     return 1;
    if (!token) return 2;

    /* clear any previous auth */
    free(c->auth_basic.user);
    free(c->auth_basic.pass);
    free(c->auth_bearer);
    c->auth_basic.user = NULL;
    c->auth_basic.pass = NULL;

    c->auth_bearer = str_dup(token);
    if (!c->auth_bearer) return 3;
    c->auth_type = 2;
    return 0;
}

/* ================================================================
 *  Pool stats
 * ================================================================ */

unsigned long https_client_pool_stats(u64 *active, u64 *idle,
                                      u64 *total, https_client *c) {
    if (!c) return 1;
    if (active) *active = c->stat_active;
    if (idle)   *idle   = c->stat_idle;
    if (total)  *total  = c->stat_total;
    return 0;
}

/* ================================================================
 *  Cleanup
 * ================================================================ */

unsigned long https_response_free(https_response *resp) {
    if (!resp) return 1;
    http_headers_destroy(&resp->headers);
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
    resp->status = 0;
    return 0;
}

unsigned long https_client_destroy(https_client *c) {
    if (!c) return 1;

    tls_config_destroy(c->tls_cfg);
    http_headers_destroy(&c->default_headers);
    free(c->proxy_url);

    if (c->cookie_jar) {
        http_cookie_jar_destroy(c->cookie_jar);
    }

    free(c->auth_basic.user);
    free(c->auth_basic.pass);
    free(c->auth_bearer);

    free(c);
    return 0;
}

/* ================================================================
 *  Gap-fill stubs — Section 36
 * ================================================================ */

unsigned long https_client_upload(https_client *c, const char *url,
                                   const char *file_path,
                                   const char *content_type,
                                   https_progress_fn progress,
                                   void *ctx) {
    if (!c) return 1;
    if (!url) return 2;
    if (!file_path) return 3;
    (void)content_type;
    (void)progress;
    (void)ctx;
    /* TODO: read file and POST with progress callback */
    return 0;
}
