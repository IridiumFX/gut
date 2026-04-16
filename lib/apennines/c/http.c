#include "apennines/http.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

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

static char *str_ndup(const char *s, size_t n) {
    char *d;
    if (!s) return NULL;
    d = (char *)malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static int ci_equal(const char *a, const char *b) {
    for (; *a && *b; ++a, ++b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

static int is_unreserved(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '-' || c == '.' || c == '_' || c == '~') return 1;
    return 0;
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static const char hex_chars[] = "0123456789ABCDEF";

static const char *method_names[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"
};
#define METHOD_COUNT (sizeof(method_names) / sizeof(method_names[0]))

/* ================================================================
 *  1. URL parsing
 * ================================================================ */

unsigned long http_url_parse(http_url *out, const char *url) {
    const char *p, *scheme_end, *authority_start, *authority_end;
    const char *userinfo_end, *host_start, *host_end, *port_start;
    const char *path_start, *query_start, *fragment_start;

    if (!out) return 1;
    if (!url) return 2;

    memset(out, 0, sizeof(*out));

    p = url;

    /* -- scheme -- */
    scheme_end = strstr(p, "://");
    if (!scheme_end) return 3; /* no scheme */
    out->scheme = str_ndup(p, (size_t)(scheme_end - p));
    if (!out->scheme) { http_url_free(out); return 4; }
    p = scheme_end + 3;

    /* -- authority: [userinfo@]host[:port] -- */
    authority_start = p;
    /* authority ends at '/', '?', '#', or end of string */
    authority_end = p;
    while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
        ++authority_end;

    /* check for userinfo */
    userinfo_end = NULL;
    {
        const char *at = (const char *)memchr(authority_start, '@',
                         (size_t)(authority_end - authority_start));
        if (at) {
            out->userinfo = str_ndup(authority_start, (size_t)(at - authority_start));
            if (!out->userinfo) { http_url_free(out); return 4; }
            userinfo_end = at;
            host_start = at + 1;
        } else {
            host_start = authority_start;
        }
    }

    /* check for port */
    port_start = NULL;
    if (*host_start == '[') {
        /* IPv6 literal */
        host_end = (const char *)memchr(host_start, ']',
                   (size_t)(authority_end - host_start));
        if (!host_end) { http_url_free(out); return 3; }
        host_end += 1; /* past ']' */
        if (host_end < authority_end && *host_end == ':')
            port_start = host_end + 1;
    } else {
        /* find last colon in host segment */
        const char *c = host_start;
        const char *last_colon = NULL;
        while (c < authority_end) {
            if (*c == ':') last_colon = c;
            ++c;
        }
        if (last_colon) {
            port_start = last_colon + 1;
            host_end = last_colon;
        } else {
            host_end = authority_end;
        }
    }

    if (host_end > host_start) {
        out->host = str_ndup(host_start, (size_t)(host_end - host_start));
        if (!out->host) { http_url_free(out); return 4; }
    }

    if (port_start && port_start < authority_end) {
        unsigned long pv = 0;
        const char *pp = port_start;
        while (pp < authority_end && *pp >= '0' && *pp <= '9') {
            pv = pv * 10 + (unsigned long)(*pp - '0');
            ++pp;
        }
        if (pv <= 65535) out->port = (u16)pv;
    }

    p = authority_end;

    /* -- path -- */
    path_start = p;
    {
        const char *path_end = p;
        while (*path_end && *path_end != '?' && *path_end != '#')
            ++path_end;
        if (path_end > path_start) {
            out->path = str_ndup(path_start, (size_t)(path_end - path_start));
        } else {
            out->path = str_dup("/");
        }
        if (!out->path) { http_url_free(out); return 4; }
        p = path_end;
    }

    /* -- query -- */
    if (*p == '?') {
        ++p;
        query_start = p;
        while (*p && *p != '#') ++p;
        out->query = str_ndup(query_start, (size_t)(p - query_start));
        if (!out->query) { http_url_free(out); return 4; }
    }

    /* -- fragment -- */
    if (*p == '#') {
        ++p;
        fragment_start = p;
        out->fragment = str_dup(fragment_start);
        if (!out->fragment) { http_url_free(out); return 4; }
    }

    return 0;
}

unsigned long http_url_free(http_url *url) {
    if (!url) return 1;
    free(url->scheme);   url->scheme   = NULL;
    free(url->host);     url->host     = NULL;
    free(url->path);     url->path     = NULL;
    free(url->query);    url->query    = NULL;
    free(url->fragment); url->fragment = NULL;
    free(url->userinfo); url->userinfo = NULL;
    url->port = 0;
    return 0;
}

unsigned long http_url_encode(char **out, u64 *out_len,
                              const char *src, u64 src_len) {
    u64 i, needed;
    char *buf, *wp;

    if (!out)     return 1;
    if (!out_len) return 2;
    if (!src)     return 3;

    /* calculate needed size */
    needed = 0;
    for (i = 0; i < src_len; ++i) {
        if (is_unreserved((unsigned char)src[i])) needed += 1;
        else needed += 3;
    }

    buf = (char *)malloc(needed + 1);
    if (!buf) return 4;

    wp = buf;
    for (i = 0; i < src_len; ++i) {
        unsigned char c = (unsigned char)src[i];
        if (is_unreserved(c)) {
            *wp++ = (char)c;
        } else {
            *wp++ = '%';
            *wp++ = hex_chars[c >> 4];
            *wp++ = hex_chars[c & 0x0F];
        }
    }
    *wp = '\0';

    *out = buf;
    *out_len = needed;
    return 0;
}

unsigned long http_url_decode(char **out, u64 *out_len,
                              const char *src, u64 src_len) {
    u64 i;
    char *buf, *wp;

    if (!out)     return 1;
    if (!out_len) return 2;
    if (!src)     return 3;

    buf = (char *)malloc(src_len + 1);
    if (!buf) return 4;

    wp = buf;
    for (i = 0; i < src_len; ++i) {
        if (src[i] == '%' && i + 2 < src_len) {
            int hi = hex_digit((unsigned char)src[i + 1]);
            int lo = hex_digit((unsigned char)src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                *wp++ = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        if (src[i] == '+') {
            *wp++ = ' ';
        } else {
            *wp++ = src[i];
        }
    }
    *wp = '\0';

    *out = buf;
    *out_len = (u64)(wp - buf);
    return 0;
}

/* ================================================================
 *  2. Query string
 * ================================================================ */

unsigned long http_query_parse(http_query *out, const char *qs, u64 qs_len) {
    const char *p, *end, *amp, *eq;

    if (!out) return 1;
    if (!qs)  return 2;

    memset(out, 0, sizeof(*out));

    if (qs_len == 0) return 0;

    p = qs;
    end = qs + qs_len;

    while (p < end) {
        http_query_param param;
        char *decoded_key = NULL, *decoded_val = NULL;
        u64 dk_len, dv_len;
        const char *key_start, *key_end, *val_start, *val_end;

        /* find next '&' or end */
        amp = (const char *)memchr(p, '&', (size_t)(end - p));
        if (!amp) amp = end;

        /* find '=' within this pair */
        eq = (const char *)memchr(p, '=', (size_t)(amp - p));

        if (eq) {
            key_start = p;
            key_end = eq;
            val_start = eq + 1;
            val_end = amp;
        } else {
            key_start = p;
            key_end = amp;
            val_start = amp;
            val_end = amp;
        }

        /* URL-decode key and value */
        if (http_url_decode(&decoded_key, &dk_len, key_start, (u64)(key_end - key_start)) != 0) {
            http_query_free(out);
            return 3;
        }
        if (http_url_decode(&decoded_val, &dv_len, val_start, (u64)(val_end - val_start)) != 0) {
            free(decoded_key);
            http_query_free(out);
            return 3;
        }

        param.key = decoded_key;
        param.value = decoded_val;

        /* grow array if needed */
        if (out->count >= out->capacity) {
            u64 new_cap = out->capacity ? out->capacity * 2 : 8;
            http_query_param *new_params = (http_query_param *)realloc(
                out->params, (size_t)(new_cap * sizeof(http_query_param)));
            if (!new_params) {
                free(decoded_key);
                free(decoded_val);
                http_query_free(out);
                return 3;
            }
            out->params = new_params;
            out->capacity = new_cap;
        }

        out->params[out->count++] = param;
        p = (amp < end) ? amp + 1 : end;
    }

    return 0;
}

unsigned long http_query_build(char **out, u64 *out_len, const http_query *q) {
    u64 i, total;
    char *buf, *wp;

    if (!out)     return 1;
    if (!out_len) return 2;
    if (!q)       return 3;

    if (q->count == 0) {
        *out = str_dup("");
        if (!*out) return 4;
        *out_len = 0;
        return 0;
    }

    /* first pass: calculate total size */
    total = 0;
    for (i = 0; i < q->count; ++i) {
        char *ek = NULL, *ev = NULL;
        u64 ek_len, ev_len;
        unsigned long rc;

        rc = http_url_encode(&ek, &ek_len, q->params[i].key,
                             (u64)strlen(q->params[i].key));
        if (rc != 0) return 4;
        rc = http_url_encode(&ev, &ev_len, q->params[i].value,
                             (u64)strlen(q->params[i].value));
        if (rc != 0) { free(ek); return 4; }

        total += ek_len + 1 + ev_len; /* key=value */
        if (i > 0) total += 1;        /* & */
        free(ek);
        free(ev);
    }

    buf = (char *)malloc((size_t)(total + 1));
    if (!buf) return 4;

    /* second pass: build string */
    wp = buf;
    for (i = 0; i < q->count; ++i) {
        char *ek = NULL, *ev = NULL;
        u64 ek_len, ev_len;

        if (i > 0) *wp++ = '&';

        http_url_encode(&ek, &ek_len, q->params[i].key,
                        (u64)strlen(q->params[i].key));
        http_url_encode(&ev, &ev_len, q->params[i].value,
                        (u64)strlen(q->params[i].value));

        memcpy(wp, ek, (size_t)ek_len); wp += ek_len;
        *wp++ = '=';
        memcpy(wp, ev, (size_t)ev_len); wp += ev_len;

        free(ek);
        free(ev);
    }
    *wp = '\0';

    *out = buf;
    *out_len = total;
    return 0;
}

unsigned long http_query_free(http_query *q) {
    u64 i;
    if (!q) return 1;
    for (i = 0; i < q->count; ++i) {
        free(q->params[i].key);
        free(q->params[i].value);
    }
    free(q->params);
    q->params = NULL;
    q->count = 0;
    q->capacity = 0;
    return 0;
}

/* ================================================================
 *  3. Headers
 * ================================================================ */

unsigned long http_headers_create(http_headers *out) {
    if (!out) return 1;
    out->items = NULL;
    out->count = 0;
    out->capacity = 0;
    return 0;
}

unsigned long http_headers_set(http_headers *h, const char *name, const char *value) {
    u64 i;
    char *nv;

    if (!h)     return 1;
    if (!name)  return 2;
    if (!value) return 3;

    /* look for existing header (case-insensitive) */
    for (i = 0; i < h->count; ++i) {
        if (ci_equal(h->items[i].name, name)) {
            nv = str_dup(value);
            if (!nv) return 4;
            free(h->items[i].value);
            h->items[i].value = nv;
            return 0;
        }
    }

    /* append new header */
    if (h->count >= h->capacity) {
        u64 new_cap = h->capacity ? h->capacity * 2 : 8;
        http_header *new_items = (http_header *)realloc(
            h->items, (size_t)(new_cap * sizeof(http_header)));
        if (!new_items) return 4;
        h->items = new_items;
        h->capacity = new_cap;
    }

    h->items[h->count].name = str_dup(name);
    if (!h->items[h->count].name) return 4;
    h->items[h->count].value = str_dup(value);
    if (!h->items[h->count].value) {
        free(h->items[h->count].name);
        return 4;
    }
    h->count++;
    return 0;
}

unsigned long http_headers_get(const char **out_value, const http_headers *h,
                               const char *name) {
    u64 i;
    if (!out_value) return 1;
    if (!h)         return 2;
    if (!name)      return 3;

    for (i = 0; i < h->count; ++i) {
        if (ci_equal(h->items[i].name, name)) {
            *out_value = h->items[i].value;
            return 0;
        }
    }
    *out_value = NULL;
    return 4; /* not found */
}

unsigned long http_headers_remove(http_headers *h, const char *name) {
    u64 i;
    if (!h)    return 1;
    if (!name) return 2;

    for (i = 0; i < h->count; ++i) {
        if (ci_equal(h->items[i].name, name)) {
            free(h->items[i].name);
            free(h->items[i].value);
            /* shift remaining */
            if (i + 1 < h->count) {
                memmove(&h->items[i], &h->items[i + 1],
                        (size_t)((h->count - i - 1) * sizeof(http_header)));
            }
            h->count--;
            return 0;
        }
    }
    return 0; /* not found is not an error */
}

unsigned long http_headers_iter(const http_headers *h,
                                http_headers_iter_fn fn, void *ctx) {
    u64 i;
    if (!h)  return 1;
    if (!fn) return 2;

    for (i = 0; i < h->count; ++i) {
        fn(h->items[i].name, h->items[i].value, ctx);
    }
    return 0;
}

unsigned long http_headers_destroy(http_headers *h) {
    u64 i;
    if (!h) return 1;
    for (i = 0; i < h->count; ++i) {
        free(h->items[i].name);
        free(h->items[i].value);
    }
    free(h->items);
    h->items = NULL;
    h->count = 0;
    h->capacity = 0;
    return 0;
}

/* ================================================================
 *  4. Request
 * ================================================================ */

unsigned long http_request_create(http_request *out, int method, const char *url) {
    if (!out) return 1;
    if (!url) return 2;
    if (method < 0 || (size_t)method >= METHOD_COUNT) return 3;

    memset(out, 0, sizeof(*out));
    out->method = method;
    out->url = str_dup(url);
    if (!out->url) return 4;

    http_headers_create(&out->headers);
    return 0;
}

unsigned long http_request_set_header(http_request *req,
                                      const char *name, const char *value) {
    if (!req)   return 1;
    if (!name)  return 2;
    if (!value) return 3;
    return http_headers_set(&req->headers, name, value);
}

unsigned long http_request_set_body(http_request *req, const u8 *body, u64 len) {
    u8 *copy;
    if (!req) return 1;

    free(req->body);
    req->body = NULL;
    req->body_len = 0;

    if (body && len > 0) {
        copy = (u8 *)malloc((size_t)len);
        if (!copy) return 2;
        memcpy(copy, body, (size_t)len);
        req->body = copy;
        req->body_len = len;
    }
    return 0;
}

unsigned long http_request_serialize(u8 **out, u64 *out_len,
                                     const http_request *req) {
    http_url parsed_url;
    char port_buf[8];
    size_t total, off;
    u8 *buf;
    u64 i;
    const char *method_str;
    const char *request_target;
    int has_host;
    char content_length_buf[32];
    int need_content_length;

    if (!out)     return 1;
    if (!out_len) return 2;
    if (!req)     return 3;

    if (req->method < 0 || (size_t)req->method >= METHOD_COUNT) return 4;
    method_str = method_names[req->method];

    /* parse URL to extract host for Host header */
    if (http_url_parse(&parsed_url, req->url) != 0) {
        /* fall back: use the URL as-is for request target */
        request_target = req->url;
    } else {
        request_target = parsed_url.path ? parsed_url.path : "/";
    }

    /* check if Host header already set */
    has_host = 0;
    for (i = 0; i < req->headers.count; ++i) {
        if (ci_equal(req->headers.items[i].name, "Host")) {
            has_host = 1;
            break;
        }
    }

    /* Content-Length if body present and not already set */
    need_content_length = 0;
    if (req->body && req->body_len > 0) {
        const char *cl_val = NULL;
        http_headers_get(&cl_val, &req->headers, "Content-Length");
        if (!cl_val) {
            snprintf(content_length_buf, sizeof(content_length_buf), "%llu",
                     (unsigned long long)req->body_len);
            need_content_length = 1;
        }
    }

    /* calculate total size */
    total = strlen(method_str) + 1 + strlen(request_target) + 11; /* " HTTP/1.1\r\n" */

    if (!has_host && parsed_url.host) {
        total += 6; /* "Host: " */
        total += strlen(parsed_url.host);
        if (parsed_url.port > 0) {
            snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned)parsed_url.port);
            total += strlen(port_buf);
        } else {
            port_buf[0] = '\0';
        }
        total += 2; /* \r\n */
    }

    if (need_content_length) {
        total += 16 + strlen(content_length_buf) + 2; /* "Content-Length: ...\r\n" */
    }

    for (i = 0; i < req->headers.count; ++i) {
        total += strlen(req->headers.items[i].name) + 2 +
                 strlen(req->headers.items[i].value) + 2;
    }
    total += 2; /* final \r\n */
    total += (size_t)req->body_len;

    buf = (u8 *)malloc(total + 1);
    if (!buf) {
        http_url_free(&parsed_url);
        return 4;
    }

    /* build the request */
    off = 0;
    #define APPEND(s, n) do { memcpy(buf + off, (s), (n)); off += (n); } while(0)
    #define APPENDS(s) do { size_t _l = strlen(s); APPEND((s), _l); } while(0)

    APPENDS(method_str);
    APPEND(" ", 1);
    APPENDS(request_target);
    APPEND(" HTTP/1.1\r\n", 11);

    /* Host header */
    if (!has_host && parsed_url.host) {
        APPEND("Host: ", 6);
        APPENDS(parsed_url.host);
        if (port_buf[0]) APPENDS(port_buf);
        APPEND("\r\n", 2);
    }

    /* Content-Length */
    if (need_content_length) {
        APPEND("Content-Length: ", 16);
        APPENDS(content_length_buf);
        APPEND("\r\n", 2);
    }

    /* user headers */
    for (i = 0; i < req->headers.count; ++i) {
        APPENDS(req->headers.items[i].name);
        APPEND(": ", 2);
        APPENDS(req->headers.items[i].value);
        APPEND("\r\n", 2);
    }

    APPEND("\r\n", 2);

    /* body */
    if (req->body && req->body_len > 0) {
        APPEND(req->body, (size_t)req->body_len);
    }

    #undef APPENDS
    #undef APPEND

    buf[off] = '\0';

    http_url_free(&parsed_url);

    *out = buf;
    *out_len = (u64)off;
    return 0;
}

unsigned long http_request_destroy(http_request *req) {
    if (!req) return 1;
    free(req->url);
    req->url = NULL;
    http_headers_destroy(&req->headers);
    free(req->body);
    req->body = NULL;
    req->body_len = 0;
    return 0;
}

/* ================================================================
 *  5. Response
 * ================================================================ */

/* Find "\r\n\r\n" in data. Returns pointer to the first '\r' or NULL. */
static const u8 *find_header_end(const u8 *data, u64 len) {
    u64 i;
    if (len < 4) return NULL;
    for (i = 0; i <= len - 4; ++i) {
        if (data[i] == '\r' && data[i+1] == '\n' &&
            data[i+2] == '\r' && data[i+3] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

/* Find "\r\n" from position p. Returns pointer to '\r' or NULL. */
static const u8 *find_crlf(const u8 *p, const u8 *end) {
    while (p + 1 < end) {
        if (p[0] == '\r' && p[1] == '\n') return p;
        ++p;
    }
    return NULL;
}

unsigned long http_response_parse(http_response *out, const u8 *data, u64 len) {
    const u8 *hdr_end, *line_start, *line_end, *body_start;
    const u8 *p;
    unsigned long status_val;
    const char *reason_start;
    size_t reason_len;
    u64 body_offset, body_len;

    if (!out)  return 1;
    if (!data) return 2;

    memset(out, 0, sizeof(*out));
    http_headers_create(&out->headers);

    /* find end of headers */
    hdr_end = find_header_end(data, len);
    if (!hdr_end) return 6; /* incomplete */

    body_start = hdr_end + 4;
    body_offset = (u64)(body_start - data);

    /* parse status line: "HTTP/1.x STATUS REASON\r\n" */
    line_end = find_crlf(data, hdr_end + 2);
    if (!line_end) return 3;

    p = data;
    /* must start with "HTTP/1." */
    if ((u64)(line_end - p) < 12) return 3;
    if (memcmp(p, "HTTP/1.", 7) != 0) return 3;
    p += 7;
    /* skip version digit (0 or 1) */
    if (*p != '0' && *p != '1') return 3;
    p++;
    if (*p != ' ') return 3;
    p++;

    /* parse status code */
    status_val = 0;
    {
        int digits = 0;
        while (p < line_end && *p >= '0' && *p <= '9') {
            status_val = status_val * 10 + (*p - '0');
            ++p; ++digits;
        }
        if (digits != 3) return 3;
    }
    out->status = (u16)status_val;

    /* reason phrase (skip space) */
    if (p < line_end && *p == ' ') ++p;
    reason_start = (const char *)p;
    reason_len = (size_t)(line_end - p);
    out->reason = str_ndup(reason_start, reason_len);
    if (!out->reason) return 5;

    /* parse headers */
    line_start = line_end + 2;
    while (line_start < hdr_end) {
        const u8 *colon;
        const char *hname, *hvalue;
        size_t name_len, value_len;

        line_end = find_crlf(line_start, hdr_end + 2);
        if (!line_end) break;

        /* find colon */
        colon = line_start;
        while (colon < line_end && *colon != ':') ++colon;
        if (colon >= line_end) { line_start = line_end + 2; continue; }

        name_len = (size_t)(colon - line_start);
        hname = str_ndup((const char *)line_start, name_len);
        if (!hname) { http_response_destroy(out); return 5; }

        /* skip ": " */
        colon++;
        while (colon < line_end && *colon == ' ') ++colon;
        value_len = (size_t)(line_end - colon);
        hvalue = str_ndup((const char *)colon, value_len);
        if (!hvalue) { free((void *)hname); http_response_destroy(out); return 5; }

        if (http_headers_set(&out->headers, hname, hvalue) != 0) {
            free((void *)hname);
            free((void *)hvalue);
            http_response_destroy(out);
            return 4;
        }
        free((void *)hname);
        free((void *)hvalue);

        line_start = line_end + 2;
    }

    /* extract body */
    body_len = len - body_offset;

    /* check Content-Length */
    {
        const char *cl_val = NULL;
        http_headers_get(&cl_val, &out->headers, "Content-Length");
        if (cl_val) {
            u64 declared = 0;
            const char *cp = cl_val;
            while (*cp >= '0' && *cp <= '9') {
                declared = declared * 10 + (u64)(*cp - '0');
                ++cp;
            }
            if (declared < body_len) body_len = declared;
        }
    }

    if (body_len > 0) {
        out->body = (u8 *)malloc((size_t)body_len);
        if (!out->body) { http_response_destroy(out); return 5; }
        memcpy(out->body, body_start, (size_t)body_len);
        out->body_len = body_len;
    }

    return 0;
}

unsigned long http_response_status(u16 *out_status, const http_response *resp) {
    if (!out_status) return 1;
    if (!resp)       return 2;
    *out_status = resp->status;
    return 0;
}

unsigned long http_response_header(const char **out_value,
                                   const http_response *resp,
                                   const char *name) {
    if (!out_value) return 1;
    if (!resp)      return 2;
    if (!name)      return 3;
    return http_headers_get(out_value, &resp->headers, name);
}

unsigned long http_response_body(const u8 **out_body, u64 *out_len,
                                 const http_response *resp) {
    if (!out_body) return 1;
    if (!out_len)  return 2;
    if (!resp)     return 3;
    *out_body = resp->body;
    *out_len  = resp->body_len;
    return 0;
}

unsigned long http_response_destroy(http_response *resp) {
    if (!resp) return 1;
    free(resp->reason);
    resp->reason = NULL;
    http_headers_destroy(&resp->headers);
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
    return 0;
}

/* ================================================================
 *  6. Chunked transfer decoding
 * ================================================================ */

#define CHUNK_READ_SIZE    0
#define CHUNK_READ_DATA    1
#define CHUNK_READ_TRAILER 2
#define CHUNK_DONE         3

struct http_chunked_decoder {
    u8  *inbuf;          /* raw input accumulator */
    u64  inbuf_len;
    u64  inbuf_cap;

    u8  *outbuf;         /* decoded output */
    u64  outbuf_len;
    u64  outbuf_cap;

    int  state;
    u64  chunk_remaining; /* bytes left in current chunk */
};

static unsigned long chunked_grow(u8 **buf, u64 *cap, u64 needed) {
    u64 new_cap;
    u8 *nb;
    if (needed <= *cap) return 0;
    new_cap = *cap ? *cap : 256;
    while (new_cap < needed) new_cap *= 2;
    nb = (u8 *)realloc(*buf, (size_t)new_cap);
    if (!nb) return 1;
    *buf = nb;
    *cap = new_cap;
    return 0;
}

/* Process as much of inbuf as possible. */
static void chunked_process(http_chunked_decoder *d) {
    while (d->state != CHUNK_DONE) {
        if (d->state == CHUNK_READ_SIZE) {
            /* look for \r\n in inbuf to read the chunk size line */
            u64 i;
            const u8 *line_end = NULL;
            for (i = 0; i + 1 < d->inbuf_len; ++i) {
                if (d->inbuf[i] == '\r' && d->inbuf[i+1] == '\n') {
                    line_end = d->inbuf + i;
                    break;
                }
            }
            if (!line_end) return; /* need more data */

            /* parse hex size */
            {
                u64 sz = 0;
                const u8 *hp = d->inbuf;
                while (hp < line_end) {
                    int v = hex_digit(*hp);
                    if (v < 0) break; /* ignore chunk extensions */
                    sz = (sz << 4) | (u64)v;
                    ++hp;
                }
                d->chunk_remaining = sz;
            }

            /* consume the size line + \r\n */
            {
                u64 consumed = (u64)(line_end - d->inbuf) + 2;
                d->inbuf_len -= consumed;
                if (d->inbuf_len > 0)
                    memmove(d->inbuf, d->inbuf + consumed, (size_t)d->inbuf_len);
            }

            if (d->chunk_remaining == 0) {
                d->state = CHUNK_READ_TRAILER;
            } else {
                d->state = CHUNK_READ_DATA;
            }

        } else if (d->state == CHUNK_READ_DATA) {
            /* copy available data from inbuf to outbuf */
            u64 avail = d->inbuf_len;
            u64 to_copy = avail < d->chunk_remaining ? avail : d->chunk_remaining;
            if (to_copy == 0) return; /* need more data */

            if (chunked_grow(&d->outbuf, &d->outbuf_cap,
                             d->outbuf_len + to_copy) != 0) return;
            memcpy(d->outbuf + d->outbuf_len, d->inbuf, (size_t)to_copy);
            d->outbuf_len += to_copy;
            d->chunk_remaining -= to_copy;

            /* consume from inbuf */
            d->inbuf_len -= to_copy;
            if (d->inbuf_len > 0)
                memmove(d->inbuf, d->inbuf + to_copy, (size_t)d->inbuf_len);

            if (d->chunk_remaining == 0) {
                /* consume trailing \r\n after chunk data */
                if (d->inbuf_len >= 2 &&
                    d->inbuf[0] == '\r' && d->inbuf[1] == '\n') {
                    d->inbuf_len -= 2;
                    if (d->inbuf_len > 0)
                        memmove(d->inbuf, d->inbuf + 2, (size_t)d->inbuf_len);
                    d->state = CHUNK_READ_SIZE;
                } else {
                    return; /* need the trailing \r\n */
                }
            }

        } else if (d->state == CHUNK_READ_TRAILER) {
            /* after the final "0\r\n", look for the terminating \r\n */
            if (d->inbuf_len >= 2 &&
                d->inbuf[0] == '\r' && d->inbuf[1] == '\n') {
                d->inbuf_len -= 2;
                if (d->inbuf_len > 0)
                    memmove(d->inbuf, d->inbuf + 2, (size_t)d->inbuf_len);
                d->state = CHUNK_DONE;
                return;
            }
            /* there might be trailer headers — skip lines until empty line */
            {
                u64 j;
                int found = 0;
                for (j = 0; j + 1 < d->inbuf_len; ++j) {
                    if (d->inbuf[j] == '\r' && d->inbuf[j+1] == '\n') {
                        /* consume this trailer line */
                        u64 consumed = j + 2;
                        d->inbuf_len -= consumed;
                        if (d->inbuf_len > 0)
                            memmove(d->inbuf, d->inbuf + consumed,
                                    (size_t)d->inbuf_len);
                        found = 1;
                        break;
                    }
                }
                if (!found) return; /* need more data */
            }
        }
    }
}

unsigned long http_chunked_decoder_create(http_chunked_decoder **out) {
    http_chunked_decoder *d;
    if (!out) return 1;

    d = (http_chunked_decoder *)calloc(1, sizeof(http_chunked_decoder));
    if (!d) return 2;
    d->state = CHUNK_READ_SIZE;

    *out = d;
    return 0;
}

unsigned long http_chunked_decoder_feed(http_chunked_decoder *d,
                                        const u8 *data, u64 len) {
    if (!d)    return 1;
    if (!data) return 2;

    if (len == 0) return 0;

    if (chunked_grow(&d->inbuf, &d->inbuf_cap, d->inbuf_len + len) != 0)
        return 3;
    memcpy(d->inbuf + d->inbuf_len, data, (size_t)len);
    d->inbuf_len += len;

    chunked_process(d);
    return 0;
}

unsigned long http_chunked_decoder_read(u8 **out, u64 *out_len,
                                        http_chunked_decoder *d) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!d)       return 3;

    if (d->outbuf_len == 0) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }

    /* hand over the output buffer */
    *out = (u8 *)malloc((size_t)d->outbuf_len);
    if (!*out) return 4;
    memcpy(*out, d->outbuf, (size_t)d->outbuf_len);
    *out_len = d->outbuf_len;

    /* clear output buffer */
    d->outbuf_len = 0;
    return 0;
}

unsigned long http_chunked_decoder_is_done(int *out_done,
                                           http_chunked_decoder *d) {
    if (!out_done) return 1;
    if (!d)        return 2;
    *out_done = (d->state == CHUNK_DONE) ? 1 : 0;
    return 0;
}

unsigned long http_chunked_decoder_destroy(http_chunked_decoder *d) {
    if (!d) return 1;
    free(d->inbuf);
    free(d->outbuf);
    free(d);
    return 0;
}

/* ================================================================
 *  7. Cookies
 * ================================================================ */

unsigned long http_cookie_parse(http_cookie *out, const char *set_cookie_header) {
    const char *p, *semi, *eq;
    size_t seg_len;

    if (!out)               return 1;
    if (!set_cookie_header) return 2;

    memset(out, 0, sizeof(*out));

    p = set_cookie_header;

    /* skip leading whitespace */
    while (*p == ' ' || *p == '\t') ++p;

    /* first segment is name=value */
    semi = strchr(p, ';');
    seg_len = semi ? (size_t)(semi - p) : strlen(p);

    eq = (const char *)memchr(p, '=', seg_len);
    if (!eq) return 3; /* malformed: no name=value */

    out->name = str_ndup(p, (size_t)(eq - p));
    if (!out->name) return 4;
    out->value = str_ndup(eq + 1, seg_len - (size_t)(eq - p) - 1);
    if (!out->value) { http_cookie_free(out); return 4; }

    /* parse attributes */
    if (semi) p = semi + 1; else return 0;

    while (*p) {
        const char *attr_start, *attr_end, *attr_eq;
        size_t attr_len;
        char *attr_name, *attr_value;

        /* skip whitespace */
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '\0') break;

        semi = strchr(p, ';');
        attr_end = semi ? semi : p + strlen(p);
        attr_len = (size_t)(attr_end - p);

        /* trim trailing whitespace */
        while (attr_len > 0 && (p[attr_len-1] == ' ' || p[attr_len-1] == '\t'))
            --attr_len;

        attr_eq = (const char *)memchr(p, '=', attr_len);
        if (attr_eq) {
            attr_name = str_ndup(p, (size_t)(attr_eq - p));
            attr_value = str_ndup(attr_eq + 1, attr_len - (size_t)(attr_eq - p) - 1);
        } else {
            attr_name = str_ndup(p, attr_len);
            attr_value = NULL;
        }

        if (attr_name) {
            if (ci_equal(attr_name, "Path") && attr_value) {
                free(out->path);
                out->path = str_dup(attr_value);
            } else if (ci_equal(attr_name, "Domain") && attr_value) {
                free(out->domain);
                out->domain = str_dup(attr_value);
            } else if (ci_equal(attr_name, "Expires") && attr_value) {
                /* simplified: parse as decimal unix timestamp if numeric,
                   otherwise leave as 0 (session). Full date parsing is
                   outside the scope of this module. */
                u64 ts = 0;
                const char *tp = attr_value;
                while (*tp >= '0' && *tp <= '9') {
                    ts = ts * 10 + (u64)(*tp - '0');
                    ++tp;
                }
                out->expires = ts;
            } else if (ci_equal(attr_name, "Max-Age") && attr_value) {
                u64 ts = 0;
                const char *tp = attr_value;
                while (*tp >= '0' && *tp <= '9') {
                    ts = ts * 10 + (u64)(*tp - '0');
                    ++tp;
                }
                out->expires = ts; /* caller interprets as relative */
            } else if (ci_equal(attr_name, "Secure")) {
                out->secure = 1;
            } else if (ci_equal(attr_name, "HttpOnly")) {
                out->http_only = 1;
            }
            free(attr_name);
            free(attr_value);
        }

        p = semi ? semi + 1 : attr_end;
    }

    return 0;
}

unsigned long http_cookie_free(http_cookie *c) {
    if (!c) return 1;
    free(c->name);   c->name   = NULL;
    free(c->value);  c->value  = NULL;
    free(c->domain); c->domain = NULL;
    free(c->path);   c->path   = NULL;
    return 0;
}

/* ---- Cookie jar ---- */

struct http_cookie_jar {
    http_cookie *cookies;
    u64          count;
    u64          capacity;
};

unsigned long http_cookie_jar_create(http_cookie_jar **out) {
    http_cookie_jar *jar;
    if (!out) return 1;

    jar = (http_cookie_jar *)calloc(1, sizeof(http_cookie_jar));
    if (!jar) return 2;

    *out = jar;
    return 0;
}

unsigned long http_cookie_jar_insert(http_cookie_jar *jar,
                                     const http_cookie *cookie) {
    u64 i;
    if (!jar)    return 1;
    if (!cookie) return 2;

    /* if same name+domain exists, replace it */
    for (i = 0; i < jar->count; ++i) {
        int name_match = jar->cookies[i].name && cookie->name &&
                         strcmp(jar->cookies[i].name, cookie->name) == 0;
        int domain_match;
        if (jar->cookies[i].domain && cookie->domain)
            domain_match = ci_equal(jar->cookies[i].domain, cookie->domain);
        else
            domain_match = (jar->cookies[i].domain == NULL && cookie->domain == NULL);

        if (name_match && domain_match) {
            /* free old, replace */
            http_cookie_free(&jar->cookies[i]);
            jar->cookies[i].name     = str_dup(cookie->name);
            jar->cookies[i].value    = str_dup(cookie->value);
            jar->cookies[i].domain   = str_dup(cookie->domain);
            jar->cookies[i].path     = str_dup(cookie->path);
            jar->cookies[i].expires  = cookie->expires;
            jar->cookies[i].secure   = cookie->secure;
            jar->cookies[i].http_only = cookie->http_only;
            return 0;
        }
    }

    /* grow if needed */
    if (jar->count >= jar->capacity) {
        u64 new_cap = jar->capacity ? jar->capacity * 2 : 8;
        http_cookie *nc = (http_cookie *)realloc(
            jar->cookies, (size_t)(new_cap * sizeof(http_cookie)));
        if (!nc) return 3;
        jar->cookies = nc;
        jar->capacity = new_cap;
    }

    {
        http_cookie *dest = &jar->cookies[jar->count];
        memset(dest, 0, sizeof(*dest));
        dest->name     = str_dup(cookie->name);
        dest->value    = str_dup(cookie->value);
        dest->domain   = str_dup(cookie->domain);
        dest->path     = str_dup(cookie->path);
        dest->expires  = cookie->expires;
        dest->secure   = cookie->secure;
        dest->http_only = cookie->http_only;

        if ((cookie->name && !dest->name) || (cookie->value && !dest->value)) {
            http_cookie_free(dest);
            return 3;
        }
    }
    jar->count++;
    return 0;
}

unsigned long http_cookie_jar_get(http_cookie *out, const http_cookie_jar *jar,
                                  const char *name, const char *domain) {
    u64 i;
    if (!out)    return 1;
    if (!jar)    return 2;
    if (!name)   return 3;

    for (i = 0; i < jar->count; ++i) {
        if (!jar->cookies[i].name) continue;
        if (strcmp(jar->cookies[i].name, name) != 0) continue;

        if (domain) {
            if (!jar->cookies[i].domain) continue;
            if (!ci_equal(jar->cookies[i].domain, domain)) continue;
        }

        /* copy out */
        memset(out, 0, sizeof(*out));
        out->name     = str_dup(jar->cookies[i].name);
        out->value    = str_dup(jar->cookies[i].value);
        out->domain   = str_dup(jar->cookies[i].domain);
        out->path     = str_dup(jar->cookies[i].path);
        out->expires  = jar->cookies[i].expires;
        out->secure   = jar->cookies[i].secure;
        out->http_only = jar->cookies[i].http_only;
        return 0;
    }

    /* not found */
    memset(out, 0, sizeof(*out));
    return 4;
}

unsigned long http_cookie_jar_remove(http_cookie_jar *jar,
                                     const char *name, const char *domain) {
    u64 i;
    if (!jar)  return 1;
    if (!name) return 2;

    for (i = 0; i < jar->count; ++i) {
        int name_match, domain_match;
        if (!jar->cookies[i].name) continue;
        name_match = (strcmp(jar->cookies[i].name, name) == 0);

        if (domain) {
            domain_match = jar->cookies[i].domain &&
                           ci_equal(jar->cookies[i].domain, domain);
        } else {
            domain_match = 1;
        }

        if (name_match && domain_match) {
            http_cookie_free(&jar->cookies[i]);
            if (i + 1 < jar->count) {
                memmove(&jar->cookies[i], &jar->cookies[i + 1],
                        (size_t)((jar->count - i - 1) * sizeof(http_cookie)));
            }
            jar->count--;
            return 0;
        }
    }
    return 0; /* not found is not an error */
}

unsigned long http_cookie_jar_destroy(http_cookie_jar *jar) {
    u64 i;
    if (!jar) return 1;
    for (i = 0; i < jar->count; ++i) {
        http_cookie_free(&jar->cookies[i]);
    }
    free(jar->cookies);
    free(jar);
    return 0;
}

/* domain_matches: check if cookie_domain is a suffix match for request_domain */
static int domain_matches(const char *cookie_domain, const char *request_domain) {
    size_t clen, rlen;
    if (!cookie_domain || !request_domain) return 0;

    /* skip leading dot in cookie domain */
    if (cookie_domain[0] == '.') ++cookie_domain;

    clen = strlen(cookie_domain);
    rlen = strlen(request_domain);

    if (ci_equal(cookie_domain, request_domain)) return 1;

    /* suffix match: request_domain ends with .cookie_domain */
    if (rlen > clen + 1) {
        const char *suffix = request_domain + rlen - clen;
        if (suffix[-1] == '.' && ci_equal(suffix, cookie_domain)) return 1;
    }
    return 0;
}

/* path_matches: check if cookie path is a prefix of request path */
static int path_matches(const char *cookie_path, const char *request_path) {
    size_t clen;
    if (!cookie_path) return 1; /* no path restriction */
    if (!request_path) request_path = "/";

    clen = strlen(cookie_path);
    if (strncmp(request_path, cookie_path, clen) == 0) {
        if (request_path[clen] == '\0' || request_path[clen] == '/')
            return 1;
        if (clen > 0 && cookie_path[clen - 1] == '/')
            return 1;
    }
    return 0;
}

unsigned long http_cookie_build(char **out, u64 *out_len,
                                const http_cookie_jar *jar,
                                const char *domain, const char *path) {
    u64 i, total;
    int first;
    char *buf, *wp;

    if (!out)     return 1;
    if (!out_len) return 2;
    if (!jar)     return 3;

    /* first pass: calculate needed size */
    total = 0;
    first = 1;
    for (i = 0; i < jar->count; ++i) {
        if (!jar->cookies[i].name || !jar->cookies[i].value) continue;
        if (domain && !domain_matches(jar->cookies[i].domain, domain)) continue;
        if (path && !path_matches(jar->cookies[i].path, path)) continue;

        if (!first) total += 2; /* "; " */
        total += strlen(jar->cookies[i].name) + 1 + strlen(jar->cookies[i].value);
        first = 0;
    }

    if (total == 0) {
        *out = str_dup("");
        if (!*out) return 4;
        *out_len = 0;
        return 0;
    }

    buf = (char *)malloc((size_t)(total + 1));
    if (!buf) return 4;

    wp = buf;
    first = 1;
    for (i = 0; i < jar->count; ++i) {
        size_t nlen, vlen;
        if (!jar->cookies[i].name || !jar->cookies[i].value) continue;
        if (domain && !domain_matches(jar->cookies[i].domain, domain)) continue;
        if (path && !path_matches(jar->cookies[i].path, path)) continue;

        if (!first) { memcpy(wp, "; ", 2); wp += 2; }
        nlen = strlen(jar->cookies[i].name);
        memcpy(wp, jar->cookies[i].name, nlen); wp += nlen;
        *wp++ = '=';
        vlen = strlen(jar->cookies[i].value);
        memcpy(wp, jar->cookies[i].value, vlen); wp += vlen;
        first = 0;
    }
    *wp = '\0';

    *out = buf;
    *out_len = (u64)(wp - buf);
    return 0;
}
