#include "apennines/http_client.h"
#include "apennines/http.h"
#include "apennines/tcp.h"
#include "apennines/dns.h"
#include "apennines/addr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ================================================================
 *  Internal struct
 * ================================================================ */

struct http_client {
    u64   timeout_ms;
    u32   max_redirects;
    char *proxy_url;
};

/* ================================================================
 *  Helpers
 * ================================================================ */

static char *str_dup_local(const char *s) {
    size_t len;
    char *d;
    if (!s) return NULL;
    len = strlen(s);
    d = (char *)malloc(len + 1);
    if (!d) return NULL;
    memcpy(d, s, len + 1);
    return d;
}

static u16 default_port_for_scheme(const char *scheme) {
    if (!scheme) return 80;
    if (strcmp(scheme, "https") == 0) return 443;
    return 80;
}

/* Read buffer sizing */
#define INITIAL_BUF_CAP  8192
#define MAX_RESPONSE_SIZE (64 * 1024 * 1024)  /* 64 MiB hard limit */

/*
 * find_header_end — locate the "\r\n\r\n" boundary in a buffer.
 * Returns the offset past the boundary, or 0 if not found.
 */
static u64 find_header_end(const u8 *buf, u64 len) {
    u64 i;
    if (len < 4) return 0;
    for (i = 0; i <= len - 4; ++i) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return 0;
}

/*
 * is_redirect — check whether status is a redirect we follow.
 */
static int is_redirect(u16 status) {
    return (status == 301 || status == 302 ||
            status == 307 || status == 308);
}

/*
 * redirect_preserves_method — 307/308 preserve the original method.
 */
static int redirect_preserves_method(u16 status) {
    return (status == 307 || status == 308);
}

/*
 * build_request_target — build the path?query portion for the request line.
 */
static char *build_request_target(const http_url *u) {
    size_t plen, qlen, total;
    char *target;

    plen = strlen(u->path);
    qlen = u->query ? strlen(u->query) : 0;
    total = plen + (qlen > 0 ? 1 + qlen : 0) + 1;

    target = (char *)malloc(total);
    if (!target) return NULL;

    memcpy(target, u->path, plen);
    if (qlen > 0) {
        target[plen] = '?';
        memcpy(target + plen + 1, u->query, qlen);
    }
    target[plen + (qlen > 0 ? 1 + qlen : 0)] = '\0';
    return target;
}

/*
 * build_host_header — "host" or "host:port" depending on default.
 */
static char *build_host_header(const http_url *u) {
    u16 def_port;
    size_t hlen;
    char *buf;

    def_port = default_port_for_scheme(u->scheme);
    hlen = strlen(u->host);

    if (u->port == 0 || u->port == def_port) {
        return str_dup_local(u->host);
    }

    /* host:port — port is at most 5 digits + colon + nul */
    buf = (char *)malloc(hlen + 7);
    if (!buf) return NULL;
    snprintf(buf, hlen + 7, "%s:%u", u->host, (unsigned)u->port);
    return buf;
}

/* ================================================================
 *  Core: single-request execution (no redirect following)
 * ================================================================ */

/*
 * execute_single_request — connect, send, receive, parse one HTTP exchange.
 *
 * Hatches:
 *   1 = url parse failed
 *   2 = dns resolution failed
 *   3 = tcp connect failed
 *   4 = request creation/serialization failed
 *   5 = tcp write failed
 *   6 = tcp read / response too large
 *   7 = response parse failed
 *   8 = alloc failure
 */
static unsigned long execute_single_request(http_response *out,
                                            http_client *c,
                                            int method,
                                            const char *url,
                                            const http_headers *hdrs,
                                            const u8 *body,
                                            u64 body_len) {
    http_url       parsed_url;
    dns_response   dns_resp;
    net_sock_addr  addr;
    tcp_conn       conn;
    http_request   req;
    u8            *serial    = NULL;
    u64            serial_len = 0;
    u8            *recv_buf  = NULL;
    u64            recv_cap  = 0;
    u64            recv_len  = 0;
    u64            bytes_rd  = 0;
    u64            written   = 0;
    char          *target    = NULL;
    char          *host_hdr  = NULL;
    unsigned long  rc;
    char           len_buf[32];
    u16            port;

    memset(&parsed_url, 0, sizeof(parsed_url));
    memset(&dns_resp, 0, sizeof(dns_resp));
    memset(&conn, 0, sizeof(conn));
    memset(&req, 0, sizeof(req));
    memset(out, 0, sizeof(*out));

    /* ---- Parse URL ---- */
    rc = http_url_parse(&parsed_url, url);
    if (rc != 0) return 1;

    port = parsed_url.port;
    if (port == 0) port = default_port_for_scheme(parsed_url.scheme);

    /* ---- DNS resolve ---- */
    rc = dns_query(&dns_resp, parsed_url.host);
    if (rc != 0) {
        http_url_free(&parsed_url);
        return 2;
    }

    /* Pick first A record from dns_response */
    if (dns_resp.count == 0 || !dns_resp.records) {
        dns_response_free(&dns_resp);
        http_url_free(&parsed_url);
        return 2;
    }

    /* Build net_sock_addr from the first A record's rdata (4 bytes for IPv4) */
    {
        dns_record *rec = &dns_resp.records[0];
        if (rec->type == DNS_TYPE_A && rec->rdata_len >= 4) {
            memset(&addr, 0, sizeof(addr));
            addr.family = 4;
            memcpy(addr.addr.v4.octets, rec->rdata, 4);
            addr.port = port;
        } else if (rec->type == DNS_TYPE_AAAA && rec->rdata_len >= 16) {
            memset(&addr, 0, sizeof(addr));
            addr.family = 6;
            memcpy(addr.addr.v6.octets, rec->rdata, 16);
            addr.port = port;
        } else {
            dns_response_free(&dns_resp);
            http_url_free(&parsed_url);
            return 2;
        }
    }
    dns_response_free(&dns_resp);

    /* ---- TCP connect ---- */
    rc = tcp_conn_create(&conn, &addr);
    if (rc != 0) {
        http_url_free(&parsed_url);
        return 3;
    }
    /* ---- Build HTTP request ---- */
    target = build_request_target(&parsed_url);
    if (!target) {
        tcp_conn_destroy(&conn);
        http_url_free(&parsed_url);
        return 8;
    }

    rc = http_request_create(&req, method, target);
    free(target);
    target = NULL;
    if (rc != 0) {
        tcp_conn_destroy(&conn);
        http_url_free(&parsed_url);
        return 4;
    }

    /* Host header */
    host_hdr = build_host_header(&parsed_url);
    if (!host_hdr) {
        http_request_destroy(&req);
        tcp_conn_destroy(&conn);
        http_url_free(&parsed_url);
        return 8;
    }
    http_request_set_header(&req, "Host", host_hdr);
    free(host_hdr);
    host_hdr = NULL;

    /* Copy caller-supplied headers */
    if (hdrs) {
        u64 i;
        for (i = 0; i < hdrs->count; ++i) {
            http_request_set_header(&req, hdrs->items[i].name,
                                    hdrs->items[i].value);
        }
    }

    /* Content-Length + body */
    if (body && body_len > 0) {
        snprintf(len_buf, sizeof(len_buf), "%llu",
                 (unsigned long long)body_len);
        http_request_set_header(&req, "Content-Length", len_buf);
        http_request_set_body(&req, body, body_len);
    }

    /* Connection: close — we don't pool */
    http_request_set_header(&req, "Connection", "close");

    http_url_free(&parsed_url);

    /* ---- Serialize & send ---- */
    rc = http_request_serialize(&serial, &serial_len, &req);
    http_request_destroy(&req);
    if (rc != 0) {
        tcp_conn_destroy(&conn);
        return 4;
    }

    rc = tcp_conn_write_all(&written, &conn, serial, serial_len);
    free(serial);
    serial = NULL;
    if (rc != 0) {
        tcp_conn_destroy(&conn);
        return 5;
    }

    /* ---- Receive response ---- */
    recv_cap = INITIAL_BUF_CAP;
    recv_buf = (u8 *)malloc(recv_cap);
    if (!recv_buf) {
        tcp_conn_destroy(&conn);
        return 8;
    }
    recv_len = 0;

    /* Read until we have the full response */
    for (;;) {
        /* Grow buffer if needed */
        if (recv_len == recv_cap) {
            u64 new_cap = recv_cap * 2;
            u8 *tmp;
            if (new_cap > MAX_RESPONSE_SIZE) {
                free(recv_buf);
                tcp_conn_destroy(&conn);
                return 6;
            }
            tmp = (u8 *)realloc(recv_buf, (size_t)new_cap);
            if (!tmp) {
                free(recv_buf);
                tcp_conn_destroy(&conn);
                return 8;
            }
            recv_buf = tmp;
            recv_cap = new_cap;
        }

        bytes_rd = 0;
        rc = tcp_conn_read(&bytes_rd, &conn,
                           recv_buf + recv_len,
                           recv_cap - recv_len);
        if (rc != 0 || bytes_rd == 0) {
            /* Connection closed or error — try to parse what we have */
            break;
        }
        recv_len += bytes_rd;

        /* Quick check: once we have headers, see if body is complete */
        {
            u64 hdr_end = find_header_end(recv_buf, recv_len);
            if (hdr_end > 0) {
                /* Try a tentative parse to read Content-Length */
                http_response tmp_resp;
                memset(&tmp_resp, 0, sizeof(tmp_resp));
                rc = http_response_parse(&tmp_resp, recv_buf, recv_len);
                if (rc == 0) {
                    /* Successful parse — we have the full response */
                    http_response_destroy(&tmp_resp);
                    break;
                }
                /* rc == 6 means incomplete — keep reading */
                if (rc != 6) {
                    http_response_destroy(&tmp_resp);
                    /* Some other parse error — we'll handle below */
                    break;
                }
                http_response_destroy(&tmp_resp);
            }
        }
    }

    tcp_conn_destroy(&conn);

    /* ---- Parse response ---- */
    if (recv_len == 0) {
        free(recv_buf);
        return 7;
    }

    rc = http_response_parse(out, recv_buf, recv_len);
    free(recv_buf);
    if (rc != 0) return 7;

    return 0;
}

/* ================================================================
 *  Public API
 * ================================================================ */

unsigned long http_client_create(http_client **out) {
    http_client *c;

    if (!out) return 1;

    c = (http_client *)calloc(1, sizeof(http_client));
    if (!c) return 2;

    c->timeout_ms     = 30000; /* 30 seconds default */
    c->max_redirects  = 10;
    c->proxy_url      = NULL;

    *out = c;
    return 0;
}

unsigned long http_client_request(http_client_response *out,
                                  http_client *c,
                                  int method, const char *url,
                                  const http_headers *hdrs,
                                  const u8 *body, u64 body_len) {
    unsigned long rc;
    http_response raw_resp;
    char *current_url    = NULL;
    char *next_url       = NULL;
    int   current_method = method;
    u32   redirects      = 0;

    if (!out) return 1;
    if (!c)   return 2;
    if (!url) return 3;

    memset(out, 0, sizeof(*out));

    current_url = str_dup_local(url);
    if (!current_url) return 4;

    for (;;) {
        memset(&raw_resp, 0, sizeof(raw_resp));

        rc = execute_single_request(&raw_resp, c, current_method,
                                    current_url, hdrs, body, body_len);
        if (rc != 0) {
            free(current_url);
            return 5 + rc;  /* offset internal hatches past our own */
        }

        /* Check for redirect */
        if (is_redirect(raw_resp.status) && redirects < c->max_redirects) {
            const char *location = NULL;
            http_response_header(&location, &raw_resp, "Location");

            if (location && strlen(location) > 0) {
                u16 redir_status = raw_resp.status;
                redirects++;

                /* Build absolute redirect URL */
                if (location[0] == '/') {
                    /* Relative redirect — reconstruct from current URL's origin */
                    http_url cur_parsed;
                    memset(&cur_parsed, 0, sizeof(cur_parsed));
                    if (http_url_parse(&cur_parsed, current_url) == 0) {
                        u16 port = cur_parsed.port;
                        u16 def  = default_port_for_scheme(cur_parsed.scheme);
                        size_t need;

                        if (port == 0 || port == def) {
                            need = strlen(cur_parsed.scheme) + 3 +
                                   strlen(cur_parsed.host) +
                                   strlen(location) + 1;
                            next_url = (char *)malloc(need);
                            if (next_url) {
                                snprintf(next_url, need, "%s://%s%s",
                                         cur_parsed.scheme, cur_parsed.host,
                                         location);
                            }
                        } else {
                            need = strlen(cur_parsed.scheme) + 3 +
                                   strlen(cur_parsed.host) + 6 +
                                   strlen(location) + 1;
                            next_url = (char *)malloc(need);
                            if (next_url) {
                                snprintf(next_url, need, "%s://%s:%u%s",
                                         cur_parsed.scheme, cur_parsed.host,
                                         (unsigned)port, location);
                            }
                        }
                        http_url_free(&cur_parsed);
                    }
                } else {
                    /* Absolute URL */
                    next_url = str_dup_local(location);
                }

                http_response_destroy(&raw_resp);
                free(current_url);

                if (!next_url) return 4;
                current_url = next_url;
                next_url = NULL;

                /* 301/302 convert to GET; 307/308 preserve method */
                if (!redirect_preserves_method(redir_status)) {
                    current_method = HTTP_GET;
                    body = NULL;
                    body_len = 0;
                }

                continue;
            }
        }

        /* Not a redirect (or max reached) — return the response */
        break;
    }

    free(current_url);

    /* Fill out the client response */
    out->status   = raw_resp.status;
    out->body     = raw_resp.body;
    out->body_len = raw_resp.body_len;

    /* Move headers from raw response */
    out->headers.items    = raw_resp.headers.items;
    out->headers.count    = raw_resp.headers.count;
    out->headers.capacity = raw_resp.headers.capacity;

    /* Detach from raw_resp so destroy doesn't free them */
    raw_resp.body          = NULL;
    raw_resp.body_len      = 0;
    raw_resp.headers.items = NULL;
    raw_resp.headers.count = 0;
    raw_resp.headers.capacity = 0;

    http_response_destroy(&raw_resp);
    return 0;
}

/* ---- Convenience wrappers ---- */

unsigned long http_client_get(http_client_response *out,
                              http_client *c, const char *url) {
    return http_client_request(out, c, HTTP_GET, url, NULL, NULL, 0);
}

unsigned long http_client_post(http_client_response *out,
                               http_client *c, const char *url,
                               const u8 *body, u64 body_len,
                               const char *content_type) {
    http_headers  hdrs;
    unsigned long rc;

    if (!out) return 1;
    if (!c)   return 2;

    rc = http_headers_create(&hdrs);
    if (rc != 0) return 3;

    if (content_type) {
        rc = http_headers_set(&hdrs, "Content-Type", content_type);
        if (rc != 0) {
            http_headers_destroy(&hdrs);
            return 3;
        }
    }

    rc = http_client_request(out, c, HTTP_POST, url, &hdrs, body, body_len);
    http_headers_destroy(&hdrs);
    return rc;
}

unsigned long http_client_put(http_client_response *out,
                              http_client *c, const char *url,
                              const u8 *body, u64 body_len,
                              const char *content_type) {
    http_headers  hdrs;
    unsigned long rc;

    if (!out) return 1;
    if (!c)   return 2;

    rc = http_headers_create(&hdrs);
    if (rc != 0) return 3;

    if (content_type) {
        rc = http_headers_set(&hdrs, "Content-Type", content_type);
        if (rc != 0) {
            http_headers_destroy(&hdrs);
            return 3;
        }
    }

    rc = http_client_request(out, c, HTTP_PUT, url, &hdrs, body, body_len);
    http_headers_destroy(&hdrs);
    return rc;
}

unsigned long http_client_delete(http_client_response *out,
                                 http_client *c, const char *url) {
    return http_client_request(out, c, HTTP_DELETE, url, NULL, NULL, 0);
}

/* ---- Configuration ---- */

unsigned long http_client_set_timeout(http_client *c, u64 ms) {
    if (!c) return 1;
    c->timeout_ms = ms;
    return 0;
}

unsigned long http_client_set_proxy(http_client *c, const char *proxy_url) {
    if (!c) return 1;

    free(c->proxy_url);
    c->proxy_url = NULL;

    if (proxy_url) {
        c->proxy_url = str_dup_local(proxy_url);
        if (!c->proxy_url) return 2;
    }
    return 0;
}

unsigned long http_client_set_max_redirects(http_client *c, u32 max) {
    if (!c) return 1;
    c->max_redirects = max;
    return 0;
}

/* ---- Cleanup ---- */

unsigned long http_client_response_free(http_client_response *resp) {
    if (!resp) return 1;

    http_headers_destroy(&resp->headers);
    free(resp->body);

    resp->body     = NULL;
    resp->body_len = 0;
    resp->status   = 0;
    return 0;
}

unsigned long http_client_destroy(http_client *c) {
    if (!c) return 1;
    free(c->proxy_url);
    free(c);
    return 0;
}
