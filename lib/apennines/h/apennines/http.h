#ifndef APENNINES_T3_HTTP_H
#define APENNINES_T3_HTTP_H


#include "apennines/types.h"

/* ================================================================
 *  HTTP/1.1 — request/response building, parsing, URL, cookies
 * ================================================================ */

/* ---- HTTP methods ---- */
#define HTTP_GET     0
#define HTTP_POST    1
#define HTTP_PUT     2
#define HTTP_DELETE  3
#define HTTP_HEAD    4
#define HTTP_PATCH   5
#define HTTP_OPTIONS 6

/* ---- URL ---- */

typedef struct {
    char *scheme;       /* "http" or "https" */
    char *host;
    u16   port;         /* 0 = not specified */
    char *path;         /* "/" if empty */
    char *query;        /* without leading '?', NULL if none */
    char *fragment;     /* without leading '#', NULL if none */
    char *userinfo;     /* "user:pass" or NULL */
} http_url;

unsigned long http_url_parse(http_url *out, const char *url);
unsigned long http_url_free(http_url *url);

/* Percent-encode/decode.
 *   out:      receives allocated string (caller frees)
 *   out_len:  receives length
 *   src:      input string
 *   src_len:  input length
 *
 * Hatches: 1=null out, 2=null out_len, 3=null src, 4=alloc failure */
unsigned long http_url_encode(char **out, u64 *out_len,
                                             const char *src, u64 src_len);
unsigned long http_url_decode(char **out, u64 *out_len,
                                             const char *src, u64 src_len);

/* ---- Query string ---- */

typedef struct {
    char *key;
    char *value;
} http_query_param;

typedef struct {
    http_query_param *params;
    u64               count;
    u64               capacity;
} http_query;

/* Parse query string "key=val&key2=val2" into params.
 * Hatches: 1=null out, 2=null qs, 3=alloc failure */
unsigned long http_query_parse(http_query *out,
                                              const char *qs, u64 qs_len);

/* Build query string from params.
 * Hatches: 1=null out, 2=null out_len, 3=null q, 4=alloc failure */
unsigned long http_query_build(char **out, u64 *out_len,
                                              const http_query *q);
unsigned long http_query_free(http_query *q);

/* ---- Headers ---- */

typedef struct {
    char *name;
    char *value;
} http_header;

typedef struct {
    http_header *items;
    u64          count;
    u64          capacity;
} http_headers;

unsigned long http_headers_create(http_headers *out);
unsigned long http_headers_set(http_headers *h,
                                              const char *name, const char *value);
unsigned long http_headers_get(const char **out_value,
                                              const http_headers *h,
                                              const char *name);
unsigned long http_headers_remove(http_headers *h, const char *name);

typedef void (*http_headers_iter_fn)(const char *name, const char *value, void *ctx);
unsigned long http_headers_iter(const http_headers *h,
                                               http_headers_iter_fn fn, void *ctx);
unsigned long http_headers_destroy(http_headers *h);

/* ---- Request ---- */

typedef struct {
    int           method;       /* HTTP_GET, etc. */
    char         *url;          /* request-target */
    http_headers  headers;
    u8           *body;
    u64           body_len;
} http_request;

/* Hatches: 1=null out, 2=null url, 3=invalid method, 4=alloc failure */
unsigned long http_request_create(http_request *out,
                                                 int method, const char *url);
unsigned long http_request_set_header(http_request *req,
                                                     const char *name,
                                                     const char *value);
unsigned long http_request_set_body(http_request *req,
                                                   const u8 *body, u64 len);

/* Serialize request to wire format.
 * Hatches: 1=null out, 2=null out_len, 3=null req, 4=alloc failure */
unsigned long http_request_serialize(u8 **out, u64 *out_len,
                                                    const http_request *req);
unsigned long http_request_destroy(http_request *req);

/* ---- Response ---- */

typedef struct {
    u16           status;       /* HTTP status code */
    char         *reason;       /* reason phrase */
    http_headers  headers;
    u8           *body;
    u64           body_len;
} http_response;

/* Parse raw HTTP response bytes.
 * Hatches: 1=null out, 2=null data, 3=malformed status line,
 *          4=malformed headers, 5=alloc failure,
 *          6=incomplete (need more data) */
unsigned long http_response_parse(http_response *out,
                                                 const u8 *data, u64 len);

unsigned long http_response_status(u16 *out_status,
                                                  const http_response *resp);
unsigned long http_response_header(const char **out_value,
                                                  const http_response *resp,
                                                  const char *name);
unsigned long http_response_body(const u8 **out_body,
                                                u64 *out_len,
                                                const http_response *resp);
unsigned long http_response_destroy(http_response *resp);

/* ---- Chunked transfer decoding ---- */

typedef struct http_chunked_decoder http_chunked_decoder;

unsigned long http_chunked_decoder_create(http_chunked_decoder **out);
unsigned long http_chunked_decoder_feed(http_chunked_decoder *d,
                                                       const u8 *data, u64 len);
unsigned long http_chunked_decoder_read(u8 **out, u64 *out_len,
                                                       http_chunked_decoder *d);
unsigned long http_chunked_decoder_is_done(int *out_done,
                                                          http_chunked_decoder *d);
unsigned long http_chunked_decoder_destroy(http_chunked_decoder *d);

/* ---- Cookie ---- */

typedef struct {
    char *name;
    char *value;
    char *domain;
    char *path;
    u64   expires;      /* unix timestamp, 0 = session */
    int   secure;
    int   http_only;
} http_cookie;

typedef struct http_cookie_jar http_cookie_jar;

unsigned long http_cookie_parse(http_cookie *out,
                                               const char *set_cookie_header);
unsigned long http_cookie_build(char **out, u64 *out_len,
                                               const http_cookie_jar *jar,
                                               const char *domain,
                                               const char *path);
unsigned long http_cookie_free(http_cookie *c);

unsigned long http_cookie_jar_create(http_cookie_jar **out);
unsigned long http_cookie_jar_insert(http_cookie_jar *jar,
                                                    const http_cookie *cookie);
unsigned long http_cookie_jar_get(http_cookie *out,
                                                 const http_cookie_jar *jar,
                                                 const char *name,
                                                 const char *domain);
unsigned long http_cookie_jar_remove(http_cookie_jar *jar,
                                                    const char *name,
                                                    const char *domain);
unsigned long http_cookie_jar_destroy(http_cookie_jar *jar);

#endif /* APENNINES_T3_HTTP_H */
