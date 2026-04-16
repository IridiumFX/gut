#ifndef APENNINES_T4_HTTP_CLIENT_H
#define APENNINES_T4_HTTP_CLIENT_H


#include "apennines/types.h"
#include "apennines/http.h"

/* ================================================================
 *  HTTP Client — connection-pooled, redirect-following
 *  Composes: DNS + TCP + HTTP/1.1 parser + redirect engine
 * ================================================================ */

typedef struct http_client http_client;

typedef struct {
    u16           status;
    http_headers  headers;
    u8           *body;
    u64           body_len;
} http_client_response;

unsigned long http_client_create(http_client **out);
unsigned long http_client_request(http_client_response *out,
                                                 http_client *c,
                                                 int method, const char *url,
                                                 const http_headers *hdrs,
                                                 const u8 *body, u64 body_len);
unsigned long http_client_get(http_client_response *out,
                                             http_client *c, const char *url);
unsigned long http_client_post(http_client_response *out,
                                              http_client *c, const char *url,
                                              const u8 *body, u64 body_len,
                                              const char *content_type);
unsigned long http_client_put(http_client_response *out,
                                             http_client *c, const char *url,
                                             const u8 *body, u64 body_len,
                                             const char *content_type);
unsigned long http_client_delete(http_client_response *out,
                                                http_client *c, const char *url);
unsigned long http_client_set_timeout(http_client *c, u64 ms);
unsigned long http_client_set_proxy(http_client *c,
                                                   const char *proxy_url);
unsigned long http_client_set_max_redirects(http_client *c, u32 max);
unsigned long http_client_response_free(http_client_response *resp);
unsigned long http_client_destroy(http_client *c);

#endif
