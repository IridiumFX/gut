#ifndef APENNINES_T4_HTTPS_CLIENT_H
#define APENNINES_T4_HTTPS_CLIENT_H


#include "apennines/types.h"
#include "apennines/http.h"

/* ================================================================
 *  HTTPS Client — DNS + TCP + TLS + HTTP + cookies + compression
 * ================================================================ */

typedef struct https_client https_client;

typedef struct {
    u16           status;
    http_headers  headers;
    u8           *body;
    u64           body_len;
} https_response;

typedef void (*https_progress_fn)(u64 downloaded, u64 total, void *ctx);

unsigned long https_client_create(https_client **out);
unsigned long https_client_request(https_response *out,
                                                  https_client *c,
                                                  int method, const char *url,
                                                  const http_headers *hdrs,
                                                  const u8 *body, u64 body_len);
unsigned long https_client_get(https_response *out,
                                              https_client *c, const char *url);
unsigned long https_client_post(https_response *out,
                                               https_client *c, const char *url,
                                               const u8 *body, u64 body_len,
                                               const char *content_type);
unsigned long https_client_put(https_response *out,
                                              https_client *c, const char *url,
                                              const u8 *body, u64 body_len,
                                              const char *content_type);
unsigned long https_client_delete(https_response *out,
                                                 https_client *c, const char *url);
unsigned long https_client_patch(https_response *out,
                                                https_client *c, const char *url,
                                                const u8 *body, u64 body_len,
                                                const char *content_type);
unsigned long https_client_head(https_response *out,
                                               https_client *c, const char *url);
unsigned long https_client_download(https_client *c, const char *url,
                                                   const char *file_path,
                                                   https_progress_fn progress,
                                                   void *ctx);
unsigned long https_client_set_header(https_client *c,
                                                     const char *name,
                                                     const char *value);
unsigned long https_client_set_timeout(https_client *c, u64 ms);
unsigned long https_client_set_proxy(https_client *c,
                                                    const char *proxy_url);
unsigned long https_client_set_cookie_jar(https_client *c, int enabled);
unsigned long https_client_set_compression(https_client *c, int enabled);
unsigned long https_client_set_redirect(https_client *c, u32 max);
unsigned long https_client_set_auth_basic(https_client *c,
                                                         const char *user,
                                                         const char *pass);
unsigned long https_client_set_auth_bearer(https_client *c,
                                                          const char *token);
unsigned long https_client_pool_stats(u64 *active, u64 *idle,
                                                     u64 *total, https_client *c);
unsigned long https_response_free(https_response *resp);
unsigned long https_client_destroy(https_client *c);

/* ---- Upload ---- */
unsigned long https_client_upload(https_client *c, const char *url,
                                                 const char *file_path,
                                                 const char *content_type,
                                                 https_progress_fn progress,
                                                 void *ctx);

#endif
