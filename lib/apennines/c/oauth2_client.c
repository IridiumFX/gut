#include "apennines/oauth2_client.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ================================================================
 *  Internal: POST a url-encoded form body and return the response.
 *  The caller owns resp->body / resp->headers and must call
 *  https_response_free when done.
 * ================================================================ */

static unsigned long post_form(https_response *resp, https_client *c,
                                const char *url,
                                const char *body, u64 body_len) {
    return https_client_post(resp, c, url,
                              (const u8 *)body, body_len,
                              "application/x-www-form-urlencoded");
}

/* ================================================================
 *  Internal: parse a token endpoint response into oauth2_token,
 *  attaching obtained_at = now. Returns 0 on success.
 * ================================================================ */

static unsigned long parse_token_response(oauth2_token *out,
                                           const u8 *body, u64 body_len) {
    u64 now = (u64)time(NULL);
    return oauth2_token_parse(out, body, body_len, now);
}

/* ================================================================
 *  oauth2_client_token_exchange
 * ================================================================ */

unsigned long oauth2_client_token_exchange(oauth2_token *out,
                                            https_client *c,
                                            const oauth2_config *cfg,
                                            const char *code,
                                            const char *code_verifier) {
    if (!out) return 1;
    if (!c) return 2;
    if (!cfg) return 3;
    if (!cfg->token_endpoint) return 4;
    if (!code) return 5;

    char *body = NULL;
    u64 body_len = 0;
    if (oauth2_token_exchange_body(&body, &body_len, cfg, code, code_verifier))
        return 6;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = post_form(&resp, c, cfg->token_endpoint, body, body_len);
    free(body);
    if (rc) { https_response_free(&resp); return 7; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 8;
    }

    rc = parse_token_response(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc) return 9;
    return 0;
}

/* ================================================================
 *  oauth2_client_token_refresh
 * ================================================================ */

unsigned long oauth2_client_token_refresh(oauth2_token *out,
                                           https_client *c,
                                           const oauth2_config *cfg,
                                           const char *refresh_token) {
    if (!out) return 1;
    if (!c) return 2;
    if (!cfg) return 3;
    if (!cfg->token_endpoint) return 4;
    if (!refresh_token) return 5;

    char *body = NULL;
    u64 body_len = 0;
    if (oauth2_token_refresh(&body, &body_len, cfg, refresh_token))
        return 6;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = post_form(&resp, c, cfg->token_endpoint, body, body_len);
    free(body);
    if (rc) { https_response_free(&resp); return 7; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 8;
    }

    rc = parse_token_response(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc) return 9;
    return 0;
}

/* ================================================================
 *  oauth2_client_client_credentials
 * ================================================================ */

unsigned long oauth2_client_client_credentials(oauth2_token *out,
                                                https_client *c,
                                                const oauth2_config *cfg) {
    if (!out) return 1;
    if (!c) return 2;
    if (!cfg) return 3;
    if (!cfg->token_endpoint) return 4;
    if (!cfg->client_id || !cfg->client_secret) return 5;

    char *body = NULL;
    u64 body_len = 0;
    if (oauth2_client_credentials_body(&body, &body_len, cfg)) return 6;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = post_form(&resp, c, cfg->token_endpoint, body, body_len);
    free(body);
    if (rc) { https_response_free(&resp); return 7; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 8;
    }

    rc = parse_token_response(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc) return 9;
    return 0;
}

/* ================================================================
 *  oauth2_client_device_authorize
 * ================================================================ */

unsigned long oauth2_client_device_authorize(oauth2_device_authz *out,
                                              https_client *c,
                                              const char *device_auth_endpoint,
                                              const oauth2_config *cfg) {
    if (!out) return 1;
    if (!c) return 2;
    if (!device_auth_endpoint) return 3;
    if (!cfg) return 4;
    if (!cfg->client_id) return 5;

    char *body = NULL;
    u64 body_len = 0;
    if (oauth2_device_authz_body(&body, &body_len, cfg)) return 6;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = post_form(&resp, c, device_auth_endpoint,
                                  body, body_len);
    free(body);
    if (rc) { https_response_free(&resp); return 7; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 8;
    }

    rc = oauth2_device_authz_parse(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc) return 9;
    return 0;
}

/* ================================================================
 *  Internal: scan an RFC 6749 error response body for a known
 *  "error":"<code>" value and return a matching hatch.
 *    authorization_pending → 11
 *    slow_down             → 12
 *    access_denied         → 13
 *    expired_token         → 14
 *    anything else         → 8
 * ================================================================ */

static unsigned long device_poll_error_code(const u8 *body, u64 body_len) {
    const struct { const char *name; unsigned long hatch; } codes[] = {
        { "authorization_pending", 11 },
        { "slow_down",             12 },
        { "access_denied",         13 },
        { "expired_token",         14 },
    };

    const char *b = (const char *)body;

    for (u64 i = 0; i + 8 < body_len; i++) {
        if (memcmp(b + i, "\"error\"", 7) != 0) continue;
        /* Advance past "error", optional whitespace, ':', whitespace, '"' */
        u64 j = i + 7;
        while (j < body_len && (b[j] == ' ' || b[j] == '\t')) j++;
        if (j >= body_len || b[j] != ':') continue;
        j++;
        while (j < body_len && (b[j] == ' ' || b[j] == '\t')) j++;
        if (j >= body_len || b[j] != '"') continue;
        j++;
        /* Match each known code by length then memcmp. */
        for (u64 k = 0; k < sizeof(codes) / sizeof(codes[0]); k++) {
            u64 nlen = strlen(codes[k].name);
            if (j + nlen <= body_len &&
                memcmp(b + j, codes[k].name, (size_t)nlen) == 0 &&
                (j + nlen == body_len || b[j + nlen] == '"')) {
                return codes[k].hatch;
            }
        }
        return 8;  /* known error field, unknown value */
    }
    return 8;  /* no error field found */
}

/* ================================================================
 *  oauth2_client_device_poll
 * ================================================================ */

unsigned long oauth2_client_device_poll(oauth2_token *out,
                                         https_client *c,
                                         const oauth2_config *cfg,
                                         const char *device_code) {
    if (!out) return 1;
    if (!c) return 2;
    if (!cfg) return 3;
    if (!cfg->token_endpoint) return 4;
    if (!device_code) return 5;

    char *body = NULL;
    u64 body_len = 0;
    if (oauth2_device_token_body(&body, &body_len, cfg, device_code))
        return 6;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = post_form(&resp, c, cfg->token_endpoint,
                                  body, body_len);
    free(body);
    if (rc) { https_response_free(&resp); return 7; }

    if (resp.status < 200 || resp.status >= 300) {
        /* Device flow uses 400 responses with specific error codes for
         * polling states — decode them into distinct hatches. */
        unsigned long eh = device_poll_error_code(resp.body, resp.body_len);
        https_response_free(&resp);
        return eh;
    }

    rc = parse_token_response(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc) return 9;
    return 0;
}
