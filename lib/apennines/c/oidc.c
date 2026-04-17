#include "apennines/oidc.h"
#include "apennines/json.h"
#include "apennines/http.h"
#include <stdlib.h>
#include <string.h>

/* ================================================================
 *  Internal helper: copy a JSON string field into a fresh malloc'd
 *  null-terminated C string. Returns NULL if the field is missing or
 *  not a string.
 * ================================================================ */

static char *json_string_dup(json_node *obj, const char *key) {
    json_node *n = NULL;
    if (json_get(&n, obj, key)) return NULL;
    if (!n || n->type != JSON_STRING) return NULL;

    u8 *data = NULL;
    u64 len = 0;
    if (json_get_str(&data, &len, n)) return NULL;

    char *out = (char *)malloc((size_t)len + 1);
    if (!out) return NULL;
    memcpy(out, data, (size_t)len);
    out[len] = '\0';
    return out;
}

/* ================================================================
 *  oidc_config_parse
 * ================================================================ */

unsigned long oidc_config_parse(oidc_config *out,
                                 const u8 *json, u64 json_len) {
    if (!out) return 1;
    if (!json) return 2;

    memset(out, 0, sizeof(*out));

    json_node *root = NULL;
    if (json_parse(&root, json, json_len) || !root) return 3;

    out->issuer = json_string_dup(root, "issuer");
    if (!out->issuer) { json_node_destroy(root); return 4; }

    out->authorization_endpoint =
        json_string_dup(root, "authorization_endpoint");
    out->token_endpoint         = json_string_dup(root, "token_endpoint");
    out->userinfo_endpoint      = json_string_dup(root, "userinfo_endpoint");
    out->jwks_uri               = json_string_dup(root, "jwks_uri");
    out->revocation_endpoint    = json_string_dup(root, "revocation_endpoint");
    out->device_authorization_endpoint =
        json_string_dup(root, "device_authorization_endpoint");
    out->end_session_endpoint   = json_string_dup(root, "end_session_endpoint");
    out->introspection_endpoint = json_string_dup(root, "introspection_endpoint");

    json_node_destroy(root);
    return 0;
}

/* ================================================================
 *  oidc_config_free
 * ================================================================ */

unsigned long oidc_config_free(oidc_config *cfg) {
    if (!cfg) return 0;
    free(cfg->issuer);
    free(cfg->authorization_endpoint);
    free(cfg->token_endpoint);
    free(cfg->userinfo_endpoint);
    free(cfg->jwks_uri);
    free(cfg->revocation_endpoint);
    free(cfg->device_authorization_endpoint);
    free(cfg->end_session_endpoint);
    free(cfg->introspection_endpoint);
    memset(cfg, 0, sizeof(*cfg));
    return 0;
}

/* ================================================================
 *  Internal: build the discovery URL from an issuer base.
 * ================================================================ */

static char *build_discovery_url(const char *issuer) {
    u64 ilen = strlen(issuer);
    /* Strip a trailing slash to avoid "//.well-known..." */
    if (ilen > 0 && issuer[ilen - 1] == '/') ilen--;

    static const char SUFFIX[] = "/.well-known/openid-configuration";
    u64 slen = sizeof(SUFFIX) - 1;

    char *url = (char *)malloc((size_t)(ilen + slen + 1));
    if (!url) return NULL;
    memcpy(url, issuer, (size_t)ilen);
    memcpy(url + ilen, SUFFIX, (size_t)slen);
    url[ilen + slen] = '\0';
    return url;
}

/* ================================================================
 *  oidc_discover
 * ================================================================ */

unsigned long oidc_discover(oidc_config *out, https_client *c,
                             const char *issuer) {
    if (!out) return 1;
    if (!c) return 2;
    if (!issuer) return 3;

    char *url = build_discovery_url(issuer);
    if (!url) return 7;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = https_client_get(&resp, c, url);
    free(url);
    if (rc) { https_response_free(&resp); return 4; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 5;
    }

    rc = oidc_config_parse(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc == 4) return 6;  /* missing issuer ⇒ parse-ish failure */
    if (rc) return 6;
    return 0;
}

/* ================================================================
 *  oidc_jwks_fetch
 * ================================================================ */

unsigned long oidc_jwks_fetch(jwks *out, https_client *c,
                               const char *jwks_uri) {
    if (!out) return 1;
    if (!c) return 2;
    if (!jwks_uri) return 3;

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = https_client_get(&resp, c, jwks_uri);
    if (rc) { https_response_free(&resp); return 4; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 5;
    }

    rc = jwks_parse(out, resp.body, resp.body_len);
    https_response_free(&resp);
    if (rc) return 6;
    return 0;
}

/* ================================================================
 *  oidc_userinfo
 * ================================================================ */

unsigned long oidc_userinfo(u8 **out, u64 *out_len,
                             https_client *c,
                             const char *userinfo_url,
                             const char *access_token) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!c) return 3;
    if (!userinfo_url) return 4;
    if (!access_token) return 5;

    /* Build "Bearer <token>" header value. */
    u64 tok_len = strlen(access_token);
    char *auth = (char *)malloc((size_t)(tok_len + 8));
    if (!auth) return 8;
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, access_token, (size_t)tok_len);
    auth[tok_len + 7] = '\0';

    http_headers hdrs;
    if (http_headers_create(&hdrs)) { free(auth); return 8; }
    if (http_headers_set(&hdrs, "Authorization", auth)) {
        free(auth);
        http_headers_destroy(&hdrs);
        return 8;
    }
    free(auth);

    https_response resp;
    memset(&resp, 0, sizeof(resp));
    unsigned long rc = https_client_request(&resp, c, HTTP_GET,
                                             userinfo_url, &hdrs, NULL, 0);
    http_headers_destroy(&hdrs);
    if (rc) { https_response_free(&resp); return 6; }
    if (resp.status < 200 || resp.status >= 300) {
        https_response_free(&resp);
        return 7;
    }

    /* Transfer the body out. */
    u8 *body = (u8 *)malloc((size_t)resp.body_len);
    if (!body) { https_response_free(&resp); return 8; }
    memcpy(body, resp.body, (size_t)resp.body_len);

    *out = body;
    *out_len = resp.body_len;
    https_response_free(&resp);
    return 0;
}
