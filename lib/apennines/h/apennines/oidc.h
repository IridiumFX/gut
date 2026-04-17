#ifndef APENNINES_T4_OIDC_H
#define APENNINES_T4_OIDC_H

#include "apennines/types.h"
#include "apennines/jwks.h"
#include "apennines/https_client.h"

/* ================================================================
 *  OIDC — OpenID Connect discovery + JWKS fetch + userinfo
 *
 *  Thin layer over t3/crypto/jwks and t4/net/https_client. Given an
 *  issuer URL, discovers the provider's endpoints and fetches the
 *  signing keys. Enough to verify ID tokens end to end.
 * ================================================================ */

typedef struct {
    char  *issuer;
    char  *authorization_endpoint;
    char  *token_endpoint;
    char  *userinfo_endpoint;
    char  *jwks_uri;
    char  *revocation_endpoint;
    char  *device_authorization_endpoint;
    char  *end_session_endpoint;
    char  *introspection_endpoint;
} oidc_config;

/* oidc_config_parse — parse an OIDC discovery document (JSON).
 *   out:       receives parsed config (caller frees via oidc_config_free)
 *   json:      raw JSON bytes
 *   json_len:  byte length
 *
 * All fields are optional except issuer; missing fields become NULL.
 * Hatches: 1=null out, 2=null json, 3=parse failure, 4=missing issuer */
unsigned long oidc_config_parse(oidc_config *out,
                                               const u8 *json, u64 json_len);

/* oidc_discover — fetch and parse the OIDC discovery document.
 *   out:     receives parsed config (caller frees via oidc_config_free)
 *   c:       HTTPS client to use
 *   issuer:  issuer URL (e.g. "https://accounts.google.com"); the
 *            function appends "/.well-known/openid-configuration"
 *
 * Hatches: 1=null out, 2=null c, 3=null issuer, 4=HTTP request failure,
 *          5=non-2xx response, 6=parse failure, 7=alloc failure */
unsigned long oidc_discover(oidc_config *out,
                                           https_client *c,
                                           const char *issuer);

/* oidc_config_free — release memory owned by a discovery document. */
unsigned long oidc_config_free(oidc_config *cfg);

/* oidc_jwks_fetch — fetch a JWKS document and parse it.
 *   out:       receives parsed jwks (caller destroys via jwks_destroy)
 *   c:         HTTPS client
 *   jwks_uri:  URL of the JWKS endpoint (typically cfg->jwks_uri)
 *
 * Hatches: 1=null out, 2=null c, 3=null jwks_uri, 4=HTTP request fail,
 *          5=non-2xx response, 6=parse failure */
unsigned long oidc_jwks_fetch(jwks *out,
                                             https_client *c,
                                             const char *jwks_uri);

/* oidc_userinfo — call the userinfo endpoint with a bearer token.
 *   out:           receives the raw JSON response body (caller frees)
 *   out_len:       receives body length
 *   c:             HTTPS client
 *   userinfo_url:  URL of the userinfo endpoint (from oidc_config)
 *   access_token:  a bearer access token with appropriate scope
 *
 * Hatches: 1=null out, 2=null out_len, 3=null c, 4=null userinfo_url,
 *          5=null access_token, 6=HTTP request failure,
 *          7=non-2xx response, 8=alloc failure */
unsigned long oidc_userinfo(u8 **out, u64 *out_len,
                                           https_client *c,
                                           const char *userinfo_url,
                                           const char *access_token);

#endif /* APENNINES_T4_OIDC_H */
