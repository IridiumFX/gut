#ifndef APENNINES_T3_OAUTH2_H
#define APENNINES_T3_OAUTH2_H

#include "apennines/types.h"

/* ================================================================
 *  OAuth2 — RFC 6749 authorization code flow
 * ================================================================ */

typedef struct {
    char *access_token;
    char *refresh_token;    /* NULL if not provided */
    char *token_type;       /* "Bearer" */
    u64   expires_in;       /* seconds until expiry */
    u64   obtained_at;      /* unix timestamp when token was obtained */
    char *scope;            /* space-delimited scopes, NULL if not returned */
} oauth2_token;

typedef struct {
    const char *auth_endpoint;      /* authorization URL */
    const char *token_endpoint;     /* token exchange URL */
    const char *client_id;
    const char *client_secret;      /* NULL for public clients */
    const char *redirect_uri;
    const char *scope;              /* space-delimited, NULL for default */
} oauth2_config;

/* oauth2_auth_url_build — build the authorization URL for user redirect.
 *   out:       receives allocated URL string (caller frees)
 *   out_len:   receives URL length
 *   cfg:       OAuth2 configuration
 *   state:     CSRF state parameter (null-terminated)
 *
 * Hatches: 1=null out, 2=null out_len, 3=null cfg,
 *          4=null auth_endpoint, 5=null client_id,
 *          6=null state, 7=alloc failure */
unsigned long oauth2_auth_url_build(char **out, u64 *out_len,
                                                   const oauth2_config *cfg,
                                                   const char *state);

/* oauth2_token_exchange — exchange authorization code for tokens.
 *   out:       receives parsed token (caller frees fields via oauth2_token_free)
 *   cfg:       OAuth2 configuration
 *   code:      authorization code received from callback
 *   response_body:  raw HTTP response body from token endpoint
 *   response_len:   response body length
 *
 * Hatches: 1=null out, 2=null cfg, 3=null code,
 *          4=null response_body, 5=malformed response,
 *          6=error in response, 7=alloc failure */
unsigned long oauth2_token_exchange(oauth2_token *out,
                                                   const oauth2_config *cfg,
                                                   const char *code,
                                                   const u8 *response_body,
                                                   u64 response_len);

/* oauth2_token_refresh — build refresh token request body.
 *   out:       receives allocated request body (caller frees)
 *   out_len:   receives body length
 *   cfg:       OAuth2 configuration
 *   refresh_token: the refresh token
 *
 * Hatches: 1=null out, 2=null out_len, 3=null cfg,
 *          4=null refresh_token, 5=alloc failure */
unsigned long oauth2_token_refresh(char **out, u64 *out_len,
                                                  const oauth2_config *cfg,
                                                  const char *refresh_token);

/* oauth2_token_parse — parse a token endpoint JSON response.
 *   out:           receives parsed token
 *   body:          JSON response body
 *   body_len:      body length
 *   now_unix:      current unix timestamp (for obtained_at)
 *
 * Hatches: 1=null out, 2=null body, 3=malformed JSON,
 *          4=missing access_token, 5=alloc failure */
unsigned long oauth2_token_parse(oauth2_token *out,
                                                const u8 *body, u64 body_len,
                                                u64 now_unix);

/* oauth2_token_is_expired — check if token is expired.
 *   out_expired:   receives 1 if expired, 0 if not
 *   tok:           the token
 *   now_unix:      current unix timestamp
 *
 * Hatches: 1=null out_expired, 2=null tok */
unsigned long oauth2_token_is_expired(int *out_expired,
                                                     const oauth2_token *tok,
                                                     u64 now_unix);

/* oauth2_token_free — free memory owned by a token. */
unsigned long oauth2_token_free(oauth2_token *tok);

/* ================================================================
 *  Token exchange body builder
 *
 *  Build the application/x-www-form-urlencoded body for the
 *  authorization-code token exchange POST to the token endpoint.
 *  Pair with an HTTP POST and oauth2_token_parse on the response.
 * ================================================================ */

/* oauth2_token_exchange_body — build POST body for code-to-token exchange.
 *   out:           receives allocated form body (caller frees)
 *   out_len:       receives body length
 *   cfg:           OAuth2 config (client_id required; client_secret and
 *                  redirect_uri included when present)
 *   code:          authorization code from the callback
 *   code_verifier: PKCE verifier (RFC 7636); pass NULL if not using PKCE
 *
 * Hatches: 1=null out, 2=null out_len, 3=null cfg,
 *          4=null client_id, 5=null code, 6=alloc failure */
unsigned long oauth2_token_exchange_body(char **out,
                                                        u64 *out_len,
                                                        const oauth2_config *cfg,
                                                        const char *code,
                                                        const char *code_verifier);

/* ================================================================
 *  PKCE — Proof Key for Code Exchange (RFC 7636)
 * ================================================================ */

/* oauth2_pkce_verifier_generate — generate a random PKCE code_verifier.
 * Emits 43 base64url characters from 32 random bytes (RFC 7636 §4.1
 * recommends 43..128; 43 is the minimum).
 *   out:     receives the verifier as a null-terminated string
 *   out_len: receives string length (43 in practice)
 *
 * Hatches: 1=null out, 2=null out_len, 3=entropy failure, 4=alloc failure */
unsigned long oauth2_pkce_verifier_generate(char **out,
                                                           u64 *out_len);

/* oauth2_pkce_challenge_s256 — derive the S256 code_challenge from a
 * verifier (RFC 7636 §4.2): base64url(SHA-256(verifier)).
 *   out:     receives the challenge as a null-terminated string
 *   out_len: receives string length (43)
 *
 * Hatches: 1=null out, 2=null out_len, 3=null verifier, 4=alloc failure */
unsigned long oauth2_pkce_challenge_s256(char **out,
                                                        u64 *out_len,
                                                        const char *verifier);

/* oauth2_auth_url_build_pkce — like oauth2_auth_url_build but adds
 * code_challenge + code_challenge_method=S256.
 * Hatches mirror oauth2_auth_url_build (1..7) plus:
 *   8=null code_challenge */
unsigned long oauth2_auth_url_build_pkce(char **out,
                                                        u64 *out_len,
                                                        const oauth2_config *cfg,
                                                        const char *state,
                                                        const char *code_challenge);

/* ================================================================
 *  Client credentials grant (RFC 6749 §4.4)
 * ================================================================ */

/* oauth2_client_credentials_body — build POST body for the
 * client_credentials grant. client_id + client_secret required.
 * Hatches: 1=null out, 2=null out_len, 3=null cfg,
 *          4=null client_id, 5=null client_secret, 6=alloc failure */
unsigned long oauth2_client_credentials_body(char **out,
                                                            u64 *out_len,
                                                            const oauth2_config *cfg);

/* ================================================================
 *  Device authorization grant (RFC 8628)
 * ================================================================ */

typedef struct {
    char *device_code;
    char *user_code;
    char *verification_uri;
    char *verification_uri_complete;  /* NULL if not provided */
    u64   expires_in;                 /* seconds */
    u64   interval;                   /* seconds — poll interval (default 5) */
} oauth2_device_authz;

/* oauth2_device_authz_body — build POST body for the device authorization
 * request. Sent to the provider's device_authorization_endpoint.
 * Hatches: 1=null out, 2=null out_len, 3=null cfg,
 *          4=null client_id, 5=alloc failure */
unsigned long oauth2_device_authz_body(char **out, u64 *out_len,
                                                      const oauth2_config *cfg);

/* oauth2_device_authz_parse — parse the device authorization response.
 *   out:       receives parsed authz (caller frees via oauth2_device_authz_free)
 *   body:      JSON response body
 *   body_len:  body length
 * Hatches: 1=null out, 2=null body, 3=parse failure,
 *          4=missing device_code, 5=alloc failure */
unsigned long oauth2_device_authz_parse(oauth2_device_authz *out,
                                                       const u8 *body,
                                                       u64 body_len);

/* oauth2_device_authz_free — release memory owned by the authz response. */
unsigned long oauth2_device_authz_free(oauth2_device_authz *authz);

/* oauth2_device_token_body — build the POST body used to poll the token
 * endpoint for a device grant (grant_type=urn:ietf:params:oauth:
 * grant-type:device_code).
 * Hatches: 1=null out, 2=null out_len, 3=null cfg,
 *          4=null client_id, 5=null device_code, 6=alloc failure */
unsigned long oauth2_device_token_body(char **out, u64 *out_len,
                                                      const oauth2_config *cfg,
                                                      const char *device_code);

#endif /* APENNINES_T3_OAUTH2_H */
