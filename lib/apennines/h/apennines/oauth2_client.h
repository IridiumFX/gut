#ifndef APENNINES_T4_OAUTH2_CLIENT_H
#define APENNINES_T4_OAUTH2_CLIENT_H

#include "apennines/types.h"
#include "apennines/oauth2.h"
#include "apennines/https_client.h"

/* ================================================================
 *  OAuth2 HTTP client
 *
 *  End-to-end wrappers over t3/crypto/oauth2 body builders and
 *  t4/net/https_client. Each call: build form body → POST to the
 *  token (or device) endpoint → parse JSON response.
 *
 *  The protocol-level helpers in t3 are still available when callers
 *  need custom transport; these are the "just do it" shortcuts.
 * ================================================================ */

/* oauth2_client_token_exchange — authorization code grant.
 * POSTs to cfg->token_endpoint with grant_type=authorization_code.
 * code_verifier may be NULL (non-PKCE flow) or the PKCE verifier.
 *
 * Hatches: 1=null out, 2=null c, 3=null cfg,
 *          4=null token_endpoint, 5=null code,
 *          6=build-body failure, 7=HTTP request failure,
 *          8=non-2xx response, 9=parse failure, 10=alloc failure */
unsigned long oauth2_client_token_exchange(
    oauth2_token *out,
    https_client *c,
    const oauth2_config *cfg,
    const char *code,
    const char *code_verifier);

/* oauth2_client_token_refresh — refresh an access token.
 * POSTs to cfg->token_endpoint with grant_type=refresh_token.
 *
 * Hatches: 1=null out, 2=null c, 3=null cfg,
 *          4=null token_endpoint, 5=null refresh_token,
 *          6=build-body failure, 7=HTTP request failure,
 *          8=non-2xx response, 9=parse failure */
unsigned long oauth2_client_token_refresh(
    oauth2_token *out,
    https_client *c,
    const oauth2_config *cfg,
    const char *refresh_token);

/* oauth2_client_client_credentials — client credentials grant
 * (RFC 6749 §4.4). POSTs to cfg->token_endpoint.
 *
 * Hatches: 1=null out, 2=null c, 3=null cfg,
 *          4=null token_endpoint, 5=null client_id or client_secret,
 *          6=build-body failure, 7=HTTP request failure,
 *          8=non-2xx response, 9=parse failure */
unsigned long oauth2_client_client_credentials(
    oauth2_token *out,
    https_client *c,
    const oauth2_config *cfg);

/* oauth2_client_device_authorize — RFC 8628 device authorization.
 * POSTs to device_auth_endpoint with client_id + scope.
 * Returns the device_code / user_code / verification URI for the
 * user to complete on a second device.
 *
 * Hatches: 1=null out, 2=null c, 3=null device_auth_endpoint,
 *          4=null cfg, 5=null client_id, 6=build-body failure,
 *          7=HTTP request failure, 8=non-2xx response,
 *          9=parse failure */
unsigned long oauth2_client_device_authorize(
    oauth2_device_authz *out,
    https_client *c,
    const char *device_auth_endpoint,
    const oauth2_config *cfg);

/* oauth2_client_device_poll — single poll of the token endpoint for
 * the device flow. Caller keeps polling until:
 *   returns 0           → *out holds the token
 *   returns 11 (pending) → authorization still in progress, sleep and retry
 *   returns 12 (slow_down) → backoff further, then retry
 *   returns 13 (access_denied) → user rejected; stop
 *   returns 14 (expired_token) → code expired; stop
 *   other hatches       → transport / other error
 *
 * Hatches: 1=null out, 2=null c, 3=null cfg, 4=null token_endpoint,
 *          5=null device_code, 6=build-body failure,
 *          7=HTTP request failure, 8=non-2xx non-pending response,
 *          9=parse failure, 10=alloc failure,
 *          11=authorization_pending, 12=slow_down,
 *          13=access_denied, 14=expired_token */
unsigned long oauth2_client_device_poll(
    oauth2_token *out,
    https_client *c,
    const oauth2_config *cfg,
    const char *device_code);

#endif /* APENNINES_T4_OAUTH2_CLIENT_H */
