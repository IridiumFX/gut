#ifndef GUT_LOGIN_H
#define GUT_LOGIN_H

#include "gut/types.h"

/*
 * gut login — OIDC device authorization flow.
 *
 * Credentials are stored at ~/.gut/credentials in INI format:
 *   [credential "<issuer>"]
 *       access_token = ...
 *       refresh_token = ...
 *       token_type = Bearer
 *       expires_at = <unix-ts>
 *       client_id = ...
 *
 * Other commands (push, fetch, leech with token) can read this file
 * to get a valid token for the configured issuer.
 */

/* Run the device flow against an OIDC issuer and store the resulting
 * token in ~/.gut/credentials.
 * issuer:     OIDC issuer URL (e.g., "https://accounts.google.com")
 * client_id:  OAuth client ID registered with the IdP
 * scope:      requested scopes (e.g., "openid email"); may be NULL */
unsigned long login_device_flow(const char *issuer,
                                const char *client_id,
                                const char *scope);

/* Read the access token for an issuer from ~/.gut/credentials.
 * Returns 0 if found and not expired; sets *out (caller frees).
 * Returns non-zero if missing/expired (call login again). */
unsigned long login_get_token(char **out, const char *issuer);

#endif /* GUT_LOGIN_H */
