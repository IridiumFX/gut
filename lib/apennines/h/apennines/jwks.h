#ifndef APENNINES_T3_JWKS_H
#define APENNINES_T3_JWKS_H

#include "apennines/types.h"
#include "apennines/buf.h"
#include "apennines/jwt.h"

/* ================================================================
 *  JWK / JWKS — RFC 7517 (JWK), RFC 7518 (JWA)
 *
 *  Parses a JWKS JSON document (as served by an IdP's `jwks_uri`),
 *  exposes per-key accessors, and verifies JWTs against the set.
 *
 *  Supported key types:
 *    kty=RSA  — used for RS256 / PS256
 *    kty=EC   — P-256 curve only, used for ES256
 *    kty=OKP  — Ed25519 curve only, used for EdDSA
 *
 *  Keys of other types are parsed and retained but cannot be used to
 *  verify (their kty accessor returns the original string).
 * ================================================================ */

typedef struct jwk jwk;

typedef struct {
    jwk **keys;
    u64   count;
} jwks;

/* ----------------------------------------------------------------
 *  Parsing / lifecycle
 * ---------------------------------------------------------------- */

/* Parse a JWKS JSON document. Expects {"keys": [ ... ]}.
 *   out:       receives parsed set (caller destroys)
 *   json:      raw JSON bytes
 *   json_len:  byte length
 * Hatches: 1=null out, 2=null json, 3=parse fail, 4=missing keys array,
 *          5=alloc failure */
unsigned long jwks_parse(jwks *out,
                                        const u8 *json, u64 json_len);

/* Destroy a parsed JWKS, freeing all keys.
 * Hatches: 1=null set */
unsigned long jwks_destroy(jwks *set);

/* Look up a JWK by kid. *out is a borrowed pointer into the set
 * (do NOT free). Returns hatch 4 if not found.
 * Hatches: 1=null out, 2=null set, 3=null kid, 4=not found */
unsigned long jwks_lookup(const jwk **out,
                                         const jwks *set, const char *kid);

/* ----------------------------------------------------------------
 *  JWK accessors — returned pointers are owned by the JWK and must
 *  not be freed by the caller. Strings are null-terminated; may be
 *  NULL if the field was not present in the JWK.
 * ---------------------------------------------------------------- */

/* Hatches: 1=null out, 2=null key */
unsigned long jwk_kid(const char **out, const jwk *key);
unsigned long jwk_alg(const char **out, const jwk *key);
unsigned long jwk_kty(const char **out, const jwk *key);
unsigned long jwk_use(const char **out, const jwk *key);

/* ----------------------------------------------------------------
 *  JWK → key-material conversion
 *
 *  These produce key bytes in the exact format that jwt_decode
 *  expects for the corresponding algorithm. jwk_verify_jwt and
 *  jwks_verify_jwt use them internally; they are also exported so
 *  callers can drive jwt_decode themselves.
 * ---------------------------------------------------------------- */

/* For an RSA JWK: produce DER PKCS#1 RSAPublicKey bytes.
 * Hatches: 1=null out, 2=null key, 3=wrong kty, 4=missing n/e, 5=alloc fail */
unsigned long jwk_to_rsa_pubkey_der(buf *out, const jwk *key);

/* For an EC JWK with crv=P-256: produce 65-byte uncompressed point
 * (0x04 || X(32) || Y(32)).
 * Hatches: 1=null out, 2=null key, 3=wrong kty or crv, 4=missing x/y */
unsigned long jwk_to_ec_pubkey_bytes(u8 out[65],
                                                    const jwk *key);

/* For an OKP JWK with crv=Ed25519: produce 32-byte Ed25519 public key.
 * Hatches: 1=null out, 2=null key, 3=wrong kty or crv, 4=missing x */
unsigned long jwk_to_ed25519_pubkey_bytes(u8 out[32],
                                                         const jwk *key);

/* ----------------------------------------------------------------
 *  JWT verification against a JWK / JWKS
 * ---------------------------------------------------------------- */

/* Verify a JWT using a single JWK. The algorithm is detected from the
 * token header and checked for kty compatibility before verification.
 *   out:       receives the parsed, verified jwt_token (caller frees)
 *   key:       the JWK to verify against
 *   token_str: null-terminated JWT string
 * Hatches: 1=null out, 2=null key, 3=null token_str, 4=malformed token,
 *          5=alg/kty mismatch, 6=signature invalid, 7=alloc failure */
unsigned long jwk_verify_jwt(jwt_token *out,
                                            const jwk *key,
                                            const char *token_str);

/* Verify a JWT against a JWKS. Reads the `kid` from the token header
 * and selects the matching JWK; if the token has no kid and the set
 * contains exactly one key, that key is used.
 *   out:       receives the parsed, verified jwt_token (caller frees)
 *   set:       the JWKS to verify against
 *   token_str: null-terminated JWT string
 * Hatches: 1=null out, 2=null set, 3=null token_str, 4=malformed token,
 *          5=no matching kid, 6=signature invalid, 7=alloc failure */
unsigned long jwks_verify_jwt(jwt_token *out,
                                             const jwks *set,
                                             const char *token_str);

/* ----------------------------------------------------------------
 *  JWT header peek — read the header segment without verification.
 *  Useful for pulling `kid` before picking a verification key.
 * ---------------------------------------------------------------- */

/* Decode the header segment of a JWT into a freshly allocated JSON
 * string. The caller owns and must free *out_header.
 * Hatches: 1=null out, 2=null out_len, 3=null token_str,
 *          4=malformed token, 5=alloc failure */
unsigned long jwt_peek_header(char **out_header,
                                             u64 *out_len,
                                             const char *token_str);

/* Extract the `kid` claim from a JWT header JSON. Caller frees *out_kid.
 * Hatches: 1=null out, 2=null header, 3=kid not found, 4=alloc failure */
unsigned long jwt_header_kid(char **out_kid,
                                            const char *header,
                                            u64 header_len);

#endif /* APENNINES_T3_JWKS_H */
