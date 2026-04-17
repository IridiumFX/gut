#ifndef APENNINES_T3_JWT_H
#define APENNINES_T3_JWT_H

#include "apennines/types.h"

/* ================================================================
 *  JWT (JSON Web Tokens) — RFC 7519
 *
 *  Tokens are three base64url-encoded segments: header.payload.signature
 *
 *  Supported algorithms and key formats:
 *    HS256  — HMAC-SHA-256.             Key = raw HMAC secret bytes.
 *    EdDSA  — Ed25519.                  Sign: 64-byte private key.
 *                                        Verify: 32-byte public key.
 *    RS256  — RSASSA-PKCS1-v1_5 SHA-256. Sign: DER PKCS#1 RSAPrivateKey.
 *                                        Verify: DER PKCS#1 RSAPublicKey.
 *    PS256  — RSASSA-PSS SHA-256.        Same DER key formats as RS256.
 *    ES256  — ECDSA-P256 SHA-256.        Sign: 32-byte raw privkey scalar.
 *                                        Verify: 65-byte uncompressed point
 *                                        (0x04 || X(32) || Y(32)).
 *
 *  For the asymmetric algorithms, caller-provided DER bytes are imported
 *  via the apennines t2/crypto/rsa module internally.
 * ================================================================ */

#define JWT_ALG_HS256   0   /* HMAC-SHA-256 */
#define JWT_ALG_EDDSA   1   /* Ed25519 */
#define JWT_ALG_RS256   2   /* RSASSA-PKCS1-v1_5 SHA-256 */
#define JWT_ALG_ES256   3   /* ECDSA P-256 SHA-256 */
#define JWT_ALG_PS256   4   /* RSASSA-PSS SHA-256 */

typedef struct {
    char *raw;           /* full encoded token (header.payload.signature) */
    u64   raw_len;
    char *header;        /* decoded header JSON */
    u64   header_len;
    char *payload;       /* decoded payload JSON */
    u64   payload_len;
    u8   *signature;     /* decoded signature bytes */
    u64   sig_len;
    int   alg;           /* JWT_ALG_* */
} jwt_token;

/* ----------------------------------------------------------------
 *  Encode / Decode
 * ---------------------------------------------------------------- */

/* jwt_encode — build and sign a JWT.
 *   out:         receives the encoded token string (caller frees out->raw)
 *   payload:     JSON payload (null-terminated)
 *   alg:         JWT_ALG_HS256 or JWT_ALG_EDDSA
 *   key:         signing key (HMAC secret or Ed25519 64-byte private key)
 *   key_len:     key length in bytes
 *
 * Hatches: 1=null out, 2=null payload, 3=unsupported alg,
 *          4=null key, 5=alloc failure, 6=sign failure */
unsigned long jwt_encode(jwt_token *out,
                                        const char *payload, int alg,
                                        const u8 *key, u64 key_len);

/* jwt_decode — decode and verify a JWT.
 *   out:         receives parsed token (caller frees fields)
 *   token:       encoded JWT string (null-terminated)
 *   key:         verification key (HMAC secret or Ed25519 32-byte public key)
 *   key_len:     key length in bytes
 *
 * Hatches: 1=null out, 2=null token, 3=malformed token,
 *          4=null key, 5=unsupported alg, 6=signature invalid,
 *          7=alloc failure */
unsigned long jwt_decode(jwt_token *out,
                                        const char *token,
                                        const u8 *key, u64 key_len);

/* ----------------------------------------------------------------
 *  Claim extraction
 * ---------------------------------------------------------------- */

/* jwt_get_claim — extract a string claim by name from decoded payload.
 *   out_val:     receives pointer into payload (NOT a copy, do not free)
 *   out_len:     receives value length
 *   tok:         decoded token
 *   name:        claim name (null-terminated)
 *
 * Hatches: 1=null out_val, 2=null out_len, 3=null tok,
 *          4=null name, 5=claim not found */
unsigned long jwt_get_claim(const char **out_val, u64 *out_len,
                                           const jwt_token *tok,
                                           const char *name);

/* jwt_get_expiry — extract "exp" claim as unix timestamp.
 *   out_exp:     receives expiration time
 *   tok:         decoded token
 *
 * Hatches: 1=null out_exp, 2=null tok, 3=no exp claim, 4=invalid exp */
unsigned long jwt_get_expiry(u64 *out_exp,
                                            const jwt_token *tok);

/* jwt_is_expired — check if token is expired.
 *   out_expired: receives 1 if expired, 0 if not
 *   tok:         decoded token
 *   now_unix:    current unix timestamp
 *
 * Hatches: 1=null out_expired, 2=null tok, 3=no exp claim */
unsigned long jwt_is_expired(int *out_expired,
                                            const jwt_token *tok,
                                            u64 now_unix);

/* jwt_token_free — free memory owned by a jwt_token. */
unsigned long jwt_token_free(jwt_token *tok);

#endif /* APENNINES_T3_JWT_H */
