#include "apennines/jwt.h"
#include "apennines/hash.h"
#include "apennines/ec.h"
#include "apennines/rsa.h"
#include "apennines/ecdsa.h"
#include "apennines/base.h"
#include "apennines/buf.h"
#include <stdlib.h>
#include <string.h>

/* ----------------------------------------------------------------
 *  Internal: header JSON literals
 * ---------------------------------------------------------------- */

static const char HS256_HDR[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
static const char EDDSA_HDR[] = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";
static const char RS256_HDR[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
static const char ES256_HDR[] = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
static const char PS256_HDR[] = "{\"alg\":\"PS256\",\"typ\":\"JWT\"}";

/* ----------------------------------------------------------------
 *  Internal: find a character in a buffer
 * ---------------------------------------------------------------- */

static u64 find_dot(const char *s, u64 start, u64 len) {
    for (u64 i = start; i < len; i++) {
        if (s[i] == '.') return i;
    }
    return len; /* not found */
}

/* ----------------------------------------------------------------
 *  Internal: detect algorithm from decoded header JSON
 * ---------------------------------------------------------------- */

static int detect_alg(const char *hdr, u64 hdr_len) {
    /* simple substring search for the algorithm name */
    for (u64 i = 0; i + 5 <= hdr_len; i++) {
        if (memcmp(hdr + i, "HS256", 5) == 0) return JWT_ALG_HS256;
        if (memcmp(hdr + i, "EdDSA", 5) == 0) return JWT_ALG_EDDSA;
        if (memcmp(hdr + i, "RS256", 5) == 0) return JWT_ALG_RS256;
        if (memcmp(hdr + i, "ES256", 5) == 0) return JWT_ALG_ES256;
        if (memcmp(hdr + i, "PS256", 5) == 0) return JWT_ALG_PS256;
    }
    return -1;
}

/* ----------------------------------------------------------------
 *  Internal: pick header JSON for an algorithm.
 * ---------------------------------------------------------------- */

static const char *header_for_alg(int alg, u64 *out_len) {
    switch (alg) {
    case JWT_ALG_HS256: *out_len = sizeof(HS256_HDR) - 1; return HS256_HDR;
    case JWT_ALG_EDDSA: *out_len = sizeof(EDDSA_HDR) - 1; return EDDSA_HDR;
    case JWT_ALG_RS256: *out_len = sizeof(RS256_HDR) - 1; return RS256_HDR;
    case JWT_ALG_ES256: *out_len = sizeof(ES256_HDR) - 1; return ES256_HDR;
    case JWT_ALG_PS256: *out_len = sizeof(PS256_HDR) - 1; return PS256_HDR;
    default: *out_len = 0; return NULL;
    }
}

/* ----------------------------------------------------------------
 *  jwt_encode
 * ---------------------------------------------------------------- */

unsigned long jwt_encode(jwt_token *out,
                         const char *payload, int alg,
                         const u8 *key, u64 key_len) {
    if (!out) return 1;
    if (!payload) return 2;
    if (alg != JWT_ALG_HS256 && alg != JWT_ALG_EDDSA &&
        alg != JWT_ALG_RS256 && alg != JWT_ALG_ES256 &&
        alg != JWT_ALG_PS256) return 3;
    if (!key) return 4;

    unsigned long rc;
    u64 hdr_json_len;
    const char *hdr_json = header_for_alg(alg, &hdr_json_len);
    if (!hdr_json) return 3;

    u64 payload_len = strlen(payload);

    /* base64url encode header */
    buf hdr_b64 = {0};
    rc = base64url_encode(&hdr_b64, (u8 *)hdr_json, hdr_json_len);
    if (rc) { return 5; }

    /* base64url encode payload */
    buf pay_b64 = {0};
    rc = base64url_encode(&pay_b64, (u8 *)payload, payload_len);
    if (rc) { buf_destroy(&hdr_b64); return 5; }

    /* build signing input: header_b64.payload_b64 */
    u64 input_len = hdr_b64.len + 1 + pay_b64.len;
    u8 *sign_input = (u8 *)malloc((size_t)(input_len));
    if (!sign_input) {
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        return 5;
    }
    memcpy(sign_input, hdr_b64.data, (size_t)hdr_b64.len);
    sign_input[hdr_b64.len] = '.';
    memcpy(sign_input + hdr_b64.len + 1, pay_b64.data, (size_t)pay_b64.len);

    /* sign — allocate signature buffer on the heap since RSA sig size is
     * variable (modulus-dependent). */
    u8 *sig_raw = NULL;
    u64 sig_raw_len = 0;

    if (alg == JWT_ALG_HS256) {
        sig_raw_len = 32;
        sig_raw = (u8 *)malloc((size_t)sig_raw_len);
        if (!sig_raw) {
            free(sign_input);
            buf_destroy(&hdr_b64);
            buf_destroy(&pay_b64);
            return 5;
        }
        rc = hmac_digest(sig_raw, HMAC_HASH_SHA256,
                         key, key_len,
                         sign_input, input_len);
    } else if (alg == JWT_ALG_EDDSA) {
        if (key_len < ED25519_PRIVKEY_LEN) {
            free(sign_input);
            buf_destroy(&hdr_b64);
            buf_destroy(&pay_b64);
            return 6;
        }
        sig_raw_len = ED25519_SIG_LEN;
        sig_raw = (u8 *)malloc((size_t)sig_raw_len);
        if (!sig_raw) {
            free(sign_input);
            buf_destroy(&hdr_b64);
            buf_destroy(&pay_b64);
            return 5;
        }
        ed25519_privkey priv;
        memcpy(priv.data, key, ED25519_PRIVKEY_LEN);
        ed25519_pubkey pub;
        rc = ed25519_pubkey_from_privkey(&pub, &priv);
        if (rc == 0) rc = ed25519_sign(sig_raw, &priv, &pub,
                                        sign_input, input_len);
    } else if (alg == JWT_ALG_RS256 || alg == JWT_ALG_PS256) {
        /* RSA private key in DER (PKCS#1 RSAPrivateKey) */
        rsa_privkey priv;
        memset(&priv, 0, sizeof(priv));
        rc = rsa_privkey_import_der(&priv, key, key_len);
        if (rc) {
            free(sign_input);
            buf_destroy(&hdr_b64);
            buf_destroy(&pay_b64);
            return 6;
        }
        buf sig_buf = {0};
        if (alg == JWT_ALG_RS256) {
            rc = rsa_sign_pkcs1v15(&sig_buf, &priv, sign_input, input_len);
        } else {
            rc = rsa_sign_pss(&sig_buf, &priv, sign_input, input_len);
        }
        rsa_privkey_destroy(&priv);
        if (rc == 0) {
            sig_raw_len = sig_buf.len;
            sig_raw = (u8 *)malloc((size_t)sig_raw_len);
            if (!sig_raw) { buf_destroy(&sig_buf); rc = 1; }
            else memcpy(sig_raw, sig_buf.data, (size_t)sig_raw_len);
            buf_destroy(&sig_buf);
        }
    } else {
        /* ES256: key is 32-byte raw P-256 private scalar.
         * Signature = R(32) || S(32) per RFC 7518 §3.4. */
        if (key_len < ECDSA_P256_PRIVKEY_LEN) {
            free(sign_input);
            buf_destroy(&hdr_b64);
            buf_destroy(&pay_b64);
            return 6;
        }
        sig_raw_len = ECDSA_P256_SIG_LEN;
        sig_raw = (u8 *)malloc((size_t)sig_raw_len);
        if (!sig_raw) {
            free(sign_input);
            buf_destroy(&hdr_b64);
            buf_destroy(&pay_b64);
            return 5;
        }
        ecdsa_privkey priv;
        memcpy(priv.data, key, ECDSA_P256_PRIVKEY_LEN);
        ecdsa_sig sig;
        rc = ecdsa_sign(&sig, &priv, sign_input, input_len);
        if (rc == 0) {
            memcpy(sig_raw, sig.r, 32);
            memcpy(sig_raw + 32, sig.s, 32);
        }
    }

    if (rc || !sig_raw) {
        free(sig_raw);
        free(sign_input);
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        return 6;
    }

    /* base64url encode signature */
    buf sig_b64 = {0};
    rc = base64url_encode(&sig_b64, sig_raw, sig_raw_len);
    if (rc) {
        free(sig_raw);
        free(sign_input);
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        return 5;
    }

    /* assemble final token: sign_input + "." + sig_b64 */
    u64 raw_len = input_len + 1 + sig_b64.len;
    char *raw = (char *)malloc((size_t)(raw_len + 1));
    if (!raw) {
        free(sig_raw);
        free(sign_input);
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        buf_destroy(&sig_b64);
        return 5;
    }
    memcpy(raw, sign_input, (size_t)input_len);
    raw[input_len] = '.';
    memcpy(raw + input_len + 1, sig_b64.data, (size_t)sig_b64.len);
    raw[raw_len] = '\0';

    /* fill output struct */
    memset(out, 0, sizeof(*out));
    out->raw = raw;
    out->raw_len = raw_len;

    /* decoded header (copy) */
    out->header = (char *)malloc((size_t)(hdr_json_len + 1));
    if (!out->header) {
        free(sig_raw);
        free(raw);
        free(sign_input);
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        buf_destroy(&sig_b64);
        return 5;
    }
    memcpy(out->header, hdr_json, (size_t)hdr_json_len);
    out->header[hdr_json_len] = '\0';
    out->header_len = hdr_json_len;

    /* decoded payload (copy) */
    out->payload = (char *)malloc((size_t)(payload_len + 1));
    if (!out->payload) {
        free(sig_raw);
        free(out->header);
        free(raw);
        free(sign_input);
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        buf_destroy(&sig_b64);
        return 5;
    }
    memcpy(out->payload, payload, (size_t)payload_len);
    out->payload[payload_len] = '\0';
    out->payload_len = payload_len;

    /* decoded signature (copy) */
    out->signature = (u8 *)malloc((size_t)sig_raw_len);
    if (!out->signature) {
        free(sig_raw);
        free(out->payload);
        free(out->header);
        free(raw);
        free(sign_input);
        buf_destroy(&hdr_b64);
        buf_destroy(&pay_b64);
        buf_destroy(&sig_b64);
        return 5;
    }
    memcpy(out->signature, sig_raw, (size_t)sig_raw_len);
    out->sig_len = sig_raw_len;
    out->alg = alg;

    free(sig_raw);
    free(sign_input);
    buf_destroy(&hdr_b64);
    buf_destroy(&pay_b64);
    buf_destroy(&sig_b64);
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_decode
 * ---------------------------------------------------------------- */

unsigned long jwt_decode(jwt_token *out,
                         const char *token,
                         const u8 *key, u64 key_len) {
    if (!out) return 1;
    if (!token) return 2;

    u64 token_len = strlen(token);

    /* find the two dots */
    u64 dot1 = find_dot(token, 0, token_len);
    if (dot1 >= token_len) return 3;
    u64 dot2 = find_dot(token, dot1 + 1, token_len);
    if (dot2 >= token_len) return 3;
    /* must not have a third dot */
    if (find_dot(token, dot2 + 1, token_len) < token_len) return 3;

    if (!key) return 4;

    /* decode header */
    buf hdr_dec = {0};
    unsigned long rc = base64url_decode(&hdr_dec, (u8 *)token, dot1);
    if (rc) return 3;

    /* detect algorithm */
    int alg = detect_alg((const char *)hdr_dec.data, hdr_dec.len);
    if (alg < 0) {
        buf_destroy(&hdr_dec);
        return 5;
    }

    /* decode payload */
    buf pay_dec = {0};
    rc = base64url_decode(&pay_dec, (u8 *)(token + dot1 + 1), dot2 - dot1 - 1);
    if (rc) {
        buf_destroy(&hdr_dec);
        return 3;
    }

    /* decode signature */
    buf sig_dec = {0};
    rc = base64url_decode(&sig_dec, (u8 *)(token + dot2 + 1), token_len - dot2 - 1);
    if (rc) {
        buf_destroy(&hdr_dec);
        buf_destroy(&pay_dec);
        return 3;
    }

    /* verify signature over "header_b64.payload_b64" */
    u64 sign_input_len = dot2; /* everything before the second dot */
    const u8 *sign_input = (const u8 *)token;

    if (alg == JWT_ALG_HS256) {
        unsigned long match = 1; /* ct_compare: 0=equal, non-zero=different */
        rc = hmac_verify(&match, sig_dec.data, HMAC_HASH_SHA256,
                         key, key_len,
                         sign_input, sign_input_len);
        if (rc || match != 0) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
    } else if (alg == JWT_ALG_EDDSA) {
        if (key_len < ED25519_PUBKEY_LEN || sig_dec.len < ED25519_SIG_LEN) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
        ed25519_pubkey pub;
        memcpy(pub.data, key, ED25519_PUBKEY_LEN);

        unsigned long valid = 0;
        rc = ed25519_verify(&valid, &pub, sig_dec.data,
                            sign_input, sign_input_len);
        if (rc || !valid) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
    } else if (alg == JWT_ALG_RS256 || alg == JWT_ALG_PS256) {
        /* RSA public key in DER (PKCS#1 RSAPublicKey) */
        rsa_pubkey pub;
        memset(&pub, 0, sizeof(pub));
        rc = rsa_pubkey_import_der(&pub, key, key_len);
        if (rc) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
        unsigned long valid = 0;
        if (alg == JWT_ALG_RS256) {
            rc = rsa_verify_pkcs1v15(&valid, &pub, sig_dec.data, sig_dec.len,
                                      sign_input, sign_input_len);
        } else {
            rc = rsa_verify_pss(&valid, &pub, sig_dec.data, sig_dec.len,
                                 sign_input, sign_input_len);
        }
        rsa_pubkey_destroy(&pub);
        if (rc || !valid) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
    } else {
        /* ES256: key is 65-byte uncompressed P-256 public point.
         * Signature is R(32) || S(32). */
        if (key_len < ECDSA_P256_PUBKEY_LEN ||
            sig_dec.len != ECDSA_P256_SIG_LEN) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
        ecdsa_pubkey pub;
        memcpy(pub.data, key, ECDSA_P256_PUBKEY_LEN);
        ecdsa_sig sig;
        memcpy(sig.r, sig_dec.data, 32);
        memcpy(sig.s, sig_dec.data + 32, 32);

        u64 valid = 0;
        rc = ecdsa_verify(&valid, &pub, sign_input, sign_input_len, &sig);
        if (rc || !valid) {
            buf_destroy(&hdr_dec);
            buf_destroy(&pay_dec);
            buf_destroy(&sig_dec);
            return 6;
        }
    }

    /* build output struct */
    memset(out, 0, sizeof(*out));

    /* raw: copy entire token */
    out->raw = (char *)malloc((size_t)(token_len + 1));
    if (!out->raw) {
        buf_destroy(&hdr_dec);
        buf_destroy(&pay_dec);
        buf_destroy(&sig_dec);
        return 7;
    }
    memcpy(out->raw, token, (size_t)token_len);
    out->raw[token_len] = '\0';
    out->raw_len = token_len;

    /* header: null-terminated copy from decoded buf */
    out->header = (char *)malloc((size_t)(hdr_dec.len + 1));
    if (!out->header) {
        free(out->raw);
        buf_destroy(&hdr_dec);
        buf_destroy(&pay_dec);
        buf_destroy(&sig_dec);
        return 7;
    }
    memcpy(out->header, hdr_dec.data, (size_t)hdr_dec.len);
    out->header[hdr_dec.len] = '\0';
    out->header_len = hdr_dec.len;

    /* payload: null-terminated copy from decoded buf */
    out->payload = (char *)malloc((size_t)(pay_dec.len + 1));
    if (!out->payload) {
        free(out->header);
        free(out->raw);
        buf_destroy(&hdr_dec);
        buf_destroy(&pay_dec);
        buf_destroy(&sig_dec);
        return 7;
    }
    memcpy(out->payload, pay_dec.data, (size_t)pay_dec.len);
    out->payload[pay_dec.len] = '\0';
    out->payload_len = pay_dec.len;

    /* signature: raw bytes copy */
    out->signature = (u8 *)malloc((size_t)sig_dec.len);
    if (!out->signature) {
        free(out->payload);
        free(out->header);
        free(out->raw);
        buf_destroy(&hdr_dec);
        buf_destroy(&pay_dec);
        buf_destroy(&sig_dec);
        return 7;
    }
    memcpy(out->signature, sig_dec.data, (size_t)sig_dec.len);
    out->sig_len = sig_dec.len;
    out->alg = alg;

    buf_destroy(&hdr_dec);
    buf_destroy(&pay_dec);
    buf_destroy(&sig_dec);
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_get_claim — simple JSON string search
 * ---------------------------------------------------------------- */

unsigned long jwt_get_claim(const char **out_val, u64 *out_len,
                            const jwt_token *tok,
                            const char *name) {
    if (!out_val) return 1;
    if (!out_len) return 2;
    if (!tok) return 3;
    if (!name) return 4;

    /*
     * Search for "name":" in the payload.
     * Build the search needle:  "name":"
     * Then extract the value between the quotes after the colon.
     */
    u64 name_len = strlen(name);

    /* needle = "name":" — length is 1 + name_len + 1 + 1 + 1 = name_len + 4 */
    u64 needle_len = name_len + 4;
    char *needle = (char *)malloc((size_t)(needle_len + 1));
    if (!needle) return 5;

    needle[0] = '"';
    memcpy(needle + 1, name, (size_t)name_len);
    needle[1 + name_len] = '"';
    needle[2 + name_len] = ':';
    needle[3 + name_len] = '"';
    needle[needle_len] = '\0';

    /* search in payload */
    const char *p = tok->payload;
    u64 plen = tok->payload_len;
    const char *found = NULL;

    for (u64 i = 0; i + needle_len <= plen; i++) {
        if (memcmp(p + i, needle, (size_t)needle_len) == 0) {
            found = p + i + needle_len;
            break;
        }
    }

    free(needle);

    if (!found) return 5;

    /* find closing quote (handle escaped quotes) */
    const char *end = found;
    u64 remaining = plen - (u64)(found - p);
    for (u64 i = 0; i < remaining; i++) {
        if (found[i] == '"' && (i == 0 || found[i - 1] != '\\')) {
            end = found + i;
            break;
        }
    }

    if (end == found && remaining > 0 && found[0] == '"') {
        /* empty string value */
        *out_val = found;
        *out_len = 0;
        return 0;
    }

    if (end == found) return 5; /* no closing quote found */

    *out_val = found;
    *out_len = (u64)(end - found);
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_get_expiry — extract "exp" claim as u64
 * ---------------------------------------------------------------- */

unsigned long jwt_get_expiry(u64 *out_exp,
                             const jwt_token *tok) {
    if (!out_exp) return 1;
    if (!tok) return 2;

    /* search for "exp": followed by a number */
    const char *needle = "\"exp\":";
    u64 needle_len = 6;
    const char *p = tok->payload;
    u64 plen = tok->payload_len;
    const char *found = NULL;

    for (u64 i = 0; i + needle_len <= plen; i++) {
        if (memcmp(p + i, needle, (size_t)needle_len) == 0) {
            found = p + i + needle_len;
            break;
        }
    }

    if (!found) return 3;

    /* skip whitespace */
    u64 remaining = plen - (u64)(found - p);
    u64 off = 0;
    while (off < remaining && (found[off] == ' ' || found[off] == '\t')) {
        off++;
    }

    if (off >= remaining) return 4;

    /* parse digits */
    u64 val = 0;
    int has_digit = 0;
    while (off < remaining && found[off] >= '0' && found[off] <= '9') {
        val = val * 10 + (u64)(found[off] - '0');
        has_digit = 1;
        off++;
    }

    if (!has_digit) return 4;

    *out_exp = val;
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_is_expired
 * ---------------------------------------------------------------- */

unsigned long jwt_is_expired(int *out_expired,
                             const jwt_token *tok,
                             u64 now_unix) {
    if (!out_expired) return 1;
    if (!tok) return 2;

    u64 exp;
    unsigned long rc = jwt_get_expiry(&exp, tok);
    if (rc) return 3;

    *out_expired = (now_unix >= exp) ? 1 : 0;
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_token_free
 * ---------------------------------------------------------------- */

unsigned long jwt_token_free(jwt_token *tok) {
    if (!tok) return 0;
    free(tok->raw);
    free(tok->header);
    free(tok->payload);
    free(tok->signature);
    memset(tok, 0, sizeof(*tok));
    return 0;
}
