#include "apennines/jwks.h"
#include "apennines/json.h"
#include "apennines/base.h"
#include "apennines/rsa.h"
#include "apennines/bigint.h"
#include <stdlib.h>
#include <string.h>

/* ================================================================
 *  Internal JWK representation
 *
 *  Raw n/e/x/y are stored as decoded big-endian byte buffers so that
 *  jwk_to_rsa_pubkey_der / jwk_to_ec_pubkey_bytes can produce their
 *  outputs without re-decoding base64url on every call.
 * ================================================================ */

struct jwk {
    char *kid;
    char *alg;
    char *kty;
    char *use;
    char *crv;   /* EC: "P-256"; OKP: "Ed25519" */

    /* RSA */
    u8 *n;  u64 n_len;
    u8 *e;  u64 e_len;

    /* EC (P-256) */
    u8 x[32]; int has_x;
    u8 y[32]; int has_y;

    /* OKP (Ed25519) */
    u8 okp_x[32]; int has_okp_x;
};

/* ----------------------------------------------------------------
 *  Internal: free all fields of a JWK (not the jwk struct itself).
 * ---------------------------------------------------------------- */

static void jwk_fields_free(jwk *k) {
    free(k->kid);
    free(k->alg);
    free(k->kty);
    free(k->use);
    free(k->crv);
    free(k->n);
    free(k->e);
    memset(k, 0, sizeof(*k));
}

/* ----------------------------------------------------------------
 *  Internal: find a string field in a JSON object and copy it as a
 *  null-terminated string (NULL if absent or non-string).
 * ---------------------------------------------------------------- */

static char *json_object_string_copy(json_node *obj, const char *key) {
    json_node *n = NULL;
    if (json_get(&n, obj, key)) return NULL;
    if (!n || n->type != JSON_STRING) return NULL;

    u8 *str_data = NULL;
    u64 str_len = 0;
    if (json_get_str(&str_data, &str_len, n)) return NULL;

    char *out = (char *)malloc((size_t)str_len + 1);
    if (!out) return NULL;
    memcpy(out, str_data, (size_t)str_len);
    out[str_len] = '\0';
    return out;
}

/* ----------------------------------------------------------------
 *  Internal: fetch a base64url string field and decode it. Returns
 *  a malloc'd byte buffer and its length; NULL on missing/decode fail.
 * ---------------------------------------------------------------- */

static u8 *json_object_b64url_decode(json_node *obj, const char *key,
                                      u64 *out_len) {
    *out_len = 0;
    json_node *n = NULL;
    if (json_get(&n, obj, key)) return NULL;
    if (!n || n->type != JSON_STRING) return NULL;

    u8 *str_data = NULL;
    u64 str_len = 0;
    if (json_get_str(&str_data, &str_len, n)) return NULL;

    buf decoded = {0};
    unsigned long rc = base64url_decode(&decoded, str_data, str_len);
    if (rc) return NULL;

    /* Transfer ownership of decoded.data to caller. */
    u8 *out = decoded.data;
    *out_len = decoded.len;
    /* Don't buf_destroy — we're keeping the data. */
    return out;
}

/* ----------------------------------------------------------------
 *  Internal: parse a single JWK object from JSON into *k.
 * ---------------------------------------------------------------- */

static unsigned long parse_one_jwk(jwk *k, json_node *obj) {
    memset(k, 0, sizeof(*k));

    k->kty = json_object_string_copy(obj, "kty");
    k->kid = json_object_string_copy(obj, "kid");
    k->alg = json_object_string_copy(obj, "alg");
    k->use = json_object_string_copy(obj, "use");
    k->crv = json_object_string_copy(obj, "crv");

    if (!k->kty) return 1;

    if (strcmp(k->kty, "RSA") == 0) {
        k->n = json_object_b64url_decode(obj, "n", &k->n_len);
        k->e = json_object_b64url_decode(obj, "e", &k->e_len);
    } else if (strcmp(k->kty, "EC") == 0) {
        u64 xlen = 0, ylen = 0;
        u8 *xb = json_object_b64url_decode(obj, "x", &xlen);
        u8 *yb = json_object_b64url_decode(obj, "y", &ylen);
        if (xb && xlen == 32) { memcpy(k->x, xb, 32); k->has_x = 1; }
        if (yb && ylen == 32) { memcpy(k->y, yb, 32); k->has_y = 1; }
        free(xb);
        free(yb);
    } else if (strcmp(k->kty, "OKP") == 0) {
        u64 xlen = 0;
        u8 *xb = json_object_b64url_decode(obj, "x", &xlen);
        if (xb && xlen == 32) { memcpy(k->okp_x, xb, 32); k->has_okp_x = 1; }
        free(xb);
    }

    return 0;
}

/* ----------------------------------------------------------------
 *  jwks_parse
 * ---------------------------------------------------------------- */

unsigned long jwks_parse(jwks *out, const u8 *json, u64 json_len) {
    if (!out) return 1;
    if (!json) return 2;

    memset(out, 0, sizeof(*out));

    json_node *root = NULL;
    unsigned long rc = json_parse(&root, json, json_len);
    if (rc || !root) return 3;

    json_node *keys_node = NULL;
    if (json_get(&keys_node, root, "keys") || !keys_node ||
        keys_node->type != JSON_ARRAY) {
        json_node_destroy(root);
        return 4;
    }

    json_node **arr = NULL;
    u64 count = 0;
    if (json_get_array(&arr, &count, keys_node)) {
        json_node_destroy(root);
        return 4;
    }

    if (count == 0) {
        out->keys = NULL;
        out->count = 0;
        json_node_destroy(root);
        return 0;
    }

    jwk **keys = (jwk **)calloc((size_t)count, sizeof(jwk *));
    if (!keys) { json_node_destroy(root); return 5; }

    u64 good = 0;
    for (u64 i = 0; i < count; i++) {
        if (!arr[i] || arr[i]->type != JSON_OBJECT) continue;
        jwk *k = (jwk *)calloc(1, sizeof(jwk));
        if (!k) continue;
        if (parse_one_jwk(k, arr[i])) {
            jwk_fields_free(k);
            free(k);
            continue;
        }
        keys[good++] = k;
    }

    json_node_destroy(root);

    out->keys = keys;
    out->count = good;
    return 0;
}

/* ----------------------------------------------------------------
 *  jwks_destroy
 * ---------------------------------------------------------------- */

unsigned long jwks_destroy(jwks *set) {
    if (!set) return 1;
    for (u64 i = 0; i < set->count; i++) {
        if (set->keys[i]) {
            jwk_fields_free(set->keys[i]);
            free(set->keys[i]);
        }
    }
    free(set->keys);
    set->keys = NULL;
    set->count = 0;
    return 0;
}

/* ----------------------------------------------------------------
 *  jwks_lookup
 * ---------------------------------------------------------------- */

unsigned long jwks_lookup(const jwk **out, const jwks *set,
                           const char *kid) {
    if (!out) return 1;
    if (!set) return 2;
    if (!kid) return 3;

    for (u64 i = 0; i < set->count; i++) {
        jwk *k = set->keys[i];
        if (k && k->kid && strcmp(k->kid, kid) == 0) {
            *out = k;
            return 0;
        }
    }
    return 4;
}

/* ----------------------------------------------------------------
 *  Accessors
 * ---------------------------------------------------------------- */

unsigned long jwk_kid(const char **out, const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    *out = key->kid;
    return 0;
}

unsigned long jwk_alg(const char **out, const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    *out = key->alg;
    return 0;
}

unsigned long jwk_kty(const char **out, const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    *out = key->kty;
    return 0;
}

unsigned long jwk_use(const char **out, const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    *out = key->use;
    return 0;
}

/* ----------------------------------------------------------------
 *  jwk_to_rsa_pubkey_der
 *
 *  Build an rsa_pubkey from raw n/e bytes and export to DER using
 *  the existing apennines t2/crypto/rsa machinery.
 * ---------------------------------------------------------------- */

unsigned long jwk_to_rsa_pubkey_der(buf *out, const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    if (!key->kty || strcmp(key->kty, "RSA") != 0) return 3;
    if (!key->n || !key->e || key->n_len == 0 || key->e_len == 0) return 4;

    rsa_pubkey pub;
    memset(&pub, 0, sizeof(pub));
    unsigned long rc = bigint_from_bytes(&pub.n, key->n, key->n_len);
    if (rc) return 5;
    rc = bigint_from_bytes(&pub.e, key->e, key->e_len);
    if (rc) { rsa_pubkey_destroy(&pub); return 5; }

    rc = rsa_pubkey_export_der(out, &pub);
    rsa_pubkey_destroy(&pub);
    if (rc) return 5;
    return 0;
}

/* ----------------------------------------------------------------
 *  jwk_to_ec_pubkey_bytes
 * ---------------------------------------------------------------- */

unsigned long jwk_to_ec_pubkey_bytes(u8 out[65], const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    if (!key->kty || strcmp(key->kty, "EC") != 0) return 3;
    if (!key->crv || strcmp(key->crv, "P-256") != 0) return 3;
    if (!key->has_x || !key->has_y) return 4;

    out[0] = 0x04;
    memcpy(out + 1,  key->x, 32);
    memcpy(out + 33, key->y, 32);
    return 0;
}

/* ----------------------------------------------------------------
 *  jwk_to_ed25519_pubkey_bytes
 * ---------------------------------------------------------------- */

unsigned long jwk_to_ed25519_pubkey_bytes(u8 out[32], const jwk *key) {
    if (!out) return 1;
    if (!key) return 2;
    if (!key->kty || strcmp(key->kty, "OKP") != 0) return 3;
    if (!key->crv || strcmp(key->crv, "Ed25519") != 0) return 3;
    if (!key->has_okp_x) return 4;

    memcpy(out, key->okp_x, 32);
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_peek_header — decode the first segment of a JWT without
 *  verifying the signature. Used to pull `kid`.
 * ---------------------------------------------------------------- */

unsigned long jwt_peek_header(char **out_header, u64 *out_len,
                               const char *token_str) {
    if (!out_header) return 1;
    if (!out_len) return 2;
    if (!token_str) return 3;

    /* Find first dot. */
    u64 i = 0;
    while (token_str[i] && token_str[i] != '.') i++;
    if (!token_str[i]) return 4;

    buf decoded = {0};
    unsigned long rc = base64url_decode(&decoded, (u8 *)token_str, i);
    if (rc) return 4;

    char *hdr = (char *)malloc((size_t)decoded.len + 1);
    if (!hdr) { buf_destroy(&decoded); return 5; }
    memcpy(hdr, decoded.data, (size_t)decoded.len);
    hdr[decoded.len] = '\0';

    *out_header = hdr;
    *out_len = decoded.len;
    buf_destroy(&decoded);
    return 0;
}

/* ----------------------------------------------------------------
 *  jwt_header_kid
 * ---------------------------------------------------------------- */

unsigned long jwt_header_kid(char **out_kid, const char *header,
                              u64 header_len) {
    if (!out_kid) return 1;
    if (!header) return 2;

    json_node *root = NULL;
    unsigned long rc = json_parse(&root, (u8 *)header, header_len);
    if (rc || !root) return 3;

    char *kid = json_object_string_copy(root, "kid");
    json_node_destroy(root);
    if (!kid) return 3;

    *out_kid = kid;
    return 0;
}

/* ----------------------------------------------------------------
 *  Internal: given a JWK, pick a JWT alg compatible with it and
 *  verify the token. Returns 0 on success, non-zero hatch on fail.
 *
 *  detected_alg is read from the token header and must align with
 *  the JWK's kty.
 * ---------------------------------------------------------------- */

static unsigned long verify_with_jwk(jwt_token *out, const jwk *key,
                                      const char *token_str,
                                      int detected_alg) {
    if (strcmp(key->kty, "RSA") == 0) {
        if (detected_alg != JWT_ALG_RS256 && detected_alg != JWT_ALG_PS256)
            return 5;
        buf der = {0};
        unsigned long rc = jwk_to_rsa_pubkey_der(&der, key);
        if (rc) return 5;
        rc = jwt_decode(out, token_str, der.data, der.len);
        buf_destroy(&der);
        return (rc == 6) ? 6 : (rc ? 7 : 0);
    }
    if (strcmp(key->kty, "EC") == 0) {
        if (detected_alg != JWT_ALG_ES256) return 5;
        u8 pub[65];
        unsigned long rc = jwk_to_ec_pubkey_bytes(pub, key);
        if (rc) return 5;
        rc = jwt_decode(out, token_str, pub, 65);
        return (rc == 6) ? 6 : (rc ? 7 : 0);
    }
    if (strcmp(key->kty, "OKP") == 0) {
        if (detected_alg != JWT_ALG_EDDSA) return 5;
        u8 pub[32];
        unsigned long rc = jwk_to_ed25519_pubkey_bytes(pub, key);
        if (rc) return 5;
        rc = jwt_decode(out, token_str, pub, 32);
        return (rc == 6) ? 6 : (rc ? 7 : 0);
    }
    return 5;
}

/* ----------------------------------------------------------------
 *  Internal: detect the alg of a JWT from its encoded header segment.
 *  Returns the JWT_ALG_* constant, or -1 on failure.
 * ---------------------------------------------------------------- */

static int token_detect_alg(const char *token_str) {
    char *hdr = NULL;
    u64 hdr_len = 0;
    if (jwt_peek_header(&hdr, &hdr_len, token_str)) return -1;

    int alg = -1;
    for (u64 i = 0; i + 5 <= hdr_len; i++) {
        if (memcmp(hdr + i, "HS256", 5) == 0) { alg = JWT_ALG_HS256; break; }
        if (memcmp(hdr + i, "EdDSA", 5) == 0) { alg = JWT_ALG_EDDSA; break; }
        if (memcmp(hdr + i, "RS256", 5) == 0) { alg = JWT_ALG_RS256; break; }
        if (memcmp(hdr + i, "ES256", 5) == 0) { alg = JWT_ALG_ES256; break; }
        if (memcmp(hdr + i, "PS256", 5) == 0) { alg = JWT_ALG_PS256; break; }
    }
    free(hdr);
    return alg;
}

/* ----------------------------------------------------------------
 *  jwk_verify_jwt
 * ---------------------------------------------------------------- */

unsigned long jwk_verify_jwt(jwt_token *out, const jwk *key,
                              const char *token_str) {
    if (!out) return 1;
    if (!key) return 2;
    if (!token_str) return 3;

    int alg = token_detect_alg(token_str);
    if (alg < 0) return 4;
    if (!key->kty) return 5;

    return verify_with_jwk(out, key, token_str, alg);
}

/* ----------------------------------------------------------------
 *  jwks_verify_jwt
 * ---------------------------------------------------------------- */

unsigned long jwks_verify_jwt(jwt_token *out, const jwks *set,
                               const char *token_str) {
    if (!out) return 1;
    if (!set) return 2;
    if (!token_str) return 3;

    int alg = token_detect_alg(token_str);
    if (alg < 0) return 4;

    /* Pull kid from the header (if present). */
    char *hdr = NULL;
    u64 hdr_len = 0;
    unsigned long rc = jwt_peek_header(&hdr, &hdr_len, token_str);
    if (rc) return 4;

    char *kid = NULL;
    unsigned long kid_rc = jwt_header_kid(&kid, hdr, hdr_len);
    free(hdr);

    const jwk *match = NULL;
    if (kid_rc == 0 && kid) {
        for (u64 i = 0; i < set->count; i++) {
            jwk *k = set->keys[i];
            if (k && k->kid && strcmp(k->kid, kid) == 0) {
                match = k;
                break;
            }
        }
        free(kid);
    } else {
        /* No kid in header; fall back to single-key sets. */
        if (set->count == 1) match = set->keys[0];
    }

    if (!match) return 5;
    unsigned long vrc = verify_with_jwk(out, match, token_str, alg);
    if (vrc == 5) return 5;   /* alg/kty mismatch */
    if (vrc == 6) return 6;   /* signature invalid */
    if (vrc == 7) return 7;   /* alloc failure */
    return vrc;
}
