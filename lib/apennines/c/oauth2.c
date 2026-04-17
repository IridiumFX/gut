#include "apennines/oauth2.h"
#include "apennines/hash.h"
#include "apennines/base.h"
#include "apennines/buf.h"
#include "apennines/entropy.h"
#include <stdlib.h>
#include <string.h>

/* ----------------------------------------------------------------
 *  Internal: RFC 3986 unreserved characters
 * ---------------------------------------------------------------- */

static int is_unreserved(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '-' || c == '_' || c == '.' || c == '~') return 1;
    return 0;
}

/* ----------------------------------------------------------------
 *  Internal: percent-encode a string (RFC 3986)
 *  Returns malloc'd string, NULL on failure.
 * ---------------------------------------------------------------- */

static char *percent_encode(const char *s) {
    if (!s) return NULL;

    u64 len = 0;
    for (const char *p = s; *p; p++) {
        len += is_unreserved((unsigned char)*p) ? 1 : 3;
    }

    char *out = (char *)malloc((size_t)(len + 1));
    if (!out) return NULL;

    static const char hex[] = "0123456789ABCDEF";
    char *d = out;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (is_unreserved(c)) {
            *d++ = (char)c;
        } else {
            *d++ = '%';
            *d++ = hex[c >> 4];
            *d++ = hex[c & 0x0F];
        }
    }
    *d = '\0';
    return out;
}

/* ----------------------------------------------------------------
 *  Internal: find a JSON string value by key
 *  Searches for "key":"value" and returns a malloc'd copy of value.
 *  Returns NULL if not found or on alloc failure.
 * ---------------------------------------------------------------- */

static char *find_json_string(const char *body, u64 body_len,
                              const char *key) {
    if (!body || !key) return NULL;

    u64 key_len = strlen(key);
    /* search pattern: "key":" */
    for (u64 i = 0; i + key_len + 4 < body_len; i++) {
        if (body[i] != '"') continue;
        if (memcmp(body + i + 1, key, (size_t)key_len) != 0) continue;
        if (body[i + 1 + key_len] != '"') continue;

        /* skip past "key" and find the colon */
        u64 j = i + 1 + key_len + 1;
        /* skip whitespace */
        while (j < body_len && (body[j] == ' ' || body[j] == '\t' ||
               body[j] == '\n' || body[j] == '\r')) j++;
        if (j >= body_len || body[j] != ':') continue;
        j++;
        /* skip whitespace */
        while (j < body_len && (body[j] == ' ' || body[j] == '\t' ||
               body[j] == '\n' || body[j] == '\r')) j++;
        if (j >= body_len || body[j] != '"') continue;
        j++; /* skip opening quote */

        /* find closing quote */
        u64 start = j;
        while (j < body_len && body[j] != '"') {
            if (body[j] == '\\' && j + 1 < body_len) j++; /* skip escaped */
            j++;
        }
        if (j >= body_len) return NULL;

        u64 val_len = j - start;
        char *val = (char *)malloc((size_t)(val_len + 1));
        if (!val) return NULL;
        memcpy(val, body + start, (size_t)val_len);
        val[val_len] = '\0';
        return val;
    }
    return NULL;
}

/* ----------------------------------------------------------------
 *  Internal: find a JSON number value by key
 *  Searches for "key":NNN and returns the integer value.
 *  Sets *found to 1 if found, 0 otherwise.
 * ---------------------------------------------------------------- */

static u64 find_json_number(const char *body, u64 body_len,
                            const char *key, int *found) {
    *found = 0;
    if (!body || !key) return 0;

    u64 key_len = strlen(key);

    for (u64 i = 0; i + key_len + 3 < body_len; i++) {
        if (body[i] != '"') continue;
        if (memcmp(body + i + 1, key, (size_t)key_len) != 0) continue;
        if (body[i + 1 + key_len] != '"') continue;

        u64 j = i + 1 + key_len + 1;
        /* skip whitespace */
        while (j < body_len && (body[j] == ' ' || body[j] == '\t' ||
               body[j] == '\n' || body[j] == '\r')) j++;
        if (j >= body_len || body[j] != ':') continue;
        j++;
        /* skip whitespace */
        while (j < body_len && (body[j] == ' ' || body[j] == '\t' ||
               body[j] == '\n' || body[j] == '\r')) j++;
        if (j >= body_len) continue;

        /* parse digits */
        if (body[j] < '0' || body[j] > '9') continue;
        u64 val = 0;
        while (j < body_len && body[j] >= '0' && body[j] <= '9') {
            val = val * 10 + (u64)(body[j] - '0');
            j++;
        }
        *found = 1;
        return val;
    }
    return 0;
}

/* ----------------------------------------------------------------
 *  oauth2_auth_url_build
 * ---------------------------------------------------------------- */

unsigned long oauth2_auth_url_build(char **out, u64 *out_len,
                                    const oauth2_config *cfg,
                                    const char *state) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!cfg->auth_endpoint) return 4;
    if (!cfg->client_id) return 5;
    if (!state) return 6;

    /* percent-encode parameters */
    char *enc_client_id   = percent_encode(cfg->client_id);
    char *enc_redirect    = cfg->redirect_uri ? percent_encode(cfg->redirect_uri) : NULL;
    char *enc_scope       = cfg->scope ? percent_encode(cfg->scope) : NULL;
    char *enc_state       = percent_encode(state);

    if (!enc_client_id || !enc_state) {
        free(enc_client_id);
        free(enc_redirect);
        free(enc_scope);
        free(enc_state);
        return 7;
    }

    /* calculate total length */
    u64 ep_len = strlen(cfg->auth_endpoint);
    /* ?response_type=code&client_id=...&state=... */
    u64 total = ep_len
        + 19  /* ?response_type=code */
        + 11  /* &client_id= */
        + strlen(enc_client_id)
        + 7   /* &state= */
        + strlen(enc_state);

    if (enc_redirect) {
        total += 14 + strlen(enc_redirect); /* &redirect_uri= */
    }
    if (enc_scope) {
        total += 7 + strlen(enc_scope); /* &scope= */
    }

    char *url = (char *)malloc((size_t)(total + 1));
    if (!url) {
        free(enc_client_id);
        free(enc_redirect);
        free(enc_scope);
        free(enc_state);
        return 7;
    }

    /* build URL */
    char *d = url;
    memcpy(d, cfg->auth_endpoint, (size_t)ep_len); d += ep_len;

    memcpy(d, "?response_type=code", 19); d += 19;

    memcpy(d, "&client_id=", 11); d += 11;
    u64 cid_len = strlen(enc_client_id);
    memcpy(d, enc_client_id, (size_t)cid_len); d += cid_len;

    if (enc_redirect) {
        memcpy(d, "&redirect_uri=", 14); d += 14;
        u64 redir_len = strlen(enc_redirect);
        memcpy(d, enc_redirect, (size_t)redir_len); d += redir_len;
    }

    if (enc_scope) {
        memcpy(d, "&scope=", 7); d += 7;
        u64 scope_len = strlen(enc_scope);
        memcpy(d, enc_scope, (size_t)scope_len); d += scope_len;
    }

    memcpy(d, "&state=", 7); d += 7;
    u64 st_len = strlen(enc_state);
    memcpy(d, enc_state, (size_t)st_len); d += st_len;

    *d = '\0';

    free(enc_client_id);
    free(enc_redirect);
    free(enc_scope);
    free(enc_state);

    *out = url;
    *out_len = (u64)(d - url);
    return 0;
}

/* ----------------------------------------------------------------
 *  Internal: parse JSON body into oauth2_token
 * ---------------------------------------------------------------- */

static unsigned long parse_token_body(oauth2_token *out,
                                      const char *body, u64 body_len,
                                      u64 now_unix) {
    memset(out, 0, sizeof(*out));

    out->access_token = find_json_string(body, body_len, "access_token");
    if (!out->access_token) return 4;

    out->refresh_token = find_json_string(body, body_len, "refresh_token");
    out->token_type    = find_json_string(body, body_len, "token_type");
    out->scope         = find_json_string(body, body_len, "scope");

    int found = 0;
    out->expires_in = find_json_number(body, body_len, "expires_in", &found);
    if (!found) out->expires_in = 0;

    /* default token_type to Bearer if not present */
    if (!out->token_type) {
        out->token_type = (char *)malloc(7);
        if (!out->token_type) {
            oauth2_token_free(out);
            return 5;
        }
        memcpy(out->token_type, "Bearer", 7);
    }

    out->obtained_at = now_unix;
    return 0;
}

/* ----------------------------------------------------------------
 *  oauth2_token_exchange
 * ---------------------------------------------------------------- */

unsigned long oauth2_token_exchange(oauth2_token *out,
                                    const oauth2_config *cfg,
                                    const char *code,
                                    const u8 *response_body,
                                    u64 response_len) {
    if (!out) return 1;
    if (!cfg) return 2;
    if (!code) return 3;
    if (!response_body) return 4;

    const char *body = (const char *)response_body;

    /* check for error in response */
    char *err = find_json_string(body, response_len, "error");
    if (err) {
        free(err);
        return 6;
    }

    /* check for opening brace — minimal JSON validation */
    int has_brace = 0;
    for (u64 i = 0; i < response_len; i++) {
        if (body[i] == '{') { has_brace = 1; break; }
    }
    if (!has_brace) return 5;

    unsigned long rc = parse_token_body(out, body, response_len, 0);
    if (rc == 4) return 5;  /* missing access_token → malformed */
    if (rc == 5) return 7;  /* alloc failure */

    /* set obtained_at to 0 — caller should set appropriately */
    return 0;
}

/* ----------------------------------------------------------------
 *  oauth2_token_refresh
 * ---------------------------------------------------------------- */

unsigned long oauth2_token_refresh(char **out, u64 *out_len,
                                   const oauth2_config *cfg,
                                   const char *refresh_token) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!refresh_token) return 4;

    char *enc_token  = percent_encode(refresh_token);
    char *enc_id     = cfg->client_id ? percent_encode(cfg->client_id) : NULL;
    char *enc_secret = cfg->client_secret ? percent_encode(cfg->client_secret) : NULL;

    if (!enc_token) {
        free(enc_id);
        free(enc_secret);
        return 5;
    }

    /* grant_type=refresh_token&refresh_token=...&client_id=...&client_secret=... */
    u64 total = 39 /* grant_type=refresh_token&refresh_token= */
        + strlen(enc_token);

    if (enc_id) {
        total += 11 + strlen(enc_id); /* &client_id= */
    }
    if (enc_secret) {
        total += 15 + strlen(enc_secret); /* &client_secret= */
    }

    char *body = (char *)malloc((size_t)(total + 1));
    if (!body) {
        free(enc_token);
        free(enc_id);
        free(enc_secret);
        return 5;
    }

    char *d = body;

    memcpy(d, "grant_type=refresh_token&refresh_token=", 39); d += 39;
    u64 tlen = strlen(enc_token);
    memcpy(d, enc_token, (size_t)tlen); d += tlen;

    if (enc_id) {
        memcpy(d, "&client_id=", 11); d += 11;
        u64 idlen = strlen(enc_id);
        memcpy(d, enc_id, (size_t)idlen); d += idlen;
    }

    if (enc_secret) {
        memcpy(d, "&client_secret=", 15); d += 15;
        u64 slen = strlen(enc_secret);
        memcpy(d, enc_secret, (size_t)slen); d += slen;
    }

    *d = '\0';

    free(enc_token);
    free(enc_id);
    free(enc_secret);

    *out = body;
    *out_len = (u64)(d - body);
    return 0;
}

/* ----------------------------------------------------------------
 *  oauth2_token_parse
 * ---------------------------------------------------------------- */

unsigned long oauth2_token_parse(oauth2_token *out,
                                 const u8 *body, u64 body_len,
                                 u64 now_unix) {
    if (!out) return 1;
    if (!body) return 2;

    const char *s = (const char *)body;

    /* minimal JSON check */
    int has_brace = 0;
    for (u64 i = 0; i < body_len; i++) {
        if (s[i] == '{') { has_brace = 1; break; }
    }
    if (!has_brace) return 3;

    unsigned long rc = parse_token_body(out, s, body_len, now_unix);
    if (rc == 4) return 4; /* missing access_token */
    if (rc == 5) return 5; /* alloc failure */

    return 0;
}

/* ----------------------------------------------------------------
 *  oauth2_token_is_expired
 * ---------------------------------------------------------------- */

unsigned long oauth2_token_is_expired(int *out_expired,
                                      const oauth2_token *tok,
                                      u64 now_unix) {
    if (!out_expired) return 1;
    if (!tok) return 2;

    if (tok->expires_in == 0) {
        /* no expiry info — treat as not expired */
        *out_expired = 0;
    } else {
        *out_expired = (now_unix >= tok->obtained_at + tok->expires_in) ? 1 : 0;
    }
    return 0;
}

/* ----------------------------------------------------------------
 *  oauth2_token_free
 * ---------------------------------------------------------------- */

unsigned long oauth2_token_free(oauth2_token *tok) {
    if (!tok) return 0;

    free(tok->access_token);
    free(tok->refresh_token);
    free(tok->token_type);
    free(tok->scope);

    memset(tok, 0, sizeof(*tok));
    return 0;
}

/* ================================================================
 *  Internal helper: append a percent-encoded key=value pair to a
 *  growing form body. The body pointer is realloc'd as needed.
 *  Returns 0 on success, non-zero on alloc failure.
 * ================================================================ */

static unsigned long form_append(char **body, u64 *len, u64 *cap,
                                  const char *key, const char *value,
                                  int first) {
    char *enc = percent_encode(value);
    if (!enc) return 1;
    u64 klen = strlen(key);
    u64 elen = strlen(enc);
    u64 need = *len + klen + 1 + elen + (first ? 0 : 1) + 1;
    if (need > *cap) {
        u64 ncap = (*cap == 0) ? 256 : *cap * 2;
        while (ncap < need) ncap *= 2;
        char *nb = (char *)realloc(*body, (size_t)ncap);
        if (!nb) { free(enc); return 1; }
        *body = nb;
        *cap = ncap;
    }
    if (!first) (*body)[(*len)++] = '&';
    memcpy(*body + *len, key, (size_t)klen);  *len += klen;
    (*body)[(*len)++] = '=';
    memcpy(*body + *len, enc, (size_t)elen); *len += elen;
    (*body)[*len] = '\0';
    free(enc);
    return 0;
}

/* ================================================================
 *  oauth2_token_exchange_body
 * ================================================================ */

unsigned long oauth2_token_exchange_body(char **out, u64 *out_len,
                                          const oauth2_config *cfg,
                                          const char *code,
                                          const char *code_verifier) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!cfg->client_id) return 4;
    if (!code) return 5;

    char *body = NULL;
    u64 len = 0, cap = 0;

    if (form_append(&body, &len, &cap,
                    "grant_type", "authorization_code", 1)) goto oom;
    if (form_append(&body, &len, &cap, "code", code, 0)) goto oom;
    if (form_append(&body, &len, &cap, "client_id", cfg->client_id, 0))
        goto oom;
    if (cfg->client_secret &&
        form_append(&body, &len, &cap, "client_secret",
                    cfg->client_secret, 0)) goto oom;
    if (cfg->redirect_uri &&
        form_append(&body, &len, &cap, "redirect_uri",
                    cfg->redirect_uri, 0)) goto oom;
    if (code_verifier &&
        form_append(&body, &len, &cap, "code_verifier",
                    code_verifier, 0)) goto oom;

    *out = body;
    *out_len = len;
    return 0;

oom:
    free(body);
    return 6;
}

/* ================================================================
 *  PKCE helpers — RFC 7636
 * ================================================================ */

unsigned long oauth2_pkce_verifier_generate(char **out, u64 *out_len) {
    if (!out) return 1;
    if (!out_len) return 2;

    u8 rnd[32];
    if (entropy_get_system(rnd, 32)) return 3;

    buf encoded = {0};
    if (base64url_encode(&encoded, rnd, 32)) return 4;

    char *s = (char *)malloc((size_t)encoded.len + 1);
    if (!s) { buf_destroy(&encoded); return 4; }
    memcpy(s, encoded.data, (size_t)encoded.len);
    s[encoded.len] = '\0';

    *out = s;
    *out_len = encoded.len;
    buf_destroy(&encoded);
    return 0;
}

unsigned long oauth2_pkce_challenge_s256(char **out, u64 *out_len,
                                          const char *verifier) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!verifier) return 3;

    u8 hash[32];
    if (sha256_digest(hash, (const u8 *)verifier, strlen(verifier))) return 4;

    buf encoded = {0};
    if (base64url_encode(&encoded, hash, 32)) return 4;

    char *s = (char *)malloc((size_t)encoded.len + 1);
    if (!s) { buf_destroy(&encoded); return 4; }
    memcpy(s, encoded.data, (size_t)encoded.len);
    s[encoded.len] = '\0';

    *out = s;
    *out_len = encoded.len;
    buf_destroy(&encoded);
    return 0;
}

unsigned long oauth2_auth_url_build_pkce(char **out, u64 *out_len,
                                          const oauth2_config *cfg,
                                          const char *state,
                                          const char *code_challenge) {
    /* Same hatch ordering as oauth2_auth_url_build, with hatch 8 for
     * the additional code_challenge arg. */
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!cfg->auth_endpoint) return 4;
    if (!cfg->client_id) return 5;
    if (!state) return 6;
    if (!code_challenge) return 8;

    char *base = NULL;
    u64 base_len = 0;
    unsigned long rc = oauth2_auth_url_build(&base, &base_len, cfg, state);
    if (rc) return rc;

    char *enc_chal = percent_encode(code_challenge);
    if (!enc_chal) { free(base); return 7; }
    u64 chal_len = strlen(enc_chal);

    /* Append: &code_challenge=<enc_chal>&code_challenge_method=S256 */
    const char suffix_a[] = "&code_challenge=";
    const char suffix_b[] = "&code_challenge_method=S256";
    u64 total = base_len + sizeof(suffix_a) - 1 + chal_len + sizeof(suffix_b) - 1;

    char *url = (char *)malloc((size_t)total + 1);
    if (!url) { free(base); free(enc_chal); return 7; }
    char *d = url;
    memcpy(d, base, (size_t)base_len); d += base_len;
    memcpy(d, suffix_a, sizeof(suffix_a) - 1); d += sizeof(suffix_a) - 1;
    memcpy(d, enc_chal, (size_t)chal_len);     d += chal_len;
    memcpy(d, suffix_b, sizeof(suffix_b) - 1); d += sizeof(suffix_b) - 1;
    *d = '\0';

    free(base);
    free(enc_chal);

    *out = url;
    *out_len = (u64)(d - url);
    return 0;
}

/* ================================================================
 *  oauth2_client_credentials_body — RFC 6749 §4.4
 * ================================================================ */

unsigned long oauth2_client_credentials_body(char **out, u64 *out_len,
                                              const oauth2_config *cfg) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!cfg->client_id) return 4;
    if (!cfg->client_secret) return 5;

    char *body = NULL;
    u64 len = 0, cap = 0;

    if (form_append(&body, &len, &cap,
                    "grant_type", "client_credentials", 1)) goto oom;
    if (form_append(&body, &len, &cap, "client_id", cfg->client_id, 0))
        goto oom;
    if (form_append(&body, &len, &cap, "client_secret",
                    cfg->client_secret, 0)) goto oom;
    if (cfg->scope &&
        form_append(&body, &len, &cap, "scope", cfg->scope, 0))
        goto oom;

    *out = body;
    *out_len = len;
    return 0;

oom:
    free(body);
    return 6;
}

/* ================================================================
 *  Device authorization grant — RFC 8628
 * ================================================================ */

unsigned long oauth2_device_authz_body(char **out, u64 *out_len,
                                        const oauth2_config *cfg) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!cfg->client_id) return 4;

    char *body = NULL;
    u64 len = 0, cap = 0;

    if (form_append(&body, &len, &cap, "client_id", cfg->client_id, 1))
        goto oom;
    if (cfg->scope &&
        form_append(&body, &len, &cap, "scope", cfg->scope, 0))
        goto oom;

    *out = body;
    *out_len = len;
    return 0;

oom:
    free(body);
    return 5;
}

unsigned long oauth2_device_authz_parse(oauth2_device_authz *out,
                                         const u8 *body, u64 body_len) {
    if (!out) return 1;
    if (!body) return 2;

    /* minimal JSON check */
    int has_brace = 0;
    for (u64 i = 0; i < body_len; i++) {
        if (body[i] == '{') { has_brace = 1; break; }
    }
    if (!has_brace) return 3;

    memset(out, 0, sizeof(*out));

    const char *b = (const char *)body;
    out->device_code = find_json_string(b, body_len, "device_code");
    if (!out->device_code) return 4;

    out->user_code = find_json_string(b, body_len, "user_code");
    out->verification_uri = find_json_string(b, body_len, "verification_uri");
    out->verification_uri_complete =
        find_json_string(b, body_len, "verification_uri_complete");

    int found = 0;
    out->expires_in = find_json_number(b, body_len, "expires_in", &found);
    if (!found) out->expires_in = 0;
    out->interval = find_json_number(b, body_len, "interval", &found);
    if (!found) out->interval = 5;

    return 0;
}

unsigned long oauth2_device_authz_free(oauth2_device_authz *authz) {
    if (!authz) return 0;
    free(authz->device_code);
    free(authz->user_code);
    free(authz->verification_uri);
    free(authz->verification_uri_complete);
    memset(authz, 0, sizeof(*authz));
    return 0;
}

unsigned long oauth2_device_token_body(char **out, u64 *out_len,
                                        const oauth2_config *cfg,
                                        const char *device_code) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!cfg) return 3;
    if (!cfg->client_id) return 4;
    if (!device_code) return 5;

    char *body = NULL;
    u64 len = 0, cap = 0;

    if (form_append(&body, &len, &cap, "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code", 1))
        goto oom;
    if (form_append(&body, &len, &cap, "device_code", device_code, 0))
        goto oom;
    if (form_append(&body, &len, &cap, "client_id", cfg->client_id, 0))
        goto oom;
    if (cfg->client_secret &&
        form_append(&body, &len, &cap, "client_secret",
                    cfg->client_secret, 0)) goto oom;

    *out = body;
    *out_len = len;
    return 0;

oom:
    free(body);
    return 6;
}
