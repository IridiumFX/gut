#include "apennines/pki.h"
#include "apennines/x509.h"
#include "apennines/hash.h"
#include "apennines/rsa.h"
#include "apennines/asn1_der.h"
#include "apennines/pem.h"
#include "apennines/buf.h"

#include <stdlib.h>
#include <string.h>

/* ================================================================
 *  pki_store — opaque struct definition
 * ================================================================ */

struct pki_store {
    pki_cert *certs;       /* trusted CA certificates (DER copies) */
    u64       cert_count;
    u64       cert_cap;
    pki_crl  *crls;        /* CRLs (DER copies) */
    u64       crl_count;
    u64       crl_cap;
};

#include <stdio.h>

/* ================================================================
 *  Internal: SHA-1 (needed for OCSP per RFC 6960)
 *  No project-level SHA-1 exists, so we provide a minimal static one.
 * ================================================================ */

#define SHA1_DIGEST_LEN 20

typedef struct {
    u32 state[5];
    u64 count;
    u8  buf[64];
} sha1_int_ctx;

static u32 sha1_rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_transform(u32 s[5], const u8 block[64]) {
    u32 w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((u32)block[i*4] << 24) | ((u32)block[i*4+1] << 16) |
               ((u32)block[i*4+2] << 8)  |  (u32)block[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    u32 a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    for (int i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;             k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else              { f = b ^ c ^ d;             k = 0xCA62C1D6; }
        u32 tmp = sha1_rotl(a, 5) + f + e + k + w[i];
        e = d; d = c; c = sha1_rotl(b, 30); b = a; a = tmp;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
}

static void sha1_int_init(sha1_int_ctx *c) {
    c->state[0] = 0x67452301; c->state[1] = 0xEFCDAB89;
    c->state[2] = 0x98BADCFE; c->state[3] = 0x10325476;
    c->state[4] = 0xC3D2E1F0; c->count = 0;
    memset(c->buf, 0, 64);
}

static void sha1_int_update(sha1_int_ctx *c, const u8 *data, u64 len) {
    u64 idx = c->count % 64;
    c->count += len;
    for (u64 i = 0; i < len; i++) {
        c->buf[idx++] = data[i];
        if (idx == 64) { sha1_transform(c->state, c->buf); idx = 0; }
    }
}

static void sha1_int_final(u8 out[20], sha1_int_ctx *c) {
    u64 bits = c->count * 8;
    u8 pad = 0x80;
    sha1_int_update(c, &pad, 1);
    pad = 0;
    while (c->count % 64 != 56) { sha1_int_update(c, &pad, 1); }
    u8 len_be[8];
    for (int i = 7; i >= 0; i--) { len_be[i] = (u8)(bits & 0xFF); bits >>= 8; }
    sha1_int_update(c, len_be, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (u8)(c->state[i] >> 24);
        out[i*4+1] = (u8)(c->state[i] >> 16);
        out[i*4+2] = (u8)(c->state[i] >> 8);
        out[i*4+3] = (u8)(c->state[i]);
    }
}

static void sha1_digest_int(u8 out[20], const u8 *data, u64 len) {
    sha1_int_ctx c;
    sha1_int_init(&c);
    sha1_int_update(&c, data, len);
    sha1_int_final(out, &c);
}

/* ================================================================
 *  Internal: time parsing (same as x509.c)
 * ================================================================ */

static int digit2(const u8 *p) {
    return (p[0] - '0') * 10 + (p[1] - '0');
}

static u64 time_to_epoch(const u8 *data, u64 len) {
    int year, month, day, hour, min, sec;
    const u8 *p = data;

    if (len == 13) {
        year = digit2(p);
        year += (year >= 50) ? 1900 : 2000;
        p += 2;
    } else if (len == 15) {
        year = digit2(p) * 100 + digit2(p + 2);
        p += 4;
    } else {
        return 0;
    }

    month = digit2(p); p += 2;
    day   = digit2(p); p += 2;
    hour  = digit2(p); p += 2;
    min   = digit2(p); p += 2;
    sec   = digit2(p);

    static const int mdays[12] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int y = year;
    int m = month;
    if (m < 1 || m > 12) return 0;
    if (day < 1 || day > 31) return 0;

    long long days = 365LL * (y - 1970);
    {
        int ya = y - 1;
        int l70 = 1969;
        days += (ya / 4 - l70 / 4) - (ya / 100 - l70 / 100) + (ya / 400 - l70 / 400);
    }
    days += mdays[m - 1] + (day - 1);
    if (m > 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) {
        days++;
    }

    long long total = days * 86400LL + hour * 3600LL + min * 60LL + sec;
    return (u64)total;
}

/* ================================================================
 *  Internal: array growth helper
 * ================================================================ */

#define INITIAL_CAP 16

static unsigned long grow_certs(pki_store *s) {
    u64 new_cap = s->cert_cap == 0 ? INITIAL_CAP : s->cert_cap * 2;
    pki_cert *tmp = (pki_cert *)realloc(s->certs, (size_t)(new_cap * sizeof(pki_cert)));
    if (!tmp) return 1;
    s->certs = tmp;
    s->cert_cap = new_cap;
    return 0;
}

static unsigned long grow_crls(pki_store *s) {
    u64 new_cap = s->crl_cap == 0 ? INITIAL_CAP : s->crl_cap * 2;
    pki_crl *tmp = (pki_crl *)realloc(s->crls, (size_t)(new_cap * sizeof(pki_crl)));
    if (!tmp) return 1;
    s->crls = tmp;
    s->crl_cap = new_cap;
    return 0;
}

/* ================================================================
 *  Internal: validate DER looks like an ASN.1 SEQUENCE
 * ================================================================ */

static int is_valid_der(const u8 *data, u64 len) {
    if (!data || len < 2) return 0;
    asn1_tlv outer;
    if (asn1_der_decode(&outer, data, len)) return 0;
    if (outer.tag != ASN1_TAG_SEQUENCE) return 0;
    return 1;
}

/* ================================================================
 *  Internal: extract public key bytes from SubjectPublicKeyInfo
 *  Returns pointer to the BIT STRING content (skipping unused-bits byte)
 * ================================================================ */

static unsigned long extract_spki_pubkey_bytes(const u8 **out, u64 *out_len,
                                                const u8 *spki, u64 spki_len) {
    asn1_tlv outer;
    if (asn1_der_decode(&outer, spki, spki_len)) return 1;
    if (outer.tag != ASN1_TAG_SEQUENCE) return 1;

    const u8 *cur = outer.value;
    u64 rem = outer.value_len;

    /* Skip AlgorithmIdentifier SEQUENCE */
    asn1_tlv alg;
    if (asn1_der_sequence_next(&alg, &cur, &rem)) return 1;

    /* BIT STRING containing the public key */
    asn1_tlv bits;
    if (asn1_der_sequence_next(&bits, &cur, &rem)) return 1;
    if (bits.tag != ASN1_TAG_BIT_STRING || bits.value_len < 1) return 1;

    /* Skip the unused-bits byte */
    *out     = bits.value + 1;
    *out_len = bits.value_len - 1;
    return 0;
}

/* ================================================================
 *  pki_store_create
 * ================================================================ */

unsigned long pki_store_create(pki_store **out) {
    if (!out) return 1;

    pki_store *s = (pki_store *)calloc(1, sizeof(pki_store));
    if (!s) return 2;

    s->certs      = NULL;
    s->cert_count = 0;
    s->cert_cap   = 0;
    s->crls       = NULL;
    s->crl_count  = 0;
    s->crl_cap    = 0;

    *out = s;
    return 0;
}

/* ================================================================
 *  pki_store_add_cert
 * ================================================================ */

unsigned long pki_store_add_cert(pki_store *store,
                                                const pki_cert *cert) {
    if (!store) return 1;
    if (!cert)  return 2;
    if (!cert->data || cert->len == 0) return 3;
    if (!is_valid_der(cert->data, cert->len)) return 3;

    if (store->cert_count >= store->cert_cap) {
        if (grow_certs(store)) return 4;
    }

    u8 *copy = (u8 *)malloc((size_t)cert->len);
    if (!copy) return 4;
    memcpy(copy, cert->data, (size_t)cert->len);

    pki_cert *slot = &store->certs[store->cert_count];
    slot->data = copy;
    slot->len  = cert->len;
    store->cert_count++;
    return 0;
}

/* ================================================================
 *  pki_store_add_crl
 * ================================================================ */

unsigned long pki_store_add_crl(pki_store *store,
                                               const pki_crl *crl) {
    if (!store) return 1;
    if (!crl)   return 2;
    if (!crl->data || crl->len == 0) return 3;
    if (!is_valid_der(crl->data, crl->len)) return 3;

    if (store->crl_count >= store->crl_cap) {
        if (grow_crls(store)) return 4;
    }

    u8 *copy = (u8 *)malloc((size_t)crl->len);
    if (!copy) return 4;
    memcpy(copy, crl->data, (size_t)crl->len);

    pki_crl *slot = &store->crls[store->crl_count];
    slot->data = copy;
    slot->len  = crl->len;
    store->crl_count++;
    return 0;
}

/* ================================================================
 *  pki_store_load_system
 * ================================================================ */

/*
 * System CA loading uses PEM bundle files on all platforms.
 * No dependency on platform-specific crypto APIs (CryptoAPI, etc.)
 * to stay zero-dep as a base runtime for Nova OS.
 */

static const char *SYSTEM_CERT_PATHS[] = {
#ifdef _WIN32
    /* Common Windows locations for CA bundles */
    "C:\\ProgramData\\ssl\\certs\\ca-bundle.crt",
    "C:\\msys64\\etc\\pki\\ca-trust\\extracted\\pem\\tls-ca-bundle.pem",
    "C:\\msys64\\usr\\ssl\\certs\\ca-bundle.crt",
#endif
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/usr/local/share/certs/ca-root-nss.crt",
    NULL
};

unsigned long pki_store_load_system(pki_store *store) {
    if (!store) return 1;

    FILE *f = NULL;
    for (int i = 0; SYSTEM_CERT_PATHS[i]; i++) {
        f = fopen(SYSTEM_CERT_PATHS[i], "rb");
        if (f) break;
    }
    if (!f) return 2;

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) { fclose(f); return 3; }

    u8 *data = (u8 *)malloc((size_t)fsize);
    if (!data) { fclose(f); return 3; }

    size_t nr = fread(data, 1, (size_t)fsize, f);
    fclose(f);
    if ((long)nr != fsize) { free(data); return 3; }

    /* Iterate PEM blocks and add each as a DER cert */
    const u8 *cursor = data;
    u64 remaining = (u64)nr;
    int loaded = 0;

    while (remaining > 0) {
        buf der;
        char label[64];
        unsigned long rc = buf_create(&der, 4096);
        if (rc) break;

        rc = pem_decode_next(&der, label, sizeof(label), &cursor, &remaining);
        if (rc) {
            buf_destroy(&der);
            break;
        }

        /* Only add if it looks like a certificate */
        if (strstr(label, "CERTIFICATE") != NULL) {
            pki_cert c;
            c.data = der.data;
            c.len  = der.len;
            rc = pki_store_add_cert(store, &c);
            if (rc == 0) loaded++;
        }

        buf_destroy(&der);
    }

    free(data);
    return loaded > 0 ? 0 : 3;
}

/* ================================================================
 *  Internal: check if a serial is in a CRL
 *
 *  CRL structure (simplified):
 *    SEQUENCE {
 *      SEQUENCE {                          -- TBSCertList
 *        [version INTEGER OPTIONAL,]
 *        signature AlgorithmIdentifier,
 *        issuer Name,
 *        thisUpdate Time,
 *        [nextUpdate Time OPTIONAL,]
 *        [revokedCertificates SEQUENCE OF SEQUENCE {
 *            userCertificate INTEGER,
 *            revocationDate  Time,
 *            [extensions ...] } ]
 *        ...
 *      }
 *      ...
 *    }
 * ================================================================ */

static int serial_in_crl(const u8 *serial, u64 serial_len,
                          const u8 *crl_data, u64 crl_len) {
    asn1_tlv outer;
    if (asn1_der_decode(&outer, crl_data, crl_len)) return 0;
    if (outer.tag != ASN1_TAG_SEQUENCE) return 0;

    const u8 *cur = outer.value;
    u64 rem = outer.value_len;

    /* TBSCertList SEQUENCE */
    asn1_tlv tbs;
    if (asn1_der_sequence_next(&tbs, &cur, &rem)) return 0;
    if (tbs.tag != ASN1_TAG_SEQUENCE) return 0;

    const u8 *tc = tbs.value;
    u64 tr = tbs.value_len;

    /* Possibly version INTEGER (optional) */
    asn1_tlv field;
    if (asn1_der_sequence_next(&field, &tc, &tr)) return 0;

    /* If it's an INTEGER with small value, it's the version; skip it */
    if (field.tag == ASN1_TAG_INTEGER && field.value_len == 1 &&
        field.value[0] <= 1) {
        /* version present, read next (signature alg) */
        if (asn1_der_sequence_next(&field, &tc, &tr)) return 0;
    }
    /* field is now signature AlgorithmIdentifier SEQUENCE — skip */

    /* issuer Name — skip */
    asn1_tlv tmp;
    if (asn1_der_sequence_next(&tmp, &tc, &tr)) return 0;

    /* thisUpdate Time — skip */
    if (asn1_der_sequence_next(&tmp, &tc, &tr)) return 0;

    /* nextUpdate Time (optional) or revokedCertificates SEQUENCE */
    if (tr == 0) return 0;
    if (asn1_der_sequence_next(&tmp, &tc, &tr)) return 0;

    /* If this is a time type, skip it and read the next */
    if (tmp.tag == ASN1_TAG_UTC_TIME || tmp.tag == ASN1_TAG_GENERALIZED_TIME) {
        if (tr == 0) return 0;
        if (asn1_der_sequence_next(&tmp, &tc, &tr)) return 0;
    }

    /* tmp should now be revokedCertificates SEQUENCE (if present) */
    if (tmp.tag != ASN1_TAG_SEQUENCE) return 0;

    /* Walk revoked entries */
    const u8 *rc2 = tmp.value;
    u64 rr = tmp.value_len;

    while (rr > 0) {
        asn1_tlv entry;
        if (asn1_der_sequence_next(&entry, &rc2, &rr)) break;
        if (entry.tag != ASN1_TAG_SEQUENCE) continue;

        const u8 *ec = entry.value;
        u64 er = entry.value_len;

        /* userCertificate INTEGER */
        asn1_tlv sn;
        if (asn1_der_sequence_next(&sn, &ec, &er)) continue;
        if (sn.tag != ASN1_TAG_INTEGER) continue;

        if (sn.value_len == serial_len &&
            memcmp(sn.value, serial, (size_t)serial_len) == 0) {
            return 1; /* Found — revoked */
        }
    }

    return 0;
}

/* ================================================================
 *  Internal: check if cert's issuer DN matches a store cert's subject DN
 * ================================================================ */

static int issuer_matches_subject(const x509_cert *cert,
                                   const x509_cert *ca) {
    if (!cert->issuer || !ca->subject) return 0;
    if (cert->issuer_len != ca->subject_len) return 0;
    return memcmp(cert->issuer, ca->subject, (size_t)cert->issuer_len) == 0;
}

/* ================================================================
 *  pki_store_verify
 * ================================================================ */

unsigned long pki_store_verify(pki_verify_result *out,
                                              const pki_store *store,
                                              const pki_cert *chain,
                                              u64 chain_len,
                                              u64 now_unix) {
    if (!out)   return 1;
    if (!store) return 2;
    if (!chain) return 3;
    if (chain_len == 0) return 4;

    memset(out, 0, sizeof(*out));

    /* Parse all certs in the provided chain */
    x509_cert *parsed = (x509_cert *)calloc((size_t)chain_len, sizeof(x509_cert));
    if (!parsed) return 6;

    for (u64 i = 0; i < chain_len; i++) {
        unsigned long rc = x509_parse(&parsed[i], chain[i].data, chain[i].len);
        if (rc) {
            for (u64 j = 0; j < i; j++) x509_destroy(&parsed[j]);
            free(parsed);
            return 5;
        }
    }

    int any_expired = 0;
    int is_revoked  = 0;
    int trusted     = 0;
    u32 depth       = 0;

    /* Walk the chain from leaf toward root */
    for (u64 i = 0; i < chain_len; i++) {
        x509_cert *cur = &parsed[i];
        depth++;

        /* Check expiry */
        unsigned long exp_flag = 0;
        x509_is_expired(&exp_flag, cur, now_unix);
        if (exp_flag) any_expired = 1;

        /* Check CRL revocation for leaf cert */
        if (i == 0) {
            for (u64 c = 0; c < store->crl_count; c++) {
                if (serial_in_crl(cur->serial, cur->serial_len,
                                  store->crls[c].data, store->crls[c].len)) {
                    is_revoked = 1;
                    break;
                }
            }
        }

        /* Check if issuer is a trusted CA in the store */
        for (u64 s = 0; s < store->cert_count; s++) {
            x509_cert ca;
            if (x509_parse(&ca, store->certs[s].data, store->certs[s].len)) continue;

            if (issuer_matches_subject(cur, &ca)) {
                trusted = 1;
                x509_destroy(&ca);
                goto done;
            }
            x509_destroy(&ca);
        }

        /* If not the last cert, verify the next cert in chain is the issuer */
        if (i + 1 < chain_len) {
            if (!issuer_matches_subject(cur, &parsed[i + 1])) {
                /* Chain is broken — issuer of current doesn't match next cert's subject */
                break;
            }
        }
    }

done:
    out->valid        = (trusted && !any_expired && !is_revoked) ? 1 : 0;
    out->expired      = any_expired;
    out->revoked      = is_revoked;
    out->chain_length = depth;

    for (u64 i = 0; i < chain_len; i++) x509_destroy(&parsed[i]);
    free(parsed);
    return 0;
}

/* ================================================================
 *  pki_store_destroy
 * ================================================================ */

unsigned long pki_store_destroy(pki_store *store) {
    if (!store) return 1;

    for (u64 i = 0; i < store->cert_count; i++) {
        free(store->certs[i].data);
    }
    free(store->certs);

    for (u64 i = 0; i < store->crl_count; i++) {
        free(store->crls[i].data);
    }
    free(store->crls);

    free(store);
    return 0;
}

/* ================================================================
 *  Internal: DER encoding helpers for OCSP
 * ================================================================ */

/* Encode a DER length into a buffer, return bytes written */
static u64 der_encode_length(u8 *out, u64 len) {
    if (len < 0x80) {
        out[0] = (u8)len;
        return 1;
    } else if (len < 0x100) {
        out[0] = 0x81;
        out[1] = (u8)len;
        return 2;
    } else if (len < 0x10000) {
        out[0] = 0x82;
        out[1] = (u8)(len >> 8);
        out[2] = (u8)(len & 0xFF);
        return 3;
    } else {
        out[0] = 0x83;
        out[1] = (u8)(len >> 16);
        out[2] = (u8)((len >> 8) & 0xFF);
        out[3] = (u8)(len & 0xFF);
        return 4;
    }
}

/* Calculate how many bytes a DER length encoding takes */
static u64 der_length_size(u64 len) {
    if (len < 0x80)    return 1;
    if (len < 0x100)   return 2;
    if (len < 0x10000) return 3;
    return 4;
}

/* Wrap content in a tag+length+value TLV, append to buf */
static unsigned long der_wrap(buf *b, u8 tag, const u8 *content, u64 clen) {
    unsigned long rc;
    rc = buf_append_byte(b, tag);
    if (rc) return rc;

    u8 lbuf[4];
    u64 lsz = der_encode_length(lbuf, clen);
    rc = buf_append(b, (u8 *)lbuf, lsz);
    if (rc) return rc;

    if (clen > 0) {
        rc = buf_append(b, (u8 *)content, clen);
        if (rc) return rc;
    }
    return 0;
}

/* ================================================================
 *  ocsp_request_build
 *
 *  Builds a minimal DER OCSP request per RFC 6960:
 *
 *  OCSPRequest ::= SEQUENCE {
 *    tbsRequest TBSRequest }
 *
 *  TBSRequest ::= SEQUENCE {
 *    requestList SEQUENCE OF Request }
 *
 *  Request ::= SEQUENCE {
 *    reqCert CertID }
 *
 *  CertID ::= SEQUENCE {
 *    hashAlgorithm  AlgorithmIdentifier (SHA-1),
 *    issuerNameHash OCTET STRING,
 *    issuerKeyHash  OCTET STRING,
 *    serialNumber   INTEGER }
 * ================================================================ */

/* OID for SHA-1: 1.3.14.3.2.26 => 2B 0E 03 02 1A */
static const u8 SHA1_OID[] = { 0x2B, 0x0E, 0x03, 0x02, 0x1A };

unsigned long ocsp_request_build(u8 **out, u64 *out_len,
                                                const pki_cert *cert,
                                                const pki_cert *issuer) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!cert || !cert->data)     return 3;
    if (!issuer || !issuer->data) return 4;

    /* Parse both certificates */
    x509_cert subj, iss;
    unsigned long rc;

    rc = x509_parse(&subj, cert->data, cert->len);
    if (rc) return 5;

    rc = x509_parse(&iss, issuer->data, issuer->len);
    if (rc) { x509_destroy(&subj); return 5; }

    /* issuerNameHash = SHA-1(issuer's subject Name DER) */
    u8 name_hash[SHA1_DIGEST_LEN];
    sha1_digest_int(name_hash, iss.subject, iss.subject_len);

    /* issuerKeyHash = SHA-1(issuer's SubjectPublicKeyInfo BIT STRING content) */
    const u8 *pk_bytes;
    u64 pk_len;
    rc = extract_spki_pubkey_bytes(&pk_bytes, &pk_len, iss.pubkey, iss.pubkey_len);
    if (rc) {
        x509_destroy(&subj);
        x509_destroy(&iss);
        return 5;
    }

    u8 key_hash[SHA1_DIGEST_LEN];
    sha1_digest_int(key_hash, pk_bytes, pk_len);

    /* Build the CertID SEQUENCE content */
    buf certid_content;
    rc = buf_create(&certid_content, 256);
    if (rc) { x509_destroy(&subj); x509_destroy(&iss); return 6; }

    /* hashAlgorithm: SEQUENCE { OID sha1, NULL } */
    {
        buf alg_seq;
        rc = buf_create(&alg_seq, 32);
        if (rc) goto fail_certid;

        /* OID */
        rc = der_wrap(&alg_seq, ASN1_TAG_OID, SHA1_OID, sizeof(SHA1_OID));
        if (rc) { buf_destroy(&alg_seq); goto fail_certid; }

        /* NULL */
        rc = buf_append_byte(&alg_seq, ASN1_TAG_NULL);
        if (!rc) rc = buf_append_byte(&alg_seq, 0x00);
        if (rc) { buf_destroy(&alg_seq); goto fail_certid; }

        rc = der_wrap(&certid_content, ASN1_TAG_SEQUENCE, alg_seq.data, alg_seq.len);
        buf_destroy(&alg_seq);
        if (rc) goto fail_certid;
    }

    /* issuerNameHash: OCTET STRING */
    rc = der_wrap(&certid_content, ASN1_TAG_OCTET_STRING, name_hash, SHA1_DIGEST_LEN);
    if (rc) goto fail_certid;

    /* issuerKeyHash: OCTET STRING */
    rc = der_wrap(&certid_content, ASN1_TAG_OCTET_STRING, key_hash, SHA1_DIGEST_LEN);
    if (rc) goto fail_certid;

    /* serialNumber: INTEGER */
    rc = der_wrap(&certid_content, ASN1_TAG_INTEGER, subj.serial, subj.serial_len);
    if (rc) goto fail_certid;

    /* Wrap into Request ::= SEQUENCE { reqCert CertID } */
    buf request_seq;
    rc = buf_create(&request_seq, 256);
    if (rc) goto fail_certid;

    /* CertID SEQUENCE */
    rc = der_wrap(&request_seq, ASN1_TAG_SEQUENCE, certid_content.data, certid_content.len);
    if (rc) { buf_destroy(&request_seq); goto fail_certid; }

    /* Request SEQUENCE */
    buf request_entry;
    rc = buf_create(&request_entry, 256);
    if (rc) { buf_destroy(&request_seq); goto fail_certid; }

    rc = der_wrap(&request_entry, ASN1_TAG_SEQUENCE, request_seq.data, request_seq.len);
    buf_destroy(&request_seq);
    if (rc) { buf_destroy(&request_entry); goto fail_certid; }

    /* requestList: SEQUENCE OF Request */
    buf request_list;
    rc = buf_create(&request_list, 256);
    if (rc) { buf_destroy(&request_entry); goto fail_certid; }

    rc = der_wrap(&request_list, ASN1_TAG_SEQUENCE, request_entry.data, request_entry.len);
    buf_destroy(&request_entry);
    if (rc) { buf_destroy(&request_list); goto fail_certid; }

    /* TBSRequest: SEQUENCE { requestList } */
    buf tbs_request;
    rc = buf_create(&tbs_request, 256);
    if (rc) { buf_destroy(&request_list); goto fail_certid; }

    rc = der_wrap(&tbs_request, ASN1_TAG_SEQUENCE, request_list.data, request_list.len);
    buf_destroy(&request_list);
    if (rc) { buf_destroy(&tbs_request); goto fail_certid; }

    /* OCSPRequest: SEQUENCE { tbsRequest } */
    buf ocsp_req;
    rc = buf_create(&ocsp_req, 256);
    if (rc) { buf_destroy(&tbs_request); goto fail_certid; }

    rc = der_wrap(&ocsp_req, ASN1_TAG_SEQUENCE, tbs_request.data, tbs_request.len);
    buf_destroy(&tbs_request);
    if (rc) { buf_destroy(&ocsp_req); goto fail_certid; }

    /* Hand off the buffer to the caller */
    *out     = ocsp_req.data;
    *out_len = ocsp_req.len;
    /* Don't destroy ocsp_req — caller owns the data pointer now */

    buf_destroy(&certid_content);
    x509_destroy(&subj);
    x509_destroy(&iss);
    return 0;

fail_certid:
    buf_destroy(&certid_content);
    x509_destroy(&subj);
    x509_destroy(&iss);
    return 6;
}

/* ================================================================
 *  ocsp_response_parse
 *
 *  OCSPResponse ::= SEQUENCE {
 *    responseStatus ENUMERATED,
 *    responseBytes  [0] EXPLICIT SEQUENCE {
 *      responseType OID,
 *      response     OCTET STRING } }
 *
 *  The OCTET STRING wraps a BasicOCSPResponse:
 *  BasicOCSPResponse ::= SEQUENCE {
 *    tbsResponseData ResponseData,
 *    signatureAlgorithm ...,
 *    signature BIT STRING,
 *    [certs [0] ...] }
 *
 *  ResponseData ::= SEQUENCE {
 *    [version [0] ...],
 *    responderID ...,
 *    producedAt GeneralizedTime,
 *    responses SEQUENCE OF SingleResponse }
 *
 *  SingleResponse ::= SEQUENCE {
 *    certID CertID,
 *    certStatus CHOICE {
 *      good    [0] IMPLICIT NULL,
 *      revoked [1] IMPLICIT ...,
 *      unknown [2] IMPLICIT NULL },
 *    thisUpdate GeneralizedTime,
 *    nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL }
 * ================================================================ */

unsigned long ocsp_response_parse(int *out_status,
                                                 const u8 *response,
                                                 u64 response_len) {
    if (!out_status) return 1;
    if (!response)   return 2;
    if (response_len < 3) return 3;

    /* Outer SEQUENCE */
    asn1_tlv outer;
    if (asn1_der_decode(&outer, response, response_len)) return 3;
    if (outer.tag != ASN1_TAG_SEQUENCE) return 3;

    const u8 *cur = outer.value;
    u64 rem = outer.value_len;

    /* responseStatus ENUMERATED */
    asn1_tlv status_tlv;
    if (asn1_der_sequence_next(&status_tlv, &cur, &rem)) return 3;
    if (status_tlv.tag != 0x0A) return 3; /* ENUMERATED tag = 0x0A */
    if (status_tlv.value_len < 1) return 3;

    int resp_status = (int)status_tlv.value[0];
    if (resp_status != 0) return 4; /* Non-successful response status */

    /* responseBytes [0] EXPLICIT */
    if (rem == 0) return 3;
    asn1_tlv resp_bytes_wrapper;
    if (asn1_der_sequence_next(&resp_bytes_wrapper, &cur, &rem)) return 3;
    if (resp_bytes_wrapper.tag != ASN1_TAG_CONTEXT_0) return 3;

    /* SEQUENCE { responseType OID, response OCTET STRING } */
    const u8 *rbc = resp_bytes_wrapper.value;
    u64 rbr = resp_bytes_wrapper.value_len;
    asn1_tlv resp_bytes_seq;
    if (asn1_der_sequence_next(&resp_bytes_seq, &rbc, &rbr)) return 3;
    if (resp_bytes_seq.tag != ASN1_TAG_SEQUENCE) return 3;

    const u8 *sc = resp_bytes_seq.value;
    u64 sr = resp_bytes_seq.value_len;

    /* OID (responseType) — skip */
    asn1_tlv oid_tlv;
    if (asn1_der_sequence_next(&oid_tlv, &sc, &sr)) return 3;

    /* OCTET STRING containing BasicOCSPResponse */
    asn1_tlv octet_tlv;
    if (asn1_der_sequence_next(&octet_tlv, &sc, &sr)) return 3;
    if (octet_tlv.tag != ASN1_TAG_OCTET_STRING) return 3;

    /* Parse BasicOCSPResponse SEQUENCE */
    asn1_tlv basic;
    if (asn1_der_decode(&basic, octet_tlv.value, octet_tlv.value_len)) return 3;
    if (basic.tag != ASN1_TAG_SEQUENCE) return 3;

    const u8 *bc = basic.value;
    u64 br = basic.value_len;

    /* tbsResponseData SEQUENCE */
    asn1_tlv tbs_resp;
    if (asn1_der_sequence_next(&tbs_resp, &bc, &br)) return 3;
    if (tbs_resp.tag != ASN1_TAG_SEQUENCE) return 3;

    /* Walk ResponseData to find responses */
    const u8 *tc = tbs_resp.value;
    u64 tr = tbs_resp.value_len;

    /* Optional version [0] EXPLICIT */
    asn1_tlv field;
    if (asn1_der_sequence_next(&field, &tc, &tr)) return 3;

    if (field.tag == ASN1_TAG_CONTEXT_0) {
        /* Version present, skip and read responderID */
        if (asn1_der_sequence_next(&field, &tc, &tr)) return 3;
    }

    /* field is responderID (byName [1] or byKey [2]) — skip it */
    /* producedAt GeneralizedTime */
    asn1_tlv produced_at;
    if (asn1_der_sequence_next(&produced_at, &tc, &tr)) return 3;

    /* responses SEQUENCE OF SingleResponse */
    asn1_tlv responses;
    if (asn1_der_sequence_next(&responses, &tc, &tr)) return 3;
    if (responses.tag != ASN1_TAG_SEQUENCE) return 3;

    /* First SingleResponse */
    const u8 *rc2 = responses.value;
    u64 rr = responses.value_len;

    asn1_tlv single;
    if (asn1_der_sequence_next(&single, &rc2, &rr)) return 3;
    if (single.tag != ASN1_TAG_SEQUENCE) return 3;

    /* SingleResponse: { certID, certStatus, thisUpdate, [nextUpdate] } */
    const u8 *snc = single.value;
    u64 snr = single.value_len;

    /* Skip certID SEQUENCE */
    asn1_tlv certid;
    if (asn1_der_sequence_next(&certid, &snc, &snr)) return 3;

    /* certStatus — context-tagged */
    asn1_tlv cert_status;
    if (asn1_der_sequence_next(&cert_status, &snc, &snr)) return 3;

    /* Tag determines status:
     *   [0] IMPLICIT = good (tag 0x80 or 0xA0)
     *   [1] IMPLICIT = revoked (tag 0x81 or 0xA1)
     *   [2] IMPLICIT = unknown (tag 0x82 or 0xA2) */
    u8 status_tag = cert_status.tag;
    if (status_tag == 0x80 || status_tag == 0xA0) {
        *out_status = 0; /* good */
    } else if (status_tag == 0x81 || status_tag == 0xA1) {
        *out_status = 1; /* revoked */
    } else if (status_tag == 0x82 || status_tag == 0xA2) {
        *out_status = 2; /* unknown */
    } else {
        return 3; /* malformed */
    }

    return 0;
}

/* ================================================================
 *  Internal: locate BasicOCSPResponse from a raw OCSP response
 *  Returns pointers to tbsResponseData and signature within the response.
 * ================================================================ */

static unsigned long parse_basic_ocsp(const u8 **tbs_out, u64 *tbs_len,
                                       const u8 **sig_out, u64 *sig_len,
                                       const u8 *response, u64 response_len) {
    asn1_tlv outer;
    if (asn1_der_decode(&outer, response, response_len)) return 1;
    if (outer.tag != ASN1_TAG_SEQUENCE) return 1;

    const u8 *cur = outer.value;
    u64 rem = outer.value_len;

    /* responseStatus */
    asn1_tlv status_tlv;
    if (asn1_der_sequence_next(&status_tlv, &cur, &rem)) return 1;
    if (status_tlv.tag != 0x0A || status_tlv.value_len < 1) return 1;
    if (status_tlv.value[0] != 0) return 1;

    /* responseBytes [0] */
    asn1_tlv wrapper;
    if (asn1_der_sequence_next(&wrapper, &cur, &rem)) return 1;
    if (wrapper.tag != ASN1_TAG_CONTEXT_0) return 1;

    const u8 *rbc = wrapper.value;
    u64 rbr = wrapper.value_len;
    asn1_tlv seq;
    if (asn1_der_sequence_next(&seq, &rbc, &rbr)) return 1;
    if (seq.tag != ASN1_TAG_SEQUENCE) return 1;

    const u8 *sc = seq.value;
    u64 sr = seq.value_len;

    /* OID — skip */
    asn1_tlv oid;
    if (asn1_der_sequence_next(&oid, &sc, &sr)) return 1;

    /* OCTET STRING containing BasicOCSPResponse */
    asn1_tlv oct;
    if (asn1_der_sequence_next(&oct, &sc, &sr)) return 1;
    if (oct.tag != ASN1_TAG_OCTET_STRING) return 1;

    /* BasicOCSPResponse SEQUENCE */
    asn1_tlv basic;
    if (asn1_der_decode(&basic, oct.value, oct.value_len)) return 1;
    if (basic.tag != ASN1_TAG_SEQUENCE) return 1;

    const u8 *bc = basic.value;
    u64 br = basic.value_len;

    /* tbsResponseData SEQUENCE (we want the raw TLV) */
    asn1_tlv tbs;
    if (asn1_der_sequence_next(&tbs, &bc, &br)) return 1;
    *tbs_out = tbs.raw;
    *tbs_len = tbs.raw_len;

    /* signatureAlgorithm — skip */
    asn1_tlv sig_alg;
    if (asn1_der_sequence_next(&sig_alg, &bc, &br)) return 1;

    /* signature BIT STRING */
    asn1_tlv sig;
    if (asn1_der_sequence_next(&sig, &bc, &br)) return 1;
    if (sig.tag != ASN1_TAG_BIT_STRING || sig.value_len < 1) return 1;

    /* Skip unused-bits byte */
    *sig_out = sig.value + 1;
    *sig_len = sig.value_len - 1;

    return 0;
}

/* ================================================================
 *  ocsp_response_verify
 * ================================================================ */

unsigned long ocsp_response_verify(int *out_valid,
                                                  const u8 *response,
                                                  u64 response_len,
                                                  const pki_cert *issuer) {
    if (!out_valid) return 1;
    if (!response)  return 2;
    if (!issuer || !issuer->data) return 3;

    *out_valid = 0;

    const u8 *tbs_data;
    u64 tbs_len;
    const u8 *sig_data;
    u64 sig_len;

    if (parse_basic_ocsp(&tbs_data, &tbs_len, &sig_data, &sig_len,
                          response, response_len)) {
        return 4;
    }

    /* Parse issuer certificate to extract its public key */
    x509_cert iss;
    if (x509_parse(&iss, issuer->data, issuer->len)) return 4;

    /* Extract the raw public key from SubjectPublicKeyInfo */
    const u8 *pk_bytes;
    u64 pk_len;
    unsigned long rc = extract_spki_pubkey_bytes(&pk_bytes, &pk_len,
                                                  iss.pubkey, iss.pubkey_len);
    if (rc) {
        x509_destroy(&iss);
        return 4;
    }

    /* Import as RSA public key and verify with PSS */
    rsa_pubkey pub;
    rc = rsa_pubkey_import_der(&pub, pk_bytes, pk_len);
    if (rc) {
        x509_destroy(&iss);
        return 5;
    }

    unsigned long valid = 0;
    rc = rsa_verify_pss(&valid, &pub, sig_data, sig_len, tbs_data, tbs_len);
    rsa_pubkey_destroy(&pub);
    x509_destroy(&iss);

    if (rc) return 5;

    *out_valid = valid ? 1 : 0;
    return 0;
}

/* ================================================================
 *  Internal: extract thisUpdate/nextUpdate from OCSP SingleResponse
 * ================================================================ */

static unsigned long ocsp_extract_times(u64 *this_update, u64 *next_update,
                                         const u8 *response, u64 response_len) {
    /* Navigate to the first SingleResponse */
    asn1_tlv outer;
    if (asn1_der_decode(&outer, response, response_len)) return 1;

    const u8 *cur = outer.value;
    u64 rem = outer.value_len;

    /* responseStatus */
    asn1_tlv status_tlv;
    if (asn1_der_sequence_next(&status_tlv, &cur, &rem)) return 1;

    /* responseBytes [0] */
    asn1_tlv wrapper;
    if (asn1_der_sequence_next(&wrapper, &cur, &rem)) return 1;

    const u8 *rbc = wrapper.value;
    u64 rbr = wrapper.value_len;
    asn1_tlv seq;
    if (asn1_der_sequence_next(&seq, &rbc, &rbr)) return 1;

    const u8 *sc = seq.value;
    u64 sr = seq.value_len;

    /* OID — skip */
    asn1_tlv oid;
    if (asn1_der_sequence_next(&oid, &sc, &sr)) return 1;

    /* OCTET STRING */
    asn1_tlv oct;
    if (asn1_der_sequence_next(&oct, &sc, &sr)) return 1;

    /* BasicOCSPResponse */
    asn1_tlv basic;
    if (asn1_der_decode(&basic, oct.value, oct.value_len)) return 1;

    const u8 *bc = basic.value;
    u64 br = basic.value_len;

    /* tbsResponseData */
    asn1_tlv tbs;
    if (asn1_der_sequence_next(&tbs, &bc, &br)) return 1;

    const u8 *tc = tbs.value;
    u64 tr = tbs.value_len;

    /* Optional version [0] */
    asn1_tlv field;
    if (asn1_der_sequence_next(&field, &tc, &tr)) return 1;
    if (field.tag == ASN1_TAG_CONTEXT_0) {
        if (asn1_der_sequence_next(&field, &tc, &tr)) return 1;
    }
    /* responderID — skip (field is it) */

    /* producedAt */
    asn1_tlv produced;
    if (asn1_der_sequence_next(&produced, &tc, &tr)) return 1;

    /* responses SEQUENCE */
    asn1_tlv responses;
    if (asn1_der_sequence_next(&responses, &tc, &tr)) return 1;

    /* First SingleResponse */
    const u8 *rc2 = responses.value;
    u64 rr = responses.value_len;
    asn1_tlv single;
    if (asn1_der_sequence_next(&single, &rc2, &rr)) return 1;

    const u8 *snc = single.value;
    u64 snr = single.value_len;

    /* certID — skip */
    asn1_tlv certid;
    if (asn1_der_sequence_next(&certid, &snc, &snr)) return 1;

    /* certStatus — skip */
    asn1_tlv cert_status;
    if (asn1_der_sequence_next(&cert_status, &snc, &snr)) return 1;

    /* thisUpdate GeneralizedTime */
    asn1_tlv this_upd;
    if (asn1_der_sequence_next(&this_upd, &snc, &snr)) return 1;
    *this_update = time_to_epoch(this_upd.value, this_upd.value_len);

    /* nextUpdate [0] EXPLICIT GeneralizedTime (optional) */
    *next_update = 0;
    if (snr > 0) {
        asn1_tlv next_wrapper;
        if (asn1_der_sequence_next(&next_wrapper, &snc, &snr) == 0) {
            if (next_wrapper.tag == ASN1_TAG_CONTEXT_0) {
                /* Explicit wrapper — contains a GeneralizedTime */
                const u8 *nc = next_wrapper.value;
                u64 nr = next_wrapper.value_len;
                asn1_tlv next_time;
                if (asn1_der_sequence_next(&next_time, &nc, &nr) == 0) {
                    *next_update = time_to_epoch(next_time.value, next_time.value_len);
                }
            } else if (next_wrapper.tag == ASN1_TAG_GENERALIZED_TIME ||
                       next_wrapper.tag == ASN1_TAG_UTC_TIME) {
                *next_update = time_to_epoch(next_wrapper.value, next_wrapper.value_len);
            }
        }
    }

    return 0;
}

/* ================================================================
 *  ocsp_staple_validate
 * ================================================================ */

unsigned long ocsp_staple_validate(int *out_status,
                                                  const u8 *stapled,
                                                  u64 stapled_len,
                                                  const pki_cert *cert,
                                                  const pki_cert *issuer,
                                                  u64 now_unix) {
    if (!out_status) return 1;
    if (!stapled)    return 2;
    if (!cert || !cert->data)     return 3;
    if (!issuer || !issuer->data) return 4;

    /* Parse the response to get cert status */
    int status;
    unsigned long rc = ocsp_response_parse(&status, stapled, stapled_len);
    if (rc) return 5;

    /* Extract thisUpdate / nextUpdate and check freshness */
    u64 this_update = 0, next_update = 0;
    rc = ocsp_extract_times(&this_update, &next_update, stapled, stapled_len);
    if (rc) return 5;

    /* thisUpdate must be in the past */
    if (this_update > now_unix) return 6;

    /* nextUpdate (if present) must be in the future */
    if (next_update > 0 && now_unix > next_update) return 6;

    /* Verify signature against issuer */
    int sig_valid = 0;
    rc = ocsp_response_verify(&sig_valid, stapled, stapled_len, issuer);
    if (rc) return 7;
    if (!sig_valid) return 7;

    *out_status = status;
    return 0;
}
