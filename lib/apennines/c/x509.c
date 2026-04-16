#include "apennines/x509.h"
#include "apennines/asn1_der.h"
#include "apennines/pem.h"
#include "apennines/hash.h"
#include "apennines/buf.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Internal: detect PEM vs DER                                       */
/* ------------------------------------------------------------------ */

static int is_pem(const u8 *data, u64 len) {
    if (len < 11) return 0;
    return memcmp(data, "-----BEGIN", 10) == 0;
}

/* ------------------------------------------------------------------ */
/*  Internal: skip past N elements in a SEQUENCE body via cursor      */
/* ------------------------------------------------------------------ */

static unsigned long skip_tlv(const u8 **cursor, u64 *remaining) {
    asn1_tlv tmp;
    return asn1_der_sequence_next(&tmp, cursor, remaining);
}

/* ------------------------------------------------------------------ */
/*  Internal: parse UTCTime / GeneralizedTime to epoch seconds        */
/*  UTCTime: YYMMDDHHMMSSZ  (13 bytes)                               */
/*  GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)                      */
/* ------------------------------------------------------------------ */

static int digit2(const u8 *p) {
    return (p[0] - '0') * 10 + (p[1] - '0');
}

static u64 time_to_epoch(const u8 *data, u64 len) {
    int year, month, day, hour, min, sec;
    const u8 *p = data;

    if (len == 13) {
        /* UTCTime: YYMMDDHHMMSSZ */
        year = digit2(p);
        year += (year >= 50) ? 1900 : 2000;
        p += 2;
    } else if (len == 15) {
        /* GeneralizedTime: YYYYMMDDHHMMSSZ */
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

    /* Days-from-epoch approximation (accurate enough for expiry checks) */
    /* Using the well-known days-since-epoch formula */
    static const int mdays[12] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int y = year;
    int m = month;
    if (m < 1 || m > 12) return 0;
    if (day < 1 || day > 31) return 0;

    /* Days since 1970-01-01 */
    long long days = 365LL * (y - 1970);
    /* Add leap years from 1970 to y-1 */
    {
        int ya = y - 1;
        int l70 = 1969; /* year before 1970 */
        days += (ya / 4 - l70 / 4) - (ya / 100 - l70 / 100) + (ya / 400 - l70 / 400);
    }
    days += mdays[m - 1] + (day - 1);
    /* Leap day in current year */
    if (m > 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) {
        days++;
    }

    long long total = days * 86400LL + hour * 3600LL + min * 60LL + sec;
    return (u64)total;
}

/* ------------------------------------------------------------------ */
/*  x509_parse                                                        */
/* ------------------------------------------------------------------ */

unsigned long x509_parse(x509_cert *out,
                                       const u8 *data, u64 len) {
    if (!out)  return 1;
    if (!data) return 2;
    if (len == 0) return 3;

    memset(out, 0, sizeof(*out));

    const u8 *der = data;
    u64 der_len = len;
    buf pem_buf;
    int used_pem = 0;

    /* Auto-detect PEM */
    if (is_pem(data, len)) {
        unsigned long rc = buf_create(&pem_buf, len);
        if (rc) return 4;
        char label[64];
        rc = pem_decode(&pem_buf, label, sizeof(label), data, len);
        if (rc) {
            buf_destroy(&pem_buf);
            return 4;
        }
        der = pem_buf.data;
        der_len = pem_buf.len;
        used_pem = 1;
    }

    /* Make an owned copy of the DER data */
    u8 *owned = (u8 *)malloc((size_t)der_len);
    if (!owned) {
        if (used_pem) buf_destroy(&pem_buf);
        return 8;
    }
    memcpy(owned, der, (size_t)der_len);
    if (used_pem) buf_destroy(&pem_buf);

    out->der_data = owned;
    out->der_len  = der_len;

    /* ---- Parse outer SEQUENCE (Certificate) ---- */
    asn1_tlv outer;
    if (asn1_der_decode(&outer, owned, der_len)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 5;
    }
    if (outer.tag != ASN1_TAG_SEQUENCE) {
        free(owned); memset(out, 0, sizeof(*out));
        return 5;
    }

    /* Walk the three children: tbsCertificate, signatureAlgorithm, signatureValue */
    const u8 *cur = outer.value;
    u64 rem = outer.value_len;

    /* ---- TBSCertificate ---- */
    asn1_tlv tbs_tlv;
    if (asn1_der_sequence_next(&tbs_tlv, &cur, &rem)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 6;
    }
    if (tbs_tlv.tag != ASN1_TAG_SEQUENCE) {
        free(owned); memset(out, 0, sizeof(*out));
        return 6;
    }
    out->tbs     = tbs_tlv.raw;
    out->tbs_len = tbs_tlv.raw_len;

    /* ---- signatureAlgorithm ---- */
    asn1_tlv sig_alg_tlv;
    if (asn1_der_sequence_next(&sig_alg_tlv, &cur, &rem)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 5;
    }
    out->sig_alg     = sig_alg_tlv.raw;
    out->sig_alg_len = sig_alg_tlv.raw_len;

    /* ---- signatureValue (BIT STRING) ---- */
    asn1_tlv sig_val_tlv;
    if (asn1_der_sequence_next(&sig_val_tlv, &cur, &rem)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 5;
    }
    /* BIT STRING has a leading "unused bits" byte we skip */
    if (sig_val_tlv.tag == ASN1_TAG_BIT_STRING && sig_val_tlv.value_len > 0) {
        out->sig_val     = sig_val_tlv.value + 1;
        out->sig_val_len = sig_val_tlv.value_len - 1;
    } else {
        out->sig_val     = sig_val_tlv.value;
        out->sig_val_len = sig_val_tlv.value_len;
    }

    /* ---- Walk TBSCertificate children ---- */
    const u8 *tc = tbs_tlv.value;
    u64 tr = tbs_tlv.value_len;

    /* Field 0: version [0] EXPLICIT (optional), or serialNumber */
    asn1_tlv field;
    if (asn1_der_sequence_next(&field, &tc, &tr)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 7;
    }

    if (field.tag == ASN1_TAG_CONTEXT_0) {
        /* Explicit wrapper around an INTEGER */
        asn1_tlv ver_int;
        const u8 *vc = field.value;
        u64 vr = field.value_len;
        if (asn1_der_sequence_next(&ver_int, &vc, &vr) == 0) {
            if (ver_int.value_len == 1) {
                out->version = (int)ver_int.value[0];
            }
        }
        /* Now read the serialNumber */
        if (asn1_der_sequence_next(&field, &tc, &tr)) {
            free(owned); memset(out, 0, sizeof(*out));
            return 7;
        }
    } else {
        /* No explicit version tag => v1 (version = 0) */
        out->version = 0;
    }

    /* field is now serialNumber (INTEGER) */
    out->serial     = field.value;
    out->serial_len = field.value_len;

    /* signature (algorithm used to sign) — skip */
    if (skip_tlv(&tc, &tr)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 7;
    }

    /* issuer */
    asn1_tlv issuer_tlv;
    if (asn1_der_sequence_next(&issuer_tlv, &tc, &tr)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 7;
    }
    out->issuer     = issuer_tlv.raw;
    out->issuer_len = issuer_tlv.raw_len;

    /* validity SEQUENCE { notBefore, notAfter } */
    asn1_tlv validity_tlv;
    if (asn1_der_sequence_next(&validity_tlv, &tc, &tr)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 7;
    }
    {
        const u8 *vc2 = validity_tlv.value;
        u64 vr2 = validity_tlv.value_len;
        asn1_tlv nb_tlv, na_tlv;
        if (asn1_der_sequence_next(&nb_tlv, &vc2, &vr2) == 0) {
            out->not_before     = nb_tlv.value;
            out->not_before_len = nb_tlv.value_len;
        }
        if (asn1_der_sequence_next(&na_tlv, &vc2, &vr2) == 0) {
            out->not_after     = na_tlv.value;
            out->not_after_len = na_tlv.value_len;
        }
    }

    /* subject */
    asn1_tlv subject_tlv;
    if (asn1_der_sequence_next(&subject_tlv, &tc, &tr)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 7;
    }
    out->subject     = subject_tlv.raw;
    out->subject_len = subject_tlv.raw_len;

    /* subjectPublicKeyInfo */
    asn1_tlv spki_tlv;
    if (asn1_der_sequence_next(&spki_tlv, &tc, &tr)) {
        free(owned); memset(out, 0, sizeof(*out));
        return 7;
    }
    out->pubkey     = spki_tlv.raw;
    out->pubkey_len = spki_tlv.raw_len;

    /* Remaining optional fields (issuerUniqueID, subjectUniqueID, extensions)
     * are accessible from tbs but not extracted into dedicated fields here. */

    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_verify_chain                                                 */
/*                                                                     */
/*  Walks from the leaf cert up to a trusted CA root in ca_bundle.     */
/*  *out = 0 means chain valid, *out = non-zero = reason code:         */
/*    1 = issuer not found in bundle                                   */
/*    2 = chain exceeds max depth (16)                                 */
/*    3 = root is not self-signed                                      */
/*  Hatches: 1=out null, 2=cert null, 3=ca_bundle null with count>0   */
/* ------------------------------------------------------------------ */

unsigned long x509_verify_chain(unsigned long *out,
                                              const x509_cert *cert,
                                              const x509_cert *ca_bundle,
                                              u64 ca_count) {
    if (!out)  return 1;
    if (!cert) return 2;
    if (!ca_bundle && ca_count > 0) return 3;

    *out = 0;

    /* Self-signed leaf with no CA bundle — accept if issuer==subject */
    if (ca_count == 0) {
        if (cert->issuer_len == cert->subject_len && cert->issuer &&
            cert->subject &&
            memcmp(cert->issuer, cert->subject, (size_t)cert->issuer_len) == 0) {
            *out = 0;
        } else {
            *out = 1;
        }
        return 0;
    }

    /* Walk the chain from leaf upward.  At each step, find the CA whose
       subject matches the current cert's issuer. */
    const x509_cert *current = cert;
    for (int depth = 0; depth < 16; depth++) {
        /* Check if current cert is self-signed — we've reached a root */
        if (current->issuer_len == current->subject_len &&
            current->issuer && current->subject &&
            memcmp(current->issuer, current->subject,
                   (size_t)current->issuer_len) == 0) {
            /* Verify this root is in the trusted bundle */
            int trusted = 0;
            for (u64 i = 0; i < ca_count; i++) {
                if (ca_bundle[i].subject_len == current->subject_len &&
                    ca_bundle[i].subject && current->subject &&
                    memcmp(ca_bundle[i].subject, current->subject,
                           (size_t)current->subject_len) == 0) {
                    trusted = 1;
                    break;
                }
            }
            *out = trusted ? 0 : 1;
            return 0;
        }

        /* Find issuer in the CA bundle */
        const x509_cert *issuer_cert = NULL;
        for (u64 i = 0; i < ca_count; i++) {
            if (ca_bundle[i].subject_len == current->issuer_len &&
                ca_bundle[i].subject && current->issuer &&
                memcmp(ca_bundle[i].subject, current->issuer,
                       (size_t)current->issuer_len) == 0) {
                issuer_cert = &ca_bundle[i];
                break;
            }
        }

        if (!issuer_cert) {
            *out = 1;
            return 0;
        }

        current = issuer_cert;
    }

    *out = 2; /* chain too long */
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_get_subject                                                  */
/* ------------------------------------------------------------------ */

unsigned long x509_get_subject(const u8 **out, u64 *out_len,
                                             const x509_cert *cert) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!cert)    return 3;
    *out     = cert->subject;
    *out_len = cert->subject_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_get_issuer                                                   */
/* ------------------------------------------------------------------ */

unsigned long x509_get_issuer(const u8 **out, u64 *out_len,
                                            const x509_cert *cert) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!cert)    return 3;
    *out     = cert->issuer;
    *out_len = cert->issuer_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_get_serial                                                   */
/* ------------------------------------------------------------------ */

unsigned long x509_get_serial(const u8 **out, u64 *out_len,
                                            const x509_cert *cert) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!cert)    return 3;
    *out     = cert->serial;
    *out_len = cert->serial_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_get_validity                                                 */
/* ------------------------------------------------------------------ */

unsigned long x509_get_validity(const u8 **not_before,
                                              u64 *not_before_len,
                                              const u8 **not_after,
                                              u64 *not_after_len,
                                              const x509_cert *cert) {
    if (!not_before)     return 1;
    if (!not_before_len) return 2;
    if (!not_after)      return 3;
    if (!not_after_len)  return 4;
    if (!cert)           return 5;
    *not_before     = cert->not_before;
    *not_before_len = cert->not_before_len;
    *not_after      = cert->not_after;
    *not_after_len  = cert->not_after_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_get_pubkey                                                   */
/* ------------------------------------------------------------------ */

unsigned long x509_get_pubkey(const u8 **out, u64 *out_len,
                                            const x509_cert *cert) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!cert)    return 3;
    *out     = cert->pubkey;
    *out_len = cert->pubkey_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_get_san — find SAN extension in v3 extensions                */
/* ------------------------------------------------------------------ */

/* OID 2.5.29.17 = 55 1D 11 */
static const u8 SAN_OID[] = { 0x55, 0x1D, 0x11 };

unsigned long x509_get_san(const u8 **out, u64 *out_len,
                                         const x509_cert *cert) {
    if (!out)     return 1;
    if (!out_len) return 2;
    if (!cert)    return 3;

    if (cert->version < 2) return 4; /* v3 required for extensions */

    /* Walk TBS to find extensions [3] EXPLICIT */
    const u8 *tc = cert->tbs;
    u64 tr = cert->tbs_len;

    /* Decode the TBS outer SEQUENCE to get inside */
    asn1_tlv tbs_outer;
    if (asn1_der_decode(&tbs_outer, tc, tr)) return 4;
    tc = tbs_outer.value;
    tr = tbs_outer.value_len;

    /* Skip all fields until we hit a CONTEXT_3 tag */
    while (tr > 0) {
        asn1_tlv elem;
        const u8 *save_tc = tc;
        u64 save_tr = tr;
        if (asn1_der_sequence_next(&elem, &tc, &tr)) break;
        if (elem.tag == ASN1_TAG_CONTEXT_3) {
            /* EXPLICIT wrapper around a SEQUENCE of extensions */
            const u8 *ec = elem.value;
            u64 er = elem.value_len;
            asn1_tlv ext_seq;
            if (asn1_der_sequence_next(&ext_seq, &ec, &er)) return 4;
            /* Walk extensions */
            const u8 *xc = ext_seq.value;
            u64 xr = ext_seq.value_len;
            while (xr > 0) {
                asn1_tlv ext_entry;
                if (asn1_der_sequence_next(&ext_entry, &xc, &xr)) break;
                if (ext_entry.tag != ASN1_TAG_SEQUENCE) continue;
                /* Each extension: SEQUENCE { OID, [BOOL,] OCTET STRING } */
                const u8 *eec = ext_entry.value;
                u64 eer = ext_entry.value_len;
                asn1_tlv oid_tlv;
                if (asn1_der_sequence_next(&oid_tlv, &eec, &eer)) continue;
                if (oid_tlv.tag != ASN1_TAG_OID) continue;
                if (oid_tlv.value_len == sizeof(SAN_OID) &&
                    memcmp(oid_tlv.value, SAN_OID, sizeof(SAN_OID)) == 0) {
                    /* Found SAN. Next is optional BOOLEAN (critical), then OCTET STRING */
                    asn1_tlv val_tlv;
                    if (asn1_der_sequence_next(&val_tlv, &eec, &eer)) return 4;
                    if (val_tlv.tag == ASN1_TAG_BOOLEAN) {
                        /* Skip critical flag, get next */
                        if (asn1_der_sequence_next(&val_tlv, &eec, &eer)) return 4;
                    }
                    /* val_tlv should be OCTET STRING wrapping the SAN SEQUENCE */
                    *out     = val_tlv.value;
                    *out_len = val_tlv.value_len;
                    return 0;
                }
            }
            return 4; /* Extensions found but no SAN */
        }
        (void)save_tc;
        (void)save_tr;
    }

    return 4; /* No extensions block found */
}

/* ------------------------------------------------------------------ */
/*  x509_is_expired                                                   */
/* ------------------------------------------------------------------ */

unsigned long x509_is_expired(unsigned long *out,
                                            const x509_cert *cert,
                                            u64 current_time) {
    if (!out)  return 1;
    if (!cert) return 2;

    u64 nb = time_to_epoch(cert->not_before, cert->not_before_len);
    u64 na = time_to_epoch(cert->not_after,  cert->not_after_len);

    *out = (current_time < nb || current_time > na) ? 1UL : 0UL;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_is_self_signed                                               */
/* ------------------------------------------------------------------ */

unsigned long x509_is_self_signed(unsigned long *out,
                                                const x509_cert *cert) {
    if (!out)  return 1;
    if (!cert) return 2;

    if (cert->issuer_len == cert->subject_len &&
        cert->issuer && cert->subject &&
        memcmp(cert->issuer, cert->subject, (size_t)cert->issuer_len) == 0) {
        *out = 1;
    } else {
        *out = 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  x509_fingerprint                                                  */
/* ------------------------------------------------------------------ */

unsigned long x509_fingerprint(u8 *out,
                                             const x509_cert *cert) {
    if (!out)  return 1;
    if (!cert) return 2;

    return sha256_digest(out, cert->der_data, cert->der_len);
}

/* ------------------------------------------------------------------ */
/*  x509_destroy                                                      */
/* ------------------------------------------------------------------ */

unsigned long x509_destroy(x509_cert *cert) {
    if (!cert) return 1;

    if (cert->der_data) {
        free(cert->der_data);
    }
    memset(cert, 0, sizeof(*cert));
    return 0;
}
/* ------------------------------------------------------------------ */
/*  PKCS#10 CSR (RFC 2986)                                            */
/* ------------------------------------------------------------------ */
/*
 *  CertificationRequest ::= SEQUENCE {
 *      certificationRequestInfo  CertificationRequestInfo,
 *      signatureAlgorithm        AlgorithmIdentifier,
 *      signature                 BIT STRING
 *  }
 *
 *  CertificationRequestInfo ::= SEQUENCE {
 *      version                   INTEGER { v1(0) },
 *      subject                   Name,
 *      subjectPKInfo             SubjectPublicKeyInfo,
 *      attributes            [0] Attributes
 *  }
 *
 *  We accept the already-DER-encoded Name and SubjectPublicKeyInfo
 *  blobs from the caller and assemble the surrounding structure.
 */

/* Build a CertificationRequestInfo (TBS) DER blob. */
unsigned long x509_csr_create(u8 **out, u64 *out_len,
                                            const u8 *subject_der,
                                            u64 subject_len,
                                            const u8 *pubkey_der,
                                            u64 pubkey_len) {
    if (!out)         return 1;
    if (!out_len)     return 2;
    if (!subject_der) return 3;
    if (!pubkey_der)  return 4;

    *out     = NULL;
    *out_len = 0;

    unsigned long rc;
    buf inner;
    rc = buf_create(&inner, 32 + subject_len + pubkey_len);
    if (rc) return 5;

    /* version  INTEGER 0 (v1) */
    {
        u8 zero = 0x00;
        rc = asn1_der_encode_integer(&inner, &zero, 1);
        if (rc) { buf_destroy(&inner); return 5; }
    }

    /* subject  Name — already DER-encoded; pass through verbatim */
    if (subject_len > 0) {
        rc = buf_append(&inner, (u8 *)subject_der, subject_len);
        if (rc) { buf_destroy(&inner); return 5; }
    }

    /* subjectPKInfo  SubjectPublicKeyInfo — already DER-encoded */
    if (pubkey_len > 0) {
        rc = buf_append(&inner, (u8 *)pubkey_der, pubkey_len);
        if (rc) { buf_destroy(&inner); return 5; }
    }

    /* attributes [0] IMPLICIT SET OF Attribute — empty */
    rc = asn1_der_encode(&inner, ASN1_TAG_CONTEXT_0, NULL, 0);
    if (rc) { buf_destroy(&inner); return 5; }

    /* Wrap everything in an outer SEQUENCE. */
    buf outer;
    rc = buf_create(&outer, inner.len + 16);
    if (rc) { buf_destroy(&inner); return 5; }

    rc = asn1_der_encode_sequence(&outer, inner.data, inner.len);
    buf_destroy(&inner);
    if (rc) { buf_destroy(&outer); return 5; }

    /* Hand the bytes off to the caller as a plain malloc'd blob.  We copy
     * so the lifecycle is independent of our internal buf allocator. */
    u8 *result = (u8 *)malloc((size_t)outer.len);
    if (!result) { buf_destroy(&outer); return 5; }
    memcpy(result, outer.data, (size_t)outer.len);
    *out     = result;
    *out_len = outer.len;
    buf_destroy(&outer);

    return 0;
}

/* Wrap TBS + AlgorithmIdentifier + signature into a CertificationRequest. */
unsigned long x509_csr_sign(u8 **out, u64 *out_len,
                                          const u8 *tbs, u64 tbs_len,
                                          const u8 *sig_algo_der,
                                          u64 sig_algo_len,
                                          const u8 *signature,
                                          u64 sig_len) {
    if (!out)          return 1;
    if (!out_len)      return 2;
    if (!tbs)          return 3;
    if (!sig_algo_der) return 4;
    if (!signature)    return 5;

    *out     = NULL;
    *out_len = 0;

    unsigned long rc;

    /* Build the BIT STRING contents: one leading "unused bits" byte (0)
     * followed by the raw signature octets. */
    buf sig_bits;
    rc = buf_create(&sig_bits, sig_len + 1);
    if (rc) return 6;
    rc = buf_append_byte(&sig_bits, 0x00);
    if (rc) { buf_destroy(&sig_bits); return 6; }
    if (sig_len > 0) {
        rc = buf_append(&sig_bits, (u8 *)signature, sig_len);
        if (rc) { buf_destroy(&sig_bits); return 6; }
    }

    /* Assemble the SEQUENCE body: tbs || AlgorithmIdentifier || BIT STRING */
    buf body;
    rc = buf_create(&body, tbs_len + sig_algo_len + sig_bits.len + 8);
    if (rc) { buf_destroy(&sig_bits); return 6; }

    if (tbs_len > 0) {
        rc = buf_append(&body, (u8 *)tbs, tbs_len);
        if (rc) { buf_destroy(&body); buf_destroy(&sig_bits); return 6; }
    }
    if (sig_algo_len > 0) {
        rc = buf_append(&body, (u8 *)sig_algo_der, sig_algo_len);
        if (rc) { buf_destroy(&body); buf_destroy(&sig_bits); return 6; }
    }
    rc = asn1_der_encode(&body, ASN1_TAG_BIT_STRING,
                         sig_bits.data, sig_bits.len);
    buf_destroy(&sig_bits);
    if (rc) { buf_destroy(&body); return 6; }

    /* Wrap the whole thing in an outer SEQUENCE. */
    buf outer;
    rc = buf_create(&outer, body.len + 16);
    if (rc) { buf_destroy(&body); return 6; }

    rc = asn1_der_encode_sequence(&outer, body.data, body.len);
    buf_destroy(&body);
    if (rc) { buf_destroy(&outer); return 6; }

    u8 *result = (u8 *)malloc((size_t)outer.len);
    if (!result) { buf_destroy(&outer); return 6; }
    memcpy(result, outer.data, (size_t)outer.len);
    *out     = result;
    *out_len = outer.len;
    buf_destroy(&outer);

    return 0;
}
