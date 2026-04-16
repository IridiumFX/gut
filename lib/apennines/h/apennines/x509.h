#ifndef APENNINES_T2_CRYPTO_X509_H
#define APENNINES_T2_CRYPTO_X509_H


#include "apennines/types.h"

typedef struct {
    u8 *der_data;     /* owned copy of DER bytes */
    u64 der_len;
    /* Parsed pointers into der_data: */
    const u8 *tbs;    u64 tbs_len;       /* TBSCertificate (raw TLV) */
    const u8 *issuer; u64 issuer_len;    /* issuer Name (raw TLV) */
    const u8 *subject; u64 subject_len;  /* subject Name (raw TLV) */
    const u8 *serial; u64 serial_len;    /* serial number value bytes */
    const u8 *not_before; u64 not_before_len;
    const u8 *not_after;  u64 not_after_len;
    const u8 *pubkey; u64 pubkey_len;    /* SubjectPublicKeyInfo (raw TLV) */
    const u8 *sig_alg; u64 sig_alg_len;  /* signature algorithm (raw TLV) */
    const u8 *sig_val; u64 sig_val_len;  /* signature value bytes */
    int version;   /* 0=v1, 1=v2, 2=v3 */
} x509_cert;

/* Parse a certificate from DER bytes or PEM text (auto-detected).
 * Hatches: 1=out null, 2=data null, 3=len zero, 4=PEM decode failed,
 *          5=outer SEQUENCE invalid, 6=TBSCertificate invalid,
 *          7=TBS inner parse failed, 8=malloc failed */
unsigned long x509_parse(x509_cert *out,
                                       const u8 *data, u64 len);

/* Verify certificate chain (stub — returns hatch 99, T3 PKI will implement) */
unsigned long x509_verify_chain(unsigned long *out,
                                              const x509_cert *cert,
                                              const x509_cert *ca_bundle,
                                              u64 ca_count);

/* Extract subject Name (raw DER bytes, pointer into cert's owned data) */
unsigned long x509_get_subject(const u8 **out, u64 *out_len,
                                             const x509_cert *cert);

/* Extract issuer Name */
unsigned long x509_get_issuer(const u8 **out, u64 *out_len,
                                            const x509_cert *cert);

/* Extract serial number (raw integer bytes) */
unsigned long x509_get_serial(const u8 **out, u64 *out_len,
                                            const x509_cert *cert);

/* Extract validity period (not_before/not_after as raw time strings) */
unsigned long x509_get_validity(const u8 **not_before,
                                              u64 *not_before_len,
                                              const u8 **not_after,
                                              u64 *not_after_len,
                                              const x509_cert *cert);

/* Extract SubjectPublicKeyInfo */
unsigned long x509_get_pubkey(const u8 **out, u64 *out_len,
                                            const x509_cert *cert);

/* Extract Subject Alternative Names (raw extensions value).
 * Hatches: 1=out null, 2=out_len null, 3=cert null, 4=no SAN found */
unsigned long x509_get_san(const u8 **out, u64 *out_len,
                                         const x509_cert *cert);

/* Check if certificate is expired given current_time as UTC epoch seconds.
 * *out = 1 if expired, 0 if valid.
 * Hatches: 1=out null, 2=cert null */
unsigned long x509_is_expired(unsigned long *out,
                                            const x509_cert *cert,
                                            u64 current_time);

/* Check if certificate is self-signed (issuer == subject).
 * *out = 1 if self-signed, 0 otherwise.
 * Hatches: 1=out null, 2=cert null */
unsigned long x509_is_self_signed(unsigned long *out,
                                                const x509_cert *cert);

/* Compute SHA-256 fingerprint of the raw DER encoding.
 * out must point to at least 32 bytes.
 * Hatches: 1=out null, 2=cert null */
unsigned long x509_fingerprint(u8 *out,
                                             const x509_cert *cert);

/* Free all resources owned by the cert struct. */
unsigned long x509_destroy(x509_cert *cert);

/* Build the CertificationRequestInfo (TBS) DER bytes of a PKCS#10 CSR
 * (RFC 2986).  subject_der is a ready-to-use Name (SEQUENCE OF RDN) DER
 * blob; pubkey_der is a full SubjectPublicKeyInfo DER blob.  Attributes
 * are encoded as an empty [0] IMPLICIT SET (no requested extensions).
 * *out receives malloc'd bytes that the caller must free().
 * Hatches: 1=out null, 2=out_len null, 3=subject null, 4=pubkey null,
 *          5=alloc / encode failure */
unsigned long x509_csr_create(u8 **out, u64 *out_len,
                                            const u8 *subject_der,
                                            u64 subject_len,
                                            const u8 *pubkey_der,
                                            u64 pubkey_len);

/* Wrap a previously-built TBS blob and its signature into the full
 * CertificationRequest DER (RFC 2986):
 *   SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING signature }.
 * sig_algo_der is the full AlgorithmIdentifier TLV (e.g., the DER
 * encoding of  SEQUENCE { OID ecdsa-with-SHA256 }  ).
 * *out receives malloc'd bytes that the caller must free().
 * Hatches: 1=out null, 2=out_len null, 3=tbs null, 4=sig_algo null,
 *          5=signature null, 6=alloc / encode failure */
unsigned long x509_csr_sign(u8 **out, u64 *out_len,
                                          const u8 *tbs, u64 tbs_len,
                                          const u8 *sig_algo_der,
                                          u64 sig_algo_len,
                                          const u8 *signature,
                                          u64 sig_len);

#endif /* APENNINES_T2_CRYPTO_X509_H */
