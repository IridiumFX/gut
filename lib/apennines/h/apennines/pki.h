#ifndef APENNINES_T3_PKI_H
#define APENNINES_T3_PKI_H


#include "apennines/types.h"

/* ================================================================
 *  PKI — certificate trust store, CRL, OCSP
 * ================================================================ */

typedef struct pki_store pki_store;

typedef struct {
    u8  *data;      /* DER-encoded certificate */
    u64  len;
} pki_cert;

typedef struct {
    u8  *data;      /* DER-encoded CRL */
    u64  len;
} pki_crl;

/* Verification result */
typedef struct {
    int   valid;            /* 1=trusted chain, 0=untrusted */
    int   expired;          /* 1=any cert in chain expired */
    int   revoked;          /* 1=leaf is revoked per CRL */
    u32   chain_length;     /* depth of verified chain */
} pki_verify_result;

/* ---- Trust store ---- */

/* Hatches: 1=null out, 2=alloc failure */
unsigned long pki_store_create(pki_store **out);

/* Hatches: 1=null store, 2=null cert, 3=invalid DER, 4=alloc failure */
unsigned long pki_store_add_cert(pki_store *store,
                                                const pki_cert *cert);

/* Hatches: 1=null store, 2=null crl, 3=invalid DER, 4=alloc failure */
unsigned long pki_store_add_crl(pki_store *store,
                                               const pki_crl *crl);

/* Load system CA bundle (platform-specific).
 * Hatches: 1=null store, 2=no system store available, 3=load error */
unsigned long pki_store_load_system(pki_store *store);

/* Verify a certificate chain.
 *   out:        receives verification result
 *   store:      trust store
 *   chain:      array of DER certs (leaf first, root last)
 *   chain_len:  number of certificates
 *   now_unix:   current time for expiry check
 *
 * Hatches: 1=null out, 2=null store, 3=null chain, 4=empty chain,
 *          5=parse error, 6=verify error */
unsigned long pki_store_verify(pki_verify_result *out,
                                              const pki_store *store,
                                              const pki_cert *chain,
                                              u64 chain_len,
                                              u64 now_unix);

/* Hatches: 1=null store */
unsigned long pki_store_destroy(pki_store *store);

/* ---- OCSP ---- */

/* Build an OCSP request for a certificate.
 *   out:       receives DER-encoded OCSP request (caller frees)
 *   out_len:   receives request length
 *   cert:      subject certificate
 *   issuer:    issuer certificate
 *
 * Hatches: 1=null out, 2=null out_len, 3=null cert, 4=null issuer,
 *          5=parse error, 6=alloc failure */
unsigned long ocsp_request_build(u8 **out, u64 *out_len,
                                                const pki_cert *cert,
                                                const pki_cert *issuer);

/* Parse an OCSP response.
 *   out_status:    receives 0=good, 1=revoked, 2=unknown
 *   response:      DER-encoded OCSP response
 *   response_len:  response length
 *
 * Hatches: 1=null out_status, 2=null response, 3=malformed,
 *          4=response error status */
unsigned long ocsp_response_parse(int *out_status,
                                                 const u8 *response,
                                                 u64 response_len);

/* Verify OCSP response signature against issuer.
 *   out_valid:     receives 1 if valid, 0 if not
 *   response:      DER-encoded OCSP response
 *   response_len:  response length
 *   issuer:        issuer certificate
 *
 * Hatches: 1=null out_valid, 2=null response, 3=null issuer,
 *          4=parse error, 5=verify error */
unsigned long ocsp_response_verify(int *out_valid,
                                                  const u8 *response,
                                                  u64 response_len,
                                                  const pki_cert *issuer);

/* Validate a stapled OCSP response for a given cert+issuer.
 *   out_status:    receives 0=good, 1=revoked, 2=unknown
 *   stapled:       stapled OCSP response bytes
 *   stapled_len:   length
 *   cert:          subject certificate
 *   issuer:        issuer certificate
 *   now_unix:      current time
 *
 * Hatches: 1=null out_status, 2=null stapled, 3=null cert,
 *          4=null issuer, 5=parse error, 6=expired, 7=verify error */
unsigned long ocsp_staple_validate(int *out_status,
                                                  const u8 *stapled,
                                                  u64 stapled_len,
                                                  const pki_cert *cert,
                                                  const pki_cert *issuer,
                                                  u64 now_unix);

#endif /* APENNINES_T3_PKI_H */
