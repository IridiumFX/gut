#ifndef APENNINES_T2_CRYPTO_RSA_H
#define APENNINES_T2_CRYPTO_RSA_H

#include "apennines/types.h"
#include "apennines/buf.h"
#include "apennines/bigint.h"

#define RSA_KEY_SIZE_2048 2048
#define RSA_KEY_SIZE_4096 4096

typedef struct {
    bigint n;    /* modulus */
    bigint e;    /* public exponent */
} rsa_pubkey;

typedef struct {
    bigint n;    /* modulus */
    bigint d;    /* private exponent */
    bigint p;    /* prime factor 1 */
    bigint q;    /* prime factor 2 */
    bigint dp;   /* d mod (p-1) */
    bigint dq;   /* d mod (q-1) */
    bigint qinv; /* q^-1 mod p */
    bigint e;    /* public exponent */
} rsa_privkey;

typedef struct {
    rsa_pubkey pub;
    rsa_privkey priv;
} rsa_keypair;

/* Key generation: hatches 1=null out, 2=invalid bit_size, 3=prime gen fail, 4=key computation fail */
unsigned long rsa_keygen(rsa_keypair *out, u64 bit_size);

/* OAEP encrypt (SHA-256): hatches 1=null out, 2=null key, 3=null pt when pt_len>0,
   4=plaintext too long, 5=padding fail, 6=encrypt fail */
unsigned long rsa_encrypt_oaep(buf *out, rsa_pubkey *key,
                                             const u8 *plaintext, u64 pt_len);

/* OAEP decrypt: hatches 1=null out, 2=null key, 3=null ct, 4=ct_len mismatch,
   5=decrypt fail, 6=padding invalid */
unsigned long rsa_decrypt_oaep(buf *out, rsa_privkey *key,
                                             const u8 *ciphertext, u64 ct_len);

/* PSS sign (SHA-256): hatches 1=null out, 2=null key, 3=null msg when msg_len>0, 4=sign fail */
unsigned long rsa_sign_pss(buf *out, rsa_privkey *key,
                                         const u8 *message, u64 msg_len);

/* PSS verify: hatches 1=null valid, 2=null key, 3=null sig, 4=null msg when msg_len>0,
   5=verify fail */
unsigned long rsa_verify_pss(unsigned long *valid, rsa_pubkey *key,
                                           const u8 *signature, u64 sig_len,
                                           const u8 *message, u64 msg_len);

/* DER export (PKCS#1 RSAPublicKey): hatches 1=null out, 2=null key, 3=encode fail */
unsigned long rsa_pubkey_export_der(buf *out, rsa_pubkey *key);

/* DER export (PKCS#1 RSAPrivateKey): hatches 1=null out, 2=null key, 3=encode fail */
unsigned long rsa_privkey_export_der(buf *out, rsa_privkey *key);

/* DER import (PKCS#1 RSAPublicKey): hatches 1=null out, 2=null data, 3=parse fail */
unsigned long rsa_pubkey_import_der(rsa_pubkey *out, const u8 *data, u64 len);

/* DER import (PKCS#1 RSAPrivateKey): hatches 1=null out, 2=null data, 3=parse fail */
unsigned long rsa_privkey_import_der(rsa_privkey *out, const u8 *data, u64 len);

/* Destroy: hatch 1=null key */
unsigned long rsa_pubkey_destroy(rsa_pubkey *key);
unsigned long rsa_privkey_destroy(rsa_privkey *key);
unsigned long rsa_keypair_destroy(rsa_keypair *kp);

/* PKCS#1 v1.5 sign (RFC 8017 §8.2, SHA-256).
   The message is hashed internally with SHA-256, then wrapped in the
   SHA-256 DigestInfo ASN.1 structure, padded EMSA-PKCS1-v1_5 style, and
   signed with the RSA private key.
   Hatches: 1=null out, 2=null key, 3=null msg when msg_len>0,
            4=modulus too small, 5=sign fail */
unsigned long rsa_sign_pkcs1v15(buf *out, rsa_privkey *key,
                                               const u8 *message, u64 msg_len);

/* PKCS#1 v1.5 verify (RFC 8017 §8.2, SHA-256).
   *valid set to 1 on success, 0 on failure.
   Hatches: 1=null valid, 2=null key, 3=null sig,
            4=null msg when msg_len>0, 5=signature length mismatch */
unsigned long rsa_verify_pkcs1v15(unsigned long *valid,
                                                 rsa_pubkey *key,
                                                 const u8 *signature,
                                                 u64 sig_len,
                                                 const u8 *message,
                                                 u64 msg_len);

#endif /* APENNINES_T2_CRYPTO_RSA_H */
