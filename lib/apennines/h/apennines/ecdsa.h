#ifndef APENNINES_T2_CRYPTO_ECDSA_H
#define APENNINES_T2_CRYPTO_ECDSA_H


#include "apennines/types.h"

/* ---- P-256 (secp256r1) constants ---- */

#define ECDSA_P256_PRIVKEY_LEN  32
#define ECDSA_P256_PUBKEY_LEN   65  /* 0x04 || x(32) || y(32) uncompressed */
#define ECDSA_P256_SIG_LEN      64  /* r(32) || s(32) */
#define ECDSA_P256_SHARED_LEN   32

/* ---- Types ---- */

typedef struct { u8 data[ECDSA_P256_PRIVKEY_LEN]; } ecdsa_privkey;
typedef struct { u8 data[ECDSA_P256_PUBKEY_LEN]; }  ecdsa_pubkey;   /* 04 || x || y */
typedef struct { u8 r[32]; u8 s[32]; }               ecdsa_sig;
typedef struct { u8 data[ECDSA_P256_SHARED_LEN]; }   ecdh_secret;

/* ---- Key generation ---- */

/* Generate a random ECDSA key pair on the P-256 curve.
   Hatches: 1=null priv, 2=null pub, 3=entropy fail, 4=keygen fail */
unsigned long ecdsa_keygen(ecdsa_privkey *priv, ecdsa_pubkey *pub);

/* Deterministic keygen from a 32-byte seed.
   Hatches: 1=null priv, 2=null pub, 3=null seed, 4=invalid seed (zero or >= n) */
unsigned long ecdsa_keygen_from_seed(ecdsa_privkey *priv,
                                                    ecdsa_pubkey *pub,
                                                    const u8 *seed32);

/* Derive the uncompressed public key from a private key.
   Hatches: 1=null pub, 2=null priv, 3=invalid privkey */
unsigned long ecdsa_pubkey_derive(ecdsa_pubkey *pub,
                                                 const ecdsa_privkey *priv);

/* ---- ECDSA sign / verify ---- */

/* Sign a message with ECDSA-SHA256 using RFC 6979 deterministic nonce.
   The message is hashed internally with SHA-256.
   Hatches: 1=null sig, 2=null key, 3=null msg when msg_len>0, 4=invalid key,
            5=signing fail */
unsigned long ecdsa_sign(ecdsa_sig *sig,
                                        const ecdsa_privkey *key,
                                        const u8 *msg, u64 msg_len);

/* Verify an ECDSA-SHA256 signature. *valid is set to 1 if OK, 0 if bad.
   Hatches: 1=null valid, 2=null pub, 3=null msg when msg_len>0, 4=null sig,
            5=invalid pubkey */
unsigned long ecdsa_verify(u64 *valid,
                                          const ecdsa_pubkey *pub,
                                          const u8 *msg, u64 msg_len,
                                          const ecdsa_sig *sig);

/* ---- ECDH ---- */

/* Compute ECDH shared secret (x-coordinate of privkey * peer_pub).
   Hatches: 1=null out, 2=null priv, 3=null peer_pub, 4=invalid privkey,
            5=invalid peer pubkey, 6=result at infinity */
unsigned long ecdh_compute(ecdh_secret *out,
                                          const ecdsa_privkey *priv,
                                          const ecdsa_pubkey *peer_pub);

#endif /* APENNINES_T2_CRYPTO_ECDSA_H */
