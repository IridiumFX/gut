#ifndef APENNINES_T2_CRYPTO_EC_H
#define APENNINES_T2_CRYPTO_EC_H


#include "apennines/types.h"

/* ---- Ed25519 constants ---- */

#define ED25519_PUBKEY_LEN   32
#define ED25519_PRIVKEY_LEN  64  /* expanded: scalar(32) + prefix(32) */
#define ED25519_SEED_LEN     32
#define ED25519_SIG_LEN      64

/* ---- X25519 constants ---- */

#define X25519_KEY_LEN       32
#define X25519_SHARED_LEN    32

/* ---- Ed25519 types ---- */

typedef struct { u8 data[ED25519_PUBKEY_LEN]; }  ed25519_pubkey;
typedef struct { u8 data[ED25519_SEED_LEN]; }    ed25519_seed;
typedef struct { u8 data[ED25519_PRIVKEY_LEN]; } ed25519_privkey;
typedef struct {
    ed25519_pubkey  pub;
    ed25519_privkey priv;
    ed25519_seed    seed;
} ed25519_keypair;

/* ---- X25519 types ---- */

typedef struct { u8 data[X25519_KEY_LEN]; } x25519_pubkey;
typedef struct { u8 data[X25519_KEY_LEN]; } x25519_privkey;
typedef struct {
    x25519_pubkey  pub;
    x25519_privkey priv;
} x25519_keypair;

/* ---- Ed25519 functions ---- */

/* Generate key pair from random seed.
   Hatches: 1=null out, 2=entropy fail, 3=expand fail */
unsigned long ed25519_keygen(ed25519_keypair *out);

/* Deterministic keygen from seed.
   Hatches: 1=null out, 2=null seed */
unsigned long ed25519_keygen_from_seed(ed25519_keypair *out,
                                                     const ed25519_seed *seed);

/* Sign message, output 64-byte signature.
   Hatches: 1=null sig_out, 2=null key, 3=null pub, 4=null msg when msg_len>0,
            5=computation fail */
unsigned long ed25519_sign(u8 *sig_out,
                                         const ed25519_privkey *key,
                                         const ed25519_pubkey *pub,
                                         const u8 *msg, u64 msg_len);

/* Verify signature. *valid set to 1 if OK, 0 if bad.
   Hatches: 1=null valid, 2=null pub, 3=null sig, 4=null msg when msg_len>0 */
unsigned long ed25519_verify(unsigned long *valid,
                                           const ed25519_pubkey *pub,
                                           const u8 *sig,
                                           const u8 *msg, u64 msg_len);

/* Derive public key from expanded private key.
   Hatches: 1=null out, 2=null priv */
unsigned long ed25519_pubkey_from_privkey(ed25519_pubkey *out,
                                                        const ed25519_privkey *priv);

/* ---- X25519 functions ---- */

/* Generate X25519 key pair.
   Hatches: 1=null out, 2=entropy fail */
unsigned long x25519_keygen(x25519_keypair *out);

/* Compute 32-byte shared secret.
   Hatches: 1=null shared_out, 2=null priv, 3=null pub, 4=low-order point */
unsigned long x25519_dh(u8 *shared_out,
                                      const x25519_privkey *priv,
                                      const x25519_pubkey *pub);

/* Derive public key from private key (scalar * base point 9).
   Hatches: 1=null out, 2=null priv */
unsigned long x25519_pubkey_from_privkey(x25519_pubkey *out,
                                                       const x25519_privkey *priv);

#endif /* APENNINES_T2_CRYPTO_EC_H */
