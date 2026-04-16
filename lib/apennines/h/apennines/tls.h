#ifndef APENNINES_T3_TLS_H
#define APENNINES_T3_TLS_H


#include "apennines/types.h"
#include "apennines/tcp.h"

/* ================================================================
 *  TLS 1.2/1.3 — client and server connections
 *
 *  Composes: cipher (AES-GCM, ChaCha20), hash (HMAC, HKDF),
 *  ec (X25519), ecdsa (P-256 ECDH), x509, pki, ct, secret
 * ================================================================ */

#define TLS_VERSION_12  0x0303
#define TLS_VERSION_13  0x0304

#define TLS_VERIFY_NONE     0
#define TLS_VERIFY_PEER     1
#define TLS_VERIFY_REQUIRED 2

typedef struct tls_config tls_config;
typedef struct tls_conn   tls_conn;

/* ---- Configuration ---- */

unsigned long tls_config_create(tls_config **out);

/* Set certificate chain (PEM or DER). */
unsigned long tls_config_set_cert(tls_config *cfg,
                                                 const u8 *data, u64 len);

/* Set private key (PEM or DER). */
unsigned long tls_config_set_key(tls_config *cfg,
                                                const u8 *data, u64 len);

/* Set CA bundle for peer verification (PEM). */
unsigned long tls_config_set_ca(tls_config *cfg,
                                               const u8 *data, u64 len);

/* Set ALPN protocol list (null-terminated strings, NULL-terminated array). */
unsigned long tls_config_set_alpn(tls_config *cfg,
                                                 const char **protocols);

/* Set min/max TLS versions. */
unsigned long tls_config_set_versions(tls_config *cfg,
                                                     u16 min_ver, u16 max_ver);

/* Set verification mode. */
unsigned long tls_config_set_verify_mode(tls_config *cfg,
                                                        int mode);

unsigned long tls_config_destroy(tls_config *cfg);

/* ---- Connection ---- */

/* Wrap a TCP connection as TLS client, perform handshake.
 * Hatches: 1=null out, 2=null tcp, 3=null cfg, 4=handshake failed,
 *          5=certificate verification failed, 6=alloc failure */
unsigned long tls_conn_create_client(tls_conn **out,
                                                    tcp_conn *tcp,
                                                    tls_config *cfg,
                                                    const char *hostname);

/* Wrap a TCP connection as TLS server, perform handshake.
 * Hatches: 1=null out, 2=null tcp, 3=null cfg, 4=handshake failed,
 *          5=no cert/key configured, 6=alloc failure */
unsigned long tls_conn_create_server(tls_conn **out,
                                                    tcp_conn *tcp,
                                                    tls_config *cfg);

unsigned long tls_conn_read(u64 *bytes_read, tls_conn *conn,
                                           u8 *buf, u64 len);
unsigned long tls_conn_write(u64 *bytes_written, tls_conn *conn,
                                            const u8 *data, u64 len);
unsigned long tls_conn_write_all(u64 *bytes_written, tls_conn *conn,
                                                const u8 *data, u64 len);

/* Get peer certificate (DER). Pointer valid until conn destroyed. */
unsigned long tls_conn_peer_cert(const u8 **out, u64 *out_len,
                                                tls_conn *conn);

/* Get negotiated ALPN protocol (null-terminated). */
unsigned long tls_conn_alpn_selected(const char **out,
                                                    tls_conn *conn);

/* Get negotiated cipher suite name. */
unsigned long tls_conn_cipher(const char **out, tls_conn *conn);

/* Get negotiated TLS version. */
unsigned long tls_conn_version(u16 *out, tls_conn *conn);

/* Send close_notify. */
unsigned long tls_conn_shutdown(tls_conn *conn);

unsigned long tls_conn_destroy(tls_conn *conn);

#endif /* APENNINES_T3_TLS_H */
