#ifndef APENNINES_T3_SSH_H
#define APENNINES_T3_SSH_H

#include "apennines/types.h"

/* ================================================================
 *  SSH Transport — RFC 4253/4252 connection, auth, channels
 * ================================================================ */

typedef struct ssh_conn    ssh_conn;
typedef struct ssh_channel ssh_channel;

/* ---- Connection ---- */

/* ssh_conn_create — create SSH connection (TCP + key exchange).
 *   out:   receives connection handle
 *   host:  server hostname
 *   port:  server port (usually 22)
 *
 * Hatches: 1=null out, 2=null host, 3=tcp connect failed,
 *          4=version exchange failed, 5=key exchange failed,
 *          6=alloc failure */
unsigned long ssh_conn_create(ssh_conn **out,
                                             const char *host, u16 port);

/* ssh_conn_auth_password — authenticate with password.
 * Hatches: 1=null conn, 2=null username, 3=null password,
 *          4=auth rejected, 5=protocol error */
unsigned long ssh_conn_auth_password(ssh_conn *conn,
                                                    const char *username,
                                                    const char *password);

/* ssh_conn_auth_pubkey — authenticate with public key.
 * Hatches: 1=null conn, 2=null username, 3=null privkey,
 *          4=auth rejected, 5=sign failure, 6=protocol error */
unsigned long ssh_conn_auth_pubkey(ssh_conn *conn,
                                                  const char *username,
                                                  const u8 *privkey, u64 privkey_len);

/* ssh_conn_auth_agent — authenticate via the running ssh-agent.
 *
 * Connects to the agent at $SSH_AUTH_SOCK (preferred, works on both
 * POSIX and Windows if exposed as AF_UNIX) or falls back to the
 * Windows named pipe \\.\pipe\openssh-ssh-agent. Picks the first
 * ed25519 identity the agent advertises and delegates session-ID
 * signing to the agent — the client never sees the private key.
 *
 * This is the practical auth path for end-users whose id_ed25519 is
 * passphrase-encrypted (OpenSSH default) — the agent holds the
 * decrypted key for the session.
 *
 * Hatches: 1=null conn, 2=null username, 3=no agent reachable,
 *          4=no matching (ed25519) key in agent, 5=agent sign failed,
 *          6=server rejected userauth / protocol error */
unsigned long ssh_conn_auth_agent(ssh_conn *conn,
                                                 const char *username);

/* ssh_conn_open_channel — open a session channel.
 * Hatches: 1=null out, 2=null conn, 3=channel open rejected,
 *          4=alloc failure */
unsigned long ssh_conn_open_channel(ssh_channel **out,
                                                   ssh_conn *conn);

unsigned long ssh_conn_destroy(ssh_conn *conn);

/* ssh_last_kex_sub_hatch — diagnostic accessor for the inner hatch
 * `ssh_key_exchange` returned before ssh_conn_create collapsed it to
 * outer hatch 5. Returns the last recorded sub-hatch (1..12), or 0 if
 * the last KEX was successful. Not thread-safe (single-caller only for
 * now — a per-conn field will replace this when concurrency lands).
 *
 * Sub-hatches from ssh_key_exchange:
 *   1  send client KEXINIT
 *   2  recv server KEXINIT / unexpected msg
 *   3  x25519_keygen
 *   4  send KEX_ECDH_INIT
 *   5  recv / parse KEX_ECDH_REPLY (incl. host-key / sig-blob parsing)
 *   6  x25519_dh (shared secret)
 *   7  sha256 hash build
 *   8  ed25519_verify failed (sig invalid or verify function error)
 *   9  transport key derivation
 *   10 send NEWKEYS
 *   11 recv NEWKEYS
 *   12 aes256 init
 *
 * Hatches: 1=null out */
unsigned long ssh_last_kex_sub_hatch(unsigned long *out);

/* ---- Channel ---- */

unsigned long ssh_channel_read(u64 *bytes_read, ssh_channel *ch,
                                              u8 *buf, u64 len);

/* ssh_channel_read_stderr — drain bytes from the channel's stderr
 * side buffer (populated by SSH_MSG_CHANNEL_EXTENDED_DATA with
 * data_type_code = 1). Non-blocking: returns 0 with *bytes_read=0
 * if nothing is buffered (does NOT pull a new packet, to avoid
 * stealing stdout bytes from the main read loop).
 *
 * Typical use: after ssh_channel_read observes EOF or the command's
 * exit status indicates failure, call this to surface whatever
 * error text the remote side wrote to stderr.
 *
 * Hatches: 1=null bytes_read, 2=null ch, 3=null buf */
unsigned long ssh_channel_read_stderr(u64 *bytes_read,
                                                     ssh_channel *ch,
                                                     u8 *buf, u64 len);

unsigned long ssh_channel_write(u64 *bytes_written, ssh_channel *ch,
                                               const u8 *data, u64 len);

/* ssh_channel_exec — run a remote command on the open session channel.
 * After success, channel_read returns the command's stdout, and
 * channel_write feeds its stdin. This is the mechanism used by git-over-ssh
 * to invoke `git-upload-pack` / `git-receive-pack` on the remote.
 *
 * Hatches: 1=null ch, 2=null command, 3=channel already closed,
 *          4=protocol/transport error, 5=server rejected exec */
unsigned long ssh_channel_exec(ssh_channel *ch, const char *command);

unsigned long ssh_channel_close(ssh_channel *ch);

#endif /* APENNINES_T3_SSH_H */
