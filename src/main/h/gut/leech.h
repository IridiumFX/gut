#ifndef GUT_LEECH_H
#define GUT_LEECH_H

#include "gut/types.h"
#include "gut/repo.h"

/*
 * gut leech/listen — ambient peer awareness.
 *
 * listen: opens a WebSocket server on a port. When any ref under
 * .git/refs/heads/ or .git/refs/tags/ changes, broadcasts a JSON event
 * to all connected clients.
 *
 * leech: connects to a peer's listen WebSocket, receives event stream,
 * prints notifications.
 *
 * Event JSON format:
 *   {
 *     "type":   "commit" | "branch-create" | "branch-delete" | "tag",
 *     "ref":    "refs/heads/main",
 *     "oid":    "40-hex",
 *     "prev":   "40-hex",              (optional — previous OID)
 *     "author": "Name <email>",        (for commit events)
 *     "message": "first line of log",  (for commit events)
 *     "ts":     unix_timestamp
 *   }
 */

/* Outbound leech subscription passed to leech_listen */
typedef struct {
    const char *url;        /* ws://host:port */
    const char *token;      /* NULL for none */
    const char *name;       /* display name + refs/leech/<name>/... */
    int         auto_fetch; /* 1 = fetch objects on update events */
} leech_outbound;

/* Start a listen server on the given port. Polls repo refs every poll_ms
 * milliseconds and broadcasts changes to inbound peers. Also maintains
 * outbound WS connections to other listeners (the "broker" model).
 *
 * token:     optional bearer token for inbound auth
 * outbound:  array of outbound subscriptions (may be NULL if count==0)
 * outbound_count: number of entries in outbound array
 *
 * Blocks until the listener is terminated (Ctrl-C). */
unsigned long leech_listen(gut_repo *repo, u16 port, u64 poll_ms,
                           const char *token,
                           const leech_outbound *outbound,
                           u64 outbound_count);

/* Connect to a peer's listen server and print incoming events.
 * url: ws://host:port or wss://host:port (wss not implemented in MVP).
 * token: optional bearer token.
 * If repo and peer_name are non-NULL, also auto-fetches the new commits
 * from the peer's /pack endpoint and stores them under
 * refs/leech/<peer_name>/<branch>.
 * Blocks until the connection closes. */
unsigned long leech_connect(const char *url, const char *token,
                            gut_repo *repo, const char *peer_name);

/* Query a peer's listen server for its list of connected leechers.
 * host: "host:port" (IPv4 literal for now). Prints JSON to stdout. */
unsigned long leech_list_peers(const char *host);

/* Set a callback invoked when a connected leecher sends a text message
 * upstream. Must be set before leech_listen() runs. NULL clears (default
 * behavior just prints to stdout). */
typedef void (*leech_on_msg_fn)(u64 peer_slot_id, const char *text, u64 len);
void leech_listen_set_on_message(leech_on_msg_fn fn);

/* Send a one-shot text message to a peer's listen server.
 * Opens TCP, does WS upgrade, sends a single masked text frame, closes.
 * url: ws://host:port  token: optional bearer auth.
 * If wait_reply is non-zero, reads and prints one reply text frame. */
unsigned long leech_send_to(const char *url, const char *token,
                            const char *text, u64 len, int wait_reply);

#endif /* GUT_LEECH_H */
