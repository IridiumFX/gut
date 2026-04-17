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

/* Start a listen server on the given port. Polls repo refs every poll_ms
 * milliseconds and broadcasts changes to connected peers.
 *
 * token: optional bearer token — if non-NULL, peers must send
 *        "Authorization: Bearer <token>" in their upgrade request.
 * Blocks until the listener is terminated (Ctrl-C). */
unsigned long leech_listen(gut_repo *repo, u16 port, u64 poll_ms,
                           const char *token);

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

#endif /* GUT_LEECH_H */
