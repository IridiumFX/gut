#include "gut/leech.h"
#include "gut/object.h"
#include "gut/odb.h"
#include "gut/pack.h"
#include "apennines/tcp.h"
#include "apennines/ws.h"
#include "apennines/addr.h"
#include "apennines/buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#define gut_sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define gut_sleep_ms(ms) usleep((ms) * 1000)
#endif

/* Custom case-insensitive strncmp to avoid platform differences */
static int gut_strncasecmp(const char *a, const char *b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

/* ====================================================================
 *  Ref snapshot — tracks (ref-name, oid) pairs for change detection
 * ==================================================================== */

typedef struct {
    char    name[256];
    gut_oid oid;
} ref_entry;

typedef struct {
    ref_entry *entries;
    u64        count;
    u64        capacity;
} ref_snapshot;

static void snap_init(ref_snapshot *s) {
    s->entries = NULL;
    s->count = 0;
    s->capacity = 0;
}

static void snap_destroy(ref_snapshot *s) {
    free(s->entries);
    s->entries = NULL;
    s->count = 0;
    s->capacity = 0;
}

static unsigned long snap_add(ref_snapshot *s, const char *name, gut_oid *oid) {
    if (s->count >= s->capacity) {
        u64 new_cap = s->capacity == 0 ? 16 : s->capacity * 2;
        ref_entry *tmp = (ref_entry *)realloc(s->entries, (size_t)(new_cap * sizeof(ref_entry)));
        if (!tmp) return __LINE__;
        s->entries = tmp;
        s->capacity = new_cap;
    }
    snprintf(s->entries[s->count].name, sizeof(s->entries[s->count].name), "%s", name);
    memcpy(s->entries[s->count].oid.bytes, oid->bytes, GUT_OID_RAW_SIZE);
    s->count++;
    return 0;
}

/* Find a ref in snapshot by name; returns NULL if not found */
static ref_entry *snap_find(ref_snapshot *s, const char *name) {
    u64 i;
    for (i = 0; i < s->count; i++) {
        if (strcmp(s->entries[i].name, name) == 0) return &s->entries[i];
    }
    return NULL;
}

/* Recursively walk a refs/ subdirectory and add all refs found */
static void walk_refs_dir(ref_snapshot *out, const char *base_dir, const char *prefix) {
    DIR *d = opendir(base_dir);
    struct dirent *ent;
    struct stat st;
    if (!d) return;
    while ((ent = readdir(d)) != NULL) {
        char full_path[2048];
        char child_prefix[512];

        if (ent->d_name[0] == '.') continue;
        snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, ent->d_name);
        snprintf(child_prefix, sizeof(child_prefix), "%s/%s", prefix, ent->d_name);

        if (stat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* Recurse */
            walk_refs_dir(out, full_path, child_prefix);
        } else {
            FILE *fp;
            char line[64];
            gut_oid oid;
            fp = fopen(full_path, "r");
            if (!fp) continue;
            if (!fgets(line, sizeof(line), fp)) { fclose(fp); continue; }
            fclose(fp);
            {
                size_t llen = strlen(line);
                while (llen > 0 && (line[llen - 1] == '\n' || line[llen - 1] == '\r' || line[llen - 1] == ' '))
                    line[--llen] = '\0';
            }
            if (oid_from_hex(&oid, line) == 0) {
                snap_add(out, child_prefix, &oid);
            }
        }
    }
    closedir(d);
}

/* Walk refs/heads, refs/tags, and refs/remotes (where push events appear) */
static unsigned long take_snapshot(ref_snapshot *out, gut_repo *repo) {
    char base_dirs[3][512];
    const char *ref_prefixes[3];
    int i;

    snprintf(base_dirs[0], sizeof(base_dirs[0]), "%s/refs/heads",   repo->git_dir);
    snprintf(base_dirs[1], sizeof(base_dirs[1]), "%s/refs/tags",    repo->git_dir);
    snprintf(base_dirs[2], sizeof(base_dirs[2]), "%s/refs/remotes", repo->git_dir);
    ref_prefixes[0] = "refs/heads";
    ref_prefixes[1] = "refs/tags";
    ref_prefixes[2] = "refs/remotes";

    for (i = 0; i < 3; i++) {
        DIR *d = opendir(base_dirs[i]);
        struct dirent *ent;
        if (!d) continue;
        while ((ent = readdir(d)) != NULL) {
            char full_path[2048];
            char ref_name[512];
            FILE *fp;
            char line[64];
            gut_oid oid;
            struct stat st;

            if (ent->d_name[0] == '.') continue;
            snprintf(full_path, sizeof(full_path), "%s/%s", base_dirs[i], ent->d_name);
            snprintf(ref_name, sizeof(ref_name), "%s/%s", ref_prefixes[i], ent->d_name);

            /* refs/remotes contains per-remote subdirs — recurse into those */
            if (i == 2 && stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                walk_refs_dir(out, full_path, ref_name);
                continue;
            }

            fp = fopen(full_path, "r");
            if (!fp) continue;
            if (!fgets(line, sizeof(line), fp)) { fclose(fp); continue; }
            fclose(fp);

            {
                size_t llen = strlen(line);
                while (llen > 0 && (line[llen - 1] == '\n' || line[llen - 1] == '\r' || line[llen - 1] == ' '))
                    line[--llen] = '\0';
            }

            if (oid_from_hex(&oid, line) == 0) {
                snap_add(out, ref_name, &oid);
            }
        }
        closedir(d);
    }
    return 0;
}

/* ====================================================================
 *  Event builder — produces JSON text for a single event
 * ==================================================================== */

static void append_json_escaped(buf *out, const char *s) {
    while (*s) {
        char c = *s++;
        if (c == '"' || c == '\\') {
            buf_append_byte(out, '\\');
            buf_append_byte(out, c);
        } else if (c == '\n') {
            buf_append(out, (u8 *)"\\n", 2);
        } else if (c == '\r') {
            buf_append(out, (u8 *)"\\r", 2);
        } else if (c == '\t') {
            buf_append(out, (u8 *)"\\t", 2);
        } else if ((u8)c < 0x20) {
            char esc[8];
            snprintf(esc, sizeof(esc), "\\u%04x", (u8)c);
            buf_append(out, (u8 *)esc, 6);
        } else {
            buf_append_byte(out, (u8)c);
        }
    }
}

/* Build a JSON event for a ref change.
 * type: "create", "update", "delete"
 * ref: "refs/heads/main"
 * new_oid, old_oid: may be NULL for create/delete */
static unsigned long build_event(buf *out, gut_repo *repo, const char *type,
                                 const char *ref,
                                 gut_oid *new_oid, gut_oid *old_oid) {
    char hex[GUT_OID_HEX_SIZE + 1];
    time_t now = time(NULL);

    buf_append(out, (u8 *)"{\"type\":\"", 9);
    append_json_escaped(out, type);
    buf_append(out, (u8 *)"\",\"ref\":\"", 9);
    append_json_escaped(out, ref);
    buf_append_byte(out, '"');

    if (new_oid) {
        oid_to_hex(hex, new_oid);
        buf_append(out, (u8 *)",\"oid\":\"", 8);
        buf_append(out, (u8 *)hex, GUT_OID_HEX_SIZE);
        buf_append_byte(out, '"');
    }
    if (old_oid) {
        oid_to_hex(hex, old_oid);
        buf_append(out, (u8 *)",\"prev\":\"", 9);
        buf_append(out, (u8 *)hex, GUT_OID_HEX_SIZE);
        buf_append_byte(out, '"');
    }

    /* If we have a new commit OID, try to extract author/message for richer event */
    if (new_oid && repo) {
        gut_object obj;
        gut_commit commit;
        if (odb_read(&obj, &repo->odb, new_oid) == 0) {
            if (obj.type == GUT_OBJ_COMMIT &&
                commit_parse(&commit, obj.data.data, obj.data.len) == 0) {
                if (commit.author) {
                    buf_append(out, (u8 *)",\"author\":\"", 11);
                    append_json_escaped(out, commit.author);
                    buf_append_byte(out, '"');
                }
                if (commit.message) {
                    /* Only take first line */
                    char first_line[256];
                    const char *nl = strchr(commit.message, '\n');
                    size_t mlen = nl ? (size_t)(nl - commit.message) : strlen(commit.message);
                    if (mlen >= sizeof(first_line)) mlen = sizeof(first_line) - 1;
                    memcpy(first_line, commit.message, mlen);
                    first_line[mlen] = '\0';
                    buf_append(out, (u8 *)",\"message\":\"", 12);
                    append_json_escaped(out, first_line);
                    buf_append_byte(out, '"');
                }
                commit_destroy(&commit);
            }
            object_destroy(&obj);
        }
    }

    {
        char ts_buf[32];
        int n = snprintf(ts_buf, sizeof(ts_buf), ",\"ts\":%lld}", (long long)now);
        buf_append(out, (u8 *)ts_buf, (u64)n);
    }

    return 0;
}

/* ====================================================================
 *  HTTP upgrade handshake (server side)
 *
 *  Reads raw HTTP request, extracts Sec-WebSocket-Key, optionally validates
 *  Authorization, builds and sends 101 response using apennines ws_handshake.
 * ==================================================================== */

/* Read an HTTP request from a connection until the blank line (CRLFCRLF).
 * Returns the full request bytes. */
static unsigned long read_http_request(buf *out, tcp_conn *conn) {
    u8 chunk[4096];
    u64 nr;
    unsigned long rc;
    u64 marker_pos = (u64)-1;

    for (;;) {
        u64 i;
        rc = tcp_conn_read(&nr, conn, chunk, sizeof(chunk));
        if (rc || nr == 0) return rc ? rc : __LINE__;

        rc = buf_append(out, chunk, nr);
        if (rc) return __LINE__;

        /* Look for \r\n\r\n */
        if (out->len >= 4) {
            for (i = 0; i + 3 < out->len; i++) {
                if (out->data[i] == '\r' && out->data[i+1] == '\n' &&
                    out->data[i+2] == '\r' && out->data[i+3] == '\n') {
                    marker_pos = i;
                    break;
                }
            }
            if (marker_pos != (u64)-1) break;
        }

        if (out->len > 65536) return __LINE__; /* too large */
    }
    return 0;
}

/* Extract a header value (case-insensitive name match). Returns pointer into req;
 * *out_len is the trimmed length of the value. Returns NULL if not found. */
static const char *find_header(u64 *out_len, const u8 *req, u64 req_len, const char *name) {
    u64 name_len = strlen(name);
    u64 i;

    /* Skip first line (request line) */
    i = 0;
    while (i + 1 < req_len) {
        if (req[i] == '\r' && req[i+1] == '\n') { i += 2; break; }
        i++;
    }

    while (i + name_len + 1 < req_len) {
        /* Case-insensitive compare */
        int match = 1;
        u64 j;
        for (j = 0; j < name_len; j++) {
            u8 a = req[i + j];
            u8 b = (u8)name[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = 0; break; }
        }
        if (match && req[i + name_len] == ':') {
            u64 v_start = i + name_len + 1;
            u64 v_end;
            /* Skip leading whitespace */
            while (v_start < req_len && (req[v_start] == ' ' || req[v_start] == '\t'))
                v_start++;
            /* Find end of line */
            v_end = v_start;
            while (v_end + 1 < req_len) {
                if (req[v_end] == '\r' && req[v_end + 1] == '\n') break;
                v_end++;
            }
            *out_len = v_end - v_start;
            return (const char *)(req + v_start);
        }
        /* Advance to next line */
        while (i + 1 < req_len) {
            if (req[i] == '\r' && req[i+1] == '\n') { i += 2; break; }
            i++;
        }
    }
    return NULL;
}

/* Send a text WebSocket frame (server → client, unmasked) */
static unsigned long ws_send_text(tcp_conn *conn, const char *text, u64 len) {
    u8 *frame = NULL;
    u64 frame_len = 0;
    u8 no_mask[4] = {0};
    unsigned long rc;
    u64 n;

    rc = ws_frame_encode(&frame, &frame_len, WS_OPCODE_TEXT,
                         (const u8 *)text, len, 0, no_mask);
    if (rc) return __LINE__;

    rc = tcp_conn_write_all(&n, conn, frame, frame_len);
    free(frame);
    return rc;
}

/* Detect a ref change between two snapshots and return the event JSON.
 * Returns number of events emitted. Events are written to `out` concatenated
 * (one per line for simpler framing later, though we send one frame each). */
static u64 diff_snapshots(gut_repo *repo, ref_snapshot *prev, ref_snapshot *curr,
                          void (*emit)(const char *json, u64 len, void *ctx),
                          void *ctx) {
    u64 count = 0;
    u64 i;

    /* For each ref in curr, check if it's new or changed */
    for (i = 0; i < curr->count; i++) {
        ref_entry *c = &curr->entries[i];
        ref_entry *p = snap_find(prev, c->name);
        buf event;
        long cmp;

        if (!p) {
            /* New ref */
            buf_create(&event, 256);
            build_event(&event, repo, "create", c->name, &c->oid, NULL);
            emit((const char *)event.data, event.len, ctx);
            buf_destroy(&event);
            count++;
        } else {
            oid_compare(&cmp, &p->oid, &c->oid);
            if (cmp != 0) {
                buf_create(&event, 256);
                build_event(&event, repo, "update", c->name, &c->oid, &p->oid);
                emit((const char *)event.data, event.len, ctx);
                buf_destroy(&event);
                count++;
            }
        }
    }

    /* For each ref in prev, check if it was deleted */
    for (i = 0; i < prev->count; i++) {
        ref_entry *p = &prev->entries[i];
        if (!snap_find(curr, p->name)) {
            buf event;
            buf_create(&event, 256);
            build_event(&event, repo, "delete", p->name, NULL, &p->oid);
            emit((const char *)event.data, event.len, ctx);
            buf_destroy(&event);
            count++;
        }
    }

    return count;
}

/* Emit callback context */
struct emit_ctx {
    tcp_conn *conn;
    int       error;
};

static void emit_via_ws(const char *json, u64 len, void *ctx_void) {
    struct emit_ctx *ctx = (struct emit_ctx *)ctx_void;
    if (ctx->error) return;
    if (ws_send_text(ctx->conn, json, len) != 0) {
        ctx->error = 1;
    }
    /* Also echo to server's stdout */
    printf("[event] ");
    fwrite(json, 1, (size_t)len, stdout);
    printf("\n");
    fflush(stdout);
}

/* ====================================================================
 *  Public: leech_listen
 * ==================================================================== */

/* ====================================================================
 *  Object closure walker (mirror of cmd_push helpers, kept local)
 * ==================================================================== */

typedef struct {
    gut_oid *items;
    u64 count;
    u64 capacity;
} l_oid_set;

static int l_oid_set_contains(l_oid_set *s, gut_oid *oid) {
    u64 i;
    for (i = 0; i < s->count; i++) {
        if (memcmp(s->items[i].bytes, oid->bytes, GUT_OID_RAW_SIZE) == 0) return 1;
    }
    return 0;
}

static unsigned long l_oid_set_add(l_oid_set *s, gut_oid *oid) {
    if (l_oid_set_contains(s, oid)) return 0;
    if (s->count >= s->capacity) {
        u64 new_cap = s->capacity == 0 ? 64 : s->capacity * 2;
        gut_oid *tmp = (gut_oid *)realloc(s->items, (size_t)(new_cap * sizeof(gut_oid)));
        if (!tmp) return __LINE__;
        s->items = tmp;
        s->capacity = new_cap;
    }
    memcpy(s->items[s->count].bytes, oid->bytes, GUT_OID_RAW_SIZE);
    s->count++;
    return 0;
}

static void l_walk_tree(l_oid_set *result, gut_odb *odb, gut_oid *tree_oid) {
    gut_object obj;
    gut_tree tree;
    u64 i;
    if (l_oid_set_contains(result, tree_oid)) return;
    l_oid_set_add(result, tree_oid);
    if (odb_read(&obj, odb, tree_oid) != 0) return;
    if (obj.type != GUT_OBJ_TREE) { object_destroy(&obj); return; }
    if (tree_parse(&tree, obj.data.data, obj.data.len) != 0) {
        object_destroy(&obj); return;
    }
    object_destroy(&obj);
    for (i = 0; i < tree.count; i++) {
        if (tree.entries[i].mode == 040000) {
            l_walk_tree(result, odb, &tree.entries[i].oid);
        } else {
            l_oid_set_add(result, &tree.entries[i].oid);
        }
    }
    tree_destroy(&tree);
}

static unsigned long l_walk_commits(l_oid_set *result, gut_odb *odb, gut_oid *start) {
    gut_oid *queue = (gut_oid *)malloc(256 * sizeof(gut_oid));
    u64 qcap = 256, qhead = 0, qtail = 1;
    if (!queue) return __LINE__;
    memcpy(queue[0].bytes, start->bytes, GUT_OID_RAW_SIZE);

    while (qhead < qtail) {
        gut_oid current;
        gut_object obj;
        gut_commit commit;
        u64 j;

        memcpy(current.bytes, queue[qhead++].bytes, GUT_OID_RAW_SIZE);
        if (l_oid_set_contains(result, &current)) continue;
        l_oid_set_add(result, &current);

        if (odb_read(&obj, odb, &current) != 0) continue;
        if (obj.type != GUT_OBJ_COMMIT) { object_destroy(&obj); continue; }
        if (commit_parse(&commit, obj.data.data, obj.data.len) != 0) {
            object_destroy(&obj); continue;
        }
        object_destroy(&obj);

        l_walk_tree(result, odb, &commit.tree_oid);

        for (j = 0; j < commit.parent_count; j++) {
            if (qtail >= qcap) {
                qcap *= 2;
                queue = (gut_oid *)realloc(queue, qcap * sizeof(gut_oid));
                if (!queue) { commit_destroy(&commit); return __LINE__; }
            }
            memcpy(queue[qtail++].bytes, commit.parent_oids[j].bytes, GUT_OID_RAW_SIZE);
        }
        commit_destroy(&commit);
    }
    free(queue);
    return 0;
}

/* ====================================================================
 *  Multi-peer state and select-based event loop
 * ==================================================================== */

#define GUT_LEECH_MAX_PEERS 64

typedef enum {
    PEER_SLOT_FREE = 0,
    PEER_HANDSHAKING,      /* inbound: accumulating HTTP upgrade request */
    PEER_CONNECTED,        /* WebSocket ready, bidirectional traffic */
} peer_state;

typedef enum {
    PEER_DIR_INBOUND = 0,  /* a leecher connected to us */
    PEER_DIR_OUTBOUND,     /* we connected to a remote listener (leech mode) */
} peer_direction;

typedef struct {
    peer_state     state;
    peer_direction dir;
    tcp_conn       conn;
    buf            recv_buf;   /* accumulated handshake bytes / frame data */
    char           addr_str[48];
    time_t         connected_at;
    u64            slot_id;
    /* For OUTBOUND only: metadata for auto-fetch and reconnect */
    char           peer_host[64];
    u16            peer_port;
    char           peer_name[64];
    int            auto_fetch;
} peer_slot;

static peer_slot g_peers[GUT_LEECH_MAX_PEERS];
static u64 g_next_slot_id = 1;
static gut_repo *g_listen_repo = NULL; /* repo for serving /pack and other endpoints */

/* Callback set by leech_listen_set_on_message — see leech.h */
static leech_on_msg_fn g_on_peer_msg = NULL;

void leech_listen_set_on_message(leech_on_msg_fn fn) { g_on_peer_msg = fn; }

/* Default handler — prints inbound messages */
static void default_inbound_handler(u64 peer_id, const char *text, u64 len) {
    printf("[from peer #%llu] %.*s\n",
           (unsigned long long)peer_id, (int)len, text);
    fflush(stdout);
}

/* Forward declaration — the discovery command reads these via a helper */
static u64 peer_count_connected(void) {
    u64 n = 0;
    int i;
    for (i = 0; i < GUT_LEECH_MAX_PEERS; i++) {
        if (g_peers[i].state == PEER_CONNECTED) n++;
    }
    return n;
}

/* Find free slot; returns -1 if none. */
static int peer_slot_alloc(void) {
    int i;
    for (i = 0; i < GUT_LEECH_MAX_PEERS; i++) {
        if (g_peers[i].state == PEER_SLOT_FREE) return i;
    }
    return -1;
}

static void peer_slot_close(int idx) {
    if (g_peers[idx].state == PEER_SLOT_FREE) return;
    buf_destroy(&g_peers[idx].recv_buf);
    tcp_conn_destroy(&g_peers[idx].conn);
    memset(&g_peers[idx], 0, sizeof(g_peers[idx]));
}

/* Forward decl — defined later alongside leech_connect */
static unsigned long parse_ws_url(const char *url, char *host, size_t host_size,
                                  u16 *port, char *path, size_t path_size);

/* Forward decl — auto-fetch helper used by outbound leech dispatcher */
static unsigned long leech_fetch_and_store(gut_repo *repo, const char *peer_name,
                                           const char *host, u16 port,
                                           const char *oid_hex,
                                           const char *ref_name);
/* Forward decl — JSON string extraction (defined later) */
static int json_get_str(char *out, size_t out_size, const char *json, const char *key);

static void set_nonblocking(socket_t fd);

/* Connect to a remote listener as an outbound leech. Does TCP+WS handshake
 * synchronously. On success, allocates a peer slot in PEER_CONNECTED state.
 * Returns slot index, or -1 on failure. */
static int start_outbound_leech(const char *url, const char *token,
                                const char *peer_name, int auto_fetch) {
    char host[256];
    char path[512];
    u16  port;
    net_sock_addr addr;
    tcp_conn conn;
    u8 ws_key[16];
    u8 *request = NULL;
    u64 request_len = 0;
    int slot;
    unsigned long rc;
    u64 n;

    rc = parse_ws_url(url, host, sizeof(host), &port, path, sizeof(path));
    if (rc) {
        fprintf(stderr, "error: bad leech URL '%s'\n", url);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;
    {
        unsigned a, b, c, d;
        if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            fprintf(stderr, "error: outbound leech requires IPv4 host, got '%s'\n", host);
            return -1;
        }
        addr.addr.v4.octets[0] = (u8)a;
        addr.addr.v4.octets[1] = (u8)b;
        addr.addr.v4.octets[2] = (u8)c;
        addr.addr.v4.octets[3] = (u8)d;
    }

    rc = tcp_conn_create(&conn, &addr);
    if (rc) {
        fprintf(stderr, "error: leech cannot connect to %s:%u\n", host, (unsigned)port);
        return -1;
    }

    /* Generate WS key */
    {
        int i;
        u64 seed = (u64)time(NULL) ^ (u64)(uintptr_t)url;
        for (i = 0; i < 16; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            ws_key[i] = (u8)(seed >> 56);
        }
    }

    rc = ws_handshake_build_request(&request, &request_len, host, path, ws_key);
    if (rc) { tcp_conn_destroy(&conn); return -1; }

    /* Inject token if provided */
    if (token && *token) {
        buf mod;
        u8 *end_pos = NULL;
        u64 i;
        for (i = 0; i + 3 < request_len; i++) {
            if (memcmp(request + i, "\r\n\r\n", 4) == 0) { end_pos = request + i + 2; break; }
        }
        if (end_pos) {
            u64 head_len = (u64)(end_pos - request);
            char auth_line[512];
            int auth_len = snprintf(auth_line, sizeof(auth_line),
                                    "Authorization: Bearer %s\r\n", token);
            buf_create(&mod, request_len + auth_len);
            buf_append(&mod, request, head_len);
            buf_append(&mod, (u8 *)auth_line, (u64)auth_len);
            buf_append(&mod, request + head_len, request_len - head_len);
            free(request);
            request = (u8 *)malloc((size_t)mod.len);
            memcpy(request, mod.data, (size_t)mod.len);
            request_len = mod.len;
            buf_destroy(&mod);
        }
    }

    rc = tcp_conn_write_all(&n, &conn, request, request_len);
    free(request);
    if (rc) { tcp_conn_destroy(&conn); return -1; }

    /* Read 101 response */
    {
        buf resp;
        int valid = 0;
        buf_create(&resp, 4096);
        rc = read_http_request(&resp, &conn);
        if (rc == 0) {
            ws_handshake_validate_response(&valid, resp.data, resp.len, ws_key);
        }
        buf_destroy(&resp);
        if (!valid) {
            fprintf(stderr, "error: leech server rejected upgrade for %s\n", url);
            tcp_conn_destroy(&conn);
            return -1;
        }
    }

    /* Claim a peer slot */
    slot = peer_slot_alloc();
    if (slot < 0) {
        fprintf(stderr, "error: peer table full, cannot add outbound leech\n");
        tcp_conn_destroy(&conn);
        return -1;
    }

    set_nonblocking(conn.fd);
    g_peers[slot].state = PEER_CONNECTED;
    g_peers[slot].dir = PEER_DIR_OUTBOUND;
    g_peers[slot].conn = conn;
    buf_create(&g_peers[slot].recv_buf, 4096);
    g_peers[slot].connected_at = time(NULL);
    g_peers[slot].slot_id = g_next_slot_id++;
    snprintf(g_peers[slot].peer_host, sizeof(g_peers[slot].peer_host), "%s", host);
    g_peers[slot].peer_port = port;
    snprintf(g_peers[slot].peer_name, sizeof(g_peers[slot].peer_name),
             "%s", peer_name ? peer_name : "peer");
    g_peers[slot].auto_fetch = auto_fetch;
    snprintf(g_peers[slot].addr_str, sizeof(g_peers[slot].addr_str),
             "%s:%u", host, (unsigned)port);

    printf("leech #%llu connected → %s (as '%s'%s)\n",
           (unsigned long long)g_peers[slot].slot_id,
           g_peers[slot].addr_str, g_peers[slot].peer_name,
           auto_fetch ? ", auto-fetch" : "");
    fflush(stdout);
    return slot;
}

/* Set a socket to non-blocking mode */
static void set_nonblocking(socket_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* Try to complete an upgrade handshake for a peer in PEER_HANDSHAKING.
 * Reads more bytes into peer->recv_buf. If complete, transitions to
 * PEER_CONNECTED (and sends 101 response). Returns 1 if still pending,
 * 0 if transitioned, <0 if failed. */
static int peer_handshake_step(int idx, const char *required_token) {
    peer_slot *p = &g_peers[idx];
    u8 chunk[2048];
    u64 nr;
    unsigned long rc;
    u64 i;
    u64 marker_pos = (u64)-1;

    rc = tcp_conn_read(&nr, &p->conn, chunk, sizeof(chunk));
    if (rc) {
        /* Non-blocking read: if no data, treat as still pending.
         * Our vendored tcp_conn_read returns error on EWOULDBLOCK, so
         * we can't distinguish. Assume pending and try again. */
        return 1;
    }
    if (nr == 0) return -1; /* peer closed */

    buf_append(&p->recv_buf, chunk, nr);

    if (p->recv_buf.len > 65536) return -1; /* too large */

    /* Search for \r\n\r\n */
    if (p->recv_buf.len >= 4) {
        for (i = 0; i + 3 < p->recv_buf.len; i++) {
            if (p->recv_buf.data[i] == '\r' && p->recv_buf.data[i+1] == '\n' &&
                p->recv_buf.data[i+2] == '\r' && p->recv_buf.data[i+3] == '\n') {
                marker_pos = i;
                break;
            }
        }
    }
    if (marker_pos == (u64)-1) return 1; /* still need more */

    /* Check if this is a WebSocket upgrade or a plain HTTP request */
    {
        u64 upgrade_len;
        const char *upgrade = find_header(&upgrade_len, p->recv_buf.data, p->recv_buf.len, "Upgrade");
        int is_websocket = (upgrade && upgrade_len >= 9 &&
                            gut_strncasecmp(upgrade, "websocket", 9) == 0);

        if (!is_websocket) {
            /* Handle as plain HTTP — currently only GET /leechers */
            const u8 *req_line_end;
            const u8 *req = p->recv_buf.data;
            u64 req_len = p->recv_buf.len;
            u64 path_start = 0, path_end = 0;
            u64 i2;

            /* Extract path from "GET /path HTTP/1.1\r\n" */
            for (i2 = 0; i2 + 1 < req_len; i2++) {
                if (req[i2] == '\r' && req[i2+1] == '\n') { req_line_end = req + i2; break; }
            }
            (void)req_line_end;

            /* Find first space (after method) then second space (before HTTP/1.1) */
            {
                u64 j;
                int space_count = 0;
                for (j = 0; j < req_len && req[j] != '\r'; j++) {
                    if (req[j] == ' ') {
                        if (space_count == 0) path_start = j + 1;
                        else if (space_count == 1) { path_end = j; break; }
                        space_count++;
                    }
                }
            }

            /* /pack?want=<40-hex> — return a pack with closure of this OID */
            if (path_end > path_start &&
                path_end - path_start >= 11 &&
                memcmp(req + path_start, "/pack?want=", 11) == 0 &&
                path_end - path_start == 11 + GUT_OID_HEX_SIZE) {
                char hex_oid[GUT_OID_HEX_SIZE + 1];
                gut_oid want;
                l_oid_set objects;
                memcpy(hex_oid, req + path_start + 11, GUT_OID_HEX_SIZE);
                hex_oid[GUT_OID_HEX_SIZE] = '\0';

                if (oid_from_hex(&want, hex_oid) != 0 || !g_listen_repo) {
                    const char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    u64 n;
                    tcp_conn_write_all(&n, &p->conn, (const u8 *)resp, strlen(resp));
                    return -1;
                }

                memset(&objects, 0, sizeof(objects));
                l_walk_commits(&objects, &g_listen_repo->odb, &want);

                if (objects.count == 0) {
                    const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    u64 n;
                    tcp_conn_write_all(&n, &p->conn, (const u8 *)resp, strlen(resp));
                    free(objects.items);
                    return -1;
                }

                /* Build pack to a temp file, read back, send */
                {
                    char pack_dir[2048];
                    char pack_hex[GUT_OID_HEX_SIZE + 1];
                    char pack_path[2048];
                    char idx_path[2048];
                    FILE *pf;
                    u8 *pack_data;
                    long pack_sz;
                    char header[256];
                    u64 n;

                    snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack",
                             g_listen_repo->git_dir);
                    if (pack_write(pack_hex, pack_dir, &g_listen_repo->odb,
                                   objects.items, objects.count) != 0) {
                        free(objects.items);
                        return -1;
                    }
                    free(objects.items);

                    snprintf(pack_path, sizeof(pack_path), "%s/pack-%s.pack",
                             pack_dir, pack_hex);
                    pf = fopen(pack_path, "rb");
                    if (!pf) return -1;
                    fseek(pf, 0, SEEK_END);
                    pack_sz = ftell(pf);
                    fseek(pf, 0, SEEK_SET);
                    pack_data = (u8 *)malloc((size_t)pack_sz);
                    if (!pack_data) { fclose(pf); return -1; }
                    fread(pack_data, 1, (size_t)pack_sz, pf);
                    fclose(pf);

                    snprintf(header, sizeof(header),
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/x-git-pack\r\n"
                        "Content-Length: %lld\r\n"
                        "Connection: close\r\n\r\n",
                        (long long)pack_sz);
                    tcp_conn_write_all(&n, &p->conn, (const u8 *)header, strlen(header));
                    tcp_conn_write_all(&n, &p->conn, pack_data, (u64)pack_sz);
                    free(pack_data);

                    /* Clean up the temp pack — remote_pack_serve created it */
                    remove(pack_path);
                    snprintf(idx_path, sizeof(idx_path), "%s/pack-%s.idx",
                             pack_dir, pack_hex);
                    remove(idx_path);
                }
                return -1;
            }

            if (path_end > path_start &&
                path_end - path_start == 9 &&
                memcmp(req + path_start, "/leechers", 9) == 0) {
                /* Build JSON response */
                buf body;
                int first = 1;
                int i3;
                char header[256];
                u64 n;

                buf_create(&body, 256);
                buf_append_byte(&body, '[');
                for (i3 = 0; i3 < GUT_LEECH_MAX_PEERS; i3++) {
                    if (g_peers[i3].state != PEER_CONNECTED) continue;
                    if (!first) buf_append_byte(&body, ',');
                    first = 0;
                    {
                        char entry[128];
                        int en = snprintf(entry, sizeof(entry),
                            "{\"id\":%llu,\"connected_at\":%lld}",
                            (unsigned long long)g_peers[i3].slot_id,
                            (long long)g_peers[i3].connected_at);
                        buf_append(&body, (u8 *)entry, (u64)en);
                    }
                }
                buf_append_byte(&body, ']');
                buf_append_byte(&body, '\n');

                snprintf(header, sizeof(header),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: %llu\r\n"
                    "Connection: close\r\n\r\n",
                    (unsigned long long)body.len);
                tcp_conn_write_all(&n, &p->conn, (const u8 *)header, strlen(header));
                tcp_conn_write_all(&n, &p->conn, body.data, body.len);
                buf_destroy(&body);
            } else {
                const char *resp =
                    "HTTP/1.1 404 Not Found\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n";
                u64 n;
                tcp_conn_write_all(&n, &p->conn, (const u8 *)resp, strlen(resp));
            }
            return -1; /* close after response */
        }
    }

    /* Validate token if required */
    if (required_token && *required_token) {
        u64 auth_len;
        const char *auth = find_header(&auth_len, p->recv_buf.data, p->recv_buf.len, "Authorization");
        const char *bearer_prefix = "Bearer ";
        size_t bp_len = strlen(bearer_prefix);
        size_t tok_len = strlen(required_token);

        if (!auth || auth_len < bp_len + tok_len ||
            gut_strncasecmp(auth, bearer_prefix, bp_len) != 0 ||
            strncmp(auth + bp_len, required_token, tok_len) != 0) {
            const char *reject =
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Length: 0\r\n\r\n";
            u64 n;
            tcp_conn_write_all(&n, &p->conn, (const u8 *)reject, strlen(reject));
            return -1;
        }
    }

    /* Extract Sec-WebSocket-Key */
    {
        u64 key_len;
        const char *key_start = find_header(&key_len, p->recv_buf.data, p->recv_buf.len, "Sec-WebSocket-Key");
        char client_key[128];
        u8 *response = NULL;
        u64 response_len = 0;
        u64 n;

        if (!key_start || key_len >= sizeof(client_key)) return -1;
        memcpy(client_key, key_start, key_len);
        client_key[key_len] = '\0';

        rc = ws_handshake_build_response(&response, &response_len, client_key);
        if (rc) return -1;

        rc = tcp_conn_write_all(&n, &p->conn, response, response_len);
        free(response);
        if (rc) return -1;
    }

    /* Transition to connected. Clear recv_buf (no longer needed). */
    buf_destroy(&p->recv_buf);
    buf_create(&p->recv_buf, 0);
    p->state = PEER_CONNECTED;
    p->connected_at = time(NULL);

    printf("peer #%llu upgraded (%llu connected)\n",
           (unsigned long long)p->slot_id,
           (unsigned long long)peer_count_connected());
    fflush(stdout);
    return 0;
}

/* Drain any incoming data from a connected peer.
 * Decodes WS frames as they arrive: text → dispatch to handler,
 * close → return -1, ping → ignore (TODO: pong).
 * Returns -1 if the peer closed or errored. */
static int peer_drain_connected(int idx) {
    peer_slot *p = &g_peers[idx];
    u8 chunk[2048];
    u64 nr;
    unsigned long rc;
    leech_on_msg_fn handler = g_on_peer_msg ? g_on_peer_msg : default_inbound_handler;

    rc = tcp_conn_read(&nr, &p->conn, chunk, sizeof(chunk));
    if (rc) return 1; /* non-blocking: no data */
    if (nr == 0) return -1; /* peer closed */

    /* Append to per-peer recv_buf and decode frames */
    if (buf_append(&p->recv_buf, chunk, nr) != 0) return -1;

    for (;;) {
        ws_frame frame;
        u64 consumed = 0;
        unsigned long drc;

        drc = ws_frame_decode(&frame, &consumed, p->recv_buf.data, p->recv_buf.len);
        if (drc == 4) break; /* need more data */
        if (drc) return -1;  /* protocol error */

        if (frame.opcode == WS_OPCODE_TEXT) {
            if (p->dir == PEER_DIR_OUTBOUND) {
                /* This is an event from a peer we're leeching. Print it
                 * (so the daemon log shows activity) and optionally auto-fetch. */
                printf("[leech %s] %.*s\n", p->peer_name,
                       (int)frame.payload_len, (const char *)frame.payload);
                fflush(stdout);

                if (p->auto_fetch && g_listen_repo) {
                    char json_copy[2048];
                    char ev_type[32], ev_oid[GUT_OID_HEX_SIZE + 1], ev_ref[256];
                    size_t cp = (size_t)frame.payload_len;
                    if (cp >= sizeof(json_copy)) cp = sizeof(json_copy) - 1;
                    memcpy(json_copy, frame.payload, cp);
                    json_copy[cp] = '\0';

                    if (json_get_str(ev_type, sizeof(ev_type), json_copy, "type") &&
                        json_get_str(ev_oid, sizeof(ev_oid), json_copy, "oid") &&
                        json_get_str(ev_ref, sizeof(ev_ref), json_copy, "ref")) {
                        if (strcmp(ev_type, "update") == 0 ||
                            strcmp(ev_type, "create") == 0) {
                            leech_fetch_and_store(g_listen_repo, p->peer_name,
                                                  p->peer_host, p->peer_port,
                                                  ev_oid, ev_ref);
                        }
                    }
                }
            } else {
                /* Inbound peer sent us a message (ask/offer/sos etc.) */
                handler(p->slot_id, (const char *)frame.payload, frame.payload_len);
            }
        } else if (frame.opcode == WS_OPCODE_CLOSE) {
            ws_frame_free(&frame);
            return -1;
        } else if (frame.opcode == WS_OPCODE_PING) {
            /* TODO: send PONG */
        }

        ws_frame_free(&frame);

        /* Consume from buffer */
        if (consumed > 0 && consumed <= p->recv_buf.len) {
            memmove(p->recv_buf.data, p->recv_buf.data + consumed,
                    (size_t)(p->recv_buf.len - consumed));
            p->recv_buf.len -= consumed;
        } else {
            break;
        }
    }

    return 0;
}

/* Broadcast a text message to all connected peers. Closes peers that fail. */
static void broadcast_to_peers(const char *text, u64 len) {
    int i;
    u8 *frame = NULL;
    u64 frame_len = 0;
    u8 no_mask[4] = {0};

    if (ws_frame_encode(&frame, &frame_len, WS_OPCODE_TEXT,
                        (const u8 *)text, len, 0, no_mask) != 0) {
        return;
    }

    for (i = 0; i < GUT_LEECH_MAX_PEERS; i++) {
        if (g_peers[i].state != PEER_CONNECTED) continue;
        if (g_peers[i].dir == PEER_DIR_OUTBOUND) continue; /* don't echo to servers we leech */
        {
            u64 n;
            if (tcp_conn_write_all(&n, &g_peers[i].conn, frame, frame_len) != 0) {
                printf("peer #%llu write failed, closing\n",
                       (unsigned long long)g_peers[i].slot_id);
                fflush(stdout);
                peer_slot_close(i);
            }
        }
    }

    free(frame);

    /* Also echo to listener's stdout */
    printf("[event] ");
    fwrite(text, 1, (size_t)len, stdout);
    printf("\n");
    fflush(stdout);
}

/* Emit callback for diff_snapshots — broadcasts to all peers */
static void emit_broadcast(const char *json, u64 len, void *ctx) {
    (void)ctx;
    broadcast_to_peers(json, len);
}

/* Current time in milliseconds (monotonic-ish) */
static u64 now_ms(void) {
#ifdef _WIN32
    return (u64)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000 + (u64)ts.tv_nsec / 1000000;
#endif
}

#ifndef _WIN32
#include <sys/select.h>
#include <fcntl.h>
#endif

unsigned long leech_listen(gut_repo *repo, u16 port, u64 poll_ms,
                           const char *token,
                           const leech_outbound *outbound,
                           u64 outbound_count) {
    tcp_listener listener;
    net_sock_addr addr;
    ref_snapshot prev_snap;
    unsigned long rc;
    u64 last_poll;
    u64 oi;

    if (!repo) return __LINE__;

    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;

    rc = tcp_listener_create(&listener, &addr, 8);
    if (rc) {
        fprintf(stderr, "error: cannot bind to port %u (rc=%lu)\n", (unsigned)port, rc);
        return __LINE__;
    }

    set_nonblocking(listener.fd);

    printf("gut listen on port %u (Ctrl-C to stop)\n", (unsigned)port);
    if (token && *token) {
        printf("  auth: bearer token required\n");
    } else {
        printf("  auth: none (any peer may connect)\n");
    }
    printf("  multi-peer, max %d concurrent\n", GUT_LEECH_MAX_PEERS);
    if (outbound_count > 0) {
        printf("  outbound subscriptions: %llu\n", (unsigned long long)outbound_count);
    }
    fflush(stdout);

    memset(g_peers, 0, sizeof(g_peers));
    g_listen_repo = repo;

    /* Initiate outbound connections */
    for (oi = 0; oi < outbound_count; oi++) {
        start_outbound_leech(outbound[oi].url, outbound[oi].token,
                             outbound[oi].name, outbound[oi].auto_fetch);
    }

    snap_init(&prev_snap);
    take_snapshot(&prev_snap, repo);
    last_poll = now_ms();

    for (;;) {
        fd_set rfds;
        socket_t maxfd;
        struct timeval tv;
        int ready;
        int i;
        u64 now;

        FD_ZERO(&rfds);
        FD_SET(listener.fd, &rfds);
        maxfd = listener.fd;

        for (i = 0; i < GUT_LEECH_MAX_PEERS; i++) {
            if (g_peers[i].state != PEER_SLOT_FREE) {
                FD_SET(g_peers[i].conn.fd, &rfds);
                if (g_peers[i].conn.fd > maxfd) maxfd = g_peers[i].conn.fd;
            }
        }

        /* Compute timeout remaining until next poll */
        now = now_ms();
        {
            u64 elapsed = now - last_poll;
            u64 remaining = (elapsed >= poll_ms) ? 0 : (poll_ms - elapsed);
            tv.tv_sec = (long)(remaining / 1000);
            tv.tv_usec = (long)((remaining % 1000) * 1000);
        }

#ifdef _WIN32
        ready = select(0, &rfds, NULL, NULL, &tv);
#else
        ready = select((int)maxfd + 1, &rfds, NULL, NULL, &tv);
#endif
        (void)ready;

        /* Accept new connections */
        if (FD_ISSET(listener.fd, &rfds)) {
            for (;;) {
                tcp_conn new_conn;
                int slot;
                if (tcp_listener_accept(&new_conn, &listener) != 0) break;

                slot = peer_slot_alloc();
                if (slot < 0) {
                    printf("refusing connection — peer table full\n");
                    fflush(stdout);
                    tcp_conn_destroy(&new_conn);
                    continue;
                }

                set_nonblocking(new_conn.fd);
                g_peers[slot].state = PEER_HANDSHAKING;
                g_peers[slot].conn = new_conn;
                buf_create(&g_peers[slot].recv_buf, 1024);
                g_peers[slot].connected_at = time(NULL);
                g_peers[slot].slot_id = g_next_slot_id++;
                snprintf(g_peers[slot].addr_str, sizeof(g_peers[slot].addr_str),
                         "peer#%llu", (unsigned long long)g_peers[slot].slot_id);

                printf("peer #%llu accepted (handshaking)\n",
                       (unsigned long long)g_peers[slot].slot_id);
                fflush(stdout);
            }
        }

        /* Handle peer I/O */
        for (i = 0; i < GUT_LEECH_MAX_PEERS; i++) {
            if (g_peers[i].state == PEER_SLOT_FREE) continue;
            if (!FD_ISSET(g_peers[i].conn.fd, &rfds)) continue;

            if (g_peers[i].state == PEER_HANDSHAKING) {
                int r = peer_handshake_step(i, token);
                if (r < 0) {
                    printf("peer #%llu handshake failed\n",
                           (unsigned long long)g_peers[i].slot_id);
                    fflush(stdout);
                    peer_slot_close(i);
                }
            } else if (g_peers[i].state == PEER_CONNECTED) {
                int r = peer_drain_connected(i);
                if (r < 0) {
                    printf("peer #%llu disconnected (%llu remaining)\n",
                           (unsigned long long)g_peers[i].slot_id,
                           (unsigned long long)(peer_count_connected() - 1));
                    fflush(stdout);
                    peer_slot_close(i);
                }
            }
        }

        /* Time to poll refs? */
        now = now_ms();
        if (now - last_poll >= poll_ms) {
            ref_snapshot curr_snap;
            snap_init(&curr_snap);
            take_snapshot(&curr_snap, repo);
            diff_snapshots(repo, &prev_snap, &curr_snap, emit_broadcast, NULL);
            snap_destroy(&prev_snap);
            prev_snap = curr_snap;
            last_poll = now;
        }
    }

    /* unreachable */
    snap_destroy(&prev_snap);
    tcp_listener_destroy(&listener);
    return 0;
}

/* ====================================================================
 *  Public: leech_connect (WebSocket client)
 * ==================================================================== */

/* Parse ws://host:port/path into components */
static unsigned long parse_ws_url(const char *url, char *host, size_t host_size,
                                  u16 *port, char *path, size_t path_size) {
    const char *p;
    int is_wss = 0;

    if (strncmp(url, "ws://", 5) == 0) {
        p = url + 5;
    } else if (strncmp(url, "wss://", 6) == 0) {
        p = url + 6;
        is_wss = 1;
    } else {
        return __LINE__;
    }

    /* Extract host[:port] path */
    {
        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');
        const char *host_end;
        const char *port_str;

        if (colon && (!slash || colon < slash)) {
            host_end = colon;
            port_str = colon + 1;
        } else {
            host_end = slash ? slash : p + strlen(p);
            port_str = NULL;
        }

        if ((size_t)(host_end - p) >= host_size) return __LINE__;
        memcpy(host, p, (size_t)(host_end - p));
        host[host_end - p] = '\0';

        if (port_str) {
            *port = (u16)atoi(port_str);
        } else {
            *port = is_wss ? 443 : 80;
        }

        if (slash) {
            snprintf(path, path_size, "%s", slash);
        } else {
            snprintf(path, path_size, "/");
        }
    }

    return 0;
}

/* Helper: extract a JSON string field value into out_buf. Returns 1 if found. */
static int json_get_str(char *out, size_t out_size, const char *json, const char *key) {
    char needle[64];
    const char *p, *vstart, *vend;
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    p = strstr(json, needle);
    if (!p) return 0;
    vstart = p + strlen(needle);
    vend = vstart;
    while (*vend && *vend != '"') {
        if (*vend == '\\' && vend[1]) vend += 2;
        else vend++;
    }
    {
        size_t len = (size_t)(vend - vstart);
        if (len >= out_size) len = out_size - 1;
        memcpy(out, vstart, len);
        out[len] = '\0';
    }
    return 1;
}

/* Download a pack from the peer's /pack?want=<oid> endpoint and write
 * to the repo's objects/pack dir. Then update refs/leech/<peer>/<branch>
 * to point to oid. Uses raw TCP HTTP since the connection is plain. */
static unsigned long leech_fetch_and_store(gut_repo *repo, const char *peer_name,
                                           const char *host, u16 port,
                                           const char *oid_hex,
                                           const char *ref_name) {
    net_sock_addr addr;
    tcp_conn conn;
    char req[512];
    int req_len;
    u64 n;
    buf resp;
    unsigned long rc;

    /* Resolve host */
    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;
    {
        unsigned a, b, c, d;
        if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return __LINE__;
        addr.addr.v4.octets[0] = (u8)a;
        addr.addr.v4.octets[1] = (u8)b;
        addr.addr.v4.octets[2] = (u8)c;
        addr.addr.v4.octets[3] = (u8)d;
    }

    rc = tcp_conn_create(&conn, &addr);
    if (rc) return __LINE__;

    req_len = snprintf(req, sizeof(req),
        "GET /pack?want=%s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Connection: close\r\n"
        "\r\n",
        oid_hex, host, (unsigned)port);
    tcp_conn_write_all(&n, &conn, (const u8 *)req, (u64)req_len);

    /* Read full response */
    buf_create(&resp, 4096);
    for (;;) {
        u8 chunk[4096];
        u64 nr;
        if (tcp_conn_read(&nr, &conn, chunk, sizeof(chunk)) != 0) break;
        if (nr == 0) break;
        buf_append(&resp, chunk, nr);
    }
    tcp_conn_destroy(&conn);

    /* Find body start */
    {
        u64 i, body_start = 0;
        for (i = 0; i + 3 < resp.len; i++) {
            if (resp.data[i] == '\r' && resp.data[i+1] == '\n' &&
                resp.data[i+2] == '\r' && resp.data[i+3] == '\n') {
                body_start = i + 4;
                break;
            }
        }
        if (body_start == 0) { buf_destroy(&resp); return __LINE__; }

        /* Verify it's a PACK */
        if (resp.len - body_start < 4 ||
            resp.data[body_start] != 'P' || resp.data[body_start+1] != 'A' ||
            resp.data[body_start+2] != 'C' || resp.data[body_start+3] != 'K') {
            buf_destroy(&resp);
            return __LINE__;
        }

        /* Write pack file to objects/pack/leech-<peer>-<oid_short>.pack */
        {
            char pack_dir[2048];
            char pack_path[2048];
            char idx_cmd[4096];
            FILE *fp;

            snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack", repo->git_dir);
#ifdef _WIN32
            _mkdir(pack_dir);
#else
            mkdir(pack_dir, 0755);
#endif
            snprintf(pack_path, sizeof(pack_path), "%s/leech-%s-%.8s.pack",
                     pack_dir, peer_name, oid_hex);
            fp = fopen(pack_path, "wb");
            if (!fp) { buf_destroy(&resp); return __LINE__; }
            fwrite(resp.data + body_start, 1, (size_t)(resp.len - body_start), fp);
            fclose(fp);

            /* Index it (uses git for now until we have our own pack indexer) */
            snprintf(idx_cmd, sizeof(idx_cmd),
                     "git index-pack \"%s\"", pack_path);
            system(idx_cmd);
        }
    }
    buf_destroy(&resp);

    /* Update ref under refs/leech/<peer>/<branch> */
    {
        char ref_dir[2048];
        char ref_path[2048];
        char tmp[2048];
        const char *branch = ref_name;
        char ref_content[GUT_OID_HEX_SIZE + 2];
        FILE *fp;

        if (strncmp(ref_name, "refs/heads/", 11) == 0) branch = ref_name + 11;
        else if (strncmp(ref_name, "refs/tags/", 10) == 0) branch = ref_name + 10;

        snprintf(ref_dir, sizeof(ref_dir), "%s/refs/leech/%s", repo->git_dir, peer_name);
        /* Recursive mkdir */
        snprintf(tmp, sizeof(tmp), "%s/refs/leech", repo->git_dir);
#ifdef _WIN32
        _mkdir(tmp);
        _mkdir(ref_dir);
#else
        mkdir(tmp, 0755);
        mkdir(ref_dir, 0755);
#endif

        snprintf(ref_path, sizeof(ref_path), "%s/%s", ref_dir, branch);
        snprintf(ref_content, sizeof(ref_content), "%s\n", oid_hex);
        fp = fopen(ref_path, "w");
        if (!fp) return __LINE__;
        fputs(ref_content, fp);
        fclose(fp);

        printf("  → fetched into refs/leech/%s/%s\n", peer_name, branch);
        fflush(stdout);
    }

    return 0;
}

unsigned long leech_connect(const char *url, const char *token,
                            gut_repo *repo, const char *peer_name) {
    char host[256];
    char path[512];
    u16  port;
    net_sock_addr addr;
    tcp_conn conn;
    u8 ws_key[16];
    u8 *request = NULL;
    u64 request_len = 0;
    unsigned long rc;
    u64 n;

    rc = parse_ws_url(url, host, sizeof(host), &port, path, sizeof(path));
    if (rc) { fprintf(stderr, "error: bad URL '%s'\n", url); return __LINE__; }

    /* Resolve host via apennines DNS would be ideal; for MVP, require IPv4 string.
     * A fuller impl would use dns_query. Let's try parsing as IPv4 first. */
    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;
    {
        unsigned a, b, c, d;
        if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
            a > 255 || b > 255 || c > 255 || d > 255) {
            fprintf(stderr, "error: leech MVP requires IPv4 host literal, got '%s'\n", host);
            return __LINE__;
        }
        addr.addr.v4.octets[0] = (u8)a;
        addr.addr.v4.octets[1] = (u8)b;
        addr.addr.v4.octets[2] = (u8)c;
        addr.addr.v4.octets[3] = (u8)d;
    }

    rc = tcp_conn_create(&conn, &addr);
    if (rc) {
        fprintf(stderr, "error: cannot connect to %s:%u (rc=%lu)\n", host, (unsigned)port, rc);
        return __LINE__;
    }

    /* Generate pseudo-random WS key (MVP: not cryptographically random) */
    {
        int i;
        u64 seed = (u64)time(NULL);
        for (i = 0; i < 16; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            ws_key[i] = (u8)(seed >> 56);
        }
    }

    /* Build Upgrade request */
    rc = ws_handshake_build_request(&request, &request_len, host, path, ws_key);
    if (rc) {
        tcp_conn_destroy(&conn);
        fprintf(stderr, "error: build request rc=%lu\n", rc);
        return __LINE__;
    }

    /* If we need to inject Authorization header, modify the request.
     * The apennines request builder doesn't take extra headers, so we
     * append one before the trailing CRLFCRLF. */
    if (token && *token) {
        buf modified;
        const char *end_marker = "\r\n\r\n";
        u8 *end_pos = NULL;
        u64 i;

        for (i = 0; i + 3 < request_len; i++) {
            if (memcmp(request + i, end_marker, 4) == 0) {
                end_pos = request + i + 2; /* insert after first CRLF of the pair */
                break;
            }
        }

        if (end_pos) {
            u64 head_len = (u64)(end_pos - request);
            char auth_line[512];
            int auth_len = snprintf(auth_line, sizeof(auth_line),
                                    "Authorization: Bearer %s\r\n", token);

            buf_create(&modified, request_len + auth_len);
            buf_append(&modified, request, head_len);
            buf_append(&modified, (u8 *)auth_line, (u64)auth_len);
            buf_append(&modified, request + head_len, request_len - head_len);

            free(request);
            request = (u8 *)malloc((size_t)modified.len);
            memcpy(request, modified.data, (size_t)modified.len);
            request_len = modified.len;
            buf_destroy(&modified);
        }
    }

    rc = tcp_conn_write_all(&n, &conn, request, request_len);
    free(request);
    if (rc) {
        tcp_conn_destroy(&conn);
        fprintf(stderr, "error: write upgrade rc=%lu\n", rc);
        return __LINE__;
    }

    /* Read response (expect 101) */
    {
        buf resp;
        buf_create(&resp, 4096);
        rc = read_http_request(&resp, &conn);
        if (rc) {
            fprintf(stderr, "error: read upgrade response rc=%lu\n", rc);
            buf_destroy(&resp);
            tcp_conn_destroy(&conn);
            return __LINE__;
        }

        {
            int valid = 0;
            ws_handshake_validate_response(&valid, resp.data, resp.len, ws_key);
            if (!valid) {
                fprintf(stderr, "error: server rejected upgrade\n");
                if (resp.len > 0) {
                    u64 show = resp.len < 200 ? resp.len : 200;
                    fwrite(resp.data, 1, (size_t)show, stderr);
                    fprintf(stderr, "\n");
                }
                buf_destroy(&resp);
                tcp_conn_destroy(&conn);
                return __LINE__;
            }
        }
        buf_destroy(&resp);
    }

    printf("leech connected to %s:%u%s\n", host, (unsigned)port, path);
    fflush(stdout);

    /* Frame read loop */
    {
        buf accum;
        buf_create(&accum, 4096);

        for (;;) {
            u8 chunk[2048];
            u64 nr;

            rc = tcp_conn_read(&nr, &conn, chunk, sizeof(chunk));
            if (rc || nr == 0) break;

            buf_append(&accum, chunk, nr);

            /* Decode as many complete frames as we can */
            for (;;) {
                ws_frame frame;
                u64 consumed = 0;
                unsigned long drc;

                drc = ws_frame_decode(&frame, &consumed, accum.data, accum.len);
                if (drc == 4) break; /* need more data */
                if (drc) break;

                if (frame.opcode == WS_OPCODE_TEXT) {
                    fwrite(frame.payload, 1, (size_t)frame.payload_len, stdout);
                    printf("\n");
                    fflush(stdout);

                    /* Auto-fetch on update event if repo is provided */
                    if (repo && peer_name) {
                        char json_copy[2048];
                        char ev_type[32], ev_oid[GUT_OID_HEX_SIZE + 1], ev_ref[256];
                        size_t copy_len = (size_t)frame.payload_len;
                        if (copy_len >= sizeof(json_copy)) copy_len = sizeof(json_copy) - 1;
                        memcpy(json_copy, frame.payload, copy_len);
                        json_copy[copy_len] = '\0';

                        if (json_get_str(ev_type, sizeof(ev_type), json_copy, "type") &&
                            json_get_str(ev_oid, sizeof(ev_oid), json_copy, "oid") &&
                            json_get_str(ev_ref, sizeof(ev_ref), json_copy, "ref")) {
                            if (strcmp(ev_type, "update") == 0 || strcmp(ev_type, "create") == 0) {
                                if (leech_fetch_and_store(repo, peer_name, host, port,
                                                          ev_oid, ev_ref) != 0) {
                                    printf("  → fetch failed for %s\n", ev_ref);
                                    fflush(stdout);
                                }
                            }
                        }
                    }
                } else if (frame.opcode == WS_OPCODE_CLOSE) {
                    ws_frame_free(&frame);
                    goto done;
                } else if (frame.opcode == WS_OPCODE_PING) {
                    /* Would send PONG — skip for MVP */
                }

                ws_frame_free(&frame);

                /* Consume from accum */
                if (consumed > 0 && consumed <= accum.len) {
                    memmove(accum.data, accum.data + consumed, (size_t)(accum.len - consumed));
                    accum.len -= consumed;
                } else {
                    break;
                }
            }
        }
done:
        buf_destroy(&accum);
    }

    tcp_conn_destroy(&conn);
    return 0;
}

/* ====================================================================
 *  Public: leech_list_peers — GET /leechers
 * ==================================================================== */

unsigned long leech_list_peers(const char *host) {
    char host_buf[128];
    u16 port = 7900;
    const char *colon;
    net_sock_addr addr;
    tcp_conn conn;
    char req[256];
    unsigned long rc;
    u64 n;
    int req_len;

    if (!host) return __LINE__;

    snprintf(host_buf, sizeof(host_buf), "%s", host);
    colon = strchr(host_buf, ':');
    if (colon) {
        port = (u16)atoi(colon + 1);
        host_buf[colon - host_buf] = '\0';
    }

    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;
    {
        unsigned a, b, c, d;
        if (sscanf(host_buf, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            fprintf(stderr, "error: leechers requires IPv4 host, got '%s'\n", host_buf);
            return __LINE__;
        }
        addr.addr.v4.octets[0] = (u8)a;
        addr.addr.v4.octets[1] = (u8)b;
        addr.addr.v4.octets[2] = (u8)c;
        addr.addr.v4.octets[3] = (u8)d;
    }

    rc = tcp_conn_create(&conn, &addr);
    if (rc) { fprintf(stderr, "error: cannot connect to %s:%u\n", host_buf, (unsigned)port); return __LINE__; }

    req_len = snprintf(req, sizeof(req),
        "GET /leechers HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Connection: close\r\n"
        "\r\n",
        host_buf, (unsigned)port);

    tcp_conn_write_all(&n, &conn, (const u8 *)req, (u64)req_len);

    /* Read response, skip headers, print body */
    {
        buf resp;
        buf_create(&resp, 4096);
        for (;;) {
            u8 chunk[2048];
            u64 nr;
            if (tcp_conn_read(&nr, &conn, chunk, sizeof(chunk)) != 0) break;
            if (nr == 0) break;
            buf_append(&resp, chunk, nr);
        }

        /* Find header/body boundary */
        {
            u64 i;
            u64 body_start = 0;
            for (i = 0; i + 3 < resp.len; i++) {
                if (resp.data[i] == '\r' && resp.data[i+1] == '\n' &&
                    resp.data[i+2] == '\r' && resp.data[i+3] == '\n') {
                    body_start = i + 4;
                    break;
                }
            }
            if (body_start > 0 && body_start <= resp.len) {
                fwrite(resp.data + body_start, 1, (size_t)(resp.len - body_start), stdout);
            }
        }
        buf_destroy(&resp);
    }

    tcp_conn_destroy(&conn);
    return 0;
}

/* ====================================================================
 *  Public: leech_send_to — one-shot client send
 * ==================================================================== */

unsigned long leech_send_to(const char *url, const char *token,
                            const char *text, u64 len, int wait_reply) {
    char host[256];
    char path[512];
    u16  port;
    net_sock_addr addr;
    tcp_conn conn;
    u8 ws_key[16];
    u8 *request = NULL;
    u64 request_len = 0;
    u8 *frame = NULL;
    u64 frame_len = 0;
    u8 mask_key[4];
    unsigned long rc;
    u64 n;

    rc = parse_ws_url(url, host, sizeof(host), &port, path, sizeof(path));
    if (rc) { fprintf(stderr, "error: bad URL '%s'\n", url); return __LINE__; }

    /* Resolve as IPv4 literal (MVP) */
    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;
    {
        unsigned a, b, c, d;
        if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
            a > 255 || b > 255 || c > 255 || d > 255) {
            fprintf(stderr, "error: send requires IPv4 host literal, got '%s'\n", host);
            return __LINE__;
        }
        addr.addr.v4.octets[0] = (u8)a;
        addr.addr.v4.octets[1] = (u8)b;
        addr.addr.v4.octets[2] = (u8)c;
        addr.addr.v4.octets[3] = (u8)d;
    }

    rc = tcp_conn_create(&conn, &addr);
    if (rc) {
        fprintf(stderr, "error: cannot connect to %s:%u\n", host, (unsigned)port);
        return __LINE__;
    }

    /* WS handshake */
    {
        int i;
        u64 seed = (u64)time(NULL) ^ (u64)(uintptr_t)&conn;
        for (i = 0; i < 16; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            ws_key[i] = (u8)(seed >> 56);
        }
    }

    rc = ws_handshake_build_request(&request, &request_len, host, path, ws_key);
    if (rc) { tcp_conn_destroy(&conn); return __LINE__; }

    /* Inject Authorization */
    if (token && *token) {
        buf modified;
        u8 *end_pos = NULL;
        u64 i;
        for (i = 0; i + 3 < request_len; i++) {
            if (memcmp(request + i, "\r\n\r\n", 4) == 0) {
                end_pos = request + i + 2; break;
            }
        }
        if (end_pos) {
            u64 head_len = (u64)(end_pos - request);
            char auth_line[512];
            int auth_len = snprintf(auth_line, sizeof(auth_line),
                                    "Authorization: Bearer %s\r\n", token);
            buf_create(&modified, request_len + auth_len);
            buf_append(&modified, request, head_len);
            buf_append(&modified, (u8 *)auth_line, (u64)auth_len);
            buf_append(&modified, request + head_len, request_len - head_len);
            free(request);
            request = (u8 *)malloc((size_t)modified.len);
            memcpy(request, modified.data, (size_t)modified.len);
            request_len = modified.len;
            buf_destroy(&modified);
        }
    }

    rc = tcp_conn_write_all(&n, &conn, request, request_len);
    free(request);
    if (rc) { tcp_conn_destroy(&conn); return __LINE__; }

    /* Read upgrade response */
    {
        buf resp;
        int valid = 0;
        buf_create(&resp, 4096);
        rc = read_http_request(&resp, &conn);
        if (rc == 0) {
            ws_handshake_validate_response(&valid, resp.data, resp.len, ws_key);
        }
        buf_destroy(&resp);
        if (!valid) {
            fprintf(stderr, "error: server rejected upgrade\n");
            tcp_conn_destroy(&conn);
            return __LINE__;
        }
    }

    /* Send the text frame, MASKED (RFC 6455: client→server must mask) */
    {
        u64 seed = (u64)time(NULL) ^ (u64)(uintptr_t)text;
        int i;
        for (i = 0; i < 4; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            mask_key[i] = (u8)(seed >> 56);
        }
    }
    rc = ws_frame_encode(&frame, &frame_len, WS_OPCODE_TEXT,
                         (const u8 *)text, len, 1, mask_key);
    if (rc) { tcp_conn_destroy(&conn); return __LINE__; }

    rc = tcp_conn_write_all(&n, &conn, frame, frame_len);
    free(frame);
    if (rc) { tcp_conn_destroy(&conn); return __LINE__; }

    /* Optionally read one reply frame */
    if (wait_reply) {
        buf accum;
        buf_create(&accum, 1024);
        for (;;) {
            u8 chunk[2048];
            u64 nr;
            ws_frame rf;
            u64 consumed = 0;
            unsigned long drc;

            if (tcp_conn_read(&nr, &conn, chunk, sizeof(chunk)) != 0) break;
            if (nr == 0) break;
            buf_append(&accum, chunk, nr);

            drc = ws_frame_decode(&rf, &consumed, accum.data, accum.len);
            if (drc == 0) {
                if (rf.opcode == WS_OPCODE_TEXT) {
                    fwrite(rf.payload, 1, (size_t)rf.payload_len, stdout);
                    printf("\n");
                    fflush(stdout);
                }
                ws_frame_free(&rf);
                break;
            }
        }
        buf_destroy(&accum);
    }

    tcp_conn_destroy(&conn);
    return 0;
}
