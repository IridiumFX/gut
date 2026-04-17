#include "gut/leech.h"
#include "gut/object.h"
#include "gut/odb.h"
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

/* Walk refs/heads and refs/tags and populate snapshot */
static unsigned long take_snapshot(ref_snapshot *out, gut_repo *repo) {
    char base_dirs[2][512];
    const char *ref_prefixes[2];
    int i;

    snprintf(base_dirs[0], sizeof(base_dirs[0]), "%s/refs/heads", repo->git_dir);
    snprintf(base_dirs[1], sizeof(base_dirs[1]), "%s/refs/tags",  repo->git_dir);
    ref_prefixes[0] = "refs/heads";
    ref_prefixes[1] = "refs/tags";

    for (i = 0; i < 2; i++) {
        DIR *d = opendir(base_dirs[i]);
        struct dirent *ent;
        if (!d) continue;
        while ((ent = readdir(d)) != NULL) {
            char full_path[2048];
            char ref_name[512];
            FILE *fp;
            char line[64];
            gut_oid oid;

            if (ent->d_name[0] == '.') continue;
            snprintf(full_path, sizeof(full_path), "%s/%s", base_dirs[i], ent->d_name);
            snprintf(ref_name, sizeof(ref_name), "%s/%s", ref_prefixes[i], ent->d_name);

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

/* Perform the WebSocket upgrade handshake on an incoming TCP connection.
 * Reads the HTTP request, validates the token if required, builds and sends
 * the 101 response. Returns 0 on success. */
static unsigned long ws_upgrade_server(tcp_conn *conn, const char *required_token) {
    buf req;
    const char *key_start;
    u64 key_len;
    char client_key[128];
    u8 *response = NULL;
    u64 response_len = 0;
    unsigned long rc;
    u64 n;

    rc = buf_create(&req, 4096);
    if (rc) return __LINE__;

    rc = read_http_request(&req, conn);
    if (rc) { buf_destroy(&req); return __LINE__; }

    /* Validate token if required */
    if (required_token && *required_token) {
        u64 auth_len;
        const char *auth = find_header(&auth_len, req.data, req.len, "Authorization");
        const char *bearer_prefix = "Bearer ";
        size_t bp_len = strlen(bearer_prefix);
        size_t tok_len = strlen(required_token);

        if (!auth || auth_len < bp_len + tok_len ||
            gut_strncasecmp(auth, bearer_prefix, bp_len) != 0 ||
            strncmp(auth + bp_len, required_token, tok_len) != 0) {
            const char *reject =
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Length: 0\r\n\r\n";
            tcp_conn_write_all(&n, conn, (const u8 *)reject, strlen(reject));
            buf_destroy(&req);
            return __LINE__;
        }
    }

    /* Extract Sec-WebSocket-Key */
    key_start = find_header(&key_len, req.data, req.len, "Sec-WebSocket-Key");
    if (!key_start || key_len >= sizeof(client_key)) {
        buf_destroy(&req);
        return __LINE__;
    }
    memcpy(client_key, key_start, key_len);
    client_key[key_len] = '\0';

    buf_destroy(&req);

    /* Build accept response */
    rc = ws_handshake_build_response(&response, &response_len, client_key);
    if (rc) return __LINE__;

    rc = tcp_conn_write_all(&n, conn, response, response_len);
    free(response);
    if (rc) return __LINE__;

    return 0;
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

unsigned long leech_listen(gut_repo *repo, u16 port, u64 poll_ms,
                           const char *token) {
    tcp_listener listener;
    net_sock_addr addr;
    unsigned long rc;

    if (!repo) return __LINE__;

    memset(&addr, 0, sizeof(addr));
    addr.family = 4;          /* IPv4 */
    addr.addr.v4.octets[0] = 0;
    addr.addr.v4.octets[1] = 0;
    addr.addr.v4.octets[2] = 0;
    addr.addr.v4.octets[3] = 0;
    addr.port = port;

    rc = tcp_listener_create(&listener, &addr, 8);
    if (rc) {
        fprintf(stderr, "error: cannot bind to port %u (rc=%lu)\n", (unsigned)port, rc);
        return __LINE__;
    }

    printf("gut listen on port %u (Ctrl-C to stop)\n", (unsigned)port);
    if (token && *token) {
        printf("  auth: bearer token required\n");
    } else {
        printf("  auth: none (any peer may connect)\n");
    }
    fflush(stdout);

    /* Single-peer MVP: accept one connection at a time, handle events */
    for (;;) {
        tcp_conn conn;
        ref_snapshot prev_snap, curr_snap;
        struct emit_ctx ectx;

        printf("waiting for leecher...\n");
        fflush(stdout);

        rc = tcp_listener_accept(&conn, &listener);
        if (rc) {
            fprintf(stderr, "accept failed rc=%lu\n", rc);
            continue;
        }

        printf("leecher connected\n");
        fflush(stdout);

        /* Perform WebSocket upgrade */
        rc = ws_upgrade_server(&conn, token);
        if (rc) {
            fprintf(stderr, "upgrade failed rc=%lu\n", rc);
            tcp_conn_destroy(&conn);
            continue;
        }

        printf("upgrade ok, streaming events\n");
        fflush(stdout);

        /* Take initial snapshot so we only report future changes */
        snap_init(&prev_snap);
        take_snapshot(&prev_snap, repo);

        ectx.conn = &conn;
        ectx.error = 0;

        /* Polling loop */
        while (!ectx.error) {
            gut_sleep_ms(poll_ms);

            snap_init(&curr_snap);
            take_snapshot(&curr_snap, repo);

            diff_snapshots(repo, &prev_snap, &curr_snap, emit_via_ws, &ectx);

            snap_destroy(&prev_snap);
            prev_snap = curr_snap;
            memset(&curr_snap, 0, sizeof(curr_snap));
        }

        snap_destroy(&prev_snap);
        printf("leecher disconnected\n");
        fflush(stdout);
        tcp_conn_destroy(&conn);
    }

    /* unreachable */
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

unsigned long leech_connect(const char *url, const char *token) {
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
