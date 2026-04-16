#include "gut/remote.h"
#include "apennines/https_client.h"
#include "apennines/http_client.h"
#include "apennines/buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- pkt-line helpers ---- */

/* Read a pkt-line length from 4 hex chars. Returns 0 for flush packet. */
static u32 pktline_len(const u8 *data) {
    u32 val = 0;
    int i;
    for (i = 0; i < 4; i++) {
        u8 c = data[i];
        val <<= 4;
        if (c >= '0' && c <= '9') val |= (c - '0');
        else if (c >= 'a' && c <= 'f') val |= (10 + c - 'a');
        else if (c >= 'A' && c <= 'F') val |= (10 + c - 'A');
        else return 0;
    }
    return val;
}

/* Write a pkt-line: 4-hex-length + data + newline */
static unsigned long pktline_write(buf *out, const char *line) {
    u64 len = strlen(line);
    u64 pkt_len = len + 5; /* 4 hex + content + newline */
    char hdr[5];
    unsigned long rc;

    snprintf(hdr, sizeof(hdr), "%04x", (unsigned)(pkt_len));
    rc = buf_append(out, (u8 *)hdr, 4);
    if (rc) return __LINE__;
    rc = buf_append(out, (u8 *)line, len);
    if (rc) return __LINE__;
    rc = buf_append_byte(out, '\n');
    if (rc) return __LINE__;
    return 0;
}

static unsigned long pktline_flush(buf *out) {
    return buf_append(out, (u8 *)"0000", 4);
}

/* ---- HTTP helpers ---- */

/* Determine if URL is HTTPS or HTTP */
static int is_https(const char *url) {
    return (strncmp(url, "https://", 8) == 0);
}

/* Perform GET request, return body. Caller frees *body. */
static unsigned long http_get(u8 **body, u64 *body_len, const char *url) {
    unsigned long rc;

    if (is_https(url)) {
        https_client *c;
        https_response resp;

        rc = https_client_create(&c);
        if (rc) return __LINE__;

        rc = https_client_get(&resp, c, url);
        if (rc) { https_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            https_response_free(&resp);
            https_client_destroy(c);
            return __LINE__;
        }

        *body = (u8 *)malloc((size_t)resp.body_len);
        if (!*body) { https_response_free(&resp); https_client_destroy(c); return __LINE__; }
        memcpy(*body, resp.body, (size_t)resp.body_len);
        *body_len = resp.body_len;

        https_response_free(&resp);
        https_client_destroy(c);
    } else {
        http_client *c;
        http_client_response resp;

        rc = http_client_create(&c);
        if (rc) return __LINE__;

        rc = http_client_get(&resp, c, url);
        if (rc) { http_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            http_client_response_free(&resp);
            http_client_destroy(c);
            return __LINE__;
        }

        *body = (u8 *)malloc((size_t)resp.body_len);
        if (!*body) { http_client_response_free(&resp); http_client_destroy(c); return __LINE__; }
        memcpy(*body, resp.body, (size_t)resp.body_len);
        *body_len = resp.body_len;

        http_client_response_free(&resp);
        http_client_destroy(c);
    }

    return 0;
}

/* Perform POST request with body. Caller frees *resp_body. */
static unsigned long http_post(u8 **resp_body, u64 *resp_body_len,
                               const char *url, const u8 *req_body, u64 req_body_len,
                               const char *content_type) {
    unsigned long rc;

    if (is_https(url)) {
        https_client *c;
        https_response resp;

        rc = https_client_create(&c);
        if (rc) return __LINE__;

        rc = https_client_post(&resp, c, url, req_body, req_body_len, content_type);
        if (rc) { https_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            https_response_free(&resp);
            https_client_destroy(c);
            return __LINE__;
        }

        *resp_body = (u8 *)malloc((size_t)resp.body_len);
        if (!*resp_body) { https_response_free(&resp); https_client_destroy(c); return __LINE__; }
        memcpy(*resp_body, resp.body, (size_t)resp.body_len);
        *resp_body_len = resp.body_len;

        https_response_free(&resp);
        https_client_destroy(c);
    } else {
        http_client *c;
        http_client_response resp;

        rc = http_client_create(&c);
        if (rc) return __LINE__;

        rc = http_client_post(&resp, c, url, req_body, req_body_len, content_type);
        if (rc) { http_client_destroy(c); return __LINE__; }

        if (resp.status < 200 || resp.status >= 300) {
            http_client_response_free(&resp);
            http_client_destroy(c);
            return __LINE__;
        }

        *resp_body = (u8 *)malloc((size_t)resp.body_len);
        if (!*resp_body) { http_client_response_free(&resp); http_client_destroy(c); return __LINE__; }
        memcpy(*resp_body, resp.body, (size_t)resp.body_len);
        *resp_body_len = resp.body_len;

        http_client_response_free(&resp);
        http_client_destroy(c);
    }

    return 0;
}

/* ---- Smart HTTP protocol ---- */

unsigned long remote_discover_refs(gut_remote_refs *out, const char *url) {
    char info_url[2048];
    u8 *body = NULL;
    u64 body_len = 0;
    u64 pos;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!url) return __LINE__;

    out->count = 0;
    out->capabilities[0] = '\0';

    /* Strip trailing slash and .git if present */
    {
        char clean_url[2048];
        size_t ulen = strlen(url);
        if (ulen >= sizeof(clean_url)) return __LINE__;
        memcpy(clean_url, url, ulen + 1);
        while (ulen > 0 && clean_url[ulen - 1] == '/') clean_url[--ulen] = '\0';

        snprintf(info_url, sizeof(info_url), "%s/info/refs?service=git-upload-pack", clean_url);
    }

    rc = http_get(&body, &body_len, info_url);
    if (rc) return __LINE__;

    /* Parse pkt-line response.
     * First line is usually "# service=git-upload-pack\n"
     * Then a flush packet "0000"
     * Then ref lines: "<oid> <refname>\n" or "<oid> <refname>\0<capabilities>\n" */
    pos = 0;

    while (pos + 4 <= body_len) {
        u32 pkt_len = pktline_len(body + pos);

        if (pkt_len == 0) {
            /* Flush packet */
            pos += 4;
            continue;
        }

        if (pkt_len < 4 || pos + pkt_len > body_len) break;

        {
            const char *line = (const char *)(body + pos + 4);
            u64 line_len = pkt_len - 4;

            /* Strip trailing newline */
            while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r'))
                line_len--;

            /* Skip service declaration lines */
            if (line[0] == '#') {
                pos += pkt_len;
                continue;
            }

            /* Parse: <40-hex-oid> <refname>[\0<capabilities>] */
            if (line_len >= GUT_OID_HEX_SIZE + 1 && out->count < GUT_REMOTE_MAX_REFS) {
                gut_remote_ref *ref = &out->refs[out->count];
                unsigned long parse_rc;

                parse_rc = oid_from_hex(&ref->oid, line);
                if (parse_rc == 0) {
                    /* Find ref name (starts after space) */
                    const char *name_start = line + GUT_OID_HEX_SIZE + 1;
                    const char *name_end = name_start;
                    const char *caps = NULL;

                    /* Name ends at \0 (capabilities follow) or end of line */
                    while (name_end < line + line_len && *name_end != '\0')
                        name_end++;

                    if (name_end < line + line_len && *name_end == '\0') {
                        caps = name_end + 1;
                    }

                    {
                        size_t nlen = (size_t)(name_end - name_start);
                        if (nlen >= sizeof(ref->name)) nlen = sizeof(ref->name) - 1;
                        memcpy(ref->name, name_start, nlen);
                        ref->name[nlen] = '\0';
                    }

                    /* Capture capabilities from first ref */
                    if (caps && out->count == 0) {
                        size_t clen = (size_t)(line + line_len - caps);
                        if (clen >= sizeof(out->capabilities)) clen = sizeof(out->capabilities) - 1;
                        memcpy(out->capabilities, caps, clen);
                        out->capabilities[clen] = '\0';
                    }

                    out->count++;
                }
            }
        }

        pos += pkt_len;
    }

    free(body);
    return 0;
}

unsigned long remote_fetch_pack(const char *url,
                                gut_oid *want_oids, u64 want_count,
                                gut_oid *have_oids, u64 have_count,
                                const char *pack_path) {
    char post_url[2048];
    buf request;
    u8 *resp_body = NULL;
    u64 resp_len = 0;
    unsigned long rc;
    u64 i;
    FILE *fp;

    if (!url || !want_oids || want_count == 0 || !pack_path) return __LINE__;

    {
        char clean_url[2048];
        size_t ulen = strlen(url);
        if (ulen >= sizeof(clean_url)) return __LINE__;
        memcpy(clean_url, url, ulen + 1);
        while (ulen > 0 && clean_url[ulen - 1] == '/') clean_url[--ulen] = '\0';

        snprintf(post_url, sizeof(post_url), "%s/git-upload-pack", clean_url);
    }

    /* Build request body */
    rc = buf_create(&request, 1024);
    if (rc) return __LINE__;

    /* want lines */
    for (i = 0; i < want_count; i++) {
        char line[128];
        char hex[GUT_OID_HEX_SIZE + 1];
        oid_to_hex(hex, &want_oids[i]);
        if (i == 0) {
            /* First want includes capabilities */
            snprintf(line, sizeof(line),
                     "want %s multi_ack_detailed side-band-64k ofs-delta", hex);
        } else {
            snprintf(line, sizeof(line), "want %s", hex);
        }
        rc = pktline_write(&request, line);
        if (rc) { buf_destroy(&request); return __LINE__; }
    }

    rc = pktline_flush(&request);
    if (rc) { buf_destroy(&request); return __LINE__; }

    /* have lines (for fetch, not clone) */
    for (i = 0; i < have_count; i++) {
        char line[128];
        char hex[GUT_OID_HEX_SIZE + 1];
        oid_to_hex(hex, &have_oids[i]);
        snprintf(line, sizeof(line), "have %s", hex);
        rc = pktline_write(&request, line);
        if (rc) { buf_destroy(&request); return __LINE__; }
    }

    /* done */
    rc = pktline_write(&request, "done");
    if (rc) { buf_destroy(&request); return __LINE__; }

    /* POST to git-upload-pack */
    rc = http_post(&resp_body, &resp_len, post_url,
                   request.data, request.len,
                   "application/x-git-upload-pack-request");
    buf_destroy(&request);
    if (rc) return __LINE__;

    /* Response: skip pkt-line header (NAK etc), find PACK signature */
    {
        u64 pack_start = 0;
        u64 pos;

        /* Scan for "PACK" signature in response */
        for (pos = 0; pos + 4 <= resp_len; pos++) {
            if (resp_body[pos] == 'P' && resp_body[pos + 1] == 'A' &&
                resp_body[pos + 2] == 'C' && resp_body[pos + 3] == 'K') {
                pack_start = pos;
                break;
            }
        }

        if (pack_start == 0 && resp_len > 4) {
            /* Maybe the whole response is the pack (no sideband) */
            if (resp_body[0] == 'P' && resp_body[1] == 'A' &&
                resp_body[2] == 'C' && resp_body[3] == 'K') {
                pack_start = 0;
            } else {
                free(resp_body);
                return __LINE__; /* no pack found */
            }
        }

        /* Write pack to file */
        fp = fopen(pack_path, "wb");
        if (!fp) { free(resp_body); return __LINE__; }

        fwrite(resp_body + pack_start, 1, (size_t)(resp_len - pack_start), fp);
        fclose(fp);
    }

    free(resp_body);
    return 0;
}
