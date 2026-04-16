#include "apennines/pem.h"
#include "apennines/base.h"
#include "apennines/buf.h"
#include <string.h>

#define PEM_BEGIN_PREFIX "-----BEGIN "
#define PEM_BEGIN_SUFFIX "-----"
#define PEM_END_PREFIX   "-----END "
#define PEM_END_SUFFIX   "-----"
#define PEM_LINE_LEN     64

/* Find a line starting with prefix in data[0..len). Returns pointer to start
   of the matched line, or NULL. */
static const u8 *find_line(const u8 *data, u64 len, const char *prefix,
                           u64 prefix_len) {
    u64 i = 0;
    while (i + prefix_len <= len) {
        /* Check if we are at start of data or right after a newline */
        if (i == 0 || data[i - 1] == '\n') {
            if (memcmp(data + i, prefix, prefix_len) == 0) {
                return data + i;
            }
        }
        i++;
    }
    return NULL;
}

/* Find needle in haystack with bounded length. Returns pointer or NULL. */
static const u8 *bounded_find(const u8 *haystack, u64 haystack_len,
                              const char *needle, u64 needle_len) {
    u64 i;
    if (needle_len > haystack_len) return NULL;
    for (i = 0; i + needle_len <= haystack_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

/* Extract label from a BEGIN line. begin points to "-----BEGIN ".
   Returns 0 on success. Writes label into label_out (NUL-terminated).
   Sets *line_end to point past the trailing newline (or end of line). */
static unsigned long extract_label(char *label_out, u64 label_max,
                                   const u8 *begin, const u8 *data_end,
                                   const u8 **line_end) {
    const u8 *p;
    const u8 *suffix;
    u64 label_len;
    u64 prefix_len = strlen(PEM_BEGIN_PREFIX);
    u64 suffix_len = strlen(PEM_BEGIN_SUFFIX);

    p = begin + prefix_len;
    /* Find the closing "-----" within bounds */
    suffix = bounded_find(p, (u64)(data_end - p), PEM_BEGIN_SUFFIX, suffix_len);
    if (!suffix) return 1;

    label_len = (u64)(suffix - p);

    if (label_out) {
        if (label_len + 1 > label_max) return 2; /* label too long */
        memcpy(label_out, p, label_len);
        label_out[label_len] = '\0';
    }

    /* Advance past "-----" and optional \r\n or \n */
    p = suffix + strlen(PEM_BEGIN_SUFFIX);
    if (p < data_end && *p == '\r') p++;
    if (p < data_end && *p == '\n') p++;
    *line_end = p;

    return 0;
}

/* Find END line matching label. Returns pointer to start of END line,
   or NULL. Sets *after_end past the end line. */
static const u8 *find_end_line(const u8 *data, u64 len,
                               const char *label, u64 label_len,
                               const u8 **after_end) {
    /* Build the expected end marker: "-----END <label>-----" */
    char end_marker[256];
    u64 marker_len;
    const u8 *p;

    marker_len = (u64)(strlen(PEM_END_PREFIX) + label_len +
                       strlen(PEM_END_SUFFIX));
    if (marker_len >= sizeof(end_marker)) return NULL;

    memcpy(end_marker, PEM_END_PREFIX, strlen(PEM_END_PREFIX));
    memcpy(end_marker + strlen(PEM_END_PREFIX), label, label_len);
    memcpy(end_marker + strlen(PEM_END_PREFIX) + label_len,
           PEM_END_SUFFIX, strlen(PEM_END_SUFFIX));
    end_marker[marker_len] = '\0';

    p = find_line(data, len, end_marker, marker_len);
    if (!p) return NULL;

    if (after_end) {
        const u8 *e = p + marker_len;
        const u8 *data_end = data + len;
        if (e < data_end && *e == '\r') e++;
        if (e < data_end && *e == '\n') e++;
        *after_end = e;
    }
    return p;
}

/* Strip whitespace from base64 body into a clean buffer for decoding */
static unsigned long strip_whitespace(buf *clean, const u8 *data, u64 len) {
    u64 i;
    unsigned long rc;
    for (i = 0; i < len; i++) {
        u8 c = data[i];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        rc = buf_append_byte(clean, c);
        if (rc) return 1;
    }
    return 0;
}

unsigned long pem_encode(buf *out, const char *label,
                         const u8 *der_data, u64 der_len) {
    unsigned long rc;
    buf b64;
    u64 label_len;
    u64 i;

    if (!out) return 1;
    if (!label) return 2;
    if (der_len > 0 && !der_data) return 3;

    /* Base64 encode the DER data */
    memset(&b64, 0, sizeof(b64));
    rc = buf_create(&b64, der_len * 2 + 16);
    if (rc) return 4;

    rc = base64_encode(&b64, (u8 *)der_data, der_len);
    if (rc) {
        buf_destroy(&b64);
        return 4;
    }

    label_len = strlen(label);

    /* Write "-----BEGIN <label>-----\n" */
    rc = buf_append(out, (u8 *)PEM_BEGIN_PREFIX, (u64)strlen(PEM_BEGIN_PREFIX));
    if (rc) { buf_destroy(&b64); return 5; }
    rc = buf_append(out, (u8 *)label, label_len);
    if (rc) { buf_destroy(&b64); return 5; }
    rc = buf_append(out, (u8 *)(PEM_BEGIN_SUFFIX "\n"),
                    (u64)(strlen(PEM_BEGIN_SUFFIX) + 1));
    if (rc) { buf_destroy(&b64); return 5; }

    /* Write base64 body in lines of PEM_LINE_LEN chars */
    i = 0;
    while (i < b64.len) {
        u64 chunk = b64.len - i;
        if (chunk > PEM_LINE_LEN) chunk = PEM_LINE_LEN;
        rc = buf_append(out, b64.data + i, chunk);
        if (rc) { buf_destroy(&b64); return 5; }
        rc = buf_append_byte(out, (u8)'\n');
        if (rc) { buf_destroy(&b64); return 5; }
        i += chunk;
    }

    /* Write "-----END <label>-----\n" */
    rc = buf_append(out, (u8 *)PEM_END_PREFIX, (u64)strlen(PEM_END_PREFIX));
    if (rc) { buf_destroy(&b64); return 5; }
    rc = buf_append(out, (u8 *)label, label_len);
    if (rc) { buf_destroy(&b64); return 5; }
    rc = buf_append(out, (u8 *)(PEM_END_SUFFIX "\n"),
                    (u64)(strlen(PEM_END_SUFFIX) + 1));
    if (rc) { buf_destroy(&b64); return 5; }

    buf_destroy(&b64);
    return 0;
}

unsigned long pem_decode(buf *out, char *label_out, u64 label_max,
                         const u8 *pem_data, u64 pem_len) {
    const u8 *begin_line;
    const u8 *body_start;
    const u8 *end_line;
    const u8 *after_end;
    char label_buf[256];
    u64 label_len;
    u64 body_len;
    buf clean;
    unsigned long rc;

    if (!out) return 1;
    if (!pem_data) return 2;
    if (pem_len < strlen(PEM_BEGIN_PREFIX) + strlen(PEM_BEGIN_SUFFIX))
        return 3;

    /* Find BEGIN line */
    begin_line = find_line(pem_data, pem_len, PEM_BEGIN_PREFIX,
                           (u64)strlen(PEM_BEGIN_PREFIX));
    if (!begin_line) return 4;

    /* Extract label */
    rc = extract_label(label_buf, sizeof(label_buf), begin_line,
                       pem_data + pem_len, &body_start);
    if (rc) return 4;

    label_len = strlen(label_buf);

    /* Copy label to output if requested */
    if (label_out) {
        if (label_len + 1 > label_max) return 6;
        memcpy(label_out, label_buf, label_len + 1);
    }

    /* Find END line */
    end_line = find_end_line(body_start, (u64)(pem_data + pem_len - body_start),
                             label_buf, label_len, &after_end);
    if (!end_line) return 5;

    /* Strip whitespace from body */
    body_len = (u64)(end_line - body_start);
    memset(&clean, 0, sizeof(clean));
    rc = buf_create(&clean, body_len);
    if (rc) return 7;

    rc = strip_whitespace(&clean, body_start, body_len);
    if (rc) {
        buf_destroy(&clean);
        return 7;
    }

    /* Base64 decode */
    rc = base64_decode(out, clean.data, clean.len);
    buf_destroy(&clean);
    if (rc) return 7;

    return 0;
}

unsigned long pem_count(u64 *out, const u8 *data, u64 len) {
    u64 count = 0;
    u64 prefix_len;
    u64 i;

    if (!out) return 1;
    if (!data) return 2;

    prefix_len = (u64)strlen(PEM_BEGIN_PREFIX);

    i = 0;
    while (i + prefix_len <= len) {
        if (i == 0 || data[i - 1] == '\n') {
            if (memcmp(data + i, PEM_BEGIN_PREFIX, prefix_len) == 0) {
                count++;
            }
        }
        i++;
    }

    *out = count;
    return 0;
}

unsigned long pem_decode_next(buf *out, char *label_out, u64 label_max,
                              const u8 **cursor, u64 *remaining) {
    const u8 *begin_line;
    const u8 *body_start;
    const u8 *end_line;
    const u8 *after_end;
    char label_buf[256];
    u64 label_len;
    u64 body_len;
    buf clean;
    unsigned long rc;
    const u8 *data;
    u64 len;

    if (!out) return 1;
    if (!cursor) return 2;
    if (!remaining) return 3;

    data = *cursor;
    len = *remaining;

    /* Find BEGIN line */
    begin_line = find_line(data, len, PEM_BEGIN_PREFIX,
                           (u64)strlen(PEM_BEGIN_PREFIX));
    if (!begin_line) return 4;

    /* Extract label */
    rc = extract_label(label_buf, sizeof(label_buf), begin_line,
                       data + len, &body_start);
    if (rc) return 4;

    label_len = strlen(label_buf);

    /* Copy label to output if requested */
    if (label_out) {
        if (label_len + 1 > label_max) return 6;
        memcpy(label_out, label_buf, label_len + 1);
    }

    /* Find END line */
    end_line = find_end_line(body_start, (u64)(data + len - body_start),
                             label_buf, label_len, &after_end);
    if (!end_line) return 5;

    /* Strip whitespace from body */
    body_len = (u64)(end_line - body_start);
    memset(&clean, 0, sizeof(clean));
    rc = buf_create(&clean, body_len + 1);
    if (rc) return 7;

    rc = strip_whitespace(&clean, body_start, body_len);
    if (rc) {
        buf_destroy(&clean);
        return 7;
    }

    /* Base64 decode */
    rc = base64_decode(out, clean.data, clean.len);
    buf_destroy(&clean);
    if (rc) return 7;

    /* Advance cursor past end line */
    {
        u64 consumed = (u64)(after_end - data);
        *cursor = after_end;
        *remaining = len - consumed;
    }

    return 0;
}
