#include "apennines/json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ---- Internal parser state ---- */

typedef struct {
    const u8 *data;
    u64 len;
    u64 pos;
} json_parser;

/* ---- Forward declarations ---- */

static unsigned long parse_value(json_node **out, json_parser *p);
static unsigned long stringify_node(buf *out, json_node *node);

/* ---- Parser helpers ---- */

static void skip_whitespace(json_parser *p) {
    while (p->pos < p->len) {
        u8 c = p->data[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else {
            break;
        }
    }
}

static int peek(json_parser *p) {
    if (p->pos >= p->len) return -1;
    return (int)p->data[p->pos];
}

static int advance(json_parser *p) {
    if (p->pos >= p->len) return -1;
    return (int)p->data[p->pos++];
}

static int match_literal(json_parser *p, const char *lit) {
    u64 slen = (u64)strlen(lit);
    if (p->pos + slen > p->len) return 0;
    if (memcmp(p->data + p->pos, lit, (size_t)slen) != 0) return 0;
    p->pos += slen;
    return 1;
}

static json_node *alloc_node(json_type type) {
    json_node *n = (json_node *)calloc(1, sizeof(json_node));
    if (n) n->type = type;
    return n;
}

/* ---- Unicode helpers ---- */

static int hex_digit(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned long parse_4hex(json_parser *p, u32 *out) {
    u32 val = 0;
    int i;
    for (i = 0; i < 4; i++) {
        int c = advance(p);
        int d = hex_digit(c);
        if (d < 0) return 1;
        val = (val << 4) | (u32)d;
    }
    *out = val;
    return 0;
}

static unsigned long encode_utf8(buf *b, u32 cp) {
    unsigned long rc;
    if (cp <= 0x7F) {
        u8 c = (u8)cp;
        rc = buf_append_byte(b, c);
        if (rc) return 1;
    } else if (cp <= 0x7FF) {
        u8 c0 = (u8)(0xC0 | (cp >> 6));
        u8 c1 = (u8)(0x80 | (cp & 0x3F));
        rc = buf_append_byte(b, c0);
        if (rc) return 1;
        rc = buf_append_byte(b, c1);
        if (rc) return 1;
    } else if (cp <= 0xFFFF) {
        u8 c0 = (u8)(0xE0 | (cp >> 12));
        u8 c1 = (u8)(0x80 | ((cp >> 6) & 0x3F));
        u8 c2 = (u8)(0x80 | (cp & 0x3F));
        rc = buf_append_byte(b, c0);
        if (rc) return 1;
        rc = buf_append_byte(b, c1);
        if (rc) return 1;
        rc = buf_append_byte(b, c2);
        if (rc) return 1;
    } else if (cp <= 0x10FFFF) {
        u8 c0 = (u8)(0xF0 | (cp >> 18));
        u8 c1 = (u8)(0x80 | ((cp >> 12) & 0x3F));
        u8 c2 = (u8)(0x80 | ((cp >> 6) & 0x3F));
        u8 c3 = (u8)(0x80 | (cp & 0x3F));
        rc = buf_append_byte(b, c0);
        if (rc) return 1;
        rc = buf_append_byte(b, c1);
        if (rc) return 1;
        rc = buf_append_byte(b, c2);
        if (rc) return 1;
        rc = buf_append_byte(b, c3);
        if (rc) return 1;
    } else {
        return 1;
    }
    return 0;
}

/* ---- Parse string ---- */

static unsigned long parse_string(u8 **out_data, u64 *out_len, json_parser *p) {
    buf tmp;
    unsigned long rc;
    int c;

    if (advance(p) != '"') return 1; /* consume opening quote */

    rc = buf_create(&tmp, 64);
    if (rc) return 2;

    for (;;) {
        c = advance(p);
        if (c < 0) { buf_destroy(&tmp); return 3; } /* unexpected end */
        if (c == '"') break; /* closing quote */

        if (c == '\\') {
            c = advance(p);
            if (c < 0) { buf_destroy(&tmp); return 3; }
            switch (c) {
            case '"':  rc = buf_append_byte(&tmp, '"'); break;
            case '\\': rc = buf_append_byte(&tmp, '\\'); break;
            case '/':  rc = buf_append_byte(&tmp, '/'); break;
            case 'b':  rc = buf_append_byte(&tmp, '\b'); break;
            case 'f':  rc = buf_append_byte(&tmp, '\f'); break;
            case 'n':  rc = buf_append_byte(&tmp, '\n'); break;
            case 'r':  rc = buf_append_byte(&tmp, '\r'); break;
            case 't':  rc = buf_append_byte(&tmp, '\t'); break;
            case 'u': {
                u32 cp;
                if (parse_4hex(p, &cp)) { buf_destroy(&tmp); return 4; }
                /* Handle surrogate pairs */
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    u32 lo;
                    if (advance(p) != '\\' || advance(p) != 'u') {
                        buf_destroy(&tmp); return 4;
                    }
                    if (parse_4hex(p, &lo)) { buf_destroy(&tmp); return 4; }
                    if (lo < 0xDC00 || lo > 0xDFFF) { buf_destroy(&tmp); return 4; }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                if (encode_utf8(&tmp, cp)) { buf_destroy(&tmp); return 5; }
                rc = 0;
                break;
            }
            default:
                buf_destroy(&tmp);
                return 4; /* invalid escape */
            }
            if (rc) { buf_destroy(&tmp); return 5; }
        } else {
            rc = buf_append_byte(&tmp, (u8)c);
            if (rc) { buf_destroy(&tmp); return 5; }
        }
    }

    *out_data = tmp.data;
    *out_len = tmp.len;
    return 0;
}

/* ---- Parse number ---- */

static unsigned long parse_number(double *out, json_parser *p) {
    u64 start = p->pos;
    char numbuf[320];
    u64 nlen;
    char *endptr;
    double val;

    /* optional minus */
    if (p->pos < p->len && p->data[p->pos] == '-') p->pos++;

    /* integer part */
    if (p->pos >= p->len) return 1;
    if (p->data[p->pos] == '0') {
        p->pos++;
    } else if (p->data[p->pos] >= '1' && p->data[p->pos] <= '9') {
        p->pos++;
        while (p->pos < p->len && p->data[p->pos] >= '0' && p->data[p->pos] <= '9')
            p->pos++;
    } else {
        return 1;
    }

    /* fractional part */
    if (p->pos < p->len && p->data[p->pos] == '.') {
        p->pos++;
        if (p->pos >= p->len || p->data[p->pos] < '0' || p->data[p->pos] > '9')
            return 1;
        while (p->pos < p->len && p->data[p->pos] >= '0' && p->data[p->pos] <= '9')
            p->pos++;
    }

    /* exponent part */
    if (p->pos < p->len && (p->data[p->pos] == 'e' || p->data[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < p->len && (p->data[p->pos] == '+' || p->data[p->pos] == '-'))
            p->pos++;
        if (p->pos >= p->len || p->data[p->pos] < '0' || p->data[p->pos] > '9')
            return 1;
        while (p->pos < p->len && p->data[p->pos] >= '0' && p->data[p->pos] <= '9')
            p->pos++;
    }

    nlen = p->pos - start;
    if (nlen >= sizeof(numbuf)) return 2;
    memcpy(numbuf, p->data + start, (size_t)nlen);
    numbuf[nlen] = '\0';

    val = strtod(numbuf, &endptr);
    if (endptr != numbuf + nlen) return 3;

    *out = val;
    return 0;
}

/* ---- Parse value (recursive descent) ---- */

static unsigned long parse_value(json_node **out, json_parser *p) {
    int c;
    json_node *node;

    skip_whitespace(p);
    c = peek(p);
    if (c < 0) return 1;

    if (c == '"') {
        /* string */
        u8 *sdata;
        u64 slen;
        unsigned long rc = parse_string(&sdata, &slen, p);
        if (rc) return 2;
        node = alloc_node(JSON_STRING);
        if (!node) { free(sdata); return 3; }
        node->str_val.data = sdata;
        node->str_val.len = slen;
        *out = node;
        return 0;
    }

    if (c == '-' || (c >= '0' && c <= '9')) {
        /* number */
        double val;
        unsigned long rc = parse_number(&val, p);
        if (rc) return 4;
        node = alloc_node(JSON_NUMBER);
        if (!node) return 3;
        node->num_val = val;
        *out = node;
        return 0;
    }

    if (c == '{') {
        /* object */
        unsigned long rc;
        advance(p); /* consume { */

        node = alloc_node(JSON_OBJECT);
        if (!node) return 3;
        node->object_val.keys = NULL;
        node->object_val.key_lens = NULL;
        node->object_val.values = NULL;
        node->object_val.count = 0;
        node->object_val.cap = 0;

        skip_whitespace(p);
        if (peek(p) == '}') {
            advance(p);
            *out = node;
            return 0;
        }

        for (;;) {
            u8 *key_data;
            u64 key_len;
            json_node *val_node;

            skip_whitespace(p);
            if (peek(p) != '"') { json_node_destroy(node); return 5; }
            rc = parse_string(&key_data, &key_len, p);
            if (rc) { json_node_destroy(node); return 5; }

            skip_whitespace(p);
            if (advance(p) != ':') { free(key_data); json_node_destroy(node); return 6; }

            rc = parse_value(&val_node, p);
            if (rc) { free(key_data); json_node_destroy(node); return 7; }

            /* grow arrays if needed */
            if (node->object_val.count >= node->object_val.cap) {
                u64 new_cap = node->object_val.cap == 0 ? 8 : node->object_val.cap * 2;
                u8 **new_keys = (u8 **)realloc(node->object_val.keys, (size_t)(new_cap * sizeof(u8 *)));
                u64 *new_klens = (u64 *)realloc(node->object_val.key_lens, (size_t)(new_cap * sizeof(u64)));
                json_node **new_vals = (json_node **)realloc(node->object_val.values, (size_t)(new_cap * sizeof(json_node *)));
                if (!new_keys || !new_klens || !new_vals) {
                    free(key_data);
                    json_node_destroy(val_node);
                    /* patch in whatever succeeded before destroying */
                    if (new_keys) node->object_val.keys = new_keys;
                    if (new_klens) node->object_val.key_lens = new_klens;
                    if (new_vals) node->object_val.values = new_vals;
                    json_node_destroy(node);
                    return 8;
                }
                node->object_val.keys = new_keys;
                node->object_val.key_lens = new_klens;
                node->object_val.values = new_vals;
                node->object_val.cap = new_cap;
            }

            {
                u64 idx = node->object_val.count;
                node->object_val.keys[idx] = key_data;
                node->object_val.key_lens[idx] = key_len;
                node->object_val.values[idx] = val_node;
                node->object_val.count++;
            }

            skip_whitespace(p);
            c = advance(p);
            if (c == '}') break;
            if (c != ',') { json_node_destroy(node); return 9; }
        }

        *out = node;
        return 0;
    }

    if (c == '[') {
        /* array */
        unsigned long rc;
        advance(p); /* consume [ */

        node = alloc_node(JSON_ARRAY);
        if (!node) return 3;
        node->array_val.items = NULL;
        node->array_val.count = 0;
        node->array_val.cap = 0;

        skip_whitespace(p);
        if (peek(p) == ']') {
            advance(p);
            *out = node;
            return 0;
        }

        for (;;) {
            json_node *item;
            rc = parse_value(&item, p);
            if (rc) { json_node_destroy(node); return 10; }

            /* grow array if needed */
            if (node->array_val.count >= node->array_val.cap) {
                u64 new_cap = node->array_val.cap == 0 ? 8 : node->array_val.cap * 2;
                json_node **new_items = (json_node **)realloc(
                    node->array_val.items, (size_t)(new_cap * sizeof(json_node *)));
                if (!new_items) {
                    json_node_destroy(item);
                    json_node_destroy(node);
                    return 11;
                }
                node->array_val.items = new_items;
                node->array_val.cap = new_cap;
            }

            node->array_val.items[node->array_val.count++] = item;

            skip_whitespace(p);
            c = advance(p);
            if (c == ']') break;
            if (c != ',') { json_node_destroy(node); return 12; }
        }

        *out = node;
        return 0;
    }

    if (c == 't') {
        if (!match_literal(p, "true")) return 13;
        node = alloc_node(JSON_BOOL);
        if (!node) return 3;
        node->bool_val = 1;
        *out = node;
        return 0;
    }

    if (c == 'f') {
        if (!match_literal(p, "false")) return 14;
        node = alloc_node(JSON_BOOL);
        if (!node) return 3;
        node->bool_val = 0;
        *out = node;
        return 0;
    }

    if (c == 'n') {
        if (!match_literal(p, "null")) return 15;
        node = alloc_node(JSON_NULL);
        if (!node) return 3;
        *out = node;
        return 0;
    }

    return 16; /* unexpected character */
}

/* ---- Stringify helpers ---- */

static unsigned long append_str_literal(buf *out, const char *s) {
    return buf_append(out, (u8 *)s, (u64)strlen(s));
}

static unsigned long stringify_string(buf *out, const u8 *data, u64 len) {
    u64 i;
    unsigned long rc;

    rc = buf_append_byte(out, '"');
    if (rc) return 1;

    for (i = 0; i < len; i++) {
        u8 c = data[i];
        switch (c) {
        case '"':  rc = append_str_literal(out, "\\\""); break;
        case '\\': rc = append_str_literal(out, "\\\\"); break;
        case '\b': rc = append_str_literal(out, "\\b"); break;
        case '\f': rc = append_str_literal(out, "\\f"); break;
        case '\n': rc = append_str_literal(out, "\\n"); break;
        case '\r': rc = append_str_literal(out, "\\r"); break;
        case '\t': rc = append_str_literal(out, "\\t"); break;
        default:
            if (c < 0x20) {
                char esc[7];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                rc = buf_append(out, (u8 *)esc, 6);
            } else {
                rc = buf_append_byte(out, c);
            }
            break;
        }
        if (rc) return 1;
    }

    rc = buf_append_byte(out, '"');
    if (rc) return 1;

    return 0;
}

static unsigned long stringify_node(buf *out, json_node *node) {
    unsigned long rc;

    switch (node->type) {
    case JSON_NULL:
        rc = append_str_literal(out, "null");
        if (rc) return 1;
        break;

    case JSON_BOOL:
        if (node->bool_val) {
            rc = append_str_literal(out, "true");
        } else {
            rc = append_str_literal(out, "false");
        }
        if (rc) return 1;
        break;

    case JSON_NUMBER: {
        char numbuf[64];
        int nlen;
        double val = node->num_val;

        /* Print integers without decimal point */
        if (val == floor(val) && !isinf(val) && val >= -1e15 && val <= 1e15) {
            nlen = snprintf(numbuf, sizeof(numbuf), "%.0f", val);
        } else {
            nlen = snprintf(numbuf, sizeof(numbuf), "%.17g", val);
        }
        if (nlen < 0 || (size_t)nlen >= sizeof(numbuf)) return 2;
        rc = buf_append(out, (u8 *)numbuf, (u64)nlen);
        if (rc) return 1;
        break;
    }

    case JSON_STRING:
        rc = stringify_string(out, node->str_val.data, node->str_val.len);
        if (rc) return 1;
        break;

    case JSON_ARRAY: {
        u64 i;
        rc = buf_append_byte(out, '[');
        if (rc) return 1;
        for (i = 0; i < node->array_val.count; i++) {
            if (i > 0) {
                rc = buf_append_byte(out, ',');
                if (rc) return 1;
            }
            rc = stringify_node(out, node->array_val.items[i]);
            if (rc) return 1;
        }
        rc = buf_append_byte(out, ']');
        if (rc) return 1;
        break;
    }

    case JSON_OBJECT: {
        u64 i;
        rc = buf_append_byte(out, '{');
        if (rc) return 1;
        for (i = 0; i < node->object_val.count; i++) {
            if (i > 0) {
                rc = buf_append_byte(out, ',');
                if (rc) return 1;
            }
            rc = stringify_string(out, node->object_val.keys[i], node->object_val.key_lens[i]);
            if (rc) return 1;
            rc = buf_append_byte(out, ':');
            if (rc) return 1;
            rc = stringify_node(out, node->object_val.values[i]);
            if (rc) return 1;
        }
        rc = buf_append_byte(out, '}');
        if (rc) return 1;
        break;
    }

    default:
        return 3;
    }

    return 0;
}

/* ---- Public API: Parsing ---- */

unsigned long json_parse(json_node **out, const u8 *data, u64 len) {
    json_parser p;
    unsigned long rc;

    if (!out) return 1;
    if (!data && len > 0) return 2;

    p.data = data;
    p.len = len;
    p.pos = 0;

    rc = parse_value(out, &p);
    if (rc) return 3;

    /* Verify no trailing non-whitespace */
    skip_whitespace(&p);
    if (p.pos != p.len) {
        json_node_destroy(*out);
        *out = NULL;
        return 4;
    }

    return 0;
}

unsigned long json_stringify(buf *out, json_node *node) {
    if (!out) return 1;
    if (!node) return 2;
    return stringify_node(out, node) ? 3 : 0;
}

/* ---- Public API: Accessors ---- */

unsigned long json_get(json_node **out, json_node *parent, const char *key) {
    u64 i;
    u64 klen;

    if (!out) return 1;
    if (!parent) return 2;
    if (!key) return 3;
    if (parent->type != JSON_OBJECT) return 4;

    klen = (u64)strlen(key);
    for (i = 0; i < parent->object_val.count; i++) {
        if (parent->object_val.key_lens[i] == klen &&
            memcmp(parent->object_val.keys[i], key, (size_t)klen) == 0) {
            *out = parent->object_val.values[i];
            return 0;
        }
    }

    return 5; /* key not found */
}

unsigned long json_get_str(u8 **out, u64 *out_len, json_node *node) {
    if (!out) return 1;
    if (!out_len) return 2;
    if (!node) return 3;
    if (node->type != JSON_STRING) return 4;
    *out = node->str_val.data;
    *out_len = node->str_val.len;
    return 0;
}

unsigned long json_get_u64(u64 *out, json_node *node) {
    if (!out) return 1;
    if (!node) return 2;
    if (node->type != JSON_NUMBER) return 3;
    if (node->num_val < 0 || node->num_val != floor(node->num_val)) return 4;
    if (node->num_val > (double)UINT64_MAX) return 4;
    *out = (u64)node->num_val;
    return 0;
}

unsigned long json_get_f64(double *out, json_node *node) {
    if (!out) return 1;
    if (!node) return 2;
    if (node->type != JSON_NUMBER) return 3;
    *out = node->num_val;
    return 0;
}

unsigned long json_get_bool(unsigned long *out, json_node *node) {
    if (!out) return 1;
    if (!node) return 2;
    if (node->type != JSON_BOOL) return 3;
    *out = node->bool_val;
    return 0;
}

unsigned long json_get_array(json_node ***out, u64 *count, json_node *node) {
    if (!out) return 1;
    if (!count) return 2;
    if (!node) return 3;
    if (node->type != JSON_ARRAY) return 4;
    *out = node->array_val.items;
    *count = node->array_val.count;
    return 0;
}

unsigned long json_get_object_count(u64 *out, json_node *node) {
    if (!out) return 1;
    if (!node) return 2;
    if (node->type != JSON_OBJECT) return 3;
    *out = node->object_val.count;
    return 0;
}

unsigned long json_node_type(json_type *out, json_node *node) {
    if (!out) return 1;
    if (!node) return 2;
    *out = node->type;
    return 0;
}

/* ---- Public API: Builder ---- */

static unsigned long builder_append(json_builder *b, const char *s) {
    return buf_append(&b->output, (u8 *)s, (u64)strlen(s));
}

static unsigned long builder_maybe_comma(json_builder *b) {
    if (b->need_comma) {
        unsigned long rc = buf_append_byte(&b->output, ',');
        if (rc) return 1;
    }
    return 0;
}

static unsigned long builder_write_escaped_string(json_builder *b, const char *s) {
    unsigned long rc;
    const u8 *p = (const u8 *)s;

    rc = buf_append_byte(&b->output, '"');
    if (rc) return 1;

    while (*p) {
        u8 c = *p;
        switch (c) {
        case '"':  rc = builder_append(b, "\\\""); break;
        case '\\': rc = builder_append(b, "\\\\"); break;
        case '\b': rc = builder_append(b, "\\b"); break;
        case '\f': rc = builder_append(b, "\\f"); break;
        case '\n': rc = builder_append(b, "\\n"); break;
        case '\r': rc = builder_append(b, "\\r"); break;
        case '\t': rc = builder_append(b, "\\t"); break;
        default:
            if (c < 0x20) {
                char esc[7];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                rc = buf_append(&b->output, (u8 *)esc, 6);
            } else {
                rc = buf_append_byte(&b->output, c);
            }
            break;
        }
        if (rc) return 1;
        p++;
    }

    rc = buf_append_byte(&b->output, '"');
    if (rc) return 1;

    return 0;
}

unsigned long json_builder_create(json_builder *b) {
    unsigned long rc;
    if (!b) return 1;
    rc = buf_create(&b->output, 256);
    if (rc) return 2;
    b->depth = 0;
    b->need_comma = 0;
    return 0;
}

unsigned long json_builder_begin_object(json_builder *b) {
    unsigned long rc;
    if (!b) return 1;
    rc = builder_maybe_comma(b);
    if (rc) return 2;
    rc = buf_append_byte(&b->output, '{');
    if (rc) return 2;
    b->depth++;
    b->need_comma = 0;
    return 0;
}

unsigned long json_builder_end_object(json_builder *b) {
    unsigned long rc;
    if (!b) return 1;
    if (b->depth == 0) return 2;
    rc = buf_append_byte(&b->output, '}');
    if (rc) return 3;
    b->depth--;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_begin_array(json_builder *b) {
    unsigned long rc;
    if (!b) return 1;
    rc = builder_maybe_comma(b);
    if (rc) return 2;
    rc = buf_append_byte(&b->output, '[');
    if (rc) return 2;
    b->depth++;
    b->need_comma = 0;
    return 0;
}

unsigned long json_builder_end_array(json_builder *b) {
    unsigned long rc;
    if (!b) return 1;
    if (b->depth == 0) return 2;
    rc = buf_append_byte(&b->output, ']');
    if (rc) return 3;
    b->depth--;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_key(json_builder *b, const char *key) {
    unsigned long rc;
    if (!b) return 1;
    if (!key) return 2;
    rc = builder_maybe_comma(b);
    if (rc) return 3;
    rc = builder_write_escaped_string(b, key);
    if (rc) return 3;
    rc = buf_append_byte(&b->output, ':');
    if (rc) return 3;
    b->need_comma = 0;
    return 0;
}

unsigned long json_builder_str(json_builder *b, const char *val) {
    unsigned long rc;
    if (!b) return 1;
    if (!val) return 2;
    rc = builder_maybe_comma(b);
    if (rc) return 3;
    rc = builder_write_escaped_string(b, val);
    if (rc) return 3;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_u64(json_builder *b, u64 val) {
    unsigned long rc;
    char numbuf[32];
    int nlen;

    if (!b) return 1;
    rc = builder_maybe_comma(b);
    if (rc) return 2;

    nlen = snprintf(numbuf, sizeof(numbuf), "%llu", (unsigned long long)val);
    if (nlen < 0 || (size_t)nlen >= sizeof(numbuf)) return 3;
    rc = buf_append(&b->output, (u8 *)numbuf, (u64)nlen);
    if (rc) return 2;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_f64(json_builder *b, double val) {
    unsigned long rc;
    char numbuf[64];
    int nlen;

    if (!b) return 1;
    rc = builder_maybe_comma(b);
    if (rc) return 2;

    if (val == floor(val) && !isinf(val) && val >= -1e15 && val <= 1e15) {
        nlen = snprintf(numbuf, sizeof(numbuf), "%.0f", val);
    } else {
        nlen = snprintf(numbuf, sizeof(numbuf), "%.17g", val);
    }
    if (nlen < 0 || (size_t)nlen >= sizeof(numbuf)) return 3;
    rc = buf_append(&b->output, (u8 *)numbuf, (u64)nlen);
    if (rc) return 2;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_bool(json_builder *b, unsigned long val) {
    unsigned long rc;
    if (!b) return 1;
    rc = builder_maybe_comma(b);
    if (rc) return 2;
    rc = builder_append(b, val ? "true" : "false");
    if (rc) return 2;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_null(json_builder *b) {
    unsigned long rc;
    if (!b) return 1;
    rc = builder_maybe_comma(b);
    if (rc) return 2;
    rc = builder_append(b, "null");
    if (rc) return 2;
    b->need_comma = 1;
    return 0;
}

unsigned long json_builder_finish(buf *out, json_builder *b) {
    if (!out) return 1;
    if (!b) return 2;
    if (b->depth != 0) return 3;
    *out = b->output;
    /* Zero out builder's copy so destroy won't double-free */
    memset(&b->output, 0, sizeof(buf));
    b->need_comma = 0;
    return 0;
}

unsigned long json_builder_destroy(json_builder *b) {
    if (!b) return 1;
    buf_destroy(&b->output);
    b->depth = 0;
    b->need_comma = 0;
    return 0;
}

/* ---- Public API: Cleanup ---- */

unsigned long json_node_destroy(json_node *node) {
    u64 i;
    if (!node) return 1;

    switch (node->type) {
    case JSON_STRING:
        free(node->str_val.data);
        break;

    case JSON_ARRAY:
        for (i = 0; i < node->array_val.count; i++) {
            json_node_destroy(node->array_val.items[i]);
        }
        free(node->array_val.items);
        break;

    case JSON_OBJECT:
        for (i = 0; i < node->object_val.count; i++) {
            free(node->object_val.keys[i]);
            json_node_destroy(node->object_val.values[i]);
        }
        free(node->object_val.keys);
        free(node->object_val.key_lens);
        free(node->object_val.values);
        break;

    default:
        break;
    }

    free(node);
    return 0;
}
unsigned long json_get_object(u8 ***out_keys, u64 **out_key_lens,
                                json_node ***out_values, u64 *out_count,
                                json_node *node) {
    if (!out_keys)     return 1;
    if (!out_key_lens) return 2;
    if (!out_values)   return 3;
    if (!out_count)    return 4;
    if (!node)         return 5;
    if (node->type != JSON_OBJECT) return 6;
    *out_keys     = node->object_val.keys;
    *out_key_lens = node->object_val.key_lens;
    *out_values   = node->object_val.values;
    *out_count    = node->object_val.count;
    return 0;
}
