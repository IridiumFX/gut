#ifndef APENNINES_T2_ENCODING_JSON_H
#define APENNINES_T2_ENCODING_JSON_H

#include "apennines/types.h"
#include "apennines/buf.h"

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_node json_node;
struct json_node {
    json_type type;
    union {
        unsigned long bool_val;
        double num_val;
        struct { u8 *data; u64 len; } str_val;
        struct { json_node **items; u64 count; u64 cap; } array_val;
        struct {
            u8 **keys; u64 *key_lens;
            json_node **values;
            u64 count; u64 cap;
        } object_val;
    };
};

typedef struct {
    buf output;
    unsigned long depth;
    unsigned long need_comma;
} json_builder;

/* Parsing */
unsigned long json_parse(json_node **out, const u8 *data, u64 len);
unsigned long json_stringify(buf *out, json_node *node);

/* Accessors */
unsigned long json_get(json_node **out, json_node *parent, const char *key);
unsigned long json_get_str(u8 **out, u64 *out_len, json_node *node);
unsigned long json_get_u64(u64 *out, json_node *node);
unsigned long json_get_f64(double *out, json_node *node);
unsigned long json_get_bool(unsigned long *out, json_node *node);
unsigned long json_get_array(json_node ***out, u64 *count, json_node *node);
unsigned long json_get_object_count(u64 *out, json_node *node);
unsigned long json_get_object(u8 ***out_keys, u64 **out_key_lens,
                                             json_node ***out_values, u64 *out_count,
                                             json_node *node);
unsigned long json_node_type(json_type *out, json_node *node);

/* Builder */
unsigned long json_builder_create(json_builder *b);
unsigned long json_builder_begin_object(json_builder *b);
unsigned long json_builder_end_object(json_builder *b);
unsigned long json_builder_begin_array(json_builder *b);
unsigned long json_builder_end_array(json_builder *b);
unsigned long json_builder_key(json_builder *b, const char *key);
unsigned long json_builder_str(json_builder *b, const char *val);
unsigned long json_builder_u64(json_builder *b, u64 val);
unsigned long json_builder_f64(json_builder *b, double val);
unsigned long json_builder_bool(json_builder *b, unsigned long val);
unsigned long json_builder_null(json_builder *b);
unsigned long json_builder_finish(buf *out, json_builder *b);
unsigned long json_builder_destroy(json_builder *b);

/* Cleanup */
unsigned long json_node_destroy(json_node *node);

#endif /* APENNINES_T2_ENCODING_JSON_H */
