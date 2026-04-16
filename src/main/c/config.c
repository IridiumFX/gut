#include "gut/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *strdup_range(const char *s, size_t len) {
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

static char *strip(const char *s, size_t *len) {
    const char *start = s;
    const char *end = s + *len;
    while (start < end && (*start == ' ' || *start == '\t')) start++;
    while (end > start && (*(end - 1) == ' ' || *(end - 1) == '\t' ||
                           *(end - 1) == '\n' || *(end - 1) == '\r')) end--;
    *len = (size_t)(end - start);
    return (char *)start;
}

unsigned long config_read(gut_config *out, const char *path) {
    FILE *fp;
    char line[1024];
    char current_section[256];

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    out->count = 0;
    current_section[0] = '\0';

    fp = fopen(path, "r");
    if (!fp) return 0; /* missing config is fine */

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        char *trimmed = strip(line, &len);

        if (len == 0 || trimmed[0] == '#' || trimmed[0] == ';') continue;

        /* Section header: [section] */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                size_t slen = (size_t)(end - trimmed - 1);
                if (slen >= sizeof(current_section)) slen = sizeof(current_section) - 1;
                memcpy(current_section, trimmed + 1, slen);
                current_section[slen] = '\0';
            }
            continue;
        }

        /* Key = value */
        {
            char *eq = strchr(trimmed, '=');
            if (eq && current_section[0] && out->count < GUT_CONFIG_MAX_ENTRIES) {
                size_t klen = (size_t)(eq - trimmed);
                size_t vlen = len - klen - 1;
                char *kstart = strip(trimmed, &klen);
                char *vstart = strip(eq + 1, &vlen);

                gut_config_entry *e = &out->entries[out->count];
                e->section = strdup_range(current_section, strlen(current_section));
                e->key = strdup_range(kstart, klen);
                e->value = strdup_range(vstart, vlen);
                if (!e->section || !e->key || !e->value) {
                    fclose(fp);
                    config_destroy(out);
                    return __LINE__;
                }
                out->count++;
            }
        }
    }

    fclose(fp);
    return 0;
}

unsigned long config_get(const char **out, gut_config *cfg,
                         const char *section, const char *key) {
    u64 i;
    if (!out) return __LINE__;
    if (!cfg) return __LINE__;
    if (!section || !key) return __LINE__;

    for (i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->entries[i].section, section) == 0 &&
            strcmp(cfg->entries[i].key, key) == 0) {
            *out = cfg->entries[i].value;
            return 0;
        }
    }
    return __LINE__; /* not found */
}

unsigned long config_destroy(gut_config *cfg) {
    u64 i;
    if (!cfg) return __LINE__;
    for (i = 0; i < cfg->count; i++) {
        free(cfg->entries[i].section);
        free(cfg->entries[i].key);
        free(cfg->entries[i].value);
    }
    cfg->count = 0;
    return 0;
}
