#ifndef GUT_CONFIG_H
#define GUT_CONFIG_H

#include "gut/types.h"

#define GUT_CONFIG_MAX_ENTRIES 64

typedef struct {
    char *section;
    char *key;
    char *value;
} gut_config_entry;

typedef struct {
    gut_config_entry entries[GUT_CONFIG_MAX_ENTRIES];
    u64 count;
} gut_config;

unsigned long config_read(gut_config *out, const char *path);
unsigned long config_get(const char **out, gut_config *cfg,
                         const char *section, const char *key);
unsigned long config_destroy(gut_config *cfg);

#endif /* GUT_CONFIG_H */
