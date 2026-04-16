#ifndef GUT_IGNORE_H
#define GUT_IGNORE_H

#include "gut/types.h"

#define GUT_IGNORE_MAX_PATTERNS 256

typedef struct {
    char *pattern;
    int   negated;
    int   dir_only;
    int   anchored;
} gut_ignore_pattern;

typedef struct {
    gut_ignore_pattern patterns[GUT_IGNORE_MAX_PATTERNS];
    u64 count;
} gut_ignore;

unsigned long ignore_read(gut_ignore *out, const char *path);
unsigned long ignore_match(unsigned long *ignored, gut_ignore *ign,
                           const char *path, int is_dir);
unsigned long ignore_destroy(gut_ignore *ign);

#endif /* GUT_IGNORE_H */
