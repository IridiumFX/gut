#include "gut/ignore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple glob matching supporting *, ?, and ** */
static int glob_match(const char *pat, const char *text) {
    while (*pat && *text) {
        if (pat[0] == '*' && pat[1] == '*') {
            /* ** matches everything including / */
            pat += 2;
            if (*pat == '/') pat++; /* skip optional / after ** */
            if (*pat == '\0') return 1;
            /* Try matching rest at every position */
            while (*text) {
                if (glob_match(pat, text)) return 1;
                text++;
            }
            return glob_match(pat, text);
        }
        if (*pat == '*') {
            pat++;
            /* * matches everything except / */
            while (*text && *text != '/') {
                if (glob_match(pat, text)) return 1;
                text++;
            }
            return glob_match(pat, text);
        }
        if (*pat == '?') {
            if (*text == '/') return 0;
            pat++;
            text++;
            continue;
        }
        if (*pat != *text) return 0;
        pat++;
        text++;
    }
    /* Handle trailing * or ** */
    while (*pat == '*') pat++;
    return (*pat == '\0' && *text == '\0');
}

unsigned long ignore_read(gut_ignore *out, const char *path) {
    FILE *fp;
    char line[1024];

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    out->count = 0;

    fp = fopen(path, "r");
    if (!fp) return 0; /* no .gitignore is fine */

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        char *p;
        gut_ignore_pattern *pat;

        /* Strip trailing whitespace */
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                           line[len - 1] == ' ' || line[len - 1] == '\t'))
            line[--len] = '\0';

        /* Skip blank lines and comments */
        if (len == 0 || line[0] == '#') continue;

        if (out->count >= GUT_IGNORE_MAX_PATTERNS) break;

        pat = &out->patterns[out->count];
        pat->negated = 0;
        pat->dir_only = 0;
        pat->anchored = 0;
        p = line;

        /* Negation */
        if (*p == '!') {
            pat->negated = 1;
            p++;
            len--;
        }

        /* Directory-only */
        if (len > 0 && p[len - 1] == '/') {
            pat->dir_only = 1;
            p[len - 1] = '\0';
            len--;
        }

        /* Anchored if contains / (not just trailing) */
        if (strchr(p, '/') != NULL) {
            pat->anchored = 1;
            /* Strip leading / */
            if (*p == '/') { p++; len--; }
        }

        pat->pattern = (char *)malloc(len + 1);
        if (!pat->pattern) { fclose(fp); return __LINE__; }
        memcpy(pat->pattern, p, len + 1);

        out->count++;
    }

    fclose(fp);
    return 0;
}

unsigned long ignore_match(unsigned long *ignored, gut_ignore *ign,
                           const char *path, int is_dir) {
    u64 i;
    if (!ignored) return __LINE__;
    if (!ign) return __LINE__;
    if (!path) return __LINE__;

    *ignored = 0;

    for (i = 0; i < ign->count; i++) {
        gut_ignore_pattern *pat = &ign->patterns[i];

        if (pat->dir_only && !is_dir) continue;

        int matched = 0;
        if (pat->anchored) {
            matched = glob_match(pat->pattern, path);
        } else {
            /* Match against basename or any path suffix */
            const char *basename = strrchr(path, '/');
            basename = basename ? basename + 1 : path;

            if (strchr(pat->pattern, '/') == NULL) {
                /* Simple pattern: match against basename */
                matched = glob_match(pat->pattern, basename);
            } else {
                /* Pattern with /: match against full path */
                matched = glob_match(pat->pattern, path);
            }
        }

        if (matched) {
            *ignored = pat->negated ? 0 : 1;
        }
    }

    return 0;
}

unsigned long ignore_destroy(gut_ignore *ign) {
    u64 i;
    if (!ign) return __LINE__;
    for (i = 0; i < ign->count; i++) {
        free(ign->patterns[i].pattern);
    }
    ign->count = 0;
    return 0;
}
