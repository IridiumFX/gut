#include "gut/repo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define gut_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#define gut_mkdir(p) mkdir(p, 0755)
#endif

static unsigned long mkdirs(const char *path) {
    char tmp[2048];
    u64 len;
    u64 i;

    len = strlen(path);
    if (len >= sizeof(tmp)) return __LINE__;
    memcpy(tmp, path, len + 1);

    for (i = 1; i < len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\\') {
            tmp[i] = '\0';
            gut_mkdir(tmp);
            tmp[i] = '/';
        }
    }
    gut_mkdir(tmp);
    return 0;
}

static unsigned long write_file(const char *path, const char *content) {
    FILE *fp;
    size_t len;

    fp = fopen(path, "w");
    if (!fp) return __LINE__;

    len = strlen(content);
    if (len > 0) {
        if (fwrite(content, 1, len, fp) != len) {
            fclose(fp);
            return __LINE__;
        }
    }
    fclose(fp);
    return 0;
}

unsigned long repo_init(gut_repo *out, const char *path) {
    char git_dir[1024];
    char sub[2048];
    unsigned long rc;
    int n;

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    n = snprintf(git_dir, sizeof(git_dir), "%s/.git", path);
    if (n < 0 || (u64)n >= sizeof(git_dir)) return __LINE__;

    /* Create directory structure */
    snprintf(sub, sizeof(sub), "%s/objects", git_dir);
    rc = mkdirs(sub);
    if (rc) return __LINE__;

    snprintf(sub, sizeof(sub), "%s/objects/pack", git_dir);
    rc = mkdirs(sub);
    if (rc) return __LINE__;

    snprintf(sub, sizeof(sub), "%s/refs/heads", git_dir);
    rc = mkdirs(sub);
    if (rc) return __LINE__;

    snprintf(sub, sizeof(sub), "%s/refs/tags", git_dir);
    rc = mkdirs(sub);
    if (rc) return __LINE__;

    /* Write HEAD */
    snprintf(sub, sizeof(sub), "%s/HEAD", git_dir);
    rc = write_file(sub, "ref: refs/heads/main\n");
    if (rc) return __LINE__;

    /* Write config */
    snprintf(sub, sizeof(sub), "%s/config", git_dir);
    rc = write_file(sub,
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = false\n"
        "\tbare = false\n");
    if (rc) return __LINE__;

    /* Write description */
    snprintf(sub, sizeof(sub), "%s/description", git_dir);
    rc = write_file(sub, "Unnamed repository; edit this file to name the repository.\n");
    if (rc) return __LINE__;

    /* Fill out repo struct */
    if (strlen(path) >= sizeof(out->root_dir)) return __LINE__;
    memcpy(out->root_dir, path, strlen(path) + 1);

    if (strlen(git_dir) >= sizeof(out->git_dir)) return __LINE__;
    memcpy(out->git_dir, git_dir, strlen(git_dir) + 1);

    snprintf(sub, sizeof(sub), "%s/objects", git_dir);
    rc = odb_open(&out->odb, sub);
    if (rc) return __LINE__;

    return 0;
}

unsigned long repo_open(gut_repo *out, const char *path) {
    char candidate[2048];
    char obj_dir[2048];
    struct stat st;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    /* Try path/.git first */
    snprintf(candidate, sizeof(candidate), "%s/.git", path);
    if (stat(candidate, &st) == 0) {
        if (strlen(path) >= sizeof(out->root_dir)) return __LINE__;
        memcpy(out->root_dir, path, strlen(path) + 1);

        if (strlen(candidate) >= sizeof(out->git_dir)) return __LINE__;
        memcpy(out->git_dir, candidate, strlen(candidate) + 1);

        snprintf(obj_dir, sizeof(obj_dir), "%s/objects", candidate);
        rc = odb_open(&out->odb, obj_dir);
        if (rc) return __LINE__;
        return 0;
    }

    /* Walk up parent directories */
    {
        char work[2048];
        if (strlen(path) >= sizeof(work)) return __LINE__;
        memcpy(work, path, strlen(path) + 1);

        for (;;) {
            char *last_sep;
            snprintf(candidate, sizeof(candidate), "%s/.git", work);
            if (stat(candidate, &st) == 0) {
                if (strlen(work) >= sizeof(out->root_dir)) return __LINE__;
                memcpy(out->root_dir, work, strlen(work) + 1);

                if (strlen(candidate) >= sizeof(out->git_dir)) return __LINE__;
                memcpy(out->git_dir, candidate, strlen(candidate) + 1);

                snprintf(obj_dir, sizeof(obj_dir), "%s/objects", candidate);
                rc = odb_open(&out->odb, obj_dir);
                if (rc) return __LINE__;
                return 0;
            }

            /* Go up one level */
            last_sep = strrchr(work, '/');
            if (!last_sep) last_sep = strrchr(work, '\\');
            if (!last_sep || last_sep == work) return __LINE__;
            *last_sep = '\0';
        }
    }
}

unsigned long repo_head_ref(char *out, u64 out_size, gut_repo *repo) {
    char head_path[2048];
    FILE *fp;
    char line[256];

    if (!out) return __LINE__;
    if (!repo) return __LINE__;

    snprintf(head_path, sizeof(head_path), "%s/HEAD", repo->git_dir);
    fp = fopen(head_path, "r");
    if (!fp) return __LINE__;

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return __LINE__;
    }
    fclose(fp);

    /* Strip trailing newline */
    {
        u64 len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
    }

    /* Check for symbolic ref */
    if (strncmp(line, "ref: ", 5) == 0) {
        if (strlen(line + 5) >= out_size) return __LINE__;
        memcpy(out, line + 5, strlen(line + 5) + 1);
    } else {
        /* Detached HEAD — raw OID hex */
        if (strlen(line) >= out_size) return __LINE__;
        memcpy(out, line, strlen(line) + 1);
    }

    return 0;
}

unsigned long repo_resolve_ref(gut_oid *out, gut_repo *repo, const char *ref) {
    char path[2048];
    FILE *fp;
    char line[256];
    int n;

    if (!out) return __LINE__;
    if (!repo) return __LINE__;
    if (!ref) return __LINE__;

    /* If ref looks like a hex OID, parse it directly */
    if (strlen(ref) == GUT_OID_HEX_SIZE) {
        unsigned long rc = oid_from_hex(out, ref);
        if (rc == 0) return 0;
    }

    /* Try as a file under .git/ */
    n = snprintf(path, sizeof(path), "%s/%s", repo->git_dir, ref);
    if (n < 0 || (u64)n >= sizeof(path)) return __LINE__;

    fp = fopen(path, "r");
    if (!fp) return __LINE__;

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return __LINE__;
    }
    fclose(fp);

    /* Strip newline */
    {
        u64 len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
    }

    /* Recursive resolve if symbolic */
    if (strncmp(line, "ref: ", 5) == 0) {
        return repo_resolve_ref(out, repo, line + 5);
    }

    return oid_from_hex(out, line);
}

unsigned long repo_update_ref(gut_repo *repo, const char *ref, gut_oid *oid) {
    char path[2048];
    char hex[GUT_OID_HEX_SIZE + 2];
    FILE *fp;
    unsigned long rc;
    int n;

    if (!repo) return __LINE__;
    if (!ref) return __LINE__;
    if (!oid) return __LINE__;

    n = snprintf(path, sizeof(path), "%s/%s", repo->git_dir, ref);
    if (n < 0 || (u64)n >= sizeof(path)) return __LINE__;

    rc = oid_to_hex(hex, oid);
    if (rc) return __LINE__;
    hex[GUT_OID_HEX_SIZE] = '\n';
    hex[GUT_OID_HEX_SIZE + 1] = '\0';

    fp = fopen(path, "w");
    if (!fp) return __LINE__;

    if (fputs(hex, fp) == EOF) {
        fclose(fp);
        return __LINE__;
    }

    fclose(fp);
    return 0;
}
