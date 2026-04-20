#include "gut/repo.h"
#include "gut/config.h"
#include "gut/oid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

/* If `candidate` is a regular file in gitfile format ("gitdir: <path>\n"),
 * read it and write the resolved absolute git dir into `out`. If it's a
 * directory, copy it into `out` as-is. Returns 0 on success.
 *
 * Gitfile paths are relative to the file's parent directory — git stores
 * them as relative paths like "../.git/modules/<name>" so repo trees can
 * be moved around safely. */
static unsigned long resolve_git_dir(char *out, u64 out_size,
                                     const char *candidate) {
    struct stat st;
    FILE *fp;
    char line[2048];
    const char *target;
    u64 target_len;

    if (stat(candidate, &st) != 0) return __LINE__;

    /* Directory: use candidate as-is. */
    if (st.st_mode & S_IFDIR) {
        u64 clen = strlen(candidate);
        if (clen >= out_size) return __LINE__;
        memcpy(out, candidate, clen + 1);
        return 0;
    }

    /* Regular file: expect "gitdir: <path>\n". */
    fp = fopen(candidate, "r");
    if (!fp) return __LINE__;
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return __LINE__; }
    fclose(fp);

    {
        u64 L = strlen(line);
        while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r' ||
                         line[L - 1] == ' ' || line[L - 1] == '\t'))
            line[--L] = '\0';
    }

    if (strncmp(line, "gitdir:", 7) != 0) return __LINE__;
    target = line + 7;
    while (*target == ' ' || *target == '\t') target++;
    target_len = strlen(target);
    if (target_len == 0) return __LINE__;

    /* If absolute, use directly; otherwise resolve against candidate's parent. */
    if (target[0] == '/' || target[0] == '\\' ||
        (target_len >= 2 && target[1] == ':')) {
        if (target_len >= out_size) return __LINE__;
        memcpy(out, target, target_len + 1);
    } else {
        /* Relative: parent dir of candidate + '/' + target */
        char parent[2048];
        const char *sep;
        u64 plen = strlen(candidate);
        if (plen >= sizeof(parent)) return __LINE__;
        memcpy(parent, candidate, plen + 1);
        sep = strrchr(parent, '/');
        if (!sep) sep = strrchr(parent, '\\');
        if (!sep) return __LINE__;
        parent[sep - parent] = '\0';
        if ((u64)snprintf(out, out_size, "%s/%s", parent, target) >= out_size)
            return __LINE__;
    }

    /* Normalize backslashes to forward slashes so downstream snprintf
     * concatenations don't end up with mixed separators. */
    {
        char *p;
        for (p = out; *p; p++) if (*p == '\\') *p = '/';
    }

    return 0;
}

/* Return the correct base directory for a ref filename. Refs under
 * `refs/...` live in the shared common_dir (all worktrees see the same
 * branches/tags). Everything else — HEAD, ORIG_HEAD, FETCH_HEAD,
 * MERGE_HEAD, CHERRY_PICK_HEAD, REVERT_HEAD — is per-worktree state
 * and lives in git_dir. */
static const char *ref_base_dir(gut_repo *repo, const char *ref) {
    if (strncmp(ref, "refs/", 5) == 0) return repo->common_dir;
    return repo->git_dir;
}

/* Same for reflogs. logs/HEAD is per-worktree; logs/refs/... is shared. */
static const char *reflog_base_dir(gut_repo *repo, const char *ref_path_rel) {
    if (strncmp(ref_path_rel, "refs/", 5) == 0) return repo->common_dir;
    return repo->git_dir;
}

/* Read <common_dir>/config and return the configured object hash algo, or
 * GUT_HASH_SHA1 if not set. Takes common_dir because config is shared across
 * worktrees. */
static gut_hash_algo read_hash_algo(const char *common_dir) {
    char cfg_path[2048];
    gut_config cfg;
    const char *v = NULL;
    gut_hash_algo algo = GUT_HASH_SHA1;
    snprintf(cfg_path, sizeof(cfg_path), "%s/config", common_dir);
    if (config_read(&cfg, cfg_path) != 0) return algo;
    if (config_get(&v, &cfg, "extensions", "objectformat") == 0 && v) {
        if (strcmp(v, "sha256") == 0) algo = GUT_HASH_SHA256;
    }
    config_destroy(&cfg);
    return algo;
}

/* Resolve a secondary worktree's commondir pointer. If `<git_dir>/commondir`
 * exists, it contains a (usually relative) path to the main `.git/`. Returns
 * 0 on success with the resolved absolute path in `out`; returns non-zero
 * if there's no commondir file (i.e., this is the main worktree — the
 * caller should alias common_dir to git_dir in that case). */
static unsigned long read_commondir(char *out, u64 out_size, const char *git_dir) {
    char cd_path[2048];
    FILE *fp;
    char line[1024];
    u64 L;

    snprintf(cd_path, sizeof(cd_path), "%s/commondir", git_dir);
    fp = fopen(cd_path, "r");
    if (!fp) return __LINE__;
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return __LINE__; }
    fclose(fp);

    L = strlen(line);
    while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
    if (L == 0) return __LINE__;

    /* Absolute path (Unix-style leading /, or Windows drive letter). */
    if (line[0] == '/' || (L > 1 && line[1] == ':')) {
        if (L >= out_size) return __LINE__;
        memcpy(out, line, L + 1);
    } else {
        /* Relative: rooted at git_dir. */
        int n = snprintf(out, (size_t)out_size, "%s/%s", git_dir, line);
        if (n < 0 || (u64)n >= out_size) return __LINE__;
    }

    /* Normalize separators. */
    {
        char *p;
        for (p = out; *p; p++) if (*p == '\\') *p = '/';
    }

    /* Collapse `/x/..` segments in place. Each iteration finds the
     * leftmost `..` with a non-`..` predecessor and removes both.
     * This lets paths printed to users look sane (.git instead of
     * .git/worktrees/<id>/../..) and keeps all downstream snprintf
     * concatenations shorter. */
    {
        for (;;) {
            char *dd = strstr(out, "/..");
            char *prev_start;
            char *p;
            if (!dd) break;
            if (dd[3] != '/' && dd[3] != '\0') break;
            /* Find the start of the segment preceding `/..` */
            if (dd == out) break;
            prev_start = dd - 1;
            while (prev_start > out && *prev_start != '/') prev_start--;
            if (*prev_start != '/') break;
            /* Don't collapse if the segment itself is ".." */
            if (dd - prev_start == 3 &&
                prev_start[1] == '.' && prev_start[2] == '.') break;
            /* Shift everything from dd+3 onward to prev_start. */
            p = dd + 3;
            while ((*prev_start++ = *p++) != '\0') {}
        }
        /* Drop trailing slash (if any) unless the whole path is "/". */
        {
            u64 L = strlen(out);
            if (L > 1 && out[L - 1] == '/') out[L - 1] = '\0';
        }
    }
    return 0;
}

/* Read .git/config and, if this repo is a partial clone, copy the promisor
 * remote's URL into `out` (empty string if none). The flow is:
 *   [extensions] partialclone = <remote-name>
 *   [remote "<remote-name>"] url = <url>
 *   [remote "<remote-name>"] promisor = true   (for sanity)
 */
static void read_promisor_url(char *out, u64 out_size, const char *common_dir) {
    char cfg_path[2048];
    char remote_section[128];
    gut_config cfg;
    const char *remote_name = NULL;
    const char *url = NULL;

    out[0] = '\0';
    snprintf(cfg_path, sizeof(cfg_path), "%s/config", common_dir);
    if (config_read(&cfg, cfg_path) != 0) return;

    if (config_get(&remote_name, &cfg, "extensions", "partialclone") != 0 || !remote_name) {
        config_destroy(&cfg);
        return;
    }

    snprintf(remote_section, sizeof(remote_section), "remote \"%s\"", remote_name);
    if (config_get(&url, &cfg, remote_section, "url") == 0 && url) {
        size_t ulen = strlen(url);
        if (ulen < out_size) memcpy(out, url, ulen + 1);
    }
    config_destroy(&cfg);
}

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#include <io.h>
#define gut_mkdir(p) _mkdir(p)
#define gut_getcwd(b, s) _getcwd(b, s)
#else
#include <unistd.h>
#define gut_mkdir(p) mkdir(p, 0755)
#define gut_getcwd(b, s) getcwd(b, s)
#endif

/* Atomic-replace rename: rename(from, to) replacing any existing `to`.
 * Returns 0 on success. On Windows, wraps MoveFileExA with REPLACE_EXISTING
 * since MinGW's rename() fails when target exists. */
static int atomic_rename(const char *from, const char *to) {
#ifdef _WIN32
    return MoveFileExA(from, to,
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : -1;
#else
    return rename(from, to);
#endif
}

/* Resolve a path to absolute, normalizing separators */
static unsigned long resolve_path(char *out, u64 out_size, const char *path) {
    char *p;
    if (!out) return __LINE__;
    if (!path) return __LINE__;

    if (path[0] == '/' || (path[0] != '\0' && path[1] == ':')) {
        /* Already absolute */
        if (strlen(path) >= out_size) return __LINE__;
        memcpy(out, path, strlen(path) + 1);
    } else {
        /* Relative — prepend cwd */
        char cwd[1024];
        int n;
        if (!gut_getcwd(cwd, sizeof(cwd))) return __LINE__;
        if (strcmp(path, ".") == 0) {
            if (strlen(cwd) >= out_size) return __LINE__;
            memcpy(out, cwd, strlen(cwd) + 1);
        } else {
            n = snprintf(out, (size_t)out_size, "%s/%s", cwd, path);
            if (n < 0 || (u64)n >= out_size) return __LINE__;
        }
    }

    /* Normalize backslashes to forward slashes */
    for (p = out; *p; p++) {
        if (*p == '\\') *p = '/';
    }

    /* Strip trailing slash */
    {
        u64 len = strlen(out);
        while (len > 1 && out[len - 1] == '/') {
            out[--len] = '\0';
        }
    }

    return 0;
}

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
    char abs_path[1024];
    char git_dir[1024];
    char sub[2048];
    unsigned long rc;
    int n;

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    rc = resolve_path(abs_path, sizeof(abs_path), path);
    if (rc) return __LINE__;

    n = snprintf(git_dir, sizeof(git_dir), "%s/.git", abs_path);
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
    if (strlen(abs_path) >= sizeof(out->root_dir)) return __LINE__;
    memcpy(out->root_dir, abs_path, strlen(abs_path) + 1);

    if (strlen(git_dir) >= sizeof(out->git_dir)) return __LINE__;
    memcpy(out->git_dir, git_dir, strlen(git_dir) + 1);

    /* Main-worktree case: common_dir aliases git_dir. */
    memcpy(out->common_dir, git_dir, strlen(git_dir) + 1);

    snprintf(sub, sizeof(sub), "%s/objects", git_dir);
    rc = odb_open(&out->odb, sub);
    if (rc) return __LINE__;

    return 0;
}

unsigned long repo_open(gut_repo *out, const char *path) {
    char abs_path[1024];
    char candidate[2048];
    char obj_dir[2048];
    struct stat st;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!path) return __LINE__;

    rc = resolve_path(abs_path, sizeof(abs_path), path);
    if (rc) return __LINE__;

    /* Try path/.git first */
    snprintf(candidate, sizeof(candidate), "%s/.git", abs_path);
    if (stat(candidate, &st) == 0) {
        if (strlen(abs_path) >= sizeof(out->root_dir)) return __LINE__;
        memcpy(out->root_dir, abs_path, strlen(abs_path) + 1);

        rc = resolve_git_dir(out->git_dir, sizeof(out->git_dir), candidate);
        if (rc) return __LINE__;

        /* If `<git_dir>/commondir` exists, this is a secondary worktree;
         * shared state lives in the pointed-to main .git/. Otherwise
         * common_dir aliases git_dir. */
        if (read_commondir(out->common_dir, sizeof(out->common_dir),
                           out->git_dir) != 0) {
            memcpy(out->common_dir, out->git_dir, strlen(out->git_dir) + 1);
        }

        snprintf(obj_dir, sizeof(obj_dir), "%s/objects", out->common_dir);
        rc = odb_open(&out->odb, obj_dir);
        if (rc) return __LINE__;
        out->hash_algo = read_hash_algo(out->common_dir);
        out->odb.hash_algo = out->hash_algo;
        read_promisor_url(out->odb.promisor_url, sizeof(out->odb.promisor_url),
                          out->common_dir);
        return 0;
    }

    /* Walk up parent directories */
    {
        char work[2048];
        if (strlen(abs_path) >= sizeof(work)) return __LINE__;
        memcpy(work, abs_path, strlen(abs_path) + 1);

        for (;;) {
            char *last_sep;
            snprintf(candidate, sizeof(candidate), "%s/.git", work);
            if (stat(candidate, &st) == 0) {
                if (strlen(work) >= sizeof(out->root_dir)) return __LINE__;
                memcpy(out->root_dir, work, strlen(work) + 1);

                rc = resolve_git_dir(out->git_dir, sizeof(out->git_dir),
                                     candidate);
                if (rc) return __LINE__;

                if (read_commondir(out->common_dir, sizeof(out->common_dir),
                                   out->git_dir) != 0) {
                    memcpy(out->common_dir, out->git_dir, strlen(out->git_dir) + 1);
                }

                snprintf(obj_dir, sizeof(obj_dir), "%s/objects", out->common_dir);
                rc = odb_open(&out->odb, obj_dir);
                if (rc) return __LINE__;
                out->hash_algo = read_hash_algo(out->common_dir);
                out->odb.hash_algo = out->hash_algo;
                read_promisor_url(out->odb.promisor_url, sizeof(out->odb.promisor_url),
                                  out->common_dir);
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
    unsigned hex_len;

    if (!out) return __LINE__;
    if (!repo) return __LINE__;
    if (!ref) return __LINE__;

    hex_len = gut_oid_hex_size(repo->hash_algo);

    /* If ref looks like a full hex OID, parse it directly */
    if (strlen(ref) == hex_len) {
        unsigned long rc = oid_from_hex_n(out, ref, hex_len);
        if (rc == 0) return 0;
    }

    /* Try as a file under .git/ or the shared common_dir, depending on ref. */
    n = snprintf(path, sizeof(path), "%s/%s", ref_base_dir(repo, ref), ref);
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

    return oid_from_hex_n(out, line, hex_len);
}

/* Resolve the committer identity for reflog entries.
 *
 * Priority: GUT_COMMITTER_NAME/EMAIL env > GUT_AUTHOR_NAME/EMAIL env >
 * GIT_COMMITTER_NAME/EMAIL env > GIT_AUTHOR_NAME/EMAIL env >
 * [user] name/email in .git/config > ("Unknown", "unknown@example.com").
 *
 * Caller-provided buffers are always filled (never left uninitialized),
 * so callers can format the reflog line unconditionally.
 *
 * Note: this duplicates the identity resolution that cmd_commit does
 * inline. When cmd_commit is refactored, both should share this helper. */
static void resolve_identity(char *name, u64 name_sz,
                             char *email, u64 email_sz,
                             gut_repo *repo) {
    const char *n = NULL;
    const char *e = NULL;
    gut_config cfg;
    int have_cfg = 0;
    char config_path[2048];

    n = getenv("GUT_COMMITTER_NAME");
    if (!n) n = getenv("GUT_AUTHOR_NAME");
    if (!n) n = getenv("GIT_COMMITTER_NAME");
    if (!n) n = getenv("GIT_AUTHOR_NAME");

    e = getenv("GUT_COMMITTER_EMAIL");
    if (!e) e = getenv("GUT_AUTHOR_EMAIL");
    if (!e) e = getenv("GIT_COMMITTER_EMAIL");
    if (!e) e = getenv("GIT_AUTHOR_EMAIL");

    if (!n || !e) {
        snprintf(config_path, sizeof(config_path), "%s/config", repo->common_dir);
        if (config_read(&cfg, config_path) == 0) {
            have_cfg = 1;
            if (!n) {
                const char *v;
                if (config_get(&v, &cfg, "user", "name") == 0) n = v;
            }
            if (!e) {
                const char *v;
                if (config_get(&v, &cfg, "user", "email") == 0) e = v;
            }
        }
    }

    if (!n) n = "Unknown";
    if (!e) e = "unknown@example.com";

    snprintf(name, (size_t)name_sz, "%s", n);
    snprintf(email, (size_t)email_sz, "%s", e);

    if (have_cfg) config_destroy(&cfg);
}

/* Format "<unix_ts> <tz_offset>" matching git's reflog/commit timestamp
 * convention. Example: "1713517200 +0100". */
static void format_reflog_time(char *out, u64 out_sz) {
    time_t now = time(NULL);
    long tz_offset_min = 0;
#ifdef _WIN32
    TIME_ZONE_INFORMATION tzi;
    if (GetTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID) {
        tz_offset_min = -(long)tzi.Bias;
    }
#else
    struct tm *lt = localtime(&now);
    if (lt) tz_offset_min = lt->tm_gmtoff / 60;
#endif
    snprintf(out, (size_t)out_sz, "%lld %+03ld%02ld",
             (long long)now, tz_offset_min / 60, labs(tz_offset_min) % 60);
}

/* Append a reflog line to .git/logs/<ref>. Creates parent directories
 * as needed. Returns 0 on success; non-zero line number on failure.
 *
 * Git's reflog line format:
 *   <old-hex> SP <new-hex> SP <name> SP "<" email ">" SP
 *   <unix-ts> SP <tz-offset> TAB <reason> LF
 *
 * Both old-hex and new-hex are written at the repo's hash width. If
 * the ref didn't exist before (initial commit, new branch), old-hex is
 * all zeros of that width. */
static unsigned long reflog_append_one(gut_repo *repo, const char *ref_path_rel,
                                       const gut_oid *old_oid,
                                       const gut_oid *new_oid,
                                       const char *name, const char *email,
                                       const char *time_str,
                                       const char *reason) {
    char log_path[2048];
    char parent_dir[2048];
    char line[1024];
    char old_hex[GUT_OID_MAX_HEX_SIZE + 1];
    char new_hex[GUT_OID_MAX_HEX_SIZE + 1];
    unsigned hex_len;
    unsigned long rc;
    FILE *fp;
    int n;
    int line_len;

    n = snprintf(log_path, sizeof(log_path), "%s/logs/%s",
                 reflog_base_dir(repo, ref_path_rel), ref_path_rel);
    if (n < 0 || (u64)n >= sizeof(log_path)) return __LINE__;

    /* Ensure parent directory exists (e.g. logs/refs/heads/). */
    {
        u64 L = strlen(log_path);
        u64 plen;
        const char *slash = strrchr(log_path, '/');
        if (!slash) return __LINE__;
        plen = (u64)(slash - log_path);
        if (plen >= sizeof(parent_dir)) return __LINE__;
        memcpy(parent_dir, log_path, plen);
        parent_dir[plen] = '\0';
        (void)L;
    }
    rc = mkdirs(parent_dir);
    if (rc) return __LINE__;

    hex_len = gut_oid_hex_size(repo->hash_algo);

    /* oid_to_hex_n takes a non-const pointer; cast away since it only
     * reads the bytes. */
    rc = oid_to_hex_n(old_hex, (gut_oid *)old_oid, hex_len);
    if (rc) return __LINE__;
    old_hex[hex_len] = '\0';
    rc = oid_to_hex_n(new_hex, (gut_oid *)new_oid, hex_len);
    if (rc) return __LINE__;
    new_hex[hex_len] = '\0';

    /* Sanitize reason: strip embedded LFs so a single log line always
     * ends exactly at our own LF. Git does the same — a stray newline
     * in a commit message would otherwise split one entry into two. */
    {
        char safe_reason[512];
        u64 i, j = 0;
        u64 rlen = strlen(reason);
        if (rlen >= sizeof(safe_reason)) rlen = sizeof(safe_reason) - 1;
        for (i = 0; i < rlen; i++) {
            char c = reason[i];
            if (c == '\n' || c == '\r') c = ' ';
            safe_reason[j++] = c;
        }
        safe_reason[j] = '\0';

        line_len = snprintf(line, sizeof(line),
                            "%s %s %s <%s> %s\t%s\n",
                            old_hex, new_hex, name, email,
                            time_str, safe_reason);
    }
    if (line_len < 0 || (u64)line_len >= sizeof(line)) return __LINE__;

    fp = fopen(log_path, "ab");
    if (!fp) return __LINE__;
    if (fwrite(line, 1, (size_t)line_len, fp) != (size_t)line_len) {
        fclose(fp);
        return __LINE__;
    }
    fclose(fp);
    return 0;
}

unsigned long repo_reflog_head(gut_repo *repo,
                               const gut_oid *old_oid,
                               const gut_oid *new_oid,
                               const char *reason) {
    char rname[256];
    char remail[256];
    char rtime[64];

    if (!repo) return __LINE__;
    if (!old_oid) return __LINE__;
    if (!new_oid) return __LINE__;
    if (!reason) return __LINE__;

    resolve_identity(rname, sizeof(rname), remail, sizeof(remail), repo);
    format_reflog_time(rtime, sizeof(rtime));
    return reflog_append_one(repo, "HEAD", old_oid, new_oid,
                             rname, remail, rtime, reason);
}

unsigned long repo_update_ref(gut_repo *repo, const char *ref,
                              gut_oid *oid, const char *reason) {
    char path[2048];
    char lock_path[2048];
    char hex[GUT_OID_MAX_HEX_SIZE + 2];
    int fd;
    unsigned long rc;
    int n;
    unsigned hex_len;
    gut_oid old_oid;
    int have_old = 0;

    if (!repo) return __LINE__;
    if (!ref) return __LINE__;
    if (!oid) return __LINE__;

    /* Snapshot the old value before we overwrite it (for the reflog).
     * Missing ref → all-zero hex, matching git's "ref didn't exist yet"
     * convention for initial commits and new branches. */
    memset(&old_oid, 0, sizeof(old_oid));
    if (reason) {
        if (repo_resolve_ref(&old_oid, repo, ref) == 0) have_old = 1;
        (void)have_old;
    }

    n = snprintf(path, sizeof(path), "%s/%s", ref_base_dir(repo, ref), ref);
    if (n < 0 || (u64)n >= sizeof(path)) return __LINE__;
    n = snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    if (n < 0 || (u64)n >= sizeof(lock_path)) return __LINE__;

    hex_len = gut_oid_hex_size(repo->hash_algo);
    rc = oid_to_hex_n(hex, oid, hex_len);
    if (rc) return __LINE__;
    hex[hex_len] = '\n';
    hex[hex_len + 1] = '\0';

    /* Create .lock exclusively. If another writer holds it, fail. */
#ifdef _WIN32
    fd = _open(lock_path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
    fd = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
#endif
    if (fd < 0) {
        /* Another writer holds the lock, or a stale lock remains.
         * Fall back to forced write for simplicity — a retry loop would be
         * better but stale locks are painful to detect. */
        return __LINE__;
    }

    /* Write the ref content */
    {
        u64 len = (u64)hex_len + 1;
#ifdef _WIN32
        int w = _write(fd, hex, (unsigned)len);
#else
        ssize_t w = write(fd, hex, (size_t)len);
#endif
        if (w != (int)len) {
#ifdef _WIN32
            _close(fd);
#else
            close(fd);
#endif
            remove(lock_path);
            return __LINE__;
        }
    }

#ifdef _WIN32
    _close(fd);
#else
    close(fd);
#endif

    /* Atomically replace path with lock file */
    if (atomic_rename(lock_path, path) != 0) {
        remove(lock_path);
        return __LINE__;
    }

    /* Reflog entry (best-effort — a failure here does not undo the ref
     * write, since the ref mutation has already succeeded and reverting
     * it would create its own divergence. We log and continue.) */
    if (reason) {
        char rname[256];
        char remail[256];
        char rtime[64];
        int is_branch = (strncmp(ref, "refs/heads/", 11) == 0);

        resolve_identity(rname, sizeof(rname),
                         remail, sizeof(remail), repo);
        format_reflog_time(rtime, sizeof(rtime));

        (void)reflog_append_one(repo, ref, &old_oid, oid,
                                rname, remail, rtime, reason);

        /* If updating a branch that HEAD currently points to, also
         * record against HEAD itself so `gut reflog` (which defaults
         * to HEAD) sees the movement. */
        if (is_branch) {
            char head_ref[256];
            if (repo_head_ref(head_ref, sizeof(head_ref), repo) == 0 &&
                strcmp(head_ref, ref) == 0) {
                (void)reflog_append_one(repo, "HEAD", &old_oid, oid,
                                        rname, remail, rtime, reason);
            }
        }
    }

    return 0;
}
