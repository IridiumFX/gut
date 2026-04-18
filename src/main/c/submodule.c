#include "gut/submodule.h"
#include "gut/config.h"
#include "gut/object.h"
#include "gut/odb.h"
#include "gut/oid.h"
#include "gut/pack.h"
#include "gut/index.h"
#include "gut/remote.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
#include <direct.h>
#define gut_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#include <sys/types.h>
#define gut_mkdir(p) mkdir(p, 0755)
#endif

/* ----- local helpers ----- */

static char *dup_range(const char *s, size_t len) {
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

/* mkdir including any missing intermediate directories. */
static unsigned long mkdirs(const char *path) {
    char buf[2048];
    u64 L = strlen(path);
    u64 i;
    if (L >= sizeof(buf)) return __LINE__;
    memcpy(buf, path, L + 1);
    for (i = 1; i < L; i++) {
        if (buf[i] == '/' || buf[i] == '\\') {
            char save = buf[i];
            buf[i] = '\0';
            gut_mkdir(buf);
            buf[i] = save;
        }
    }
    gut_mkdir(buf);
    return 0;
}

/* ----- .gitmodules parser -----
 *
 * .gitmodules shares git's INI dialect, so config_read handles it. What's
 * specific here is the [submodule "<name>"] section syntax: we strip the
 * `submodule "..."` form and pull out name / path / url into structs. */
unsigned long submodules_read(gut_submodule **out, u64 *count,
                              const char *gitmodules_path) {
    gut_config cfg;
    gut_submodule *list = NULL;
    u64 list_cap = 0;
    u64 list_n = 0;
    unsigned long rc;
    u64 i;
    struct stat st;

    if (!out || !count) return __LINE__;
    *out = NULL; *count = 0;

    if (stat(gitmodules_path, &st) != 0) return 0; /* missing is fine */

    rc = config_read(&cfg, gitmodules_path);
    if (rc) return __LINE__;

    /* Each submodule entry produces up to 3 lines in cfg (path, url,
     * optionally branch). We merge by logical name. */
    for (i = 0; i < cfg.count; i++) {
        const char *section = cfg.entries[i].section;
        const char *key     = cfg.entries[i].key;
        const char *value   = cfg.entries[i].value;
        const char *name_start;
        const char *quote_end;
        u64 name_len;
        char name_buf[256];
        u64 j;
        gut_submodule *target = NULL;

        /* Section format: submodule "the-name" */
        if (strncmp(section, "submodule", 9) != 0) continue;
        name_start = section + 9;
        while (*name_start == ' ' || *name_start == '\t') name_start++;
        if (*name_start != '"') continue;
        name_start++;
        quote_end = strrchr(name_start, '"');
        if (!quote_end || quote_end == name_start) continue;
        name_len = (u64)(quote_end - name_start);
        if (name_len >= sizeof(name_buf)) continue;
        memcpy(name_buf, name_start, name_len);
        name_buf[name_len] = '\0';

        /* Merge: find-or-create by name */
        for (j = 0; j < list_n; j++) {
            if (strcmp(list[j].name, name_buf) == 0) {
                target = &list[j];
                break;
            }
        }
        if (!target) {
            if (list_n == list_cap) {
                u64 new_cap = list_cap ? list_cap * 2 : 8;
                gut_submodule *tmp = (gut_submodule *)realloc(list,
                    (size_t)(new_cap * sizeof(gut_submodule)));
                if (!tmp) { config_destroy(&cfg); return __LINE__; }
                list = tmp;
                list_cap = new_cap;
            }
            list[list_n].name = dup_range(name_buf, name_len);
            list[list_n].path = NULL;
            list[list_n].url  = NULL;
            if (!list[list_n].name) { config_destroy(&cfg); return __LINE__; }
            target = &list[list_n];
            list_n++;
        }

        if      (strcmp(key, "path") == 0 && !target->path)
            target->path = dup_range(value, strlen(value));
        else if (strcmp(key, "url")  == 0 && !target->url)
            target->url  = dup_range(value, strlen(value));
        /* branch, update, shallow etc. ignored in MVP */
    }

    config_destroy(&cfg);

    /* Drop any half-filled entries missing path or url. */
    {
        u64 w = 0;
        for (i = 0; i < list_n; i++) {
            if (!list[i].path || !list[i].url) {
                free(list[i].name); free(list[i].path); free(list[i].url);
                continue;
            }
            if (w != i) list[w] = list[i];
            w++;
        }
        list_n = w;
    }

    *out = list;
    *count = list_n;
    return 0;
}

unsigned long submodules_destroy(gut_submodule *arr, u64 count) {
    u64 i;
    if (!arr) return 0;
    for (i = 0; i < count; i++) {
        free(arr[i].name);
        free(arr[i].path);
        free(arr[i].url);
    }
    free(arr);
    return 0;
}

/* ----- helpers for submodules_update_all ----- */

/* Walk the parent's HEAD tree looking for a gitlink (mode 160000) entry
 * at `path` (slash-separated). Writes the pinned OID into *out. */
static unsigned long resolve_gitlink(gut_oid *out, gut_odb *odb,
                                     gut_oid *tree_oid, const char *path,
                                     gut_hash_algo algo) {
    const char *slash = strchr(path, '/');
    gut_object obj;
    gut_tree tree;
    u64 i;
    unsigned long rc;

    rc = odb_read(&obj, odb, tree_oid);
    if (rc) return __LINE__;
    if (obj.type != GUT_OBJ_TREE) { object_destroy(&obj); return __LINE__; }
    rc = tree_parse_algo(&tree, obj.data.data, obj.data.len, algo);
    object_destroy(&obj);
    if (rc) return __LINE__;

    for (i = 0; i < tree.count; i++) {
        gut_tree_entry *e = &tree.entries[i];
        if (slash) {
            u64 dir_len = (u64)(slash - path);
            if (e->mode == 040000 &&
                strlen(e->name) == dir_len &&
                memcmp(e->name, path, dir_len) == 0) {
                rc = resolve_gitlink(out, odb, &e->oid, slash + 1, algo);
                tree_destroy(&tree);
                return rc;
            }
        } else {
            if (e->mode == 0160000 && strcmp(e->name, path) == 0) {
                memcpy(out->bytes, e->oid.bytes, sizeof(e->oid.bytes));
                tree_destroy(&tree);
                return 0;
            }
        }
    }
    tree_destroy(&tree);
    return __LINE__;
}

/* Materialize a tree into `workdir` by recursively reading blobs from
 * `odb`. Skips mode-160000 entries (nested submodules handled by
 * recursion). Used by submodule checkout after pack indexing. */
static unsigned long write_tree_to_workdir(gut_odb *odb, gut_oid *tree_oid,
                                           const char *workdir,
                                           gut_hash_algo algo) {
    gut_object obj;
    gut_tree tree;
    u64 i;
    unsigned long rc;

    rc = odb_read(&obj, odb, tree_oid);
    if (rc) return __LINE__;
    if (obj.type != GUT_OBJ_TREE) { object_destroy(&obj); return __LINE__; }
    rc = tree_parse_algo(&tree, obj.data.data, obj.data.len, algo);
    object_destroy(&obj);
    if (rc) return __LINE__;

    for (i = 0; i < tree.count; i++) {
        gut_tree_entry *e = &tree.entries[i];
        char sub_path[2048];
        snprintf(sub_path, sizeof(sub_path), "%s/%s", workdir, e->name);

        if (e->mode == 040000) {
            gut_mkdir(sub_path);
            rc = write_tree_to_workdir(odb, &e->oid, sub_path, algo);
            if (rc) { tree_destroy(&tree); return rc; }
        } else if (e->mode == 0160000) {
            /* Nested submodule pointer — just make the directory. The
             * recursive update pass will populate it later. */
            gut_mkdir(sub_path);
        } else {
            /* Blob — write contents. */
            gut_object blob;
            FILE *fp;
            if (odb_read(&blob, odb, &e->oid) != 0) continue;
            fp = fopen(sub_path, "wb");
            if (fp) {
                if (blob.data.len > 0)
                    fwrite(blob.data.data, 1, (size_t)blob.data.len, fp);
                fclose(fp);
            }
            object_destroy(&blob);
        }
    }
    tree_destroy(&tree);
    return 0;
}

/* Clone `url` into `git_dir` (which must not already exist), then write
 * a gitfile at `<work_dir>/.git` pointing to `git_dir` via
 * `<gitfile_relative>`. Checks out `pinned_oid` into the work dir. */
static unsigned long clone_submodule(const char *url,
                                     const char *git_dir,
                                     const char *work_dir,
                                     const char *gitfile_relative,
                                     gut_oid *pinned_oid) {
    char obj_dir[2048];
    char pack_dir[2048];
    char pack_path[2048];
    char idx_path[2048];
    char head_path[2048];
    char refs_dir[2048];
    char gitfile_path[2048];
    gut_remote_refs refs;
    gut_oid *wants = NULL;
    u64 want_count = 0;
    u64 i, j;
    unsigned long rc;
    gut_hash_algo algo;

    /* Create the <parent>/.git/modules/<name>/ tree. */
    rc = mkdirs(git_dir);
    if (rc) return __LINE__;

    snprintf(obj_dir, sizeof(obj_dir), "%s/objects", git_dir);
    if (mkdirs(obj_dir) != 0) return __LINE__;

    snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack", git_dir);
    if (mkdirs(pack_dir) != 0) return __LINE__;

    snprintf(refs_dir, sizeof(refs_dir), "%s/refs/heads", git_dir);
    if (mkdirs(refs_dir) != 0) return __LINE__;

    /* Discover refs — also gives us the remote's hash algo. */
    rc = remote_discover_refs(&refs, url);
    if (rc) return __LINE__;
    algo = refs.hash_algo;

    /* Write minimal config with the remote URL and object-format. */
    {
        char cfg_path[2048];
        FILE *cf;
        snprintf(cfg_path, sizeof(cfg_path), "%s/config", git_dir);
        cf = fopen(cfg_path, "w");
        if (!cf) return __LINE__;
        fputs("[core]\n", cf);
        if (algo == GUT_HASH_SHA256)
            fputs("\trepositoryformatversion = 1\n", cf);
        else
            fputs("\trepositoryformatversion = 0\n", cf);
        fputs("\tfilemode = false\n", cf);
        fputs("\tbare = false\n", cf);
        if (algo == GUT_HASH_SHA256)
            fputs("[extensions]\n\tobjectformat = sha256\n", cf);
        fprintf(cf, "[remote \"origin\"]\n\turl = %s\n"
                    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n", url);
        fclose(cf);
    }

    /* Want the pinned commit. We also want any HEAD ref so we can later
     * use branch tracking — but for the MVP checkout the pinned OID is
     * enough. */
    wants = (gut_oid *)malloc(sizeof(gut_oid) * (refs.count + 1));
    if (!wants) return __LINE__;
    wants[0] = *pinned_oid;
    want_count = 1;
    for (i = 0; i < refs.count; i++) {
        int dup = 0;
        for (j = 0; j < want_count; j++) {
            long cmp;
            oid_compare(&cmp, &wants[j], &refs.refs[i].oid);
            if (cmp == 0) { dup = 1; break; }
        }
        if (!dup) {
            memcpy(wants[want_count].bytes, refs.refs[i].oid.bytes,
                   sizeof(refs.refs[i].oid.bytes));
            want_count++;
        }
    }

    snprintf(pack_path, sizeof(pack_path),
             "%s/objects/pack/gut-submodule.pack", git_dir);
    rc = remote_fetch_pack_algo(url, wants, want_count, NULL, 0, pack_path,
                                0, NULL, NULL, algo);
    free(wants);
    if (rc) return __LINE__;

    if (pack_index_create_algo(pack_path, NULL, algo) != 0) return __LINE__;

    /* Write refs/heads/* from discovered refs + HEAD. */
    {
        unsigned hex_len = gut_oid_hex_size(algo);
        for (i = 0; i < refs.count; i++) {
            const char *name = refs.refs[i].name;
            char ref_path[2048];
            char ref_line[GUT_OID_MAX_HEX_SIZE + 2];
            FILE *rf;
            if (strcmp(name, "HEAD") == 0) continue;
            if (strncmp(name, "refs/heads/", 11) != 0) continue;
            snprintf(ref_path, sizeof(ref_path), "%s/refs/heads/%s",
                     git_dir, name + 11);
            oid_to_hex_n(ref_line, &refs.refs[i].oid, hex_len);
            ref_line[hex_len] = '\n';
            ref_line[hex_len + 1] = '\0';
            rf = fopen(ref_path, "w");
            if (rf) { fputs(ref_line, rf); fclose(rf); }
        }
    }

    /* Detached HEAD at the pinned commit. */
    snprintf(head_path, sizeof(head_path), "%s/HEAD", git_dir);
    {
        unsigned hex_len = gut_oid_hex_size(algo);
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        FILE *hf = fopen(head_path, "w");
        if (!hf) return __LINE__;
        oid_to_hex_n(hex, pinned_oid, hex_len);
        fprintf(hf, "%s\n", hex);
        fclose(hf);
    }

    /* Reopen the now-complete submodule repo and materialize the tree
     * from the pinned commit. We do this inline (via ODB + walk_tree)
     * rather than bouncing through repo_open/index to avoid pulling in
     * workdir/index reconciliation code. */
    {
        gut_odb odb;
        gut_object commit_obj;
        gut_commit c;
        rc = odb_open(&odb, obj_dir);
        if (rc) return __LINE__;
        odb.hash_algo = algo;
        rc = odb_read(&commit_obj, &odb, pinned_oid);
        if (rc) return __LINE__;
        if (commit_obj.type != GUT_OBJ_COMMIT) {
            object_destroy(&commit_obj);
            return __LINE__;
        }
        rc = commit_parse(&c, commit_obj.data.data, commit_obj.data.len);
        object_destroy(&commit_obj);
        if (rc) return __LINE__;

        if (mkdirs(work_dir) != 0) { commit_destroy(&c); return __LINE__; }
        rc = write_tree_to_workdir(&odb, &c.tree_oid, work_dir, algo);
        commit_destroy(&c);
        if (rc) return __LINE__;
    }

    /* Write the gitfile at <work_dir>/.git. */
    snprintf(gitfile_path, sizeof(gitfile_path), "%s/.git", work_dir);
    {
        FILE *gf = fopen(gitfile_path, "w");
        if (!gf) return __LINE__;
        fprintf(gf, "gitdir: %s\n", gitfile_relative);
        fclose(gf);
    }

    (void)idx_path;
    return 0;
}

/* Build a relative path from `<work>/<path>/.git` back up to
 * `<parent-git>/modules/<name>`. For path "a/b/c" that's "../../../"
 * (one ".." per slash plus one for the submodule dir itself). */
static unsigned long build_gitfile_relative(char *out, u64 out_size,
                                            const char *sub_path,
                                            const char *name) {
    u64 slashes = 0;
    u64 i;
    u64 pos = 0;
    u64 plen = strlen(sub_path);

    for (i = 0; i < plen; i++) {
        if (sub_path[i] == '/') slashes++;
    }

    /* depth = slashes + 1 (one for the leaf directory itself) */
    for (i = 0; i <= slashes; i++) {
        if (pos + 3 >= out_size) return __LINE__;
        out[pos++] = '.'; out[pos++] = '.'; out[pos++] = '/';
    }
    {
        int n = snprintf(out + pos, out_size - pos, ".git/modules/%s", name);
        if (n < 0 || (u64)n >= out_size - pos) return __LINE__;
    }
    return 0;
}

unsigned long submodules_update_all(gut_repo *parent, int recursive) {
    char gm_path[2048];
    char head_ref[256];
    gut_oid head_oid;
    gut_object head_obj;
    gut_commit head_commit;
    gut_submodule *list = NULL;
    u64 count = 0;
    u64 i;
    unsigned long rc;

    if (!parent) return __LINE__;

    snprintf(gm_path, sizeof(gm_path), "%s/.gitmodules", parent->root_dir);
    rc = submodules_read(&list, &count, gm_path);
    if (rc) return __LINE__;
    if (count == 0) { submodules_destroy(list, count); return 0; }

    /* Resolve parent HEAD → commit → tree. We need the tree so we can
     * pull the pinned OIDs out of each gitlink entry. */
    rc = repo_head_ref(head_ref, sizeof(head_ref), parent);
    if (rc) { submodules_destroy(list, count); return __LINE__; }
    rc = repo_resolve_ref(&head_oid, parent, head_ref);
    if (rc) { submodules_destroy(list, count); return __LINE__; }
    rc = odb_read(&head_obj, &parent->odb, &head_oid);
    if (rc) { submodules_destroy(list, count); return __LINE__; }
    if (head_obj.type != GUT_OBJ_COMMIT) {
        object_destroy(&head_obj);
        submodules_destroy(list, count);
        return __LINE__;
    }
    rc = commit_parse(&head_commit, head_obj.data.data, head_obj.data.len);
    object_destroy(&head_obj);
    if (rc) { submodules_destroy(list, count); return __LINE__; }

    for (i = 0; i < count; i++) {
        gut_oid pinned;
        char sub_git_dir[2048];
        char sub_work_dir[2048];
        char gitfile_rel[512];

        printf("Submodule '%s' from %s\n", list[i].name, list[i].url);

        /* gut only speaks http/https — SSH URLs (git@host:path) and file://
         * aren't supported yet. Skip cleanly with a clear reason rather
         * than letting discover_refs fail deep. */
        if (strncmp(list[i].url, "http://", 7) != 0 &&
            strncmp(list[i].url, "https://", 8) != 0) {
            printf("  skipped: unsupported URL scheme "
                   "(gut only speaks http/https)\n");
            continue;
        }

        rc = resolve_gitlink(&pinned, &parent->odb, &head_commit.tree_oid,
                             list[i].path, parent->hash_algo);
        if (rc) {
            fprintf(stderr,
                    "  warning: no gitlink entry for '%s' in HEAD tree (line %lu)\n",
                    list[i].path, rc);
            continue;
        }

        snprintf(sub_git_dir, sizeof(sub_git_dir),
                 "%s/modules/%s", parent->git_dir, list[i].name);
        snprintf(sub_work_dir, sizeof(sub_work_dir),
                 "%s/%s", parent->root_dir, list[i].path);
        rc = build_gitfile_relative(gitfile_rel, sizeof(gitfile_rel),
                                    list[i].path, list[i].name);
        if (rc) continue;

        rc = clone_submodule(list[i].url, sub_git_dir, sub_work_dir,
                             gitfile_rel, &pinned);
        if (rc) {
            fprintf(stderr,
                    "  warning: submodule clone failed (line %lu)\n", rc);
            continue;
        }

        /* Record in parent .git/config so subsequent `submodule update`
         * without init can find the URL. */
        {
            char cfg_path[2048];
            FILE *cf;
            snprintf(cfg_path, sizeof(cfg_path), "%s/config", parent->git_dir);
            cf = fopen(cfg_path, "a");
            if (cf) {
                fprintf(cf, "[submodule \"%s\"]\n\turl = %s\n",
                        list[i].name, list[i].url);
                fclose(cf);
            }
        }

        if (recursive) {
            gut_repo sub_repo;
            if (repo_open(&sub_repo, sub_work_dir) == 0) {
                submodules_update_all(&sub_repo, 1);
            }
        }
    }

    commit_destroy(&head_commit);
    submodules_destroy(list, count);
    return 0;
}
