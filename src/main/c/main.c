#include "gut/repo.h"
#include "gut/oid.h"
#include "gut/object.h"
#include "gut/index.h"
#include "gut/config.h"
#include "gut/ignore.h"
#include "gut/remote.h"
#include "gut/pack.h"
#include "gut/leech.h"
#include <dirent.h>
#include "apennines/diff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define gut_getcwd(buf, size) _getcwd(buf, size)
#else
#include <unistd.h>
#define gut_getcwd(buf, size) getcwd(buf, size)
#endif

static void usage(void) {
    fprintf(stderr,
        "usage: gut <command> [<args>]\n"
        "\n"
        "Commands:\n"
        "   init        Create an empty gut repository\n"
        "   clone       Clone a repository via HTTP(S)\n"
        "   fetch       Fetch refs + objects from a remote\n"
        "   push        Push refs + objects to a remote\n"
        "   pack-objects Create a pack from OIDs on stdin\n"
        "   repack      Pack all loose objects and remove them\n"
        "   listen      Broadcast ref change events via WebSocket\n"
        "   leech       Subscribe to a peer's gut listen events\n"
        "   leechers    Query a listener for its connected peers\n"
        "   add         Add file contents to the index\n"
        "   unstage     Remove file from the index (keep working tree)\n"
        "   rm          Remove file from index and working tree\n"
        "   branch      Create or delete a branch\n"
        "   branches    List all branches\n"
        "   tag         Create a lightweight tag\n"
        "   tags        List all tags\n"
        "   checkout    Switch branches\n"
        "   merge       Merge a branch into the current branch\n"
        "   diff        Show changes between working tree and index\n"
        "   commit      Record changes to the repository\n"
        "   log         Show commit logs\n"
        "   status      Show the working tree status\n"
        "   last        Show the last commit\n"
        "   amend       Amend the last commit\n"
        "   undo        Undo the last commit (keep changes)\n"
        "   restore     Restore working tree or index files\n"
        "   reset       Reset HEAD to a different commit\n"
        "   hash-object Hash a file and optionally write to object database\n"
        "   cat-file    Display object contents\n"
    );
}

/* Forward declarations */
static int resolve_object(gut_oid *out, gut_repo *repo, const char *ref);
static unsigned long ensure_parent_dirs(const char *file_path);
static int workdir_write_from_index(gut_repo *repo, gut_index *idx);

/* Normalize path separators to forward slashes */
static void normalize_path(char *path) {
    char *p;
    for (p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

/* Compute a path relative to repo root from an argv argument */
static void make_relative(char *rel_out, size_t rel_size,
                          const char *arg, const char *cwd,
                          const char *root_dir) {
    char full[2048];
    if (arg[0] == '/' || (arg[0] != '\0' && arg[1] == ':')) {
        snprintf(full, sizeof(full), "%s", arg);
    } else {
        snprintf(full, sizeof(full), "%s/%s", cwd, arg);
    }
    normalize_path(full);
    {
        size_t root_len = strlen(root_dir);
        if (strncmp(full, root_dir, root_len) == 0) {
            const char *rel = full + root_len;
            if (*rel == '/' || *rel == '\\') rel++;
            snprintf(rel_out, rel_size, "%s", rel);
        } else {
            snprintf(rel_out, rel_size, "%s", arg);
        }
    }
    normalize_path(rel_out);
}

static int cmd_init(int argc, char **argv) {
    gut_repo repo;
    unsigned long rc;
    const char *path;
    char cwd[2048];

    if (argc > 0) {
        path = argv[0];
    } else {
        if (!gut_getcwd(cwd, sizeof(cwd))) {
            fprintf(stderr, "error: cannot get current directory\n");
            return 1;
        }
        path = cwd;
    }

    rc = repo_init(&repo, path);
    if (rc) {
        fprintf(stderr, "error: failed to initialize repository (line %lu)\n", rc);
        return 1;
    }

    printf("Initialized empty gut repository in %s/.git/\n", path);
    return 0;
}

/* ---- gut clone ---- */

static int cmd_clone(int argc, char **argv) {
    const char *url;
    const char *dir = NULL;
    gut_remote_refs refs;
    gut_repo repo;
    char dest[2048];
    char pack_path[2048];
    char idx_cmd[4096];
    unsigned long rc;
    u64 i;
    int found_head_target = 0;
    char head_target_ref[256];

    if (argc < 1) {
        fprintf(stderr, "usage: gut clone <url> [<directory>]\n");
        return 1;
    }

    url = argv[0];
    if (argc >= 2) {
        dir = argv[1];
    } else {
        const char *last_slash = strrchr(url, '/');
        if (last_slash) {
            static char name_buf[256];
            size_t nlen;
            snprintf(name_buf, sizeof(name_buf), "%s", last_slash + 1);
            nlen = strlen(name_buf);
            if (nlen > 4 && strcmp(name_buf + nlen - 4, ".git") == 0)
                name_buf[nlen - 4] = '\0';
            dir = name_buf;
        }
    }

    if (!dir || dir[0] == '\0') {
        fprintf(stderr, "error: cannot determine directory name from URL\n");
        return 1;
    }

    printf("Cloning into '%s'...\n", dir);

    {
        char cwd[2048];
        if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
        snprintf(dest, sizeof(dest), "%s/%s", cwd, dir);
    }

#ifdef _WIN32
    _mkdir(dest);
#else
    mkdir(dest, 0755);
#endif

    rc = repo_init(&repo, dest);
    if (rc) {
        fprintf(stderr, "fatal: cannot init repository in '%s'\n", dir);
        return 1;
    }

    printf("Discovering refs...\n");
    rc = remote_discover_refs(&refs, url);
    if (rc) {
        fprintf(stderr, "fatal: cannot discover refs from '%s' (line %lu)\n", url, rc);
        return 1;
    }

    if (refs.count == 0) {
        printf("warning: remote has no refs (empty repository)\n");
        return 0;
    }

    printf("Found %llu refs\n", (unsigned long long)refs.count);

    /* Collect unique want OIDs */
    {
        gut_oid *wants;
        u64 want_count = 0;
        u64 j;

        wants = (gut_oid *)malloc(refs.count * sizeof(gut_oid));
        if (!wants) return 1;

        for (i = 0; i < refs.count; i++) {
            if (strcmp(refs.refs[i].name, "HEAD") == 0) continue;
            {
                int dup = 0;
                for (j = 0; j < want_count; j++) {
                    long cmp;
                    oid_compare(&cmp, &wants[j], &refs.refs[i].oid);
                    if (cmp == 0) { dup = 1; break; }
                }
                if (!dup) {
                    memcpy(wants[want_count].bytes, refs.refs[i].oid.bytes, GUT_OID_RAW_SIZE);
                    want_count++;
                }
            }
        }

        if (want_count == 0) {
            free(wants);
            printf("warning: nothing to fetch\n");
            return 0;
        }

        printf("Fetching objects (%llu wants)...\n", (unsigned long long)want_count);
        snprintf(pack_path, sizeof(pack_path), "%s/objects/pack/gut-clone.pack",
                 repo.git_dir);

        rc = remote_fetch_pack(url, wants, want_count, NULL, 0, pack_path);
        free(wants);

        if (rc) {
            fprintf(stderr, "fatal: fetch failed (line %lu)\n", rc);
            return 1;
        }
    }

    /* Index the pack (use git index-pack until we have our own) */
    printf("Indexing pack...\n");
    snprintf(idx_cmd, sizeof(idx_cmd),
             "git index-pack \"%s/objects/pack/gut-clone.pack\"", repo.git_dir);
    if (system(idx_cmd) != 0) {
        fprintf(stderr, "warning: git index-pack failed\n");
    }

    /* Create refs */
    for (i = 0; i < refs.count; i++) {
        if (strcmp(refs.refs[i].name, "HEAD") == 0) continue;

        if (strncmp(refs.refs[i].name, "refs/heads/", 11) == 0) {
            char ref_path[2048];
            char ref_dir[2048];
            char ref_content[GUT_OID_HEX_SIZE + 2];
            FILE *fp;

            /* Remote tracking ref */
            snprintf(ref_dir, sizeof(ref_dir), "%s/refs/remotes/origin", repo.git_dir);
            ensure_parent_dirs(ref_dir);
#ifdef _WIN32
            _mkdir(ref_dir);
#else
            mkdir(ref_dir, 0755);
#endif

            snprintf(ref_path, sizeof(ref_path), "%s/refs/remotes/origin/%s",
                     repo.git_dir, refs.refs[i].name + 11);
            oid_to_hex(ref_content, &refs.refs[i].oid);
            ref_content[GUT_OID_HEX_SIZE] = '\n';
            ref_content[GUT_OID_HEX_SIZE + 1] = '\0';
            fp = fopen(ref_path, "w");
            if (fp) { fputs(ref_content, fp); fclose(fp); }

            /* Find default branch (matches HEAD OID) */
            if (!found_head_target) {
                u64 hi;
                for (hi = 0; hi < refs.count; hi++) {
                    if (strcmp(refs.refs[hi].name, "HEAD") == 0) {
                        long cmp;
                        oid_compare(&cmp, &refs.refs[hi].oid, &refs.refs[i].oid);
                        if (cmp == 0) {
                            found_head_target = 1;
                            snprintf(head_target_ref, sizeof(head_target_ref),
                                     "%s", refs.refs[i].name + 11);
                            /* Create local branch */
                            snprintf(ref_path, sizeof(ref_path), "%s/%s",
                                     repo.git_dir, refs.refs[i].name);
                            fp = fopen(ref_path, "w");
                            if (fp) { fputs(ref_content, fp); fclose(fp); }
                            break;
                        }
                    }
                }
            }
        } else if (strncmp(refs.refs[i].name, "refs/tags/", 10) == 0) {
            char ref_path[2048];
            char ref_content[GUT_OID_HEX_SIZE + 2];
            FILE *fp;

            snprintf(ref_path, sizeof(ref_path), "%s/%s", repo.git_dir, refs.refs[i].name);
            oid_to_hex(ref_content, &refs.refs[i].oid);
            ref_content[GUT_OID_HEX_SIZE] = '\n';
            ref_content[GUT_OID_HEX_SIZE + 1] = '\0';
            fp = fopen(ref_path, "w");
            if (fp) { fputs(ref_content, fp); fclose(fp); }
        }
    }

    /* Update HEAD */
    if (found_head_target) {
        char head_path[2048];
        char head_content[256];
        FILE *fp;
        snprintf(head_path, sizeof(head_path), "%s/HEAD", repo.git_dir);
        snprintf(head_content, sizeof(head_content), "ref: refs/heads/%s\n", head_target_ref);
        fp = fopen(head_path, "w");
        if (fp) { fputs(head_content, fp); fclose(fp); }
    }

    /* Save remote config */
    {
        char config_path[2048];
        FILE *fp;
        snprintf(config_path, sizeof(config_path), "%s/config", repo.git_dir);
        fp = fopen(config_path, "a");
        if (fp) {
            fprintf(fp, "[remote \"origin\"]\n\turl = %s\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n", url);
            fclose(fp);
        }
    }

    /* Checkout HEAD */
    if (found_head_target) {
        gut_oid head_oid;
        gut_index new_idx;
        gut_object commit_obj;
        gut_commit commit;
        char index_path[2048];
        char ref_name[256];

        snprintf(ref_name, sizeof(ref_name), "refs/heads/%s", head_target_ref);
        rc = repo_resolve_ref(&head_oid, &repo, ref_name);
        if (rc == 0) {
            rc = odb_read(&commit_obj, &repo.odb, &head_oid);
            if (rc == 0) {
                rc = commit_parse(&commit, commit_obj.data.data, commit_obj.data.len);
                object_destroy(&commit_obj);
                if (rc == 0) {
                    rc = index_read_tree(&new_idx, &repo.odb, &commit.tree_oid);
                    commit_destroy(&commit);
                    if (rc == 0) {
                        workdir_write_from_index(&repo, &new_idx);
                        snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
                        index_write(&new_idx, index_path);
                        index_destroy(&new_idx);
                    }
                }
            }
        }
    }

    printf("done.\n");
    return 0;
}

/* ---- gut listen ---- */

static int cmd_listen(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    unsigned long rc;
    u16 port = 7900;
    u64 poll_ms = 1000;
    const char *token = NULL;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (u16)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--poll") == 0 && i + 1 < argc) {
            poll_ms = (u64)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    rc = leech_listen(&repo, port, poll_ms, token);
    return rc ? 1 : 0;
}

/* ---- gut leechers ---- */

static int cmd_leechers(int argc, char **argv) {
    const char *host;
    if (argc < 1) {
        fprintf(stderr, "usage: gut leechers <host:port>\n");
        return 1;
    }
    host = argv[0];
    return leech_list_peers(host) ? 1 : 0;
}

/* ---- gut leech ---- */

static int cmd_leech(int argc, char **argv) {
    const char *url = NULL;
    const char *token = NULL;
    unsigned long rc;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (argv[i][0] != '-') {
            url = argv[i];
        }
    }

    if (!url) {
        fprintf(stderr, "usage: gut leech <ws://host:port> [--token <t>]\n");
        return 1;
    }

    rc = leech_connect(url, token);
    return rc ? 1 : 0;
}

/* ---- gut repack ---- */
/* Collects all loose objects and packs them into a single .pack + .idx, then
 * deletes the loose objects. */
static int cmd_repack(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char objects_dir[2048];
    char pack_dir[2048];
    char pack_hex[GUT_OID_HEX_SIZE + 1];
    gut_oid *oids = NULL;
    u64 count = 0;
    u64 capacity = 128;
    unsigned long rc;
    DIR *d1, *d2;
    struct dirent *ent1, *ent2;

    (void)argc;
    (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    snprintf(objects_dir, sizeof(objects_dir), "%s/objects", repo.git_dir);
    snprintf(pack_dir, sizeof(pack_dir), "%s/pack", objects_dir);

    /* Walk .git/objects/XX/YYY... directories collecting all loose OIDs */
    oids = (gut_oid *)malloc(capacity * sizeof(gut_oid));
    if (!oids) return 1;

    d1 = opendir(objects_dir);
    if (!d1) { free(oids); fprintf(stderr, "error: cannot open objects directory\n"); return 1; }

    while ((ent1 = readdir(d1)) != NULL) {
        char sub_dir[2048];

        /* We only want two-char hex dir names */
        if (strlen(ent1->d_name) != 2) continue;
        if (!((ent1->d_name[0] >= '0' && ent1->d_name[0] <= '9') ||
              (ent1->d_name[0] >= 'a' && ent1->d_name[0] <= 'f'))) continue;
        if (!((ent1->d_name[1] >= '0' && ent1->d_name[1] <= '9') ||
              (ent1->d_name[1] >= 'a' && ent1->d_name[1] <= 'f'))) continue;

        snprintf(sub_dir, sizeof(sub_dir), "%s/%s", objects_dir, ent1->d_name);
        d2 = opendir(sub_dir);
        if (!d2) continue;

        while ((ent2 = readdir(d2)) != NULL) {
            char hex_full[GUT_OID_HEX_SIZE + 1];
            gut_oid oid;

            if (strlen(ent2->d_name) != 38) continue;

            snprintf(hex_full, sizeof(hex_full), "%s%s", ent1->d_name, ent2->d_name);
            if (oid_from_hex(&oid, hex_full) != 0) continue;

            if (count >= capacity) {
                gut_oid *tmp;
                capacity *= 2;
                tmp = (gut_oid *)realloc(oids, capacity * sizeof(gut_oid));
                if (!tmp) { free(oids); closedir(d2); closedir(d1); return 1; }
                oids = tmp;
            }
            memcpy(oids[count].bytes, oid.bytes, GUT_OID_RAW_SIZE);
            count++;
        }
        closedir(d2);
    }
    closedir(d1);

    if (count == 0) {
        printf("Nothing to repack.\n");
        free(oids);
        return 0;
    }

    printf("Packing %llu loose objects...\n", (unsigned long long)count);

    rc = pack_write(pack_hex, pack_dir, &repo.odb, oids, count);
    if (rc) {
        fprintf(stderr, "error: pack_write failed (line %lu)\n", rc);
        free(oids);
        return 1;
    }

    printf("Pack created: pack-%s.pack\n", pack_hex);

    /* Delete the loose object files */
    {
        u64 i;
        u64 removed = 0;
        for (i = 0; i < count; i++) {
            char path[2048];
            char prefix[3];
            char suffix[39];

            oid_path_prefix(prefix, &oids[i]);
            oid_path_suffix(suffix, &oids[i]);
            snprintf(path, sizeof(path), "%s/%s/%s", objects_dir, prefix, suffix);

            if (remove(path) == 0) removed++;
        }
        printf("Removed %llu loose objects.\n", (unsigned long long)removed);
    }

    /* Try to remove now-empty fan-out directories */
    {
        d1 = opendir(objects_dir);
        if (d1) {
            while ((ent1 = readdir(d1)) != NULL) {
                char sub_dir[2048];
                if (strlen(ent1->d_name) != 2) continue;
                snprintf(sub_dir, sizeof(sub_dir), "%s/%s", objects_dir, ent1->d_name);
#ifdef _WIN32
                _rmdir(sub_dir);
#else
                rmdir(sub_dir);
#endif
            }
            closedir(d1);
        }
    }

    free(oids);
    return 0;
}

/* ---- gut pack-objects ---- */
/* Takes object names on stdin, one per line, creates a pack containing them.
 * Prints the pack hash. */
static int cmd_pack_objects(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char pack_dir[2048];
    char pack_hex[GUT_OID_HEX_SIZE + 1];
    char line[256];
    gut_oid *oids = NULL;
    u64 count = 0;
    u64 capacity = 64;
    unsigned long rc;

    (void)argc;
    (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    oids = (gut_oid *)malloc(capacity * sizeof(gut_oid));
    if (!oids) return 1;

    /* Read OID hexes from stdin */
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        gut_oid oid;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' || line[len - 1] == ' ')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        /* Accept short SHAs too */
        if (resolve_object(&oid, &repo, line)) {
            fprintf(stderr, "error: unknown object '%s'\n", line);
            free(oids);
            return 1;
        }

        if (count >= capacity) {
            capacity *= 2;
            oids = (gut_oid *)realloc(oids, capacity * sizeof(gut_oid));
            if (!oids) return 1;
        }
        memcpy(oids[count].bytes, oid.bytes, GUT_OID_RAW_SIZE);
        count++;
    }

    if (count == 0) {
        fprintf(stderr, "error: no objects provided\n");
        free(oids);
        return 1;
    }

    snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack", repo.git_dir);
    rc = pack_write(pack_hex, pack_dir, &repo.odb, oids, count);
    free(oids);
    if (rc) {
        fprintf(stderr, "error: pack_write failed (line %lu)\n", rc);
        return 1;
    }

    printf("%s\n", pack_hex);
    return 0;
}

/* ---- gut fetch ---- */
/* Usage: gut fetch [<url>]
 * If no URL given, reads [remote "origin"] url from .git/config. */
static int cmd_fetch(int argc, char **argv) {
    gut_repo repo;
    gut_remote_refs remote_refs;
    gut_oid *wants = NULL;
    u64 want_count = 0;
    gut_oid *haves = NULL;
    u64 have_count = 0;
    char cwd[2048];
    char url_buf[1024];
    const char *url = NULL;
    char pack_path[2048];
    char idx_cmd[4096];
    unsigned long rc;
    u64 i, j;

    if (argc > 0) {
        url = argv[0];
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    /* Read URL from config if not provided */
    if (!url) {
        gut_config cfg;
        char config_path[2048];
        const char *v;
        snprintf(config_path, sizeof(config_path), "%s/config", repo.git_dir);
        rc = config_read(&cfg, config_path);
        if (rc) { fprintf(stderr, "error: cannot read config\n"); return 1; }
        if (config_get(&v, &cfg, "remote \"origin\"", "url") == 0) {
            snprintf(url_buf, sizeof(url_buf), "%s", v);
            url = url_buf;
        }
        config_destroy(&cfg);
        if (!url) {
            fprintf(stderr, "error: no remote configured. Usage: gut fetch [<url>]\n");
            return 1;
        }
    }

    printf("Fetching from %s\n", url);

    /* Discover remote refs */
    rc = remote_discover_refs(&remote_refs, url);
    if (rc) {
        fprintf(stderr, "error: cannot discover refs (line %lu)\n", rc);
        return 1;
    }
    if (remote_refs.count == 0) {
        printf("No refs on remote.\n");
        return 0;
    }
    printf("Discovered %llu remote refs\n", (unsigned long long)remote_refs.count);

    /* Collect haves: our local branch tips that exist in ODB */
    {
        char heads_dir[2048];
        DIR *d;
        struct dirent *ent;
        u64 have_cap = 32;
        snprintf(heads_dir, sizeof(heads_dir), "%s/refs/heads", repo.git_dir);
        haves = (gut_oid *)malloc(have_cap * sizeof(gut_oid));
        if (!haves) return 1;

        d = opendir(heads_dir);
        if (d) {
            while ((ent = readdir(d)) != NULL) {
                char ref_path[2048];
                char local_ref[256];
                gut_oid oid;
                if (ent->d_name[0] == '.') continue;
                snprintf(local_ref, sizeof(local_ref), "refs/heads/%s", ent->d_name);
                if (repo_resolve_ref(&oid, &repo, local_ref) != 0) continue;
                if (have_count >= have_cap) {
                    have_cap *= 2;
                    haves = (gut_oid *)realloc(haves, have_cap * sizeof(gut_oid));
                    if (!haves) { closedir(d); return 1; }
                }
                memcpy(haves[have_count].bytes, oid.bytes, GUT_OID_RAW_SIZE);
                have_count++;
                (void)ref_path;
            }
            closedir(d);
        }
    }

    /* Compute wants: any remote ref OID that differs from our local */
    wants = (gut_oid *)malloc(remote_refs.count * sizeof(gut_oid));
    if (!wants) { free(haves); return 1; }
    for (i = 0; i < remote_refs.count; i++) {
        const char *rname = remote_refs.refs[i].name;
        gut_oid *rid = &remote_refs.refs[i].oid;
        long cmp;
        int already_have = 0;

        if (strcmp(rname, "HEAD") == 0) continue;

        /* Skip if we already have this exact OID as a branch tip */
        for (j = 0; j < have_count; j++) {
            oid_compare(&cmp, &haves[j], rid);
            if (cmp == 0) { already_have = 1; break; }
        }
        /* Skip duplicate wants */
        for (j = 0; j < want_count && !already_have; j++) {
            oid_compare(&cmp, &wants[j], rid);
            if (cmp == 0) { already_have = 1; break; }
        }
        if (already_have) continue;

        memcpy(wants[want_count].bytes, rid->bytes, GUT_OID_RAW_SIZE);
        want_count++;
    }

    if (want_count == 0) {
        printf("Already up to date.\n");
        free(wants);
        free(haves);
        return 0;
    }

    printf("Fetching %llu new commits (with %llu haves)...\n",
           (unsigned long long)want_count, (unsigned long long)have_count);

    snprintf(pack_path, sizeof(pack_path), "%s/objects/pack/gut-fetch.pack", repo.git_dir);
    rc = remote_fetch_pack(url, wants, want_count, haves, have_count, pack_path);
    free(wants);
    free(haves);
    if (rc) {
        fprintf(stderr, "error: fetch failed (line %lu)\n", rc);
        return 1;
    }

    /* Index the pack */
    printf("Indexing pack...\n");
    snprintf(idx_cmd, sizeof(idx_cmd),
             "git index-pack \"%s/objects/pack/gut-fetch.pack\"", repo.git_dir);
    if (system(idx_cmd) != 0) {
        fprintf(stderr, "warning: git index-pack failed\n");
    }

    /* Update remote tracking refs: refs/remotes/origin/* */
    {
        char ref_dir[2048];
        snprintf(ref_dir, sizeof(ref_dir), "%s/refs/remotes/origin", repo.git_dir);
#ifdef _WIN32
        _mkdir(ref_dir);
#else
        mkdir(ref_dir, 0755);
#endif
        for (i = 0; i < remote_refs.count; i++) {
            const char *rname = remote_refs.refs[i].name;
            char ref_path[2048];
            char hex[GUT_OID_HEX_SIZE + 2];
            FILE *fp;
            if (strcmp(rname, "HEAD") == 0) continue;
            if (strncmp(rname, "refs/heads/", 11) != 0) continue;
            snprintf(ref_path, sizeof(ref_path), "%s/%s", ref_dir, rname + 11);
            oid_to_hex(hex, &remote_refs.refs[i].oid);
            hex[GUT_OID_HEX_SIZE] = '\n';
            hex[GUT_OID_HEX_SIZE + 1] = '\0';
            fp = fopen(ref_path, "w");
            if (fp) { fputs(hex, fp); fclose(fp); }
        }
    }

    printf("done.\n");
    return 0;
}

/* ---- gut push ---- */

/* Object set: dynamic array with linear search dedup. Sufficient for MVP sizes. */
typedef struct {
    gut_oid *items;
    u64 count;
    u64 capacity;
} oid_set;

static int oid_set_contains(oid_set *s, gut_oid *oid) {
    u64 i;
    for (i = 0; i < s->count; i++) {
        if (memcmp(s->items[i].bytes, oid->bytes, GUT_OID_RAW_SIZE) == 0) return 1;
    }
    return 0;
}

static unsigned long oid_set_add(oid_set *s, gut_oid *oid) {
    if (oid_set_contains(s, oid)) return 0;
    if (s->count >= s->capacity) {
        u64 new_cap = s->capacity == 0 ? 64 : s->capacity * 2;
        gut_oid *tmp = (gut_oid *)realloc(s->items, (size_t)(new_cap * sizeof(gut_oid)));
        if (!tmp) return __LINE__;
        s->items = tmp;
        s->capacity = new_cap;
    }
    memcpy(s->items[s->count].bytes, oid->bytes, GUT_OID_RAW_SIZE);
    s->count++;
    return 0;
}

/* Walk a tree recursively, adding all referenced object OIDs to `result`. */
static unsigned long walk_tree_objects(oid_set *result, gut_odb *odb, gut_oid *tree_oid) {
    gut_object obj;
    gut_tree tree;
    u64 i;
    unsigned long rc;

    if (oid_set_contains(result, tree_oid)) return 0;
    rc = oid_set_add(result, tree_oid);
    if (rc) return rc;

    rc = odb_read(&obj, odb, tree_oid);
    if (rc) return 0; /* skip unreadable */
    if (obj.type != GUT_OBJ_TREE) { object_destroy(&obj); return 0; }

    rc = tree_parse(&tree, obj.data.data, obj.data.len);
    object_destroy(&obj);
    if (rc) return 0;

    for (i = 0; i < tree.count; i++) {
        if (tree.entries[i].mode == 040000) {
            walk_tree_objects(result, odb, &tree.entries[i].oid);
        } else {
            oid_set_add(result, &tree.entries[i].oid);
        }
    }

    tree_destroy(&tree);
    return 0;
}

/* Walk commits from `start`, stopping when reaching any OID in `stop_at`.
 * Adds all reachable commits, trees, and blobs to `result`. */
static unsigned long walk_commits_for_push(oid_set *result, gut_odb *odb,
                                           gut_oid *start,
                                           gut_oid *stop_at, u64 stop_count) {
    /* Simple BFS using an explicit queue */
    gut_oid *queue;
    u64 qcap = 256, qhead = 0, qtail = 0;
    unsigned long rc;
    u64 j;

    queue = (gut_oid *)malloc(qcap * sizeof(gut_oid));
    if (!queue) return __LINE__;

    /* Seed */
    memcpy(queue[0].bytes, start->bytes, GUT_OID_RAW_SIZE);
    qtail = 1;

    while (qhead < qtail) {
        gut_oid current;
        gut_object obj;
        gut_commit commit;
        int is_stop = 0;

        memcpy(current.bytes, queue[qhead++].bytes, GUT_OID_RAW_SIZE);

        for (j = 0; j < stop_count; j++) {
            if (memcmp(current.bytes, stop_at[j].bytes, GUT_OID_RAW_SIZE) == 0) {
                is_stop = 1; break;
            }
        }
        if (is_stop) continue;

        if (oid_set_contains(result, &current)) continue;
        rc = oid_set_add(result, &current);
        if (rc) { free(queue); return rc; }

        rc = odb_read(&obj, odb, &current);
        if (rc) continue;
        if (obj.type != GUT_OBJ_COMMIT) { object_destroy(&obj); continue; }

        rc = commit_parse(&commit, obj.data.data, obj.data.len);
        object_destroy(&obj);
        if (rc) continue;

        /* Walk this commit's tree */
        walk_tree_objects(result, odb, &commit.tree_oid);

        /* Enqueue parents */
        for (j = 0; j < commit.parent_count; j++) {
            if (qtail >= qcap) {
                qcap *= 2;
                queue = (gut_oid *)realloc(queue, qcap * sizeof(gut_oid));
                if (!queue) { commit_destroy(&commit); return __LINE__; }
            }
            memcpy(queue[qtail++].bytes, commit.parent_oids[j].bytes, GUT_OID_RAW_SIZE);
        }

        commit_destroy(&commit);
    }

    free(queue);
    return 0;
}

static int cmd_push(int argc, char **argv) {
    gut_repo repo;
    gut_remote_refs remote_refs;
    char cwd[2048];
    char url_buf[1024];
    const char *url = NULL;
    const char *token = NULL;
    char head_ref[256];
    char branch_name[128];
    gut_oid local_oid, remote_oid;
    int has_remote_oid = 0;
    unsigned long rc;
    int i;

    /* Parse args: gut push [<url>] [--token <t>] */
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (argv[i][0] != '-') {
            if (!url) url = argv[i];
        }
    }
    if (!token) token = getenv("GUT_TOKEN");

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    /* Read URL from config if not provided */
    if (!url) {
        gut_config cfg;
        char config_path[2048];
        const char *v;
        snprintf(config_path, sizeof(config_path), "%s/config", repo.git_dir);
        if (config_read(&cfg, config_path) == 0) {
            if (config_get(&v, &cfg, "remote \"origin\"", "url") == 0) {
                snprintf(url_buf, sizeof(url_buf), "%s", v);
                url = url_buf;
            }
            config_destroy(&cfg);
        }
        if (!url) {
            fprintf(stderr, "error: no remote configured. Usage: gut push [<url>] [--token <t>]\n");
            return 1;
        }
    }

    /* Resolve current HEAD */
    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }
    if (strncmp(head_ref, "refs/heads/", 11) != 0) {
        fprintf(stderr, "error: HEAD is not on a branch\n");
        return 1;
    }
    snprintf(branch_name, sizeof(branch_name), "%s", head_ref + 11);

    rc = repo_resolve_ref(&local_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "error: cannot resolve %s\n", head_ref); return 1; }

    printf("Pushing branch '%s' to %s\n", branch_name, url);

    /* Discover remote refs */
    rc = remote_discover_refs_for_push(&remote_refs, url, token);
    if (rc) {
        fprintf(stderr, "error: cannot discover remote refs (line %lu)\n", rc);
        return 1;
    }

    /* Find the remote's current OID for our branch */
    {
        u64 j;
        for (j = 0; j < remote_refs.count; j++) {
            if (strcmp(remote_refs.refs[j].name, head_ref) == 0) {
                memcpy(remote_oid.bytes, remote_refs.refs[j].oid.bytes, GUT_OID_RAW_SIZE);
                has_remote_oid = 1;
                break;
            }
        }
    }

    /* Already up to date? */
    if (has_remote_oid &&
        memcmp(local_oid.bytes, remote_oid.bytes, GUT_OID_RAW_SIZE) == 0) {
        printf("Already up to date.\n");
        return 0;
    }

    /* Compute object closure: walk from local_oid, stopping at remote_oid */
    {
        oid_set objects;
        char pack_dir[2048];
        char pack_hex[GUT_OID_HEX_SIZE + 1];
        char pack_path[2048];
        u8 *pack_data = NULL;
        u64 pack_len = 0;
        FILE *pf;
        long fsz;
        gut_remote_update update;
        char *server_msg = NULL;

        memset(&objects, 0, sizeof(objects));
        if (has_remote_oid) {
            walk_commits_for_push(&objects, &repo.odb, &local_oid, &remote_oid, 1);
        } else {
            walk_commits_for_push(&objects, &repo.odb, &local_oid, NULL, 0);
        }

        if (objects.count == 0) {
            free(objects.items);
            fprintf(stderr, "error: no objects to push\n");
            return 1;
        }

        printf("Packing %llu objects...\n", (unsigned long long)objects.count);

        /* Write pack to pack dir */
        snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack", repo.git_dir);
        rc = pack_write(pack_hex, pack_dir, &repo.odb, objects.items, objects.count);
        free(objects.items);
        if (rc) { fprintf(stderr, "error: pack_write failed (line %lu)\n", rc); return 1; }

        /* Read the pack back into memory */
        snprintf(pack_path, sizeof(pack_path), "%s/pack-%s.pack", pack_dir, pack_hex);
        pf = fopen(pack_path, "rb");
        if (!pf) { fprintf(stderr, "error: cannot open written pack\n"); return 1; }
        fseek(pf, 0, SEEK_END);
        fsz = ftell(pf);
        fseek(pf, 0, SEEK_SET);
        pack_data = (u8 *)malloc((size_t)fsz);
        if (!pack_data) { fclose(pf); return 1; }
        fread(pack_data, 1, (size_t)fsz, pf);
        pack_len = (u64)fsz;
        fclose(pf);

        /* Build update record */
        if (has_remote_oid) {
            memcpy(update.old_oid.bytes, remote_oid.bytes, GUT_OID_RAW_SIZE);
        } else {
            memset(update.old_oid.bytes, 0, GUT_OID_RAW_SIZE);
        }
        memcpy(update.new_oid.bytes, local_oid.bytes, GUT_OID_RAW_SIZE);
        snprintf(update.ref_name, sizeof(update.ref_name), "%s", head_ref);

        printf("Sending pack (%llu bytes) and update command...\n",
               (unsigned long long)pack_len);

        rc = remote_send_pack(&server_msg, url, token, &update, 1, pack_data, pack_len);
        free(pack_data);

        /* Clean up the pack we just wrote — server has it now */
        remove(pack_path);
        {
            char idx_path[2048];
            snprintf(idx_path, sizeof(idx_path), "%s/pack-%s.idx", pack_dir, pack_hex);
            remove(idx_path);
        }

        if (rc) {
            if (server_msg) {
                fprintf(stderr, "server response:\n%s\n", server_msg);
                free(server_msg);
            }
            fprintf(stderr, "error: push failed (line %lu)\n", rc);
            return 1;
        }

        if (server_msg) {
            printf("server: %s\n", server_msg);
            free(server_msg);
        }
    }

    printf("done.\n");
    return 0;
}

static int cmd_hash_object(int argc, char **argv) {
    gut_repo repo;
    gut_oid oid;
    char hex[GUT_OID_HEX_SIZE + 1];
    unsigned long rc;
    int do_write = 0;
    const char *file_path = NULL;
    char cwd[2048];
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            do_write = 1;
        } else {
            file_path = argv[i];
        }
    }

    if (!file_path) {
        fprintf(stderr, "usage: gut hash-object [-w] <file>\n");
        return 1;
    }

    if (do_write) {
        if (!gut_getcwd(cwd, sizeof(cwd))) {
            fprintf(stderr, "error: cannot get current directory\n");
            return 1;
        }
        rc = repo_open(&repo, cwd);
        if (rc) {
            fprintf(stderr, "error: not a gut repository\n");
            return 1;
        }

        rc = odb_write_file(&oid, &repo.odb, file_path);
        if (rc) {
            fprintf(stderr, "error: failed to hash file (line %lu)\n", rc);
            return 1;
        }
    } else {
        /* Just compute hash without writing */
        FILE *fp = fopen(file_path, "rb");
        long size;
        u8 *data;
        buf serialized;

        if (!fp) {
            fprintf(stderr, "error: cannot open '%s'\n", file_path);
            return 1;
        }

        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        data = NULL;
        if (size > 0) {
            data = (u8 *)malloc((size_t)size);
            if (!data) { fclose(fp); return 1; }
            if (fread(data, 1, (size_t)size, fp) != (size_t)size) {
                free(data);
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);

        rc = buf_create(&serialized, (u64)size + 64);
        if (rc) { free(data); return 1; }

        rc = obj_serialize(&serialized, GUT_OBJ_BLOB, data, (u64)size);
        free(data);
        if (rc) { buf_destroy(&serialized); return 1; }

        rc = oid_hash(&oid, serialized.data, serialized.len);
        buf_destroy(&serialized);
        if (rc) return 1;
    }

    rc = oid_to_hex(hex, &oid);
    if (rc) return 1;

    printf("%s\n", hex);
    return 0;
}

static int cmd_cat_file(int argc, char **argv) {
    gut_repo repo;
    gut_oid oid;
    gut_object obj;
    unsigned long rc;
    char cwd[2048];
    const char *mode = NULL;
    const char *object_ref = NULL;
    int i;

    for (i = 0; i < argc; i++) {
        if (argv[i][0] == '-') {
            mode = argv[i];
        } else {
            object_ref = argv[i];
        }
    }

    if (!mode || !object_ref) {
        fprintf(stderr, "usage: gut cat-file (-t | -s | -p) <object>\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    if (resolve_object(&oid, &repo, object_ref)) {
        fprintf(stderr, "error: invalid object name '%s'\n", object_ref);
        return 1;
    }

    rc = odb_read(&obj, &repo.odb, &oid);
    if (rc) {
        fprintf(stderr, "error: object not found (line %lu)\n", rc);
        return 1;
    }

    if (strcmp(mode, "-t") == 0) {
        const char *tname;
        rc = obj_type_name(&tname, obj.type);
        if (rc) { object_destroy(&obj); return 1; }
        printf("%s\n", tname);
    } else if (strcmp(mode, "-s") == 0) {
        printf("%llu\n", (unsigned long long)obj.size);
    } else if (strcmp(mode, "-p") == 0) {
        if (obj.type == GUT_OBJ_BLOB) {
            fwrite(obj.data.data, 1, (size_t)obj.data.len, stdout);
        } else if (obj.type == GUT_OBJ_TREE) {
            gut_tree tree;
            rc = tree_parse(&tree, obj.data.data, obj.data.len);
            if (rc) { object_destroy(&obj); return 1; }
            for (u64 j = 0; j < tree.count; j++) {
                char entry_hex[GUT_OID_HEX_SIZE + 1];
                const char *entry_type = (tree.entries[j].mode == 040000) ? "tree" : "blob";
                oid_to_hex(entry_hex, &tree.entries[j].oid);
                printf("%06o %s %s\t%s\n",
                       tree.entries[j].mode, entry_type, entry_hex,
                       tree.entries[j].name);
            }
            tree_destroy(&tree);
        } else if (obj.type == GUT_OBJ_COMMIT) {
            fwrite(obj.data.data, 1, (size_t)obj.data.len, stdout);
        } else {
            fwrite(obj.data.data, 1, (size_t)obj.data.len, stdout);
        }
    } else {
        fprintf(stderr, "error: unknown mode '%s'\n", mode);
        object_destroy(&obj);
        return 1;
    }

    object_destroy(&obj);
    return 0;
}

/* ---- gut add ---- */

/* ---- helpers ---- */

#include <dirent.h>

typedef void (*dir_callback)(const char *name, void *ctx);

static void list_dir(const char *dir_path, dir_callback cb, void *ctx) {
    DIR *d = opendir(dir_path);
    struct dirent *ent;
    if (!d) return;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        cb(ent->d_name, ctx);
    }
    closedir(d);
}

/* Resolve an object ref: try full hex, then short prefix, then ref name */
static int resolve_object(gut_oid *out, gut_repo *repo, const char *ref) {
    unsigned long rc;

    /* Try as full hex OID */
    if (strlen(ref) == GUT_OID_HEX_SIZE) {
        rc = oid_from_hex(out, ref);
        if (rc == 0) return 0;
    }

    /* Try as short SHA prefix */
    if (strlen(ref) >= 4 && strlen(ref) < GUT_OID_HEX_SIZE) {
        rc = odb_resolve_prefix(out, &repo->odb, ref);
        if (rc == 0) return 0;
    }

    /* Try as ref name (HEAD, branch, tag) */
    if (strcmp(ref, "HEAD") == 0) {
        char head_ref[256];
        rc = repo_head_ref(head_ref, sizeof(head_ref), repo);
        if (rc == 0) {
            rc = repo_resolve_ref(out, repo, head_ref);
            if (rc == 0) return 0;
        }
    }

    {
        char full_ref[256];
        snprintf(full_ref, sizeof(full_ref), "refs/heads/%s", ref);
        rc = repo_resolve_ref(out, repo, full_ref);
        if (rc == 0) return 0;
    }

    {
        char full_ref[256];
        snprintf(full_ref, sizeof(full_ref), "refs/tags/%s", ref);
        rc = repo_resolve_ref(out, repo, full_ref);
        if (rc == 0) return 0;
    }

    return 1;
}

/* ---- gut unstage ---- */

static int cmd_unstage(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    int i;

    if (argc < 1) {
        fprintf(stderr, "usage: gut unstage <file>...\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index (line %lu)\n", rc);
        return 1;
    }

    for (i = 0; i < argc; i++) {
        char rel_path[2048];
        make_relative(rel_path, sizeof(rel_path), argv[i], cwd, repo.root_dir);

        rc = index_remove(&idx, rel_path);
        if (rc) {
            fprintf(stderr, "error: pathspec '%s' did not match any known files\n", argv[i]);
            index_destroy(&idx);
            return 1;
        }
    }

    rc = index_write(&idx, index_path);
    index_destroy(&idx);
    if (rc) {
        fprintf(stderr, "error: cannot write index (line %lu)\n", rc);
        return 1;
    }

    return 0;
}

/* ---- gut rm ---- */

static int cmd_rm(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    int i;
    int cached_only = 0;
    int file_start = 0;

    if (argc < 1) {
        fprintf(stderr, "usage: gut rm [--cached] <file>...\n");
        return 1;
    }

    /* Parse --cached flag */
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--cached") == 0) {
            cached_only = 1;
        } else {
            break;
        }
    }
    file_start = i;

    if (file_start >= argc) {
        fprintf(stderr, "usage: gut rm [--cached] <file>...\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index (line %lu)\n", rc);
        return 1;
    }

    for (i = file_start; i < argc; i++) {
        char rel_path[2048];
        make_relative(rel_path, sizeof(rel_path), argv[i], cwd, repo.root_dir);

        rc = index_remove(&idx, rel_path);
        if (rc) {
            fprintf(stderr, "error: pathspec '%s' did not match any known files\n", argv[i]);
            index_destroy(&idx);
            return 1;
        }

        if (!cached_only) {
            char full_path[2048];
            snprintf(full_path, sizeof(full_path), "%s/%s", repo.root_dir, rel_path);
            remove(full_path);
        }
    }

    rc = index_write(&idx, index_path);
    index_destroy(&idx);
    if (rc) {
        fprintf(stderr, "error: cannot write index (line %lu)\n", rc);
        return 1;
    }

    return 0;
}

/* ---- gut branch ---- */

static int cmd_branch(int argc, char **argv) {
    gut_repo repo;
    gut_oid head_oid;
    char cwd[2048];
    char ref_path[2048];
    char head_ref[256];
    char hex[GUT_OID_HEX_SIZE + 2];
    unsigned long rc;

    if (argc < 1) {
        fprintf(stderr, "usage: gut branch [-d] <name>\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    /* Delete branch */
    if (argc >= 2 && strcmp(argv[0], "-d") == 0) {
        const char *name = argv[1];

        /* Refuse to delete current branch */
        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc == 0) {
            char current_ref[256];
            snprintf(current_ref, sizeof(current_ref), "refs/heads/%s", name);
            if (strcmp(head_ref, current_ref) == 0) {
                fprintf(stderr, "error: cannot delete branch '%s' checked out at HEAD\n", name);
                return 1;
            }
        }

        snprintf(ref_path, sizeof(ref_path), "%s/refs/heads/%s", repo.git_dir, name);
        if (remove(ref_path) != 0) {
            fprintf(stderr, "error: branch '%s' not found\n", name);
            return 1;
        }
        printf("Deleted branch %s\n", name);
        return 0;
    }

    /* Create branch */
    {
        const char *name = argv[0];
        struct stat st;

        snprintf(ref_path, sizeof(ref_path), "%s/refs/heads/%s", repo.git_dir, name);
        if (stat(ref_path, &st) == 0) {
            fprintf(stderr, "fatal: a branch named '%s' already exists\n", name);
            return 1;
        }

        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc) {
            fprintf(stderr, "error: cannot read HEAD\n");
            return 1;
        }
        rc = repo_resolve_ref(&head_oid, &repo, head_ref);
        if (rc) {
            fprintf(stderr, "fatal: not a valid object name: 'HEAD'\n");
            return 1;
        }

        rc = oid_to_hex(hex, &head_oid);
        if (rc) return 1;
        hex[GUT_OID_HEX_SIZE] = '\n';
        hex[GUT_OID_HEX_SIZE + 1] = '\0';

        {
            FILE *fp = fopen(ref_path, "w");
            if (!fp) {
                fprintf(stderr, "error: cannot create branch '%s'\n", name);
                return 1;
            }
            fputs(hex, fp);
            fclose(fp);
        }
    }

    return 0;
}

/* ---- gut branches ---- */

struct branches_ctx {
    const char *current;  /* e.g. "main" */
};

static void print_branch(const char *name, void *ctx) {
    struct branches_ctx *bc = (struct branches_ctx *)ctx;
    if (bc->current && strcmp(name, bc->current) == 0) {
        printf("* %s\n", name);
    } else {
        printf("  %s\n", name);
    }
}

static int cmd_branches(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char heads_dir[2048];
    char head_ref[256];
    struct branches_ctx ctx;
    unsigned long rc;

    (void)argc; (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    ctx.current = NULL;
    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc == 0 && strncmp(head_ref, "refs/heads/", 11) == 0) {
        ctx.current = head_ref + 11;
    }

    snprintf(heads_dir, sizeof(heads_dir), "%s/refs/heads", repo.git_dir);
    list_dir(heads_dir, print_branch, &ctx);

    return 0;
}

/* ---- gut tag ---- */

static int cmd_tag(int argc, char **argv) {
    gut_repo repo;
    gut_oid target;
    char cwd[2048];
    char ref_path[2048];
    char hex[GUT_OID_HEX_SIZE + 2];
    unsigned long rc;
    struct stat st;

    if (argc < 1) {
        fprintf(stderr, "usage: gut tag <name> [<commit>]\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(ref_path, sizeof(ref_path), "%s/refs/tags/%s", repo.git_dir, argv[0]);
    if (stat(ref_path, &st) == 0) {
        fprintf(stderr, "fatal: tag '%s' already exists\n", argv[0]);
        return 1;
    }

    if (argc >= 2) {
        /* Tag specific commit */
        rc = oid_from_hex(&target, argv[1]);
        if (rc) {
            fprintf(stderr, "error: invalid object name '%s'\n", argv[1]);
            return 1;
        }
    } else {
        /* Tag HEAD */
        char head_ref[256];
        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }
        rc = repo_resolve_ref(&target, &repo, head_ref);
        if (rc) { fprintf(stderr, "fatal: not a valid object name: 'HEAD'\n"); return 1; }
    }

    rc = oid_to_hex(hex, &target);
    if (rc) return 1;
    hex[GUT_OID_HEX_SIZE] = '\n';
    hex[GUT_OID_HEX_SIZE + 1] = '\0';

    {
        FILE *fp = fopen(ref_path, "w");
        if (!fp) {
            fprintf(stderr, "error: cannot create tag '%s'\n", argv[0]);
            return 1;
        }
        fputs(hex, fp);
        fclose(fp);
    }

    return 0;
}

/* ---- gut tags ---- */

static void print_tag(const char *name, void *ctx) {
    (void)ctx;
    printf("%s\n", name);
}

static int cmd_tags(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char tags_dir[2048];
    unsigned long rc;

    (void)argc; (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(tags_dir, sizeof(tags_dir), "%s/refs/tags", repo.git_dir);
    list_dir(tags_dir, print_tag, NULL);

    return 0;
}

/* ---- working tree helpers ---- */

static unsigned long ensure_parent_dirs(const char *file_path) {
    char tmp[2048];
    size_t len, i;
    len = strlen(file_path);
    if (len >= sizeof(tmp)) return __LINE__;
    memcpy(tmp, file_path, len + 1);
    for (i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
#ifdef _WIN32
            _mkdir(tmp);
#else
            mkdir(tmp, 0755);
#endif
            tmp[i] = '/';
        }
    }
    return 0;
}

static int workdir_write_from_index(gut_repo *repo, gut_index *idx) {
    u64 i;
    for (i = 0; i < idx->count; i++) {
        gut_object obj;
        char full_path[2048];
        FILE *fp;
        unsigned long rc;

        snprintf(full_path, sizeof(full_path), "%s/%s",
                 repo->root_dir, idx->entries[i].path);

        rc = odb_read(&obj, &repo->odb, &idx->entries[i].oid);
        if (rc) return 1;

        ensure_parent_dirs(full_path);

        fp = fopen(full_path, "wb");
        if (!fp) { object_destroy(&obj); return 1; }

        if (obj.data.len > 0) {
            fwrite(obj.data.data, 1, (size_t)obj.data.len, fp);
        }
        fclose(fp);
        object_destroy(&obj);

        /* Update index stat info */
        {
            struct stat st;
            if (stat(full_path, &st) == 0) {
                idx->entries[i].mtime_sec = (u32)st.st_mtime;
                idx->entries[i].file_size = (u32)st.st_size;
            }
        }
    }
    return 0;
}

static int workdir_is_dirty(gut_repo *repo, gut_index *idx) {
    u64 i;
    for (i = 0; i < idx->count; i++) {
        char full_path[2048];
        struct stat st;
        snprintf(full_path, sizeof(full_path), "%s/%s",
                 repo->root_dir, idx->entries[i].path);
        if (stat(full_path, &st) != 0) return 1;
        if ((u32)st.st_mtime != idx->entries[i].mtime_sec ||
            (u32)st.st_size != idx->entries[i].file_size) return 1;
    }
    return 0;
}

/* Remove working tree files in old index but not in new index */
static void workdir_remove_stale(gut_repo *repo, gut_index *old_idx, gut_index *new_idx) {
    u64 i;
    for (i = 0; i < old_idx->count; i++) {
        u64 pos;
        if (index_find(&pos, new_idx, old_idx->entries[i].path) == 0) {
            if (pos >= new_idx->count ||
                strcmp(new_idx->entries[pos].path, old_idx->entries[i].path) != 0) {
                char full_path[2048];
                snprintf(full_path, sizeof(full_path), "%s/%s",
                         repo->root_dir, old_idx->entries[i].path);
                remove(full_path);
            }
        }
    }
}

/* ---- gut checkout ---- */

static int cmd_checkout(int argc, char **argv) {
    gut_repo repo;
    gut_index old_idx, new_idx;
    gut_oid target_oid, tree_oid;
    gut_object commit_obj;
    gut_commit commit;
    char cwd[2048];
    char index_path[2048];
    char ref_path[2048];
    char head_path[2048];
    char head_content[256];
    unsigned long rc;
    struct stat st;

    if (argc < 1) {
        fprintf(stderr, "usage: gut checkout <branch>\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    /* Verify target branch exists */
    snprintf(ref_path, sizeof(ref_path), "%s/refs/heads/%s", repo.git_dir, argv[0]);
    if (stat(ref_path, &st) != 0) {
        fprintf(stderr, "error: branch '%s' not found\n", argv[0]);
        return 1;
    }

    /* Resolve target branch to commit */
    {
        char ref_name[256];
        snprintf(ref_name, sizeof(ref_name), "refs/heads/%s", argv[0]);
        rc = repo_resolve_ref(&target_oid, &repo, ref_name);
        if (rc) {
            fprintf(stderr, "error: cannot resolve branch '%s'\n", argv[0]);
            return 1;
        }
    }

    /* Read target commit to get tree */
    rc = odb_read(&commit_obj, &repo.odb, &target_oid);
    if (rc) {
        fprintf(stderr, "error: cannot read commit (line %lu)\n", rc);
        return 1;
    }
    rc = commit_parse(&commit, commit_obj.data.data, commit_obj.data.len);
    object_destroy(&commit_obj);
    if (rc) {
        fprintf(stderr, "error: cannot parse commit\n");
        return 1;
    }
    memcpy(tree_oid.bytes, commit.tree_oid.bytes, GUT_OID_RAW_SIZE);
    commit_destroy(&commit);

    /* Read current index and check for dirty working tree */
    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&old_idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index\n");
        return 1;
    }

    if (workdir_is_dirty(&repo, &old_idx)) {
        fprintf(stderr, "error: your local changes would be overwritten by checkout\n");
        fprintf(stderr, "Please commit or stash them before switching branches.\n");
        index_destroy(&old_idx);
        return 1;
    }

    /* Build new index from target tree */
    rc = index_read_tree(&new_idx, &repo.odb, &tree_oid);
    if (rc) {
        fprintf(stderr, "error: cannot read tree (line %lu)\n", rc);
        index_destroy(&old_idx);
        return 1;
    }

    /* Remove stale files, then write new files */
    workdir_remove_stale(&repo, &old_idx, &new_idx);
    index_destroy(&old_idx);

    if (workdir_write_from_index(&repo, &new_idx)) {
        fprintf(stderr, "error: cannot write working tree\n");
        index_destroy(&new_idx);
        return 1;
    }

    /* Write new index */
    rc = index_write(&new_idx, index_path);
    index_destroy(&new_idx);
    if (rc) {
        fprintf(stderr, "error: cannot write index\n");
        return 1;
    }

    /* Update HEAD */
    snprintf(head_path, sizeof(head_path), "%s/HEAD", repo.git_dir);
    snprintf(head_content, sizeof(head_content), "ref: refs/heads/%s\n", argv[0]);
    {
        FILE *fp = fopen(head_path, "w");
        if (!fp) {
            fprintf(stderr, "error: cannot update HEAD\n");
            return 1;
        }
        fputs(head_content, fp);
        fclose(fp);
    }

    printf("Switched to branch '%s'\n", argv[0]);
    return 0;
}

/* ---- gut add ---- */

static int cmd_add(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    int i;

    if (argc < 1) {
        fprintf(stderr, "usage: gut add <file>...\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index (line %lu)\n", rc);
        return 1;
    }

    for (i = 0; i < argc; i++) {
        gut_oid oid;
        struct stat st;
        char rel_path[2048];
        char full_path[2048];

        make_relative(rel_path, sizeof(rel_path), argv[i], cwd, repo.root_dir);
        snprintf(full_path, sizeof(full_path), "%s/%s", repo.root_dir, rel_path);

        if (stat(full_path, &st) != 0) {
            fprintf(stderr, "error: pathspec '%s' did not match any files\n", argv[i]);
            index_destroy(&idx);
            return 1;
        }

        /* Hash and write blob */
        rc = odb_write_file(&oid, &repo.odb, full_path);
        if (rc) {
            fprintf(stderr, "error: cannot hash '%s' (line %lu)\n", argv[i], rc);
            index_destroy(&idx);
            return 1;
        }

        /* Add to index */
        rc = index_add(&idx, rel_path, &oid, 0100644, (u32)st.st_size,
                        (u32)st.st_mtime);
        if (rc) {
            fprintf(stderr, "error: cannot add '%s' to index (line %lu)\n", argv[i], rc);
            index_destroy(&idx);
            return 1;
        }
    }

    rc = index_write(&idx, index_path);
    index_destroy(&idx);
    if (rc) {
        fprintf(stderr, "error: cannot write index (line %lu)\n", rc);
        return 1;
    }

    return 0;
}

/* ---- gut commit ---- */

static int cmd_commit(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    gut_oid tree_oid, commit_oid, parent_oid;
    char cwd[2048];
    char index_path[2048];
    char obj_dir[2048];
    char hex[GUT_OID_HEX_SIZE + 1];
    char head_ref[256];
    const char *message = NULL;
    unsigned long rc;
    int has_parent = 0;
    int i;
    buf commit_buf;
    time_t now;
    char timestamp[128];
    const char *author_name;
    const char *author_email;

    /* Parse -m <message> */
    for (i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], "-m") == 0) {
            message = argv[i + 1];
            break;
        }
    }

    if (!message) {
        fprintf(stderr, "usage: gut commit -m <message>\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index (line %lu)\n", rc);
        return 1;
    }

    if (idx.count == 0) {
        fprintf(stderr, "nothing to commit (empty index)\n");
        index_destroy(&idx);
        return 1;
    }

    /* Write tree from index */
    snprintf(obj_dir, sizeof(obj_dir), "%s/objects", repo.git_dir);
    rc = index_write_tree(&tree_oid, &idx, obj_dir);
    index_destroy(&idx);
    if (rc) {
        fprintf(stderr, "error: cannot write tree (line %lu)\n", rc);
        return 1;
    }

    /* Resolve current HEAD for parent */
    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) {
        fprintf(stderr, "error: cannot read HEAD\n");
        return 1;
    }

    rc = repo_resolve_ref(&parent_oid, &repo, head_ref);
    if (rc == 0) {
        has_parent = 1;
    }

    /* Resolve author: env vars > .git/config > fallback */
    author_name = getenv("GUT_AUTHOR_NAME");
    if (!author_name) author_name = getenv("GIT_AUTHOR_NAME");
    author_email = getenv("GUT_AUTHOR_EMAIL");
    if (!author_email) author_email = getenv("GIT_AUTHOR_EMAIL");
    if (!author_name || !author_email) {
        gut_config cfg;
        char config_path[2048];
        snprintf(config_path, sizeof(config_path), "%s/config", repo.git_dir);
        if (config_read(&cfg, config_path) == 0) {
            if (!author_name) {
                const char *v;
                if (config_get(&v, &cfg, "user", "name") == 0)
                    author_name = v;
            }
            if (!author_email) {
                const char *v;
                if (config_get(&v, &cfg, "user", "email") == 0)
                    author_email = v;
            }
            /* Note: cfg lifetime covers commit build below; destroyed after use */
        }
    }
    if (!author_name) author_name = "Unknown";
    if (!author_email) author_email = "unknown@example.com";

    now = time(NULL);

    {
        long tz_offset = 0;
#ifdef _WIN32
        {
            TIME_ZONE_INFORMATION tzi;
            if (GetTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID) {
                tz_offset = -(long)tzi.Bias;
            }
        }
#else
        tz_offset = tm_info->tm_gmtoff / 60;
#endif
        snprintf(timestamp, sizeof(timestamp), "%lld %+03ld%02ld",
                 (long long)now, tz_offset / 60, labs(tz_offset) % 60);
    }

    rc = buf_create(&commit_buf, 512);
    if (rc) return 1;

    /* tree <hex>\n */
    oid_to_hex(hex, &tree_oid);
    buf_append(&commit_buf, (u8 *)"tree ", 5);
    buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
    buf_append_byte(&commit_buf, '\n');

    /* parent <hex>\n (if exists) */
    if (has_parent) {
        oid_to_hex(hex, &parent_oid);
        buf_append(&commit_buf, (u8 *)"parent ", 7);
        buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
        buf_append_byte(&commit_buf, '\n');
    }

    /* author */
    {
        char author_line[512];
        int n = snprintf(author_line, sizeof(author_line), "author %s <%s> %s\n",
                         author_name, author_email, timestamp);
        buf_append(&commit_buf, (u8 *)author_line, (u64)n);
    }

    /* committer */
    {
        char committer_line[512];
        int n = snprintf(committer_line, sizeof(committer_line), "committer %s <%s> %s\n",
                         author_name, author_email, timestamp);
        buf_append(&commit_buf, (u8 *)committer_line, (u64)n);
    }

    /* blank line + message */
    buf_append_byte(&commit_buf, '\n');
    buf_append(&commit_buf, (u8 *)message, (u64)strlen(message));
    buf_append_byte(&commit_buf, '\n');

    /* Write commit to ODB */
    rc = odb_write(&commit_oid, &repo.odb, GUT_OBJ_COMMIT,
                   commit_buf.data, commit_buf.len);
    buf_destroy(&commit_buf);
    if (rc) {
        fprintf(stderr, "error: cannot write commit (line %lu)\n", rc);
        return 1;
    }

    /* Update ref */
    rc = repo_update_ref(&repo, head_ref, &commit_oid);
    if (rc) {
        fprintf(stderr, "error: cannot update ref (line %lu)\n", rc);
        return 1;
    }

    oid_to_hex(hex, &commit_oid);
    printf("[%s %.*s] %s\n",
           has_parent ? "main" : "(root-commit)",
           7, hex, message);

    return 0;
}

/* ---- gut log ---- */

static int cmd_log(int argc, char **argv) {
    gut_repo repo;
    gut_oid current_oid;
    char cwd[2048];
    char head_ref[256];
    unsigned long rc;
    int max_count = -1;
    int shown = 0;

    (void)argv;
    if (argc > 0) {
        /* Could parse -n <count> */
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) {
        fprintf(stderr, "error: cannot read HEAD\n");
        return 1;
    }

    rc = repo_resolve_ref(&current_oid, &repo, head_ref);
    if (rc) {
        fprintf(stderr, "fatal: bad default revision 'HEAD'\n");
        return 1;
    }

    while (1) {
        gut_object obj;
        gut_commit commit;
        char hex[GUT_OID_HEX_SIZE + 1];

        if (max_count >= 0 && shown >= max_count) break;

        rc = odb_read(&obj, &repo.odb, &current_oid);
        if (rc) break;

        if (obj.type != GUT_OBJ_COMMIT) {
            object_destroy(&obj);
            break;
        }

        rc = commit_parse(&commit, obj.data.data, obj.data.len);
        object_destroy(&obj);
        if (rc) break;

        oid_to_hex(hex, &current_oid);
        printf("commit %s\n", hex);
        if (commit.author) printf("Author: %s\n", commit.author);
        printf("\n");
        if (commit.message) printf("    %s\n", commit.message);
        printf("\n");

        shown++;

        if (commit.parent_count > 0) {
            memcpy(current_oid.bytes, commit.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
            commit_destroy(&commit);
        } else {
            commit_destroy(&commit);
            break;
        }
    }

    return 0;
}

/* ---- gut diff ---- */

/* Print a unified diff hunk using apennines diff_result.
 * The apennines diff_result has edits with off_a/off_b (line indices) and len. */
static void diff_file_pair(const char *path, const u8 *old_data, u64 old_len,
                           const u8 *new_data, u64 new_len) {
    diff_result result;
    unsigned long rc;

    /* Use apennines patience diff (git's default algorithm) */
    rc = diff_patience(&result,
                       (const char *)old_data, old_len,
                       (const char *)new_data, new_len);
    if (rc) return;

    /* Check if there are any actual changes */
    {
        int has_changes = 0;
        u64 i;
        for (i = 0; i < result.len; i++) {
            if (result.edits[i].op != DIFF_EQUAL) { has_changes = 1; break; }
        }
        if (!has_changes) { diff_destroy(&result); return; }
    }

    /* Use apennines format_unified for output.
     * It writes to a pre-allocated buffer, so estimate size. */
    {
        u64 buf_size = old_len + new_len + result.len * 80 + 256;
        char *buf = (char *)malloc((size_t)buf_size);
        u64 out_len = 0;
        if (!buf) { diff_destroy(&result); return; }

        /* Write header ourselves (apennines uses generic "a"/"b" labels) */
        printf("--- a/%s\n+++ b/%s\n", path, path);

        rc = diff_format_unified(buf, buf_size, &out_len,
                                 (const char *)old_data, old_len,
                                 (const char *)new_data, new_len,
                                 &result, 3);
        if (rc == 0 && out_len > 0) {
            /* Skip the "--- a\n+++ b\n" that apennines prepends */
            char *body = buf;
            char *hunk = strstr(body, "@@ ");
            if (hunk) {
                fwrite(hunk, 1, out_len - (u64)(hunk - body), stdout);
            } else {
                fwrite(buf, 1, (size_t)out_len, stdout);
            }
        }
        free(buf);
    }

    diff_destroy(&result);
}

static int cmd_diff(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    int staged = 0;
    u64 i;

    for (i = 0; i < (u64)argc; i++) {
        if (strcmp(argv[i], "--staged") == 0 || strcmp(argv[i], "--cached") == 0)
            staged = 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index\n");
        return 1;
    }

    if (staged) {
        /* Compare index vs HEAD */
        char head_ref[256];
        gut_oid head_oid;
        gut_object head_obj;
        gut_commit head_commit;

        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc) { index_destroy(&idx); return 0; }
        rc = repo_resolve_ref(&head_oid, &repo, head_ref);
        if (rc) { index_destroy(&idx); return 0; }

        rc = odb_read(&head_obj, &repo.odb, &head_oid);
        if (rc) { index_destroy(&idx); return 0; }
        rc = commit_parse(&head_commit, head_obj.data.data, head_obj.data.len);
        object_destroy(&head_obj);
        if (rc) { index_destroy(&idx); return 0; }

        for (i = 0; i < idx.count; i++) {
            gut_oid head_blob_oid;
            long cmp;

            rc = tree_lookup_path(&head_blob_oid, &repo.odb,
                                  &head_commit.tree_oid, idx.entries[i].path);
            if (rc) {
                /* New file in index, not in HEAD */
                gut_object blob;
                rc = odb_read(&blob, &repo.odb, &idx.entries[i].oid);
                if (rc == 0) {
                    diff_file_pair(idx.entries[i].path, NULL, 0,
                                   blob.data.data, blob.data.len);
                    object_destroy(&blob);
                }
                continue;
            }

            oid_compare(&cmp, &head_blob_oid, &idx.entries[i].oid);
            if (cmp != 0) {
                gut_object old_blob, new_blob;
                rc = odb_read(&old_blob, &repo.odb, &head_blob_oid);
                if (rc) continue;
                rc = odb_read(&new_blob, &repo.odb, &idx.entries[i].oid);
                if (rc) { object_destroy(&old_blob); continue; }

                diff_file_pair(idx.entries[i].path,
                               old_blob.data.data, old_blob.data.len,
                               new_blob.data.data, new_blob.data.len);
                object_destroy(&old_blob);
                object_destroy(&new_blob);
            }
        }
        commit_destroy(&head_commit);
    } else {
        /* Compare working tree vs index */
        for (i = 0; i < idx.count; i++) {
            char full_path[2048];
            struct stat st;

            snprintf(full_path, sizeof(full_path), "%s/%s",
                     repo.root_dir, idx.entries[i].path);

            if (stat(full_path, &st) != 0) continue;
            if ((u32)st.st_mtime == idx.entries[i].mtime_sec &&
                (u32)st.st_size == idx.entries[i].file_size) continue;

            /* File changed — diff it */
            {
                gut_object old_blob;
                FILE *fp;
                u8 *new_data;
                long size;

                rc = odb_read(&old_blob, &repo.odb, &idx.entries[i].oid);
                if (rc) continue;

                fp = fopen(full_path, "rb");
                if (!fp) { object_destroy(&old_blob); continue; }
                fseek(fp, 0, SEEK_END);
                size = ftell(fp);
                fseek(fp, 0, SEEK_SET);

                new_data = NULL;
                if (size > 0) {
                    new_data = (u8 *)malloc((size_t)size);
                    if (new_data) {
                        if (fread(new_data, 1, (size_t)size, fp) != (size_t)size) {
                            free(new_data);
                            new_data = NULL;
                            size = 0;
                        }
                    }
                }
                fclose(fp);

                diff_file_pair(idx.entries[i].path,
                               old_blob.data.data, old_blob.data.len,
                               new_data, (u64)(size > 0 ? size : 0));
                free(new_data);
                object_destroy(&old_blob);
            }
        }
    }

    index_destroy(&idx);
    return 0;
}

/* ---- gut status ---- */

static int cmd_status(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    u64 i;

    (void)argc;
    (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository\n");
        return 1;
    }

    /* Read HEAD ref to determine branch */
    {
        char head_ref[256];
        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc == 0) {
            if (strncmp(head_ref, "refs/heads/", 11) == 0) {
                printf("On branch %s\n", head_ref + 11);
            } else {
                printf("HEAD detached at %.7s\n", head_ref);
            }
        }
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) {
        fprintf(stderr, "error: cannot read index\n");
        return 1;
    }

    /* Check if there's a HEAD commit */
    {
        char head_ref[256];
        gut_oid head_oid;
        int has_head = 0;

        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc == 0) {
            rc = repo_resolve_ref(&head_oid, &repo, head_ref);
            if (rc == 0) has_head = 1;
        }

        if (!has_head && idx.count > 0) {
            printf("\nChanges to be committed:\n");
            for (i = 0; i < idx.count; i++) {
                printf("  new file:   %s\n", idx.entries[i].path);
            }
        } else if (has_head) {
            /* Compare index to HEAD tree */
            gut_object head_obj;
            gut_commit head_commit;

            rc = odb_read(&head_obj, &repo.odb, &head_oid);
            if (rc == 0 && head_obj.type == GUT_OBJ_COMMIT) {
                rc = commit_parse(&head_commit, head_obj.data.data, head_obj.data.len);
                object_destroy(&head_obj);
                if (rc == 0) {
                    /* For now, just report staged files */
                    /* TODO: deep tree comparison against index */
                    commit_destroy(&head_commit);
                }
            } else {
                object_destroy(&head_obj);
            }
        }
    }

    /* Check working directory against index */
    {
        int has_changes = 0;

        for (i = 0; i < idx.count; i++) {
            char full_path[2048];
            struct stat st;

            snprintf(full_path, sizeof(full_path), "%s/%s",
                     repo.root_dir, idx.entries[i].path);

            if (stat(full_path, &st) != 0) {
                if (!has_changes) {
                    printf("\nChanges not staged for commit:\n");
                    has_changes = 1;
                }
                printf("  deleted:    %s\n", idx.entries[i].path);
            } else if ((u32)st.st_mtime != idx.entries[i].mtime_sec ||
                       (u32)st.st_size != idx.entries[i].file_size) {
                if (!has_changes) {
                    printf("\nChanges not staged for commit:\n");
                    has_changes = 1;
                }
                printf("  modified:   %s\n", idx.entries[i].path);
            }
        }
    }

    /* Walk working tree for untracked files */
    {
        gut_ignore ign;
        char ign_path[2048];
        int has_untracked = 0;

        snprintf(ign_path, sizeof(ign_path), "%s/.gitignore", repo.root_dir);
        ignore_read(&ign, ign_path);

        /* Recursive walk */
        {
            typedef struct { const char *dir; const char *prefix; } walk_frame;
            walk_frame stack[64];
            int sp = 0;

            stack[sp].dir = repo.root_dir;
            stack[sp].prefix = "";
            sp++;

            while (sp > 0) {
                char dir_path[2048];
                char prefix_buf[2048];
                DIR *d;
                struct dirent *ent;

                sp--;
                snprintf(dir_path, sizeof(dir_path), "%s", stack[sp].dir);
                snprintf(prefix_buf, sizeof(prefix_buf), "%s", stack[sp].prefix);

                d = opendir(dir_path);
                if (!d) continue;

                while ((ent = readdir(d)) != NULL) {
                    char full[2048];
                    char rel[2048];
                    struct stat st;
                    unsigned long ign_result;

                    if (strcmp(ent->d_name, ".") == 0 ||
                        strcmp(ent->d_name, "..") == 0 ||
                        strcmp(ent->d_name, ".git") == 0) continue;

                    snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);
                    if (prefix_buf[0])
                        snprintf(rel, sizeof(rel), "%s/%s", prefix_buf, ent->d_name);
                    else
                        snprintf(rel, sizeof(rel), "%s", ent->d_name);

                    if (stat(full, &st) != 0) continue;

                    if (S_ISDIR(st.st_mode)) {
                        ignore_match(&ign_result, &ign, rel, 1);
                        if (ign_result) continue;
                        if (sp < 64) {
                            /* Push directory for later traversal */
                            static char dir_bufs[64][2048];
                            static char pre_bufs[64][2048];
                            snprintf(dir_bufs[sp], sizeof(dir_bufs[sp]), "%s", full);
                            snprintf(pre_bufs[sp], sizeof(pre_bufs[sp]), "%s", rel);
                            stack[sp].dir = dir_bufs[sp];
                            stack[sp].prefix = pre_bufs[sp];
                            sp++;
                        }
                    } else {
                        ignore_match(&ign_result, &ign, rel, 0);
                        if (ign_result) continue;

                        /* Check if tracked in index */
                        {
                            u64 pos;
                            index_find(&pos, &idx, rel);
                            if (pos < idx.count &&
                                strcmp(idx.entries[pos].path, rel) == 0)
                                continue; /* tracked */
                        }

                        if (!has_untracked) {
                            printf("\nUntracked files:\n");
                            has_untracked = 1;
                        }
                        printf("  %s\n", rel);
                    }
                }
                closedir(d);
            }
        }

        ignore_destroy(&ign);
    }

    index_destroy(&idx);
    printf("\n");
    return 0;
}

/* ---- gut last ---- */

static int cmd_last(int argc, char **argv) {
    gut_repo repo;
    gut_oid head_oid;
    gut_object obj;
    gut_commit commit;
    char cwd[2048];
    char head_ref[256];
    char hex[GUT_OID_HEX_SIZE + 1];
    unsigned long rc;

    (void)argc; (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }

    rc = repo_resolve_ref(&head_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "fatal: bad default revision 'HEAD'\n"); return 1; }

    rc = odb_read(&obj, &repo.odb, &head_oid);
    if (rc) { fprintf(stderr, "error: cannot read HEAD commit\n"); return 1; }

    rc = commit_parse(&commit, obj.data.data, obj.data.len);
    object_destroy(&obj);
    if (rc) { fprintf(stderr, "error: cannot parse commit\n"); return 1; }

    oid_to_hex(hex, &head_oid);
    printf("commit %s\n", hex);
    if (commit.author) printf("Author: %s\n", commit.author);
    printf("\n");
    if (commit.message) printf("    %s\n", commit.message);
    printf("\n");

    commit_destroy(&commit);
    return 0;
}

/* ---- gut amend ---- */

static int cmd_amend(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    gut_oid tree_oid, new_commit_oid, old_head_oid;
    gut_object old_obj;
    gut_commit old_commit;
    char cwd[2048];
    char index_path[2048];
    char obj_dir[2048];
    char head_ref[256];
    char hex[GUT_OID_HEX_SIZE + 1];
    const char *message = NULL;
    unsigned long rc;
    buf commit_buf;
    int i;

    /* Parse -m <message> (optional for amend — reuse old message if not given) */
    for (i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], "-m") == 0) {
            message = argv[i + 1];
            break;
        }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    /* Read old HEAD commit */
    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }
    rc = repo_resolve_ref(&old_head_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "fatal: no commits to amend\n"); return 1; }

    rc = odb_read(&old_obj, &repo.odb, &old_head_oid);
    if (rc) { fprintf(stderr, "error: cannot read commit\n"); return 1; }
    rc = commit_parse(&old_commit, old_obj.data.data, old_obj.data.len);
    object_destroy(&old_obj);
    if (rc) { fprintf(stderr, "error: cannot parse commit\n"); return 1; }

    if (!message) message = old_commit.message;

    /* Build tree from current index */
    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) { commit_destroy(&old_commit); return 1; }

    snprintf(obj_dir, sizeof(obj_dir), "%s/objects", repo.git_dir);
    rc = index_write_tree(&tree_oid, &idx, obj_dir);
    index_destroy(&idx);
    if (rc) { commit_destroy(&old_commit); return 1; }

    rc = buf_create(&commit_buf, 512);
    if (rc) { commit_destroy(&old_commit); return 1; }

    oid_to_hex(hex, &tree_oid);
    buf_append(&commit_buf, (u8 *)"tree ", 5);
    buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
    buf_append_byte(&commit_buf, '\n');

    {
        u64 pi;
        for (pi = 0; pi < old_commit.parent_count; pi++) {
            oid_to_hex(hex, &old_commit.parent_oids[pi]);
            buf_append(&commit_buf, (u8 *)"parent ", 7);
            buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
            buf_append_byte(&commit_buf, '\n');
        }
    }

    /* Reuse original author, update committer timestamp */
    {
        char line[512];
        int n = snprintf(line, sizeof(line), "author %s\n", old_commit.author);
        buf_append(&commit_buf, (u8 *)line, (u64)n);
        n = snprintf(line, sizeof(line), "committer %s\n", old_commit.committer);
        buf_append(&commit_buf, (u8 *)line, (u64)n);
    }

    buf_append_byte(&commit_buf, '\n');
    buf_append(&commit_buf, (u8 *)message, (u64)strlen(message));
    if (message[strlen(message) - 1] != '\n')
        buf_append_byte(&commit_buf, '\n');

    rc = odb_write(&new_commit_oid, &repo.odb, GUT_OBJ_COMMIT,
                   commit_buf.data, commit_buf.len);
    buf_destroy(&commit_buf);
    commit_destroy(&old_commit);
    if (rc) { fprintf(stderr, "error: cannot write commit\n"); return 1; }

    rc = repo_update_ref(&repo, head_ref, &new_commit_oid);
    if (rc) { fprintf(stderr, "error: cannot update ref\n"); return 1; }

    oid_to_hex(hex, &new_commit_oid);
    printf("[%.*s] %s\n", 7, hex, message);
    return 0;
}

/* ---- gut undo ---- */

static int cmd_undo(int argc, char **argv) {
    gut_repo repo;
    gut_oid head_oid;
    gut_object obj;
    gut_commit commit;
    char cwd[2048];
    char head_ref[256];
    char hex[GUT_OID_HEX_SIZE + 1];
    unsigned long rc;

    (void)argc; (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }

    rc = repo_resolve_ref(&head_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "fatal: no commits to undo\n"); return 1; }

    rc = odb_read(&obj, &repo.odb, &head_oid);
    if (rc) { fprintf(stderr, "error: cannot read commit\n"); return 1; }

    rc = commit_parse(&commit, obj.data.data, obj.data.len);
    object_destroy(&obj);
    if (rc) { fprintf(stderr, "error: cannot parse commit\n"); return 1; }

    if (commit.parent_count == 0) {
        /* Root commit — remove the ref to go back to unborn state */
        char ref_path[2048];
        snprintf(ref_path, sizeof(ref_path), "%s/%s", repo.git_dir, head_ref);
        remove(ref_path);
        commit_destroy(&commit);
        printf("Undone root commit. Branch is now empty.\n");
        return 0;
    }

    /* Move HEAD to parent */
    rc = repo_update_ref(&repo, head_ref, &commit.parent_oids[0]);
    oid_to_hex(hex, &commit.parent_oids[0]);
    commit_destroy(&commit);

    if (rc) { fprintf(stderr, "error: cannot update ref\n"); return 1; }

    printf("HEAD is now at %.*s\n", 7, hex);
    return 0;
}

/* ---- rev-spec parser ---- */

static int resolve_rev(gut_oid *out, gut_repo *repo, const char *rev) {
    char head_ref[256];
    gut_oid oid;
    unsigned long rc;
    int steps = 0;
    const char *tilde;

    if (!out || !repo || !rev) return 1;

    /* Parse HEAD~N */
    tilde = strchr(rev, '~');
    if (tilde) {
        steps = atoi(tilde + 1);
        if (steps < 1) steps = 1;
    }

    /* Resolve base */
    if (strncmp(rev, "HEAD", 4) == 0) {
        rc = repo_head_ref(head_ref, sizeof(head_ref), repo);
        if (rc) return 1;
        rc = repo_resolve_ref(&oid, repo, head_ref);
        if (rc) return 1;
    } else {
        rc = oid_from_hex(&oid, rev);
        if (rc) return 1;
    }

    /* Walk parents */
    while (steps > 0) {
        gut_object obj;
        gut_commit commit;
        rc = odb_read(&obj, &repo->odb, &oid);
        if (rc) return 1;
        rc = commit_parse(&commit, obj.data.data, obj.data.len);
        object_destroy(&obj);
        if (rc) return 1;
        if (commit.parent_count == 0) {
            commit_destroy(&commit);
            return 1; /* no more parents */
        }
        memcpy(oid.bytes, commit.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&commit);
        steps--;
    }

    memcpy(out->bytes, oid.bytes, GUT_OID_RAW_SIZE);
    return 0;
}

/* ---- gut restore ---- */

static int cmd_restore(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    int staged = 0;
    int file_start = 0;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--staged") == 0) {
            staged = 1;
            file_start = i + 1;
        }
    }
    if (file_start == 0 && argc > 0 && argv[0][0] != '-') file_start = 0;
    if (file_start >= argc) {
        fprintf(stderr, "usage: gut restore [--staged] <file>...\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc) { fprintf(stderr, "error: cannot read index\n"); return 1; }

    if (staged) {
        /* Restore index from HEAD tree */
        char head_ref[256];
        gut_oid head_oid;
        gut_object head_obj;
        gut_commit head_commit;

        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc) { index_destroy(&idx); return 1; }
        rc = repo_resolve_ref(&head_oid, &repo, head_ref);
        if (rc) { index_destroy(&idx); return 1; }
        rc = odb_read(&head_obj, &repo.odb, &head_oid);
        if (rc) { index_destroy(&idx); return 1; }
        rc = commit_parse(&head_commit, head_obj.data.data, head_obj.data.len);
        object_destroy(&head_obj);
        if (rc) { index_destroy(&idx); return 1; }

        for (i = file_start; i < argc; i++) {
            char rel_path[2048];
            gut_oid blob_oid;

            make_relative(rel_path, sizeof(rel_path), argv[i], cwd, repo.root_dir);

            rc = tree_lookup_path(&blob_oid, &repo.odb,
                                  &head_commit.tree_oid, rel_path);
            if (rc) {
                /* Not in HEAD: remove from index */
                index_remove(&idx, rel_path);
            } else {
                /* Restore index entry from HEAD */
                index_add(&idx, rel_path, &blob_oid, 0100644, 0, 0);
            }
        }
        commit_destroy(&head_commit);
    } else {
        /* Restore working tree from index */
        for (i = file_start; i < argc; i++) {
            char rel_path[2048];
            u64 pos;

            make_relative(rel_path, sizeof(rel_path), argv[i], cwd, repo.root_dir);

            rc = index_find(&pos, &idx, rel_path);
            if (rc || pos >= idx.count ||
                strcmp(idx.entries[pos].path, rel_path) != 0) {
                fprintf(stderr, "error: pathspec '%s' not in index\n", argv[i]);
                continue;
            }

            {
                gut_object blob;
                char full_path[2048];
                FILE *fp;

                rc = odb_read(&blob, &repo.odb, &idx.entries[pos].oid);
                if (rc) { fprintf(stderr, "error: cannot read '%s'\n", argv[i]); continue; }

                snprintf(full_path, sizeof(full_path), "%s/%s", repo.root_dir, rel_path);
                ensure_parent_dirs(full_path);

                fp = fopen(full_path, "wb");
                if (!fp) { object_destroy(&blob); continue; }
                if (blob.data.len > 0)
                    fwrite(blob.data.data, 1, (size_t)blob.data.len, fp);
                fclose(fp);
                object_destroy(&blob);

                /* Update index stat */
                {
                    struct stat st;
                    if (stat(full_path, &st) == 0) {
                        idx.entries[pos].mtime_sec = (u32)st.st_mtime;
                        idx.entries[pos].file_size = (u32)st.st_size;
                    }
                }
            }
        }
    }

    rc = index_write(&idx, index_path);
    index_destroy(&idx);
    if (rc) { fprintf(stderr, "error: cannot write index\n"); return 1; }

    return 0;
}

/* ---- gut reset ---- */

static int cmd_reset(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char head_ref[256];
    unsigned long rc;
    int hard = 0;
    const char *rev_spec = NULL;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--soft") == 0) { /* default behavior */ }
        else if (strcmp(argv[i], "--hard") == 0) { hard = 1; }
        else { rev_spec = argv[i]; }
    }

    if (!rev_spec) {
        fprintf(stderr, "usage: gut reset [--soft|--hard] <rev>\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    {
        gut_oid target_oid;
        char hex[GUT_OID_HEX_SIZE + 1];

        if (resolve_rev(&target_oid, &repo, rev_spec)) {
            fprintf(stderr, "fatal: invalid revision '%s'\n", rev_spec);
            return 1;
        }

        /* Move ref */
        rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
        if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }

        rc = repo_update_ref(&repo, head_ref, &target_oid);
        if (rc) { fprintf(stderr, "error: cannot update ref\n"); return 1; }

        if (hard) {
            /* Reset index and working tree */
            gut_object commit_obj;
            gut_commit commit;
            gut_index old_idx, new_idx;
            char index_path[2048];

            rc = odb_read(&commit_obj, &repo.odb, &target_oid);
            if (rc) { fprintf(stderr, "error: cannot read target commit\n"); return 1; }
            rc = commit_parse(&commit, commit_obj.data.data, commit_obj.data.len);
            object_destroy(&commit_obj);
            if (rc) { fprintf(stderr, "error: cannot parse commit\n"); return 1; }

            snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);

            /* Read current index for stale file removal */
            rc = index_read(&old_idx, index_path);
            if (rc) { commit_destroy(&commit); return 1; }

            /* Build new index from target tree */
            rc = index_read_tree(&new_idx, &repo.odb, &commit.tree_oid);
            commit_destroy(&commit);
            if (rc) { index_destroy(&old_idx); return 1; }

            /* Remove stale files and write new ones */
            workdir_remove_stale(&repo, &old_idx, &new_idx);
            index_destroy(&old_idx);

            workdir_write_from_index(&repo, &new_idx);

            rc = index_write(&new_idx, index_path);
            index_destroy(&new_idx);
            if (rc) { fprintf(stderr, "error: cannot write index\n"); return 1; }
        }

        oid_to_hex(hex, &target_oid);
        printf("HEAD is now at %.*s\n", 7, hex);
    }

    return 0;
}

/* ---- merge base finder ---- */

/* Collect all ancestor OIDs from a commit by walking first-parents.
 * Returns a malloc'd array of OIDs. */
static gut_oid *collect_ancestors(gut_odb *odb, gut_oid *start, u64 *count) {
    u64 cap = 64;
    u64 n = 0;
    gut_oid *list = (gut_oid *)malloc(cap * sizeof(gut_oid));
    gut_oid current;
    if (!list) return NULL;

    memcpy(current.bytes, start->bytes, GUT_OID_RAW_SIZE);

    while (1) {
        gut_object obj;
        gut_commit commit;
        unsigned long rc;

        if (n >= cap) {
            cap *= 2;
            list = (gut_oid *)realloc(list, cap * sizeof(gut_oid));
            if (!list) return NULL;
        }
        memcpy(list[n].bytes, current.bytes, GUT_OID_RAW_SIZE);
        n++;

        rc = odb_read(&obj, odb, &current);
        if (rc) break;
        rc = commit_parse(&commit, obj.data.data, obj.data.len);
        object_destroy(&obj);
        if (rc) break;

        if (commit.parent_count == 0) { commit_destroy(&commit); break; }
        memcpy(current.bytes, commit.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&commit);
    }

    *count = n;
    return list;
}

/* Find merge base: first common ancestor between two commits */
static int find_merge_base(gut_oid *out, gut_odb *odb,
                           gut_oid *ours, gut_oid *theirs) {
    gut_oid *a_list;
    u64 a_count, i;
    gut_oid current;

    a_list = collect_ancestors(odb, ours, &a_count);
    if (!a_list) return 1;

    /* Walk theirs chain, checking against ours set */
    memcpy(current.bytes, theirs->bytes, GUT_OID_RAW_SIZE);
    while (1) {
        gut_object obj;
        gut_commit commit;
        unsigned long rc;
        long cmp;

        for (i = 0; i < a_count; i++) {
            oid_compare(&cmp, &current, &a_list[i]);
            if (cmp == 0) {
                memcpy(out->bytes, current.bytes, GUT_OID_RAW_SIZE);
                free(a_list);
                return 0;
            }
        }

        rc = odb_read(&obj, odb, &current);
        if (rc) break;
        rc = commit_parse(&commit, obj.data.data, obj.data.len);
        object_destroy(&obj);
        if (rc) break;

        if (commit.parent_count == 0) { commit_destroy(&commit); break; }
        memcpy(current.bytes, commit.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&commit);
    }

    free(a_list);
    return 1; /* no common ancestor */
}

/* ---- gut merge ---- */

static int cmd_merge(int argc, char **argv) {
    gut_repo repo;
    gut_oid our_oid, their_oid, base_oid;
    char cwd[2048];
    char head_ref[256];
    char hex[GUT_OID_HEX_SIZE + 1];
    unsigned long rc;
    long cmp;
    const char *branch_name;

    if (argc < 1) {
        fprintf(stderr, "usage: gut merge <branch>\n");
        return 1;
    }
    branch_name = argv[0];

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository\n"); return 1; }

    /* Resolve HEAD */
    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }
    rc = repo_resolve_ref(&our_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "fatal: HEAD not valid\n"); return 1; }

    /* Resolve target branch */
    {
        char ref[256];
        snprintf(ref, sizeof(ref), "refs/heads/%s", branch_name);
        rc = repo_resolve_ref(&their_oid, &repo, ref);
        if (rc) {
            fprintf(stderr, "fatal: branch '%s' not found\n", branch_name);
            return 1;
        }
    }

    /* Already up to date? */
    oid_compare(&cmp, &our_oid, &their_oid);
    if (cmp == 0) {
        printf("Already up to date.\n");
        return 0;
    }

    /* Find merge base */
    if (find_merge_base(&base_oid, &repo.odb, &our_oid, &their_oid)) {
        fprintf(stderr, "fatal: no common ancestor\n");
        return 1;
    }

    /* Fast-forward: if base == ours, just move HEAD to theirs */
    oid_compare(&cmp, &base_oid, &our_oid);
    if (cmp == 0) {
        gut_index new_idx;
        gut_object commit_obj;
        gut_commit commit;
        gut_index old_idx;
        char index_path[2048];

        /* Read theirs commit tree */
        rc = odb_read(&commit_obj, &repo.odb, &their_oid);
        if (rc) { fprintf(stderr, "error: cannot read commit\n"); return 1; }
        rc = commit_parse(&commit, commit_obj.data.data, commit_obj.data.len);
        object_destroy(&commit_obj);
        if (rc) { fprintf(stderr, "error: cannot parse commit\n"); return 1; }

        snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
        index_read(&old_idx, index_path);

        rc = index_read_tree(&new_idx, &repo.odb, &commit.tree_oid);
        commit_destroy(&commit);
        if (rc) { index_destroy(&old_idx); return 1; }

        workdir_remove_stale(&repo, &old_idx, &new_idx);
        index_destroy(&old_idx);
        workdir_write_from_index(&repo, &new_idx);

        index_write(&new_idx, index_path);
        index_destroy(&new_idx);

        repo_update_ref(&repo, head_ref, &their_oid);

        oid_to_hex(hex, &their_oid);
        printf("Fast-forward to %.*s\n", 7, hex);
        return 0;
    }

    /* Fast-forward: if base == theirs, already up to date */
    oid_compare(&cmp, &base_oid, &their_oid);
    if (cmp == 0) {
        printf("Already up to date.\n");
        return 0;
    }

    /* True three-way merge */
    {
        gut_object base_commit_obj, our_commit_obj, their_commit_obj;
        gut_commit base_commit, our_commit, their_commit;
        gut_oid base_tree, our_tree, their_tree;
        gut_index base_idx, our_idx, their_idx, merged_idx;
        char index_path[2048];
        char obj_dir[2048];
        gut_oid merge_tree_oid, merge_commit_oid;
        int has_conflicts = 0;
        u64 i;

        /* Get trees for all three commits */
        rc = odb_read(&base_commit_obj, &repo.odb, &base_oid);
        if (rc) { fprintf(stderr, "error: cannot read base commit\n"); return 1; }
        commit_parse(&base_commit, base_commit_obj.data.data, base_commit_obj.data.len);
        object_destroy(&base_commit_obj);
        memcpy(base_tree.bytes, base_commit.tree_oid.bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&base_commit);

        rc = odb_read(&our_commit_obj, &repo.odb, &our_oid);
        if (rc) { fprintf(stderr, "error: cannot read our commit\n"); return 1; }
        commit_parse(&our_commit, our_commit_obj.data.data, our_commit_obj.data.len);
        object_destroy(&our_commit_obj);
        memcpy(our_tree.bytes, our_commit.tree_oid.bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&our_commit);

        rc = odb_read(&their_commit_obj, &repo.odb, &their_oid);
        if (rc) { fprintf(stderr, "error: cannot read their commit\n"); return 1; }
        commit_parse(&their_commit, their_commit_obj.data.data, their_commit_obj.data.len);
        object_destroy(&their_commit_obj);
        memcpy(their_tree.bytes, their_commit.tree_oid.bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&their_commit);

        /* Expand all three trees into indexes */
        index_read_tree(&base_idx, &repo.odb, &base_tree);
        index_read_tree(&our_idx, &repo.odb, &our_tree);
        index_read_tree(&their_idx, &repo.odb, &their_tree);

        /* Build merged index: for each file, three-way merge */
        index_init(&merged_idx);

        /* Process all files from ours */
        for (i = 0; i < our_idx.count; i++) {
            const char *path = our_idx.entries[i].path;
            u64 base_pos, their_pos;
            int in_base, in_theirs;
            gut_oid *our_blob = &our_idx.entries[i].oid;

            index_find(&base_pos, &base_idx, path);
            in_base = (base_pos < base_idx.count && strcmp(base_idx.entries[base_pos].path, path) == 0);
            index_find(&their_pos, &their_idx, path);
            in_theirs = (their_pos < their_idx.count && strcmp(their_idx.entries[their_pos].path, path) == 0);

            if (!in_theirs) {
                if (in_base) {
                    /* Deleted by theirs — check if we modified it */
                    long c;
                    oid_compare(&c, our_blob, &base_idx.entries[base_pos].oid);
                    if (c == 0) continue; /* unmodified, accept deletion */
                    /* Modified by us but deleted by them — conflict */
                    fprintf(stderr, "CONFLICT (modify/delete): %s\n", path);
                    has_conflicts = 1;
                    index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                } else {
                    /* Added by us only */
                    index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                }
                continue;
            }

            {
                gut_oid *their_blob = &their_idx.entries[their_pos].oid;
                long c_ours_theirs, c_ours_base;

                oid_compare(&c_ours_theirs, our_blob, their_blob);
                if (c_ours_theirs == 0) {
                    /* Both same — just use ours */
                    index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                    continue;
                }

                if (!in_base) {
                    /* Both added same file differently — conflict */
                    fprintf(stderr, "CONFLICT (add/add): %s\n", path);
                    has_conflicts = 1;
                    index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                    continue;
                }

                oid_compare(&c_ours_base, our_blob, &base_idx.entries[base_pos].oid);
                if (c_ours_base == 0) {
                    /* We didn't change, theirs did — take theirs */
                    index_add(&merged_idx, path, their_blob, their_idx.entries[their_pos].mode, 0, 0);
                    continue;
                }

                {
                    long c_theirs_base;
                    oid_compare(&c_theirs_base, their_blob, &base_idx.entries[base_pos].oid);
                    if (c_theirs_base == 0) {
                        /* Theirs didn't change, ours did — take ours */
                        index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                        continue;
                    }
                }

                /* Both modified — three-way content merge */
                {
                    gut_object b_obj, o_obj, t_obj;
                    diff_merge_result mr;

                    if (odb_read(&b_obj, &repo.odb, &base_idx.entries[base_pos].oid) ||
                        odb_read(&o_obj, &repo.odb, our_blob) ||
                        odb_read(&t_obj, &repo.odb, their_blob)) {
                        fprintf(stderr, "error: cannot read blobs for %s\n", path);
                        has_conflicts = 1;
                        index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                        continue;
                    }

                    rc = diff_three_way(&mr,
                        (const char *)b_obj.data.data, b_obj.data.len,
                        (const char *)o_obj.data.data, o_obj.data.len,
                        (const char *)t_obj.data.data, t_obj.data.len,
                        "HEAD", branch_name,
                        DIFF_MERGE_STYLE_STANDARD);

                    object_destroy(&b_obj);
                    object_destroy(&o_obj);
                    object_destroy(&t_obj);

                    if (rc) {
                        fprintf(stderr, "error: merge failed for %s\n", path);
                        has_conflicts = 1;
                        index_add(&merged_idx, path, our_blob, our_idx.entries[i].mode, 0, 0);
                    } else {
                        /* Write merged content as blob */
                        gut_oid merged_blob;
                        odb_write(&merged_blob, &repo.odb, GUT_OBJ_BLOB,
                                  (u8 *)mr.data, mr.len);
                        index_add(&merged_idx, path, &merged_blob,
                                  our_idx.entries[i].mode, 0, 0);
                        if (mr.has_conflicts) {
                            fprintf(stderr, "CONFLICT (content): merge conflict in %s\n", path);
                            has_conflicts = 1;
                        }
                        diff_merge_destroy(&mr);
                    }
                }
            }
        }

        /* Files only in theirs (new files they added) */
        for (i = 0; i < their_idx.count; i++) {
            const char *path = their_idx.entries[i].path;
            u64 our_pos;
            index_find(&our_pos, &our_idx, path);
            if (our_pos < our_idx.count && strcmp(our_idx.entries[our_pos].path, path) == 0)
                continue; /* already handled */
            /* Theirs-only file */
            index_add(&merged_idx, path, &their_idx.entries[i].oid,
                      their_idx.entries[i].mode, 0, 0);
        }

        index_destroy(&base_idx);
        index_destroy(&our_idx);
        index_destroy(&their_idx);

        /* Write merged index and working tree */
        snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
        {
            gut_index old_idx;
            index_read(&old_idx, index_path);
            workdir_remove_stale(&repo, &old_idx, &merged_idx);
            index_destroy(&old_idx);
        }
        workdir_write_from_index(&repo, &merged_idx);

        if (has_conflicts) {
            index_write(&merged_idx, index_path);
            index_destroy(&merged_idx);
            fprintf(stderr, "Automatic merge failed; fix conflicts and commit.\n");
            return 1;
        }

        /* Write merge tree and commit */
        snprintf(obj_dir, sizeof(obj_dir), "%s/objects", repo.git_dir);
        index_write_tree(&merge_tree_oid, &merged_idx, obj_dir);
        index_write(&merged_idx, index_path);
        index_destroy(&merged_idx);

        /* Build merge commit (two parents) */
        {
            buf commit_buf;
            const char *author_name, *author_email;
            char timestamp[128];
            time_t now = time(NULL);

            author_name = getenv("GUT_AUTHOR_NAME");
            if (!author_name) author_name = getenv("GIT_AUTHOR_NAME");
            author_email = getenv("GUT_AUTHOR_EMAIL");
            if (!author_email) author_email = getenv("GIT_AUTHOR_EMAIL");
            if (!author_name || !author_email) {
                gut_config cfg;
                char config_path[2048];
                snprintf(config_path, sizeof(config_path), "%s/config", repo.git_dir);
                if (config_read(&cfg, config_path) == 0) {
                    const char *v;
                    if (!author_name && config_get(&v, &cfg, "user", "name") == 0)
                        author_name = v;
                    if (!author_email && config_get(&v, &cfg, "user", "email") == 0)
                        author_email = v;
                }
            }
            if (!author_name) author_name = "Unknown";
            if (!author_email) author_email = "unknown@example.com";

            {
                long tz_offset = 0;
#ifdef _WIN32
                TIME_ZONE_INFORMATION tzi;
                if (GetTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID)
                    tz_offset = -(long)tzi.Bias;
#endif
                snprintf(timestamp, sizeof(timestamp), "%lld %+03ld%02ld",
                         (long long)now, tz_offset / 60, labs(tz_offset) % 60);
            }

            buf_create(&commit_buf, 512);

            oid_to_hex(hex, &merge_tree_oid);
            buf_append(&commit_buf, (u8 *)"tree ", 5);
            buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
            buf_append_byte(&commit_buf, '\n');

            /* Two parents */
            oid_to_hex(hex, &our_oid);
            buf_append(&commit_buf, (u8 *)"parent ", 7);
            buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
            buf_append_byte(&commit_buf, '\n');

            oid_to_hex(hex, &their_oid);
            buf_append(&commit_buf, (u8 *)"parent ", 7);
            buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
            buf_append_byte(&commit_buf, '\n');

            {
                char line[512];
                int n = snprintf(line, sizeof(line), "author %s <%s> %s\n",
                                 author_name, author_email, timestamp);
                buf_append(&commit_buf, (u8 *)line, (u64)n);
                n = snprintf(line, sizeof(line), "committer %s <%s> %s\n",
                             author_name, author_email, timestamp);
                buf_append(&commit_buf, (u8 *)line, (u64)n);
            }

            {
                char msg[256];
                snprintf(msg, sizeof(msg), "\nMerge branch '%s'\n", branch_name);
                buf_append(&commit_buf, (u8 *)msg, (u64)strlen(msg));
            }

            odb_write(&merge_commit_oid, &repo.odb, GUT_OBJ_COMMIT,
                      commit_buf.data, commit_buf.len);
            buf_destroy(&commit_buf);
        }

        repo_update_ref(&repo, head_ref, &merge_commit_oid);

        oid_to_hex(hex, &merge_commit_oid);
        printf("Merge made by the 'recursive' strategy.\n");
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "init") == 0) {
        return cmd_init(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "clone") == 0) {
        return cmd_clone(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "fetch") == 0) {
        return cmd_fetch(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "push") == 0) {
        return cmd_push(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "pack-objects") == 0) {
        return cmd_pack_objects(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "repack") == 0) {
        return cmd_repack(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "listen") == 0) {
        return cmd_listen(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "leech") == 0) {
        return cmd_leech(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "leechers") == 0) {
        return cmd_leechers(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "add") == 0) {
        return cmd_add(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "unstage") == 0) {
        return cmd_unstage(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "rm") == 0) {
        return cmd_rm(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "branch") == 0) {
        return cmd_branch(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "branches") == 0) {
        return cmd_branches(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "tag") == 0) {
        return cmd_tag(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "tags") == 0) {
        return cmd_tags(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "checkout") == 0) {
        return cmd_checkout(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "merge") == 0) {
        return cmd_merge(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "diff") == 0) {
        return cmd_diff(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "commit") == 0) {
        return cmd_commit(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "log") == 0) {
        return cmd_log(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "status") == 0) {
        return cmd_status(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "last") == 0) {
        return cmd_last(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "amend") == 0) {
        return cmd_amend(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "undo") == 0) {
        return cmd_undo(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "restore") == 0) {
        return cmd_restore(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "reset") == 0) {
        return cmd_reset(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "hash-object") == 0) {
        return cmd_hash_object(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "cat-file") == 0) {
        return cmd_cat_file(argc - 2, argv + 2);
    }

    if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("gut version 0.1.0\n");
        return 0;
    }

    fprintf(stderr, "gut: '%s' is not a gut command\n", argv[1]);
    return 1;
}
