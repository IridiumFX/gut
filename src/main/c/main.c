#include "gut/repo.h"
#include "gut/oid.h"
#include "gut/object.h"
#include "gut/index.h"
#include "gut/config.h"
#include "gut/ignore.h"
#include "gut/remote.h"
#include "gut/pack.h"
#include "gut/leech.h"
#include "gut/login.h"
#include "gut/submodule.h"
#include <dirent.h>
#include "apennines/diff.h"
#include "apennines/base.h"
#include "apennines/tcp.h"
#include "apennines/addr.h"
#include "apennines/tls.h"
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
    printf(
        "gut — a clean git implementation in C11, with P2P extensions.\n"
        "\n"
        "Usage: gut <command> [<args>]\n"
        "\n"
        "Working tree\n"
        "  init            Create an empty repository\n"
        "  add             Stage file contents\n"
        "  unstage         Remove a path from the index (keep working tree)\n"
        "  rm              Remove file from index + working tree\n"
        "  mv              Rename a tracked file + move its index entry\n"
        "  ls-files        List every tracked path, one per line\n"
        "  restore         Restore working tree or index files\n"
        "  status          Show what's staged / modified / untracked\n"
        "\n"
        "Commits\n"
        "  commit          Record staged changes as a new commit\n"
        "  amend           Replace HEAD commit with new index + message\n"
        "  undo            Move HEAD back one commit (keep working tree)\n"
        "  wip             Commit with a 'WIP:' prefix\n"
        "  squash <N>      Collapse the last N commits into one\n"
        "  last            Show the most recent commit\n"
        "\n"
        "History & inspection\n"
        "  log             Show commit history  (--oneline, --graph, -n)\n"
        "  reflog [<ref>]  Show local ref movements (HEAD default, -n to cap)\n"
        "  show [<commit>] Pretty-print a commit + its diff from parent\n"
        "  diff            Show changes  (--staged, --stat)\n"
        "  blame <path>    Per-line commit attribution\n"
        "  bisect          Binary search for a regression\n"
        "  hash-object     Hash a file, optionally write to ODB\n"
        "  cat-file        Print object contents by OID\n"
        "\n"
        "Refs\n"
        "  branch          Create or delete a branch\n"
        "  branches        List branches\n"
        "  tag / tags      Create / list tags\n"
        "  checkout        Switch branches\n"
        "  merge           Merge a branch into HEAD\n"
        "  cherry-pick <c> Apply one commit's diff onto HEAD\n"
        "  reset           Move HEAD (--soft or --hard)\n"
        "  stash           Snapshot working tree, reset to HEAD\n"
        "                    subcommands: pop, list\n"
        "  revert-file <c> <path>  Restore a file from any commit\n"
        "\n"
        "Remote / packing\n"
        "  clone           Clone from a smart-HTTP remote (--depth N)\n"
        "  fetch           Incremental fetch from remote\n"
        "  push            Upload pack to remote\n"
        "  remote          add / remove / list / set-url named remotes\n"
        "  config          get / set / --list keys in .git/config\n"
        "  repack          Pack loose objects, remove originals\n"
        "  pack-objects    Write a pack from OIDs on stdin\n"
        "  index-pack      Write .idx for an existing .pack\n"
        "  login           OIDC device flow to get a push token\n"
        "\n"
        "P2P (broker + ambient awareness)\n"
        "  listen          Run broker daemon (--port, --background, --leech <url>)\n"
        "  leech           Subscribe to a peer listener's event stream\n"
        "  leechers        Query a listener for its connected peers\n"
        "  send            One-shot text message to a listener\n"
        "  ask             Request a ref's tip from a peer (fetches into refs/leech)\n"
        "  offer           Advertise a ref (or --patch for a single file)\n"
        "  offers          List / apply / reject received patch-offers\n"
        "  sos             Broadcast a conflict-help message\n"
        "  feeling         Predict merge conflicts from leech state\n"
        "                    --offer-to <url> --as <name> to auto-offer on CONFLICT\n"
        "                    --since <2h>    to filter old peers\n"
        "\n"
        "Server\n"
        "  server          Serve repos over smart HTTP\n"
        "                    --port N  --repo <path>  OR  --root <dir>\n"
        "                    --auth-token <t>  --cert / --key (TLS)\n"
        "\n"
        "Global env:\n"
        "  GUT_NO_FEELING=1   silence post-add conflict warnings\n"
        "  GUT_SKIP_HOOKS=1   bypass pre/post-commit / pre-push hooks\n"
    );
}

/* Suggest a close match on typo. Levenshtein distance, top hit if <=2. */
static void suggest_command(const char *typo) {
    static const char *known[] = {
        "init", "clone", "fetch", "push", "pack-objects", "index-pack",
        "repack", "remote", "listen", "leech", "send", "leechers",
        "ask", "offer", "offers", "sos", "feeling", "login",
        "add", "unstage", "rm", "mv", "ls-files", "config",
        "branch", "branches", "tag", "tags",
        "checkout", "merge", "cherry-pick", "diff", "commit", "wip", "squash",
        "log", "reflog", "show", "status", "last", "amend", "undo", "restore",
        "reset", "stash", "blame", "bisect", "revert-file",
        "hash-object", "cat-file", "server", "help", NULL
    };
    int best_d = 99;
    const char *best = NULL;
    int i;
    u64 tl = strlen(typo);
    for (i = 0; known[i]; i++) {
        u64 kl = strlen(known[i]);
        /* Crude: common-prefix length + length delta as proxy */
        u64 cp = 0;
        u64 limit = tl < kl ? tl : kl;
        while (cp < limit && typo[cp] == known[i][cp]) cp++;
        {
            int d = (int)((tl + kl) - 2 * cp);
            if (d < best_d) { best_d = d; best = known[i]; }
        }
    }
    if (best && best_d <= 4) {
        fprintf(stderr, "  did you mean: gut %s ?\n", best);
    }
}

/* Forward declarations */
static int resolve_object(gut_oid *out, gut_repo *repo, const char *ref);
static unsigned long ensure_parent_dirs(const char *file_path);
static int workdir_write_from_index(gut_repo *repo, gut_index *idx);
static int run_hook(gut_repo *repo, const char *name, int abort_on_fail);

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
    const char *path = NULL;
    char cwd[2048];
    gut_hash_algo algo = GUT_HASH_SHA1;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--object-format") == 0 && i + 1 < argc) {
            const char *f = argv[++i];
            if      (strcmp(f, "sha1")   == 0) algo = GUT_HASH_SHA1;
            else if (strcmp(f, "sha256") == 0) algo = GUT_HASH_SHA256;
            else {
                fprintf(stderr, "error: unknown --object-format '%s'\n", f);
                return 1;
            }
        } else if (argv[i][0] != '-') {
            if (!path) path = argv[i];
        }
    }

    if (!path) {
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

    /* If SHA-256 requested, rewrite .git/config with repositoryformatversion=1
     * and the objectformat extension. Git requires v1 whenever any
     * extensions section is present, otherwise it errors out. */
    if (algo == GUT_HASH_SHA256) {
        char cfg_path[2048];
        FILE *fp;
        snprintf(cfg_path, sizeof(cfg_path), "%s/config", repo.git_dir);
        fp = fopen(cfg_path, "w");
        if (fp) {
            fputs("[core]\n"
                  "\trepositoryformatversion = 1\n"
                  "\tfilemode = false\n"
                  "\tbare = false\n"
                  "[extensions]\n"
                  "\tobjectformat = sha256\n", fp);
            fclose(fp);
        }
        printf("Initialized empty gut repository in %s/.git/ (object-format: sha256)\n",
               path);
    } else {
        printf("Initialized empty gut repository in %s/.git/\n", path);
    }
    return 0;
}

/* ---- gut clone ---- */

static int cmd_clone(int argc, char **argv) {
    const char *url = NULL;
    const char *dir = NULL;
    gut_remote_refs refs;
    gut_repo repo;
    char dest[2048];
    char pack_path[2048];
    unsigned long rc;
    u64 i;
    int found_head_target = 0;
    char head_target_ref[256];
    int depth = 0;
    int recurse_submodules = 0;
    int ai;

    /* Parse flags first, then positional */
    for (ai = 0; ai < argc; ai++) {
        if (strcmp(argv[ai], "--depth") == 0 && ai + 1 < argc) {
            depth = atoi(argv[++ai]);
            if (depth <= 0) {
                fprintf(stderr, "error: --depth must be > 0\n"); return 1;
            }
        } else if (strcmp(argv[ai], "--recurse-submodules") == 0 ||
                   strcmp(argv[ai], "--recursive") == 0) {
            recurse_submodules = 1;
        } else if (argv[ai][0] != '-') {
            if (!url)      url = argv[ai];
            else if (!dir) dir = argv[ai];
        }
    }

    if (!url) {
        fprintf(stderr, "usage: gut clone [--depth N] [--recurse-submodules] <url> [<directory>]\n");
        return 1;
    }

    /* Derived dir name if not provided */
    if (!dir) {
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

    /* If the remote advertised sha256, flip this repo to sha256 before we
     * write any refs or fetch a pack. Git requires repositoryformatversion=1
     * whenever an extensions section is present. */
    if (refs.hash_algo == GUT_HASH_SHA256) {
        char cfg_path[2048];
        FILE *cf;
        snprintf(cfg_path, sizeof(cfg_path), "%s/config", repo.git_dir);
        cf = fopen(cfg_path, "w");
        if (cf) {
            fputs("[core]\n"
                  "\trepositoryformatversion = 1\n"
                  "\tfilemode = false\n"
                  "\tbare = false\n"
                  "[extensions]\n"
                  "\tobjectformat = sha256\n", cf);
            fclose(cf);
        }
        repo.hash_algo = GUT_HASH_SHA256;
        repo.odb.hash_algo = GUT_HASH_SHA256;
        printf("Remote uses SHA-256 object format\n");
    }

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
                    memcpy(wants[want_count].bytes, refs.refs[i].oid.bytes,
                           sizeof(refs.refs[i].oid.bytes));
                    want_count++;
                }
            }
        }

        if (want_count == 0) {
            free(wants);
            printf("warning: nothing to fetch\n");
            return 0;
        }

        printf("Fetching objects (%llu wants%s)...\n",
               (unsigned long long)want_count,
               depth > 0 ? ", shallow" : "");
        snprintf(pack_path, sizeof(pack_path), "%s/objects/pack/gut-clone.pack",
                 repo.git_dir);

        {
            gut_oid *shallows = NULL;
            u64 n_shallows = 0;

            rc = remote_fetch_pack_algo(url, wants, want_count, NULL, 0, pack_path,
                                        depth, &shallows, &n_shallows,
                                        repo.hash_algo);
            free(wants);

            if (rc) {
                fprintf(stderr, "fatal: fetch failed (line %lu)\n", rc);
                free(shallows);
                return 1;
            }

            /* If we got back a shallow boundary, persist it. Further fetches
             * will walk history up to these OIDs and treat them as leaves. */
            if (n_shallows > 0) {
                char sh_path[2048];
                FILE *sf;
                u64 si;
                unsigned hex_len = gut_oid_hex_size(repo.hash_algo);
                snprintf(sh_path, sizeof(sh_path), "%s/shallow", repo.git_dir);
                sf = fopen(sh_path, "w");
                if (sf) {
                    for (si = 0; si < n_shallows; si++) {
                        char hex[GUT_OID_MAX_HEX_SIZE + 1];
                        oid_to_hex_n(hex, &shallows[si], hex_len);
                        fprintf(sf, "%s\n", hex);
                    }
                    fclose(sf);
                    printf("shallow clone — %llu boundary commit(s) recorded\n",
                           (unsigned long long)n_shallows);
                }
            }
            free(shallows);
        }
    }

    /* Index the pack */
    printf("Indexing pack...\n");
    {
        char pack_to_index[2048];
        snprintf(pack_to_index, sizeof(pack_to_index),
                 "%s/objects/pack/gut-clone.pack", repo.git_dir);
        if (pack_index_create_algo(pack_to_index, NULL, repo.hash_algo) != 0) {
            fprintf(stderr, "warning: pack indexing failed\n");
        }
    }

    /* Create refs */
    {
    unsigned hex_len = gut_oid_hex_size(repo.hash_algo);
    for (i = 0; i < refs.count; i++) {
        if (strcmp(refs.refs[i].name, "HEAD") == 0) continue;

        if (strncmp(refs.refs[i].name, "refs/heads/", 11) == 0) {
            char ref_path[2048];
            char ref_dir[2048];
            char ref_content[GUT_OID_MAX_HEX_SIZE + 2];
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
            oid_to_hex_n(ref_content, &refs.refs[i].oid, hex_len);
            ref_content[hex_len] = '\n';
            ref_content[hex_len + 1] = '\0';
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
            char ref_content[GUT_OID_MAX_HEX_SIZE + 2];
            FILE *fp;

            snprintf(ref_path, sizeof(ref_path), "%s/%s", repo.git_dir, refs.refs[i].name);
            oid_to_hex_n(ref_content, &refs.refs[i].oid, hex_len);
            ref_content[hex_len] = '\n';
            ref_content[hex_len + 1] = '\0';
            fp = fopen(ref_path, "w");
            if (fp) { fputs(ref_content, fp); fclose(fp); }
        }
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

    /* Recurse into submodules if requested. */
    if (recurse_submodules) {
        printf("Initializing submodules...\n");
        if (submodules_update_all(&repo, 1) != 0) {
            fprintf(stderr, "warning: some submodules failed to initialize\n");
        }
    }

    printf("done.\n");
    return 0;
}

/* ---- gut submodule ---- */

static int cmd_submodule(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    unsigned long rc;
    int recursive = 0;
    int i;
    const char *sub = (argc > 0) ? argv[0] : NULL;

    if (!sub) {
        fprintf(stderr, "usage: gut submodule update [--init] [--recursive]\n");
        return 1;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--recursive") == 0) recursive = 1;
        else if (strcmp(argv[i], "--init")   == 0) { /* init implied */ }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }
    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

    if (strcmp(sub, "update") == 0) {
        rc = submodules_update_all(&repo, recursive);
        if (rc) return 1;
        return 0;
    }

    fprintf(stderr, "usage: gut submodule update [--init] [--recursive]\n");
    return 1;
}

/* ---- gut login ---- */

static int cmd_login(int argc, char **argv) {
    const char *issuer = NULL;
    const char *client_id = NULL;
    const char *scope = "openid email";
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--client-id") == 0 && i + 1 < argc) {
            client_id = argv[++i];
        } else if (strcmp(argv[i], "--scope") == 0 && i + 1 < argc) {
            scope = argv[++i];
        } else if (argv[i][0] != '-') {
            issuer = argv[i];
        }
    }

    if (!issuer) {
        fprintf(stderr, "usage: gut login <issuer-url> [--client-id <id>] [--scope <s>]\n");
        fprintf(stderr, "  e.g.: gut login https://github.com --client-id Iv1.b507a08c87ecfe98\n");
        return 1;
    }
    if (!client_id) {
        fprintf(stderr, "error: --client-id required (register your app with the IdP)\n");
        return 1;
    }

    return login_device_flow(issuer, client_id, scope) ? 1 : 0;
}

/* ---- gut listen ---- */

#define GUT_LISTEN_MAX_OUTBOUND 16

/* Daemon helpers: PID file + log file paths live in ~/.gut/ */
static void listen_pid_path(char *out, size_t out_size, u16 port) {
    const char *home;
#ifdef _WIN32
    home = getenv("USERPROFILE"); if (!home) home = "C:";
#else
    home = getenv("HOME"); if (!home) home = "/tmp";
#endif
    snprintf(out, out_size, "%s/.gut/listen-%u.pid", home, (unsigned)port);
}

static void listen_log_path(char *out, size_t out_size, u16 port) {
    const char *home;
#ifdef _WIN32
    home = getenv("USERPROFILE"); if (!home) home = "C:";
#else
    home = getenv("HOME"); if (!home) home = "/tmp";
#endif
    snprintf(out, out_size, "%s/.gut/listen-%u.log", home, (unsigned)port);
}

/* Ensure ~/.gut exists */
static void ensure_gut_home(void) {
    const char *home;
    char gut_dir[1024];
#ifdef _WIN32
    home = getenv("USERPROFILE"); if (!home) home = "C:";
    snprintf(gut_dir, sizeof(gut_dir), "%s/.gut", home);
    _mkdir(gut_dir);
#else
    home = getenv("HOME"); if (!home) home = "/tmp";
    snprintf(gut_dir, sizeof(gut_dir), "%s/.gut", home);
    mkdir(gut_dir, 0755);
#endif
}

/* Check if a PID is still alive */
static int pid_is_alive(long pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return 0;
    {
        DWORD code;
        GetExitCodeProcess(h, &code);
        CloseHandle(h);
        return code == STILL_ACTIVE;
    }
#else
    return (kill((pid_t)pid, 0) == 0);
#endif
}

static long read_pid_file(u16 port) {
    char path[1024];
    FILE *fp;
    long pid = 0;
    listen_pid_path(path, sizeof(path), port);
    fp = fopen(path, "r");
    if (!fp) return 0;
    fscanf(fp, "%ld", &pid);
    fclose(fp);
    return pid;
}

static int cmd_listen_status(u16 port) {
    long pid = read_pid_file(port);
    if (pid == 0) {
        printf("gut listen on port %u: not running\n", (unsigned)port);
        return 1;
    }
    if (pid_is_alive(pid)) {
        char log_path[1024];
        listen_log_path(log_path, sizeof(log_path), port);
        printf("gut listen on port %u: running (pid %ld)\n  log: %s\n",
               (unsigned)port, pid, log_path);
        return 0;
    }
    printf("gut listen on port %u: stale PID %ld (process not alive)\n",
           (unsigned)port, pid);
    return 1;
}

static int cmd_listen_stop(u16 port) {
    long pid = read_pid_file(port);
    char pid_path[1024];
    if (pid == 0) {
        fprintf(stderr, "no gut listen recorded on port %u\n", (unsigned)port);
        return 1;
    }
    if (!pid_is_alive(pid)) {
        fprintf(stderr, "process %ld no longer running\n", pid);
    } else {
#ifdef _WIN32
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
#else
        kill((pid_t)pid, SIGTERM);
#endif
        printf("stopped gut listen on port %u (pid %ld)\n", (unsigned)port, pid);
    }
    listen_pid_path(pid_path, sizeof(pid_path), port);
    remove(pid_path);
    return 0;
}

/* ====================================================================
 *  Listener op-dispatcher — parses incoming messages, routes by "op".
 *
 *  Supported ops:
 *    { "op": "ask",   "ref": "refs/heads/main" }
 *        → reply: { "op": "offer",  "ref": "...", "oid": "<40-hex>" }
 *                  or { "op": "nack", "ref": "...", "reason": "..." }
 *    { "op": "offer", "ref": "...", "oid": "..." }   → logged
 *    { "op": "sos",   "file": "..." , ... }          → logged
 * ==================================================================== */

static gut_repo *g_op_repo = NULL;

/* Minimal JSON string extractor (same shape as leech.c's one) */
static int op_json_str(char *out, size_t out_size,
                       const char *json, const char *key) {
    char needle[64];
    const char *p, *vstart, *vend;
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    p = strstr(json, needle);
    if (!p) return 0;
    vstart = p + strlen(needle);
    vend = vstart;
    while (*vend && *vend != '"') {
        if (*vend == '\\' && vend[1]) vend += 2;
        else vend++;
    }
    {
        size_t len = (size_t)(vend - vstart);
        if (len >= out_size) len = out_size - 1;
        memcpy(out, vstart, len);
        out[len] = '\0';
    }
    return 1;
}

static void op_handle_ask(u64 peer_id, const char *json) {
    char ref[256];
    gut_oid oid;
    char reply[512];
    int n;

    if (!op_json_str(ref, sizeof(ref), json, "ref")) {
        n = snprintf(reply, sizeof(reply),
                     "{\"op\":\"nack\",\"reason\":\"missing ref\"}");
        leech_listen_reply(peer_id, reply, (u64)n);
        return;
    }
    if (!g_op_repo || repo_resolve_ref(&oid, g_op_repo, ref) != 0) {
        n = snprintf(reply, sizeof(reply),
                     "{\"op\":\"nack\",\"ref\":\"%s\",\"reason\":\"unknown ref\"}",
                     ref);
        leech_listen_reply(peer_id, reply, (u64)n);
        return;
    }
    {
        char oid_hex[GUT_OID_HEX_SIZE + 1];
        oid_to_hex(oid_hex, &oid);
        n = snprintf(reply, sizeof(reply),
                     "{\"op\":\"offer\",\"ref\":\"%s\",\"oid\":\"%s\"}",
                     ref, oid_hex);
        leech_listen_reply(peer_id, reply, (u64)n);
    }
    printf("[peer #%llu] ask %s → offer\n", (unsigned long long)peer_id, ref);
    fflush(stdout);
}

static void op_handle_offer(u64 peer_id, const char *json) {
    printf("[peer #%llu] offer %s\n", (unsigned long long)peer_id, json);
    fflush(stdout);
}

static void op_handle_sos(u64 peer_id, const char *json) {
    printf("[peer #%llu] SOS %s\n", (unsigned long long)peer_id, json);
    fflush(stdout);
}

/* Extract a JSON string field by scanning past "<key>":" up to the next
 * unescaped ". Allocates *out_ptr on success (caller frees). Needed when
 * the value is too large for op_json_str's fixed buffer (base64 payload). */
static int op_json_str_alloc(char **out_ptr, u64 *out_len,
                             const char *json, const char *key) {
    char needle[64];
    const char *p, *vstart, *vend;
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    p = strstr(json, needle);
    if (!p) return 0;
    vstart = p + strlen(needle);
    vend = vstart;
    while (*vend && *vend != '"') {
        if (*vend == '\\' && vend[1]) vend += 2;
        else vend++;
    }
    {
        u64 n = (u64)(vend - vstart);
        char *buf = (char *)malloc((size_t)n + 1);
        if (!buf) return 0;
        memcpy(buf, vstart, (size_t)n);
        buf[n] = '\0';
        *out_ptr = buf;
        if (out_len) *out_len = n;
    }
    return 1;
}

/* Reply to the peer that sent us an offer-patch, so `gut offer --patch`
 * can surface the outcome synchronously. status is "offer-accepted" or
 * "offer-rejected"; reason is optional. */
static void offer_reply(u64 peer_id, const char *status,
                        const char *target_hex, const char *reason) {
    char msg[512];
    int n;
    if (reason) {
        n = snprintf(msg, sizeof(msg),
            "{\"op\":\"%s\",\"target_oid\":\"%s\",\"reason\":\"%s\"}",
            status, target_hex ? target_hex : "", reason);
    } else {
        n = snprintf(msg, sizeof(msg),
            "{\"op\":\"%s\",\"target_oid\":\"%s\"}",
            status, target_hex ? target_hex : "");
    }
    leech_listen_reply(peer_id, msg, (u64)n);
}

static void op_handle_offer_patch(u64 peer_id, const char *json) {
    char path[512];
    char target_hex[GUT_OID_HEX_SIZE + 1];
    char base_hex_buf[GUT_OID_HEX_SIZE + 1];
    char from[128];
    char *b64_copy = NULL;
    u64 b64_len = 0;
    buf decoded;
    gut_oid computed_oid;
    char computed_hex[GUT_OID_HEX_SIZE + 1];

    if (!g_op_repo) {
        printf("[peer #%llu] offer-patch received but no repo bound — dropping\n",
               (unsigned long long)peer_id);
        offer_reply(peer_id, "offer-rejected", NULL, "no repo bound");
        return;
    }

    if (!op_json_str(path, sizeof(path), json, "path") ||
        !op_json_str(target_hex, sizeof(target_hex), json, "target_oid")) {
        printf("[peer #%llu] malformed offer-patch: %s\n",
               (unsigned long long)peer_id, json);
        offer_reply(peer_id, "offer-rejected", NULL, "malformed");
        return;
    }
    op_json_str(base_hex_buf, sizeof(base_hex_buf), json, "base_oid");
    op_json_str(from, sizeof(from), json, "from");

    /* Tie-break: scan .git/offers-sent/ for a live outgoing record with
     * the same path. "Live" = written in the last 60s. Stale records
     * (older than 60s) are pruned during the scan. On collision:
     * lex-smaller `as` vs incoming `from` wins. */
#define GUT_TIEBREAK_WINDOW 60
    {
        char sent_dir[2048];
        DIR *sd;
        struct dirent *sde;
        char winning_side = 0; /* 'u' = us, 't' = them, 0 = no collision */
        char our_as[64] = {0};
        char colliding_file[2048] = {0};
        time_t now_ts = time(NULL);

        snprintf(sent_dir, sizeof(sent_dir), "%s/offers-sent",
                 g_op_repo->git_dir);
        sd = opendir(sent_dir);
        if (sd) {
            while ((sde = readdir(sd)) != NULL) {
                char rec_path[2048];
                struct stat rec_st;
                FILE *rf;
                char buf[1024];
                size_t n;
                char rec_path_field[512];
                char rec_as[64];
                if (sde->d_name[0] == '.') continue;
                snprintf(rec_path, sizeof(rec_path), "%s/%s", sent_dir, sde->d_name);
                if (stat(rec_path, &rec_st) != 0) continue;
                if ((long)(now_ts - rec_st.st_mtime) > GUT_TIEBREAK_WINDOW) {
                    /* Stale — prune and keep scanning. */
                    remove(rec_path);
                    continue;
                }
                rf = fopen(rec_path, "r");
                if (!rf) continue;
                n = fread(buf, 1, sizeof(buf) - 1, rf);
                fclose(rf);
                buf[n] = 0;
                if (!op_json_str(rec_path_field, sizeof(rec_path_field),
                                 buf, "path")) continue;
                if (strcmp(rec_path_field, path) != 0) continue;
                op_json_str(rec_as, sizeof(rec_as), buf, "as");
                if (winning_side) continue; /* keep pruning stale after first hit */
                snprintf(colliding_file, sizeof(colliding_file), "%s", rec_path);
                snprintf(our_as, sizeof(our_as), "%s", rec_as);
                if (strcmp(rec_as, from) < 0) {
                    winning_side = 'u';
                } else {
                    winning_side = 't';
                }
            }
            closedir(sd);
        }

        if (winning_side == 'u') {
            char reason[160];
            snprintf(reason, sizeof(reason),
                     "tie-break: our name '%s' wins over '%s'", our_as, from);
            printf("[peer #%llu] collision on %s — we win (lex %s < %s)\n",
                   (unsigned long long)peer_id, path, our_as, from);
            fflush(stdout);
            offer_reply(peer_id, "offer-rejected", target_hex, reason);
            return;
        }
        if (winning_side == 't') {
            printf("[peer #%llu] collision on %s — they win (lex %s < %s), "
                   "dropping our outgoing record\n",
                   (unsigned long long)peer_id, path, from, our_as);
            fflush(stdout);
            remove(colliding_file);
            /* Fall through and accept the incoming offer normally */
        }
    }

    if (!op_json_str_alloc(&b64_copy, &b64_len, json, "content_b64")) {
        printf("[peer #%llu] offer-patch missing content_b64\n",
               (unsigned long long)peer_id);
        offer_reply(peer_id, "offer-rejected", target_hex, "missing content_b64");
        return;
    }

    if (b64_len > 0) {
        /* Inline payload — decode and write blob to ODB */
        if (buf_create(&decoded, b64_len + 16) != 0 ||
            base64_decode(&decoded, (u8 *)b64_copy, b64_len) != 0) {
            printf("[peer #%llu] offer-patch base64 decode failed\n",
                   (unsigned long long)peer_id);
            free(b64_copy);
            offer_reply(peer_id, "offer-rejected", target_hex, "base64 decode failed");
            return;
        }
        free(b64_copy);

        if (odb_write(&computed_oid, &g_op_repo->odb, GUT_OBJ_BLOB,
                      decoded.data, decoded.len) != 0) {
            printf("[peer #%llu] offer-patch: odb_write failed\n",
                   (unsigned long long)peer_id);
            buf_destroy(&decoded);
            offer_reply(peer_id, "offer-rejected", target_hex, "odb_write failed");
            return;
        }
        buf_destroy(&decoded);

        oid_to_hex(computed_hex, &computed_oid);
        if (strcmp(computed_hex, target_hex) != 0) {
            printf("[peer #%llu] offer-patch: target_oid mismatch "
                   "(claimed %s, computed %s) — ignoring\n",
                   (unsigned long long)peer_id, target_hex, computed_hex);
            offer_reply(peer_id, "offer-rejected", target_hex, "target_oid mismatch");
            return;
        }
    } else {
        /* No inline content — need fetch_url to pull the blob. */
        char fetch_url[512];
        free(b64_copy);
        if (!op_json_str(fetch_url, sizeof(fetch_url), json, "fetch_url") ||
            fetch_url[0] == 0) {
            printf("[peer #%llu] offer-patch: no content and no fetch_url — "
                   "dropping\n", (unsigned long long)peer_id);
            offer_reply(peer_id, "offer-rejected", target_hex,
                        "no content and no fetch_url");
            return;
        }
        {
            char synth_ref[128];
            snprintf(synth_ref, sizeof(synth_ref), "offer-%.8s", target_hex);
            if (leech_fetch(g_op_repo, fetch_url,
                            from[0] ? from : "peer",
                            target_hex, synth_ref) != 0) {
                printf("[peer #%llu] offer-patch: fetch from %s failed\n",
                       (unsigned long long)peer_id, fetch_url);
                offer_reply(peer_id, "offer-rejected", target_hex, "fetch failed");
                return;
            }
        }
        if (oid_from_hex(&computed_oid, target_hex) != 0) {
            offer_reply(peer_id, "offer-rejected", target_hex, "bad target_oid");
            return;
        }
        {
            unsigned long found = 0;
            if (odb_exists(&found, &g_op_repo->odb, &computed_oid) != 0 || !found) {
                printf("[peer #%llu] offer-patch: fetched but target %s "
                       "not in ODB\n", (unsigned long long)peer_id, target_hex);
                offer_reply(peer_id, "offer-rejected", target_hex,
                            "fetched but missing");
                return;
            }
        }
    }

    /* Write offer record to .git/offers/<timestamp>-<from>-<target8>.json.
     * Store the bare facts — the blob itself now lives in ODB. */
    {
        char offers_dir[2048];
        char offer_path[2048];
        char id[128];
        time_t now = time(NULL);
        FILE *ofp;

        snprintf(offers_dir, sizeof(offers_dir), "%s/offers", g_op_repo->git_dir);
#ifdef _WIN32
        _mkdir(offers_dir);
#else
        mkdir(offers_dir, 0755);
#endif

        snprintf(id, sizeof(id), "%ld-%s-%.8s",
                 (long)now, from[0] ? from : "peer", target_hex);
        snprintf(offer_path, sizeof(offer_path), "%s/%s.json", offers_dir, id);

        ofp = fopen(offer_path, "w");
        if (ofp) {
            fprintf(ofp,
                    "{\"id\":\"%s\",\"path\":\"%s\","
                    "\"base_oid\":\"%s\",\"target_oid\":\"%s\","
                    "\"from\":\"%s\",\"received_at\":%ld}\n",
                    id, path, base_hex_buf, target_hex,
                    from[0] ? from : "peer", (long)now);
            fclose(ofp);
            printf("[peer #%llu] offer-patch stored: %s for %s (from %s)\n"
                   "    run `gut offers` to review\n",
                   (unsigned long long)peer_id, id, path,
                   from[0] ? from : "peer");
            fflush(stdout);
            offer_reply(peer_id, "offer-accepted", target_hex, NULL);
        } else {
            printf("[peer #%llu] offer-patch: cannot write %s\n",
                   (unsigned long long)peer_id, offer_path);
            offer_reply(peer_id, "offer-rejected", target_hex,
                        "cannot write offer record");
        }
    }
}

static void op_handle_offer_patch(u64 peer_id, const char *json);

static void on_peer_op(u64 peer_id, const char *text, u64 len) {
    char *json_copy;
    char op[32];

    /* Heap-allocate — offer-patch can carry inline base64 up to ~700 KB. */
    json_copy = (char *)malloc((size_t)len + 1);
    if (!json_copy) return;
    memcpy(json_copy, text, (size_t)len);
    json_copy[len] = '\0';

    if (!op_json_str(op, sizeof(op), json_copy, "op")) {
        printf("[peer #%llu] %s\n", (unsigned long long)peer_id, json_copy);
        fflush(stdout);
        free(json_copy);
        return;
    }
    if      (strcmp(op, "ask")         == 0) op_handle_ask(peer_id, json_copy);
    else if (strcmp(op, "offer")       == 0) op_handle_offer(peer_id, json_copy);
    else if (strcmp(op, "offer-patch") == 0) op_handle_offer_patch(peer_id, json_copy);
    else if (strcmp(op, "sos")         == 0) op_handle_sos(peer_id, json_copy);
    else {
        printf("[peer #%llu] unknown op '%s': %s\n",
               (unsigned long long)peer_id, op, json_copy);
        fflush(stdout);
    }
    free(json_copy);
}

/* ---- I/O abstraction: plain TCP or TLS ---- */
typedef struct {
    tcp_conn  tcp;
    tls_conn *tls;   /* non-NULL if TLS is in use */
} srv_io;

static unsigned long srv_read(srv_io *io, u8 *out, u64 cap, u64 *n_out) {
    if (io->tls) return tls_conn_read(n_out, io->tls, out, cap);
    return tcp_conn_read(n_out, &io->tcp, out, cap);
}

static unsigned long srv_write_all(srv_io *io, const u8 *data, u64 len) {
    u64 n;
    if (io->tls) return tls_conn_write_all(&n, io->tls, data, len);
    return tcp_conn_write_all(&n, &io->tcp, data, len);
}

static void srv_io_close(srv_io *io) {
    if (io->tls) {
        tls_conn_shutdown(io->tls);
        tls_conn_destroy(io->tls);
        io->tls = NULL;
    }
    tcp_conn_destroy(&io->tcp);
}

/* ---- gut server (clone-only MVP) ----
 * Serves a single gut/git repository over smart HTTP so real `git clone
 * http://host:port/` works. Endpoints:
 *   GET  /info/refs?service=git-upload-pack  — advertise refs
 *   POST /git-upload-pack                    — respond to want list with pack
 *
 * No auth, no TLS, no push, no multi-repo. One request per connection,
 * close after. Intended for trusted local networks and CI fetches. */

static void srv_pkt_write(buf *out, const char *line) {
    char hdr[8];
    size_t len = strlen(line);
    size_t plen = len + 4 + 1; /* +1 for trailing \n */
    snprintf(hdr, sizeof(hdr), "%04zx", plen);
    buf_append(out, (u8 *)hdr, 4);
    buf_append(out, (u8 *)line, (u64)len);
    buf_append_byte(out, '\n');
}
static void srv_pkt_flush(buf *out) {
    buf_append(out, (u8 *)"0000", 4);
}

static void srv_send_status(srv_io *io, int code, const char *msg) {
    char header[256];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        code, msg);
    srv_write_all(io, (const u8 *)header, (u64)n);
}

static void srv_send_body(srv_io *io, const char *ctype,
                          const u8 *body, u64 body_len) {
    char header[512];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        "\r\n",
        ctype, (unsigned long long)body_len);
    srv_write_all(io, (const u8 *)header, (u64)n);
    if (body_len > 0) srv_write_all(io, body, body_len);
}

/* Walk refs/heads/* and refs/tags/* — emit (oid, refname) pairs into `out`. */
typedef struct { gut_oid oid; char name[256]; } srv_ref;
static void srv_collect_refs(srv_ref **out, u64 *count, gut_repo *repo,
                             const char *subdir, const char *prefix) {
    char dir[2048];
    DIR *d;
    struct dirent *de;
    unsigned hex_len = gut_oid_hex_size(repo->hash_algo);
    snprintf(dir, sizeof(dir), "%s/refs/%s", repo->git_dir, subdir);
    d = opendir(dir);
    if (!d) return;
    while ((de = readdir(d)) != NULL) {
        char path[2048];
        FILE *fp;
        char hex[GUT_OID_MAX_HEX_SIZE + 2];
        gut_oid oid;
        if (de->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        fp = fopen(path, "r");
        if (!fp) continue;
        if (fgets(hex, sizeof(hex), fp)) {
            size_t L = strlen(hex);
            while (L > 0 && (hex[L-1] == '\n' || hex[L-1] == '\r' ||
                             hex[L-1] == ' ')) hex[--L] = 0;
            if (L == hex_len && oid_from_hex_n(&oid, hex, hex_len) == 0) {
                *out = (srv_ref *)realloc(*out, (*count + 1) * sizeof(srv_ref));
                if (*out) {
                    (*out)[*count].oid = oid;
                    snprintf((*out)[*count].name, sizeof((*out)[*count].name),
                             "%s%s", prefix, de->d_name);
                    (*count)++;
                }
            }
        }
        fclose(fp);
    }
    closedir(d);
}

/* Closure walk: for each want OID (a commit), collect itself + its tree
 * closure + all ancestor commits (and their trees). Linear list, linear
 * dedup — fine for MVP. */
typedef struct { gut_oid *ids; u64 n; u64 cap; } srv_oid_set;
static int srv_set_has(srv_oid_set *s, gut_oid *o) {
    u64 i;
    for (i = 0; i < s->n; i++) {
        long c;
        oid_compare(&c, &s->ids[i], o);
        if (c == 0) return 1;
    }
    return 0;
}
static void srv_set_add(srv_oid_set *s, gut_oid *o) {
    if (srv_set_has(s, o)) return;
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 64;
        s->ids = (gut_oid *)realloc(s->ids, s->cap * sizeof(gut_oid));
    }
    if (s->ids) s->ids[s->n++] = *o;
}
static void srv_walk_tree(srv_oid_set *out, gut_odb *odb, gut_oid *tree_oid) {
    gut_object obj;
    gut_tree t;
    u64 i;
    if (srv_set_has(out, tree_oid)) return;
    srv_set_add(out, tree_oid);
    if (odb_read(&obj, odb, tree_oid) != 0) return;
    if (tree_parse_algo(&t, obj.data.data, obj.data.len, odb->hash_algo) != 0) {
        object_destroy(&obj); return;
    }
    object_destroy(&obj);
    for (i = 0; i < t.count; i++) {
        if (t.entries[i].mode & 040000) {
            srv_walk_tree(out, odb, &t.entries[i].oid);
        } else {
            srv_set_add(out, &t.entries[i].oid);
        }
    }
    tree_destroy(&t);
}
static unsigned long srv_closure(srv_oid_set *out, gut_odb *odb, gut_oid *start) {
    gut_oid *queue = NULL;
    u64 qn = 0, qcap = 0, qhead = 0;

    queue = (gut_oid *)malloc(sizeof(gut_oid));
    if (!queue) return __LINE__;
    queue[qn++] = *start;
    qcap = 1;

    while (qhead < qn) {
        gut_oid cur = queue[qhead++];
        gut_object obj;
        gut_commit c;
        u64 i;
        if (srv_set_has(out, &cur)) continue;
        srv_set_add(out, &cur);
        if (odb_read(&obj, odb, &cur) != 0) continue;
        if (obj.type != GUT_OBJ_COMMIT) { object_destroy(&obj); continue; }
        if (commit_parse(&c, obj.data.data, obj.data.len) != 0) {
            object_destroy(&obj); continue;
        }
        object_destroy(&obj);
        srv_walk_tree(out, odb, &c.tree_oid);
        for (i = 0; i < c.parent_count; i++) {
            if (qn == qcap) {
                qcap = qcap ? qcap * 2 : 64;
                queue = (gut_oid *)realloc(queue, qcap * sizeof(gut_oid));
                if (!queue) { commit_destroy(&c); return __LINE__; }
            }
            queue[qn++] = c.parent_oids[i];
        }
        commit_destroy(&c);
    }
    free(queue);
    return 0;
}

static int srv_handle_info_refs(srv_io *io, gut_repo *repo,
                                const char *service) {
    buf body;
    srv_ref *refs = NULL;
    u64 count = 0;
    u64 i;
    gut_oid head_oid;
    char head_target[256];
    int have_head = 0;
    int emitted_first = 0;
    int is_push = (strcmp(service, "git-receive-pack") == 0);
    char service_line[64];
    char content_type[64];
    unsigned hex_len = gut_oid_hex_size(repo->hash_algo);
    const char *obj_fmt_cap =
        (repo->hash_algo == GUT_HASH_SHA256) ? " object-format=sha256" : "";

    if (repo_head_ref(head_target, sizeof(head_target), repo) == 0 &&
        repo_resolve_ref(&head_oid, repo, head_target) == 0) {
        have_head = 1;
    }

    srv_collect_refs(&refs, &count, repo, "heads", "refs/heads/");
    srv_collect_refs(&refs, &count, repo, "tags",  "refs/tags/");

    if (buf_create(&body, 4096) != 0) {
        srv_send_status(io, 500, "Internal Error");
        free(refs); return 0;
    }

    snprintf(service_line, sizeof(service_line), "# service=%s", service);
    srv_pkt_write(&body, service_line);
    srv_pkt_flush(&body);

    /* Empty-repo edge case: send zero-id capability advertisement
     * (required by the receive-pack protocol so client can push the
     * first ref). */
    if (count == 0 && !have_head && is_push) {
        char caps[128];
        char line[256];
        u64 pktlen;
        char hdr[8];
        int n;
        unsigned zi;
        snprintf(caps, sizeof(caps), "report-status ofs-delta%s", obj_fmt_cap);
        /* hex_len zero chars */
        n = 0;
        for (zi = 0; zi < hex_len; zi++) line[n++] = '0';
        n += snprintf(line + n, sizeof(line) - n, " capabilities^{}");
        pktlen = (u64)n + 1 + strlen(caps) + 1 + 4;
        snprintf(hdr, sizeof(hdr), "%04llx", (unsigned long long)pktlen);
        buf_append(&body, (u8 *)hdr, 4);
        buf_append(&body, (u8 *)line, (u64)n);
        buf_append_byte(&body, 0);
        buf_append(&body, (u8 *)caps, strlen(caps));
        buf_append_byte(&body, '\n');
        emitted_first = 1;
    }

    /* HEAD first (fetch path only — receive-pack doesn't advertise HEAD) */
    if (have_head && !is_push) {
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        char line[512];
        char caps_buf[512];
        u64 pktlen;
        char hdr[8];
        int n;
        oid_to_hex_n(hex, &head_oid, hex_len);
        n = snprintf(line, sizeof(line), "%s HEAD", hex);
        snprintf(caps_buf, sizeof(caps_buf),
                 "multi_ack_detailed side-band-64k ofs-delta shallow%s "
                 "symref=HEAD:%s", obj_fmt_cap, head_target);
        pktlen = (u64)n + 1 + strlen(caps_buf) + 1 + 4;
        snprintf(hdr, sizeof(hdr), "%04llx", (unsigned long long)pktlen);
        buf_append(&body, (u8 *)hdr, 4);
        buf_append(&body, (u8 *)line, (u64)n);
        buf_append_byte(&body, 0);
        buf_append(&body, (u8 *)caps_buf, strlen(caps_buf));
        buf_append_byte(&body, '\n');
        emitted_first = 1;
    }

    for (i = 0; i < count; i++) {
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        char line[512];
        oid_to_hex_n(hex, &refs[i].oid, hex_len);
        if (!emitted_first) {
            u64 pktlen;
            char hdr[8];
            char caps[256];
            snprintf(caps, sizeof(caps), "%s%s",
                     is_push
                         ? "report-status ofs-delta"
                         : "multi_ack_detailed side-band-64k ofs-delta shallow",
                     obj_fmt_cap);
            int n = snprintf(line, sizeof(line), "%s %s", hex, refs[i].name);
            pktlen = (u64)n + 1 + strlen(caps) + 1 + 4;
            snprintf(hdr, sizeof(hdr), "%04llx", (unsigned long long)pktlen);
            buf_append(&body, (u8 *)hdr, 4);
            buf_append(&body, (u8 *)line, (u64)n);
            buf_append_byte(&body, 0);
            buf_append(&body, (u8 *)caps, strlen(caps));
            buf_append_byte(&body, '\n');
            emitted_first = 1;
        } else {
            snprintf(line, sizeof(line), "%s %s", hex, refs[i].name);
            srv_pkt_write(&body, line);
        }
    }
    srv_pkt_flush(&body);

    snprintf(content_type, sizeof(content_type),
             "application/x-%s-advertisement", service);
    srv_send_body(io, content_type, body.data, body.len);
    buf_destroy(&body);
    free(refs);
    return 0;
}

/* ---- Receive-pack (push) handler ---- */

typedef struct {
    gut_oid old_oid;
    gut_oid new_oid;
    char    name[256];
    int     ok;                 /* 1 if applied, 0 if rejected */
    char    reason[128];
} srv_ref_update;

static int srv_handle_receive_pack(srv_io *io, gut_repo *repo,
                                   const u8 *body, u64 body_len) {
    srv_ref_update *updates = NULL;
    u64 n_updates = 0;
    u64 p = 0;
    u64 flush_after = 0;
    int seen_flush = 0;
    buf response;
    int pack_ok = 1;
    u64 i;
    unsigned hex_len = gut_oid_hex_size(repo->hash_algo);

    /* Parse command list (pkt-lines) up to the flush packet. Each line:
     *   <old-hex> SP <new-hex> SP <ref-name>[\0capabilities]\n  */
    while (p + 4 <= body_len) {
        u32 plen;
        char hdr[5];
        memcpy(hdr, body + p, 4); hdr[4] = 0;
        plen = (u32)strtoul(hdr, NULL, 16);
        if (plen == 0) {
            flush_after = p + 4;
            seen_flush = 1;
            break;
        }
        if (plen < 4 || p + plen > body_len) break;
        {
            const char *line = (const char *)(body + p + 4);
            u64 llen = plen - 4;
            /* Strip trailing LF and any \0-separated caps tail */
            while (llen > 0 && (line[llen - 1] == '\n' || line[llen - 1] == '\r'))
                llen--;
            {
                u64 k;
                for (k = 0; k < llen; k++) {
                    if (line[k] == 0) { llen = k; break; }
                }
            }
            if (llen >= (u64)hex_len * 2 + 2 + 1) {
                srv_ref_update u;
                char old_hex[GUT_OID_MAX_HEX_SIZE + 1];
                char new_hex[GUT_OID_MAX_HEX_SIZE + 1];
                u64 ref_off = (u64)hex_len + 1 + (u64)hex_len + 1;
                memset(&u, 0, sizeof(u));
                memcpy(old_hex, line, hex_len);
                old_hex[hex_len] = 0;
                memcpy(new_hex, line + hex_len + 1, hex_len);
                new_hex[hex_len] = 0;
                if (oid_from_hex_n(&u.old_oid, old_hex, hex_len) == 0 &&
                    oid_from_hex_n(&u.new_oid, new_hex, hex_len) == 0 &&
                    llen > ref_off && llen - ref_off < sizeof(u.name)) {
                    memcpy(u.name, line + ref_off, llen - ref_off);
                    u.name[llen - ref_off] = 0;
                    updates = (srv_ref_update *)realloc(updates,
                        (n_updates + 1) * sizeof(srv_ref_update));
                    if (updates) updates[n_updates++] = u;
                }
            }
        }
        p += plen;
    }

    if (!seen_flush || n_updates == 0) {
        free(updates);
        srv_send_status(io, 400, "Bad Request");
        return 0;
    }

    /* Remaining bytes after the flush are the packfile (if any update
     * creates or changes a non-zero OID). Deletes alone carry no pack. */
    {
        int needs_pack = 0;
        gut_oid zero; memset(&zero, 0, sizeof(zero));
        for (i = 0; i < n_updates; i++) {
            long c;
            oid_compare(&c, &updates[i].new_oid, &zero);
            if (c != 0) { needs_pack = 1; break; }
        }

        if (needs_pack) {
            u64 pack_len = body_len - flush_after;
            if (pack_len < 32 ||
                body[flush_after] != 'P' || body[flush_after+1] != 'A' ||
                body[flush_after+2] != 'C' || body[flush_after+3] != 'K') {
                pack_ok = 0;
            } else {
                /* Write pack to .git/objects/pack, then index it */
                char pack_dir[2048];
                char pack_path[2048];
                long ts;
                FILE *fp;

                snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack",
                         repo->git_dir);
#ifdef _WIN32
                _mkdir(pack_dir);
#else
                mkdir(pack_dir, 0755);
#endif
                ts = (long)time(NULL);
                snprintf(pack_path, sizeof(pack_path),
                         "%s/gut-receive-%ld.pack", pack_dir, ts);
                fp = fopen(pack_path, "wb");
                if (!fp) {
                    pack_ok = 0;
                } else {
                    fwrite(body + flush_after, 1, (size_t)pack_len, fp);
                    fclose(fp);
                    if (pack_index_create_algo(pack_path, NULL,
                                               repo->hash_algo) != 0)
                        pack_ok = 0;
                }
            }
        }
    }

    /* Validate + apply each ref update */
    for (i = 0; i < n_updates; i++) {
        srv_ref_update *u = &updates[i];
        gut_oid current;
        gut_oid zero; memset(&zero, 0, sizeof(zero));
        int has_current = (repo_resolve_ref(&current, repo, u->name) == 0);
        long c_old_zero, c_new_zero;
        oid_compare(&c_old_zero, &u->old_oid, &zero);
        oid_compare(&c_new_zero, &u->new_oid, &zero);

        if (!pack_ok && c_new_zero != 0) {
            u->ok = 0;
            snprintf(u->reason, sizeof(u->reason), "pack invalid");
            continue;
        }

        /* old == 0: create. old != 0: fast-forward check (strict: exact match). */
        if (c_old_zero == 0) {
            if (has_current) {
                u->ok = 0;
                snprintf(u->reason, sizeof(u->reason), "ref exists");
                continue;
            }
        } else {
            long c_cur_old;
            if (!has_current) {
                u->ok = 0;
                snprintf(u->reason, sizeof(u->reason), "no such ref");
                continue;
            }
            oid_compare(&c_cur_old, &current, &u->old_oid);
            if (c_cur_old != 0) {
                u->ok = 0;
                snprintf(u->reason, sizeof(u->reason), "not fast-forward");
                continue;
            }
        }

        if (c_new_zero == 0) {
            /* Delete */
            char ref_file[2048];
            snprintf(ref_file, sizeof(ref_file), "%s/%s", repo->git_dir, u->name);
            if (remove(ref_file) == 0) {
                u->ok = 1;
            } else {
                u->ok = 0;
                snprintf(u->reason, sizeof(u->reason), "delete failed");
            }
        } else {
            if (repo_update_ref(repo, u->name, &u->new_oid, "push") == 0) {
                u->ok = 1;
            } else {
                u->ok = 0;
                snprintf(u->reason, sizeof(u->reason), "update failed");
            }
        }
    }

    /* Build report-status response */
    if (buf_create(&response, 1024) != 0) {
        free(updates);
        srv_send_status(io, 500, "OOM");
        return 0;
    }
    srv_pkt_write(&response, pack_ok ? "unpack ok" : "unpack pack invalid");
    for (i = 0; i < n_updates; i++) {
        char line[384];
        if (updates[i].ok) {
            snprintf(line, sizeof(line), "ok %s", updates[i].name);
        } else {
            snprintf(line, sizeof(line), "ng %s %s",
                     updates[i].name, updates[i].reason);
        }
        srv_pkt_write(&response, line);
    }
    srv_pkt_flush(&response);

    srv_send_body(io, "application/x-git-receive-pack-result",
                  response.data, response.len);
    buf_destroy(&response);
    free(updates);
    return 0;
}

static int srv_handle_upload_pack(srv_io *io, gut_repo *repo,
                                  const u8 *req_body, u64 req_len) {
    srv_oid_set wants;
    srv_oid_set closure;
    u64 p = 0;
    char tmp_pack_dir[2048];
    char tmp_pack_path[2048];
    char pack_hex[GUT_OID_MAX_HEX_SIZE + 1];
    u8 *pack_data = NULL;
    long pack_sz = 0;
    FILE *pf;
    buf resp;
    unsigned hex_len = gut_oid_hex_size(repo->hash_algo);

    memset(&wants,   0, sizeof(wants));
    memset(&closure, 0, sizeof(closure));

    /* Parse pkt-lines to find "want <oid>" entries. */
    while (p + 4 <= req_len) {
        u32 plen;
        char hdr[5];
        memcpy(hdr, req_body + p, 4); hdr[4] = 0;
        plen = (u32)strtoul(hdr, NULL, 16);
        if (plen == 0) { p += 4; continue; }
        if (plen < 4 || p + plen > req_len) break;
        {
            const char *payload = (const char *)(req_body + p + 4);
            u64 plen_body = plen - 4;
            if (plen_body >= 5 + hex_len &&
                memcmp(payload, "want ", 5) == 0) {
                gut_oid w;
                char hex[GUT_OID_MAX_HEX_SIZE + 1];
                memcpy(hex, payload + 5, hex_len);
                hex[hex_len] = 0;
                if (oid_from_hex_n(&w, hex, hex_len) == 0) srv_set_add(&wants, &w);
            }
        }
        p += plen;
    }

    if (wants.n == 0) {
        free(wants.ids);
        srv_send_status(io, 400, "Bad Request");
        return 0;
    }

    /* Compute closure (commits + trees + blobs reachable from wants) */
    {
        u64 i;
        for (i = 0; i < wants.n; i++) srv_closure(&closure, &repo->odb, &wants.ids[i]);
    }
    free(wants.ids);

    if (closure.n == 0) {
        srv_send_status(io, 500, "No Objects");
        return 0;
    }

    /* Write a temp pack */
    snprintf(tmp_pack_dir, sizeof(tmp_pack_dir), "%s/objects/pack", repo->git_dir);
    if (pack_write(pack_hex, tmp_pack_dir, &repo->odb,
                   closure.ids, closure.n) != 0) {
        free(closure.ids);
        srv_send_status(io, 500, "Pack Build Failed");
        return 0;
    }
    free(closure.ids);

    snprintf(tmp_pack_path, sizeof(tmp_pack_path),
             "%s/pack-%s.pack", tmp_pack_dir, pack_hex);
    pf = fopen(tmp_pack_path, "rb");
    if (!pf) { srv_send_status(io, 500, "Pack Read Failed"); return 0; }
    fseek(pf, 0, SEEK_END);
    pack_sz = ftell(pf);
    fseek(pf, 0, SEEK_SET);
    pack_data = (u8 *)malloc((size_t)pack_sz);
    if (!pack_data) { fclose(pf); srv_send_status(io, 500, "OOM"); return 0; }
    fread(pack_data, 1, (size_t)pack_sz, pf);
    fclose(pf);

    /* Build response: NAK pkt-line + sideband-wrapped pack (band 1, chunks) */
    if (buf_create(&resp, (u64)pack_sz + 4096) != 0) {
        free(pack_data); srv_send_status(io, 500, "OOM"); return 0;
    }
    srv_pkt_write(&resp, "NAK");
    {
        u64 off = 0;
        while (off < (u64)pack_sz) {
            u64 chunk = (u64)pack_sz - off;
            char hdr[8];
            u64 plen;
            if (chunk > 65515) chunk = 65515; /* sideband limit minus band byte + 4 hdr */
            plen = chunk + 1 /*band*/ + 4 /*hdr*/;
            snprintf(hdr, sizeof(hdr), "%04llx", (unsigned long long)plen);
            buf_append(&resp, (u8 *)hdr, 4);
            buf_append_byte(&resp, 0x01); /* band 1 = pack data */
            buf_append(&resp, pack_data + off, chunk);
            off += chunk;
        }
    }
    srv_pkt_flush(&resp);
    free(pack_data);

    srv_send_body(io, "application/x-git-upload-pack-result",
                  resp.data, resp.len);
    buf_destroy(&resp);
    return 0;
}

/* ================================================================
 *  REST browse API
 * ================================================================
 *
 *   GET /repos                  — JSON array of repo names served
 *   GET /commits/<oid>          — commit as JSON (single-repo mode)
 *   GET /<repo>/commits/<oid>   — commit as JSON (multi-repo mode)
 *   GET /tree/<oid>             — tree entries (single-repo mode)
 *   GET /<repo>/tree/<oid>      — tree entries (multi-repo mode)
 *
 * Responses are application/json. No pagination or filtering — these
 * endpoints exist for quick browsing and tooling, not as a general
 * hosting API. */

static void srv_json_escape_str(buf *out, const char *s) {
    buf_append_byte(out, '"');
    for (; s && *s; s++) {
        u8 c = (u8)*s;
        if (c == '"' || c == '\\') {
            buf_append_byte(out, '\\');
            buf_append_byte(out, c);
        } else if (c == '\n') {
            buf_append_byte(out, '\\'); buf_append_byte(out, 'n');
        } else if (c == '\r') {
            buf_append_byte(out, '\\'); buf_append_byte(out, 'r');
        } else if (c == '\t') {
            buf_append_byte(out, '\\'); buf_append_byte(out, 't');
        } else if (c < 0x20) {
            char esc[8];
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            buf_append(out, (u8 *)esc, 6);
        } else {
            buf_append_byte(out, c);
        }
    }
    buf_append_byte(out, '"');
}

static int srv_handle_repos_list(srv_io *io, int single_mode,
                                 const char *single_repo_path,
                                 const char *root_path) {
    buf body;
    if (buf_create(&body, 512) != 0) {
        srv_send_status(io, 500, "Internal Error");
        return 0;
    }
    buf_append_byte(&body, '[');

    if (single_mode) {
        const char *name = single_repo_path;
        const char *slash = strrchr(single_repo_path, '/');
        const char *bs    = strrchr(single_repo_path, '\\');
        if (bs && (!slash || bs > slash)) slash = bs;
        if (slash) name = slash + 1;
        srv_json_escape_str(&body, name);
    } else {
        DIR *d = opendir(root_path);
        int first = 1;
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                char candidate[2048];
                struct stat st;
                if (de->d_name[0] == '.') continue;
                snprintf(candidate, sizeof(candidate), "%s/%s/.git",
                         root_path, de->d_name);
                if (stat(candidate, &st) != 0) continue;
                if (!first) buf_append_byte(&body, ',');
                srv_json_escape_str(&body, de->d_name);
                first = 0;
            }
            closedir(d);
        }
    }
    buf_append_byte(&body, ']');
    srv_send_body(io, "application/json", body.data, body.len);
    buf_destroy(&body);
    return 0;
}

static int srv_handle_rest_commit(srv_io *io, gut_repo *repo,
                                  const char *oid_hex) {
    gut_oid oid;
    gut_object obj;
    gut_commit commit;
    buf body;
    unsigned hex_len = gut_oid_hex_size(repo->hash_algo);
    char oid_hex_buf[GUT_OID_MAX_HEX_SIZE + 1];
    u64 len;
    u64 i;

    len = strlen(oid_hex);
    if (len == hex_len) {
        if (oid_from_hex_n(&oid, oid_hex, hex_len) != 0) {
            srv_send_status(io, 400, "Bad OID"); return 0;
        }
    } else if (len >= 4 && len < hex_len) {
        if (odb_resolve_prefix(&oid, &repo->odb, oid_hex) != 0) {
            srv_send_status(io, 404, "OID Not Found"); return 0;
        }
    } else {
        srv_send_status(io, 400, "Bad OID"); return 0;
    }

    if (odb_read(&obj, &repo->odb, &oid) != 0) {
        srv_send_status(io, 404, "Object Not Found"); return 0;
    }
    if (obj.type != GUT_OBJ_COMMIT) {
        object_destroy(&obj);
        srv_send_status(io, 400, "Not a Commit"); return 0;
    }
    if (commit_parse(&commit, obj.data.data, obj.data.len) != 0) {
        object_destroy(&obj);
        srv_send_status(io, 500, "Parse Error"); return 0;
    }
    object_destroy(&obj);

    if (buf_create(&body, 1024) != 0) {
        commit_destroy(&commit);
        srv_send_status(io, 500, "Internal Error"); return 0;
    }

    buf_append(&body, (u8 *)"{\"oid\":", 7);
    oid_to_hex_n(oid_hex_buf, &oid, hex_len);
    srv_json_escape_str(&body, oid_hex_buf);

    buf_append(&body, (u8 *)",\"tree\":", 8);
    oid_to_hex_n(oid_hex_buf, &commit.tree_oid, hex_len);
    srv_json_escape_str(&body, oid_hex_buf);

    buf_append(&body, (u8 *)",\"parents\":[", 12);
    for (i = 0; i < commit.parent_count; i++) {
        if (i) buf_append_byte(&body, ',');
        oid_to_hex_n(oid_hex_buf, &commit.parent_oids[i], hex_len);
        srv_json_escape_str(&body, oid_hex_buf);
    }
    buf_append_byte(&body, ']');

    if (commit.author) {
        buf_append(&body, (u8 *)",\"author\":", 10);
        srv_json_escape_str(&body, commit.author);
    }
    if (commit.committer) {
        buf_append(&body, (u8 *)",\"committer\":", 13);
        srv_json_escape_str(&body, commit.committer);
    }
    if (commit.message) {
        buf_append(&body, (u8 *)",\"message\":", 11);
        srv_json_escape_str(&body, commit.message);
    }
    buf_append_byte(&body, '}');

    srv_send_body(io, "application/json", body.data, body.len);
    buf_destroy(&body);
    commit_destroy(&commit);
    return 0;
}

static int srv_handle_rest_tree(srv_io *io, gut_repo *repo,
                                const char *oid_hex) {
    gut_oid oid;
    gut_object obj;
    gut_tree tree;
    buf body;
    unsigned hex_len = gut_oid_hex_size(repo->hash_algo);
    char entry_hex[GUT_OID_MAX_HEX_SIZE + 1];
    u64 len;
    u64 i;

    len = strlen(oid_hex);
    if (len == hex_len) {
        if (oid_from_hex_n(&oid, oid_hex, hex_len) != 0) {
            srv_send_status(io, 400, "Bad OID"); return 0;
        }
    } else if (len >= 4 && len < hex_len) {
        if (odb_resolve_prefix(&oid, &repo->odb, oid_hex) != 0) {
            srv_send_status(io, 404, "OID Not Found"); return 0;
        }
    } else {
        srv_send_status(io, 400, "Bad OID"); return 0;
    }

    if (odb_read(&obj, &repo->odb, &oid) != 0) {
        srv_send_status(io, 404, "Object Not Found"); return 0;
    }
    if (obj.type != GUT_OBJ_TREE) {
        object_destroy(&obj);
        srv_send_status(io, 400, "Not a Tree"); return 0;
    }
    if (tree_parse_algo(&tree, obj.data.data, obj.data.len, repo->hash_algo) != 0) {
        object_destroy(&obj);
        srv_send_status(io, 500, "Parse Error"); return 0;
    }
    object_destroy(&obj);

    if (buf_create(&body, 1024) != 0) {
        tree_destroy(&tree);
        srv_send_status(io, 500, "Internal Error"); return 0;
    }

    buf_append_byte(&body, '[');
    for (i = 0; i < tree.count; i++) {
        char buf_chunk[64];
        const char *type;
        if (i) buf_append_byte(&body, ',');
        if      (tree.entries[i].mode == 040000)  type = "tree";
        else if (tree.entries[i].mode == 0160000) type = "submodule";
        else                                      type = "blob";

        buf_append(&body, (u8 *)"{\"mode\":", 8);
        snprintf(buf_chunk, sizeof(buf_chunk), "\"%06o\"",
                 tree.entries[i].mode);
        buf_append(&body, (u8 *)buf_chunk, strlen(buf_chunk));

        buf_append(&body, (u8 *)",\"type\":", 8);
        srv_json_escape_str(&body, type);

        buf_append(&body, (u8 *)",\"name\":", 8);
        srv_json_escape_str(&body, tree.entries[i].name);

        buf_append(&body, (u8 *)",\"oid\":", 7);
        oid_to_hex_n(entry_hex, &tree.entries[i].oid, hex_len);
        srv_json_escape_str(&body, entry_hex);

        buf_append_byte(&body, '}');
    }
    buf_append_byte(&body, ']');

    srv_send_body(io, "application/json", body.data, body.len);
    buf_destroy(&body);
    tree_destroy(&tree);
    return 0;
}

/* If `path` ends with "/commits/<oid>" or "/tree/<oid>", dispatches to
 * the REST handler and returns 1. Returns 0 if the path isn't a REST
 * endpoint. The caller handles /repos separately since it doesn't need
 * a resolved repo. */
static int srv_try_handle_rest(srv_io *io, gut_repo *repo, const char *path) {
    const char *p;
    if ((p = strstr(path, "/commits/")) != NULL) {
        const char *oid = p + 9; /* strlen("/commits/") */
        char oid_buf[GUT_OID_MAX_HEX_SIZE + 1];
        u64 n = 0;
        while (oid[n] && oid[n] != '/' && oid[n] != '?' && n < sizeof(oid_buf) - 1) {
            oid_buf[n] = oid[n]; n++;
        }
        oid_buf[n] = 0;
        srv_handle_rest_commit(io, repo, oid_buf);
        return 1;
    }
    if ((p = strstr(path, "/tree/")) != NULL) {
        const char *oid = p + 6; /* strlen("/tree/") */
        char oid_buf[GUT_OID_MAX_HEX_SIZE + 1];
        u64 n = 0;
        while (oid[n] && oid[n] != '/' && oid[n] != '?' && n < sizeof(oid_buf) - 1) {
            oid_buf[n] = oid[n]; n++;
        }
        oid_buf[n] = 0;
        srv_handle_rest_tree(io, repo, oid_buf);
        return 1;
    }
    return 0;
}

/* Read an entire HTTP request (headers + body) into buf. Returns 1 on
 * success with headers parsed into method/path/content_length. */
static int srv_read_request(srv_io *io, buf *out,
                            char *method, u64 method_cap,
                            char *path,   u64 path_cap,
                            u64  *body_start,
                            u64  *body_len) {
    u8 chunk[4096];
    u64 nr;
    u64 headers_end = 0;
    u64 cl = 0;
    u64 total_needed;

    if (buf_create(out, 8192) != 0) return 0;

    /* Read until end-of-headers */
    while (headers_end == 0) {
        if (srv_read(io, chunk, sizeof(chunk), &nr) != 0) break;
        if (nr == 0) break;
        buf_append(out, chunk, nr);
        {
            u64 i;
            if (out->len >= 4) {
                for (i = 0; i + 3 < out->len; i++) {
                    if (out->data[i] == '\r' && out->data[i+1] == '\n' &&
                        out->data[i+2] == '\r' && out->data[i+3] == '\n') {
                        headers_end = i + 4;
                        break;
                    }
                }
            }
        }
    }
    if (headers_end == 0) { buf_destroy(out); return 0; }

    /* Parse METHOD SP PATH SP HTTP/... */
    {
        const char *s = (const char *)out->data;
        u64 i = 0;
        u64 ms, me, ps, pe;
        ms = 0; me = 0;
        while (i < headers_end && s[i] != ' ') i++;
        me = i; i++;
        ps = i;
        while (i < headers_end && s[i] != ' ') i++;
        pe = i;
        if (me == 0 || pe == ps) { buf_destroy(out); return 0; }
        if (me >= method_cap) me = method_cap - 1;
        memcpy(method, s, me);
        method[me] = 0;
        {
            u64 plen = pe - ps;
            if (plen >= path_cap) plen = path_cap - 1;
            memcpy(path, s + ps, plen);
            path[plen] = 0;
        }
    }

    /* Find Content-Length (case-insensitive) */
    {
        const char *s = (const char *)out->data;
        const char *found = NULL;
        u64 i;
        const char *key = "content-length:";
        u64 klen = 15;
        for (i = 0; i + klen < headers_end; i++) {
            u64 j;
            int ok = 1;
            for (j = 0; j < klen; j++) {
                char a = s[i + j]; char b = key[j];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (a != b) { ok = 0; break; }
            }
            if (ok) { found = s + i + klen; break; }
        }
        if (found) cl = (u64)strtoull(found, NULL, 10);
    }

    *body_start = headers_end;
    *body_len = cl;

    /* Read remaining body if not yet all received */
    total_needed = headers_end + cl;
    while (out->len < total_needed) {
        if (srv_read(io, chunk, sizeof(chunk), &nr) != 0) break;
        if (nr == 0) break;
        buf_append(out, chunk, nr);
    }

    return 1;
}

/* Scan HTTP headers for a case-insensitive header name and copy its value
 * (trimmed) into out. Returns 1 on success. */
static int srv_get_header(const u8 *req, u64 req_len, u64 headers_end,
                          const char *name,
                          char *out, u64 out_cap) {
    u64 i, nlen = strlen(name);
    for (i = 0; i + nlen + 1 < headers_end; i++) {
        /* Require header to be at start of a line */
        if (i > 0 && (req[i - 1] != '\n' && !(i == 1 && req[0] == '\n'))) continue;
        {
            u64 k; int ok = 1;
            for (k = 0; k < nlen; k++) {
                char a = (char)req[i + k]; char b = name[k];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { ok = 0; break; }
            }
            if (!ok || req[i + nlen] != ':') continue;
        }
        {
            u64 vs = i + nlen + 1;
            u64 ve;
            while (vs < headers_end && (req[vs] == ' ' || req[vs] == '\t')) vs++;
            ve = vs;
            while (ve < headers_end && req[ve] != '\r' && req[ve] != '\n') ve++;
            if (ve - vs >= out_cap) return 0;
            memcpy(out, req + vs, (size_t)(ve - vs));
            out[ve - vs] = 0;
            (void)req_len;
            return 1;
        }
    }
    return 0;
}

/* Returns 1 if Authorization header presents `Bearer <token>` or `Basic`
 * whose decoded user:pass has pass == token (any user). If no auth
 * required (expected_token == NULL), always returns 1. */
static int srv_auth_ok(const u8 *req, u64 req_len, u64 headers_end,
                       const char *expected_token) {
    char auth[512];
    if (!expected_token) return 1;
    if (!srv_get_header(req, req_len, headers_end, "authorization",
                        auth, sizeof(auth))) {
        return 0;
    }
    if (strncmp(auth, "Bearer ", 7) == 0) {
        return strcmp(auth + 7, expected_token) == 0;
    }
    if (strncmp(auth, "Basic ", 6) == 0) {
        buf decoded;
        const char *b64 = auth + 6;
        int ok = 0;
        if (buf_create(&decoded, strlen(b64) + 16) != 0) return 0;
        if (base64_decode(&decoded, (u8 *)b64, (u64)strlen(b64)) == 0) {
            const char *colon;
            decoded.data[decoded.len < decoded.cap - 1 ? decoded.len : decoded.cap - 1] = 0;
            colon = strchr((const char *)decoded.data, ':');
            if (colon) {
                ok = (strcmp(colon + 1, expected_token) == 0);
            }
        }
        buf_destroy(&decoded);
        return ok;
    }
    return 0;
}

/* Send a 401 with a WWW-Authenticate challenge. */
static void srv_send_401(srv_io *io) {
    const char *msg = "Unauthorized\n";
    char header[256];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"gut\"\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        (int)strlen(msg));
    srv_write_all(io, (const u8 *)header, (u64)n);
    srv_write_all(io, (const u8 *)msg, (u64)strlen(msg));
}

/* Split a URL path like "/<repo>/info/refs" (or ".../git-upload-pack",
 * ".../git-receive-pack") into the repo-portion (output via repo_out,
 * without leading/trailing slashes) and the endpoint-portion (output via
 * endpoint_out). Returns 1 on success, 0 if no known endpoint found. */
static int srv_split_path(const char *path,
                          char *repo_out, u64 repo_cap,
                          char *endpoint_out, u64 endpoint_cap) {
    static const char *endpoints[] = {
        "/info/refs", "/git-upload-pack", "/git-receive-pack", NULL
    };
    int i;
    const char *best = NULL;
    const char *best_ep = NULL;
    for (i = 0; endpoints[i]; i++) {
        const char *pos = strstr(path, endpoints[i]);
        if (pos && (!best || pos < best)) {
            best = pos;
            best_ep = endpoints[i];
        }
    }
    if (!best) return 0;

    {
        u64 repo_len = (u64)(best - path);
        /* trim leading/trailing slashes and reject .. segments */
        u64 s = 0;
        while (s < repo_len && path[s] == '/') s++;
        while (repo_len > s && path[repo_len - 1] == '/') repo_len--;
        if (repo_len - s >= repo_cap) return 0;
        if (strstr(path + s, "..") &&
            (strstr(path + s, "/..") || !strncmp(path + s, "../", 3) ||
             !strcmp(path + s, ".."))) return 0;
        memcpy(repo_out, path + s, (size_t)(repo_len - s));
        repo_out[repo_len - s] = 0;
    }
    snprintf(endpoint_out, endpoint_cap, "%s", best_ep);
    return 1;
}

static int cmd_server(int argc, char **argv) {
    gut_repo single_repo;
    int single_mode = 0;
    char cwd[2048];
    u16 port = 8080;
    const char *single_repo_path = NULL;
    const char *root_path = NULL;
    int ai;
    net_sock_addr addr;
    tcp_listener listener;

    const char *auth_token = NULL;
    const char *cert_path = NULL;
    const char *key_path = NULL;
    tls_config *tlscfg = NULL;
    for (ai = 0; ai < argc; ai++) {
        if (strcmp(argv[ai], "--port") == 0 && ai + 1 < argc) {
            port = (u16)atoi(argv[++ai]);
        } else if (strcmp(argv[ai], "--repo") == 0 && ai + 1 < argc) {
            single_repo_path = argv[++ai];
        } else if (strcmp(argv[ai], "--root") == 0 && ai + 1 < argc) {
            root_path = argv[++ai];
        } else if (strcmp(argv[ai], "--auth-token") == 0 && ai + 1 < argc) {
            auth_token = argv[++ai];
        } else if (strcmp(argv[ai], "--cert") == 0 && ai + 1 < argc) {
            cert_path = argv[++ai];
        } else if (strcmp(argv[ai], "--key") == 0 && ai + 1 < argc) {
            key_path = argv[++ai];
        }
    }

    if ((cert_path && !key_path) || (!cert_path && key_path)) {
        fprintf(stderr, "error: --cert and --key must be set together\n");
        return 1;
    }
    if (cert_path && key_path) {
        /* PEM → DER for each of cert/key. Apennines tls_config_set_cert
         * expects DER (single-cert, no PEM armor). */
        u8 *cert_der = NULL, *key_der = NULL;
        u64 cert_len = 0, key_len = 0;
        int i;

        for (i = 0; i < 2; i++) {
            const char *path = i == 0 ? cert_path : key_path;
            FILE *fp;
            long raw_sz;
            u8 *raw;
            const char *begin, *end;
            buf b64_body, der;

            fp = fopen(path, "rb");
            if (!fp) {
                fprintf(stderr, "error: cannot read %s\n", path);
                free(cert_der); return 1;
            }
            fseek(fp, 0, SEEK_END); raw_sz = ftell(fp); fseek(fp, 0, SEEK_SET);
            raw = (u8 *)malloc((size_t)raw_sz + 1);
            fread(raw, 1, (size_t)raw_sz, fp); fclose(fp);
            raw[raw_sz] = 0;

            begin = strstr((const char *)raw, "-----BEGIN");
            if (begin) begin = strchr(begin, '\n');
            end = strstr((const char *)raw, "-----END");
            if (!begin || !end || end <= begin) {
                fprintf(stderr, "error: %s is not PEM\n", path);
                free(raw); free(cert_der); return 1;
            }
            begin++;

            if (buf_create(&b64_body, (u64)(end - begin)) != 0) {
                free(raw); free(cert_der); return 1;
            }
            {
                const char *p;
                for (p = begin; p < end; p++) {
                    if (*p != '\n' && *p != '\r' && *p != ' ' && *p != '\t') {
                        buf_append_byte(&b64_body, (u8)*p);
                    }
                }
            }
            if (buf_create(&der, b64_body.len) != 0 ||
                base64_decode(&der, b64_body.data, b64_body.len) != 0) {
                fprintf(stderr, "error: base64 decode of %s failed\n", path);
                buf_destroy(&b64_body); free(raw); free(cert_der); return 1;
            }
            buf_destroy(&b64_body);
            free(raw);

            if (i == 0) {
                cert_der = (u8 *)malloc((size_t)der.len);
                memcpy(cert_der, der.data, (size_t)der.len);
                cert_len = der.len;
            } else {
                key_der = (u8 *)malloc((size_t)der.len);
                memcpy(key_der, der.data, (size_t)der.len);
                key_len = der.len;
            }
            buf_destroy(&der);
        }

        if (tls_config_create(&tlscfg) != 0 ||
            tls_config_set_cert(tlscfg, cert_der, cert_len) != 0 ||
            tls_config_set_key (tlscfg, key_der,  key_len)  != 0) {
            fprintf(stderr, "error: TLS config init failed\n");
            free(cert_der); free(key_der); return 1;
        }
        free(cert_der); free(key_der);
    }

    if (single_repo_path && root_path) {
        fprintf(stderr, "error: --repo and --root are mutually exclusive\n");
        return 1;
    }
    if (!single_repo_path && !root_path) {
        /* Default: serve cwd as single repo */
        if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
        single_repo_path = cwd;
    }

    if (single_repo_path) {
        if (repo_open(&single_repo, single_repo_path) != 0) {
            fprintf(stderr, "error: not a gut repository: %s\n", single_repo_path);
            return 1;
        }
        single_mode = 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.family = 4;
    addr.port = port;

    if (tcp_listener_create(&listener, &addr, 8) != 0) {
        fprintf(stderr, "error: cannot bind to :%u\n", (unsigned)port); return 1;
    }

    if (single_mode) {
        printf("gut server on :%u (single repo %s)\n",
               (unsigned)port, single_repo_path);
        printf("  test:  git clone http://localhost:%u/\n", (unsigned)port);
    } else {
        printf("gut server on :%u (root %s, multi-repo)\n",
               (unsigned)port, root_path);
        printf("  test:  git clone http://localhost:%u/<repo-name>/\n",
               (unsigned)port);
    }
    if (auth_token) printf("  auth:  required (Bearer or Basic)\n");
    if (tlscfg)     printf("  tls:   enabled\n");

    for (;;) {
        srv_io io;
        buf req;
        char method[16];
        char path[1024];
        u64 body_start = 0, body_len = 0;
        gut_repo *repo_for_request = NULL;
        gut_repo per_request_repo;
        int have_per_request = 0;
        char full_repo_path[2048];

        memset(&io, 0, sizeof(io));
        if (tcp_listener_accept(&io.tcp, &listener) != 0) continue;

        if (tlscfg) {
            unsigned long tls_rc = tls_conn_create_server(&io.tls, &io.tcp, tlscfg);
            if (tls_rc != 0) {
                fprintf(stderr, "[server] TLS handshake failed (hatch %lu)\n", tls_rc);
                tcp_conn_destroy(&io.tcp);
                continue;
            }
        }

        if (!srv_read_request(&io, &req, method, sizeof(method),
                              path, sizeof(path), &body_start, &body_len)) {
            srv_io_close(&io);
            continue;
        }

        printf("[server] %s %s (body=%llu)\n", method, path,
               (unsigned long long)body_len);
        fflush(stdout);

        if (auth_token &&
            !srv_auth_ok(req.data, req.len, body_start, auth_token)) {
            srv_send_401(&io);
            buf_destroy(&req);
            srv_io_close(&io);
            continue;
        }

        /* REST endpoint: /repos is global (no repo needed). */
        if (strcmp(method, "GET") == 0 &&
            (strcmp(path, "/repos") == 0 ||
             strncmp(path, "/repos?", 7) == 0)) {
            srv_handle_repos_list(&io, single_mode,
                                  single_repo_path, root_path);
            buf_destroy(&req);
            srv_io_close(&io);
            continue;
        }

        /* Resolve which repo to serve this request from. */
        if (single_mode) {
            repo_for_request = &single_repo;
        } else {
            char repo_seg[512];
            char endpoint[64];
            if (!srv_split_path(path, repo_seg, sizeof(repo_seg),
                                endpoint, sizeof(endpoint))) {
                /* Not a git smart-HTTP endpoint. Try REST: for REST the
                 * path shape is /<repo>/commits/<oid> or /<repo>/tree/<oid>.
                 * Extract <repo> as the first path segment and look for
                 * /commits/ or /tree/ after it. */
                const char *rest_kw = NULL;
                const char *keywords[] = { "/commits/", "/tree/", NULL };
                int k;
                for (k = 0; keywords[k]; k++) {
                    const char *pos = strstr(path, keywords[k]);
                    if (pos && (!rest_kw || pos < rest_kw)) rest_kw = pos;
                }
                if (!rest_kw) {
                    srv_send_status(&io, 404, "Not Found");
                    buf_destroy(&req);
                    srv_io_close(&io);
                    continue;
                }
                {
                    u64 start = 0, end = (u64)(rest_kw - path);
                    while (start < end && path[start] == '/') start++;
                    if (end <= start || end - start >= sizeof(repo_seg)) {
                        srv_send_status(&io, 404, "Not Found");
                        buf_destroy(&req);
                        srv_io_close(&io);
                        continue;
                    }
                    memcpy(repo_seg, path + start, (size_t)(end - start));
                    repo_seg[end - start] = 0;
                }
            }
            snprintf(full_repo_path, sizeof(full_repo_path), "%s/%s",
                     root_path, repo_seg);
            if (repo_open(&per_request_repo, full_repo_path) != 0) {
                srv_send_status(&io, 404, "Repo Not Found");
                buf_destroy(&req);
                srv_io_close(&io);
                continue;
            }
            repo_for_request = &per_request_repo;
            have_per_request = 1;
        }

        if (strcmp(method, "GET") == 0 && strstr(path, "/info/refs")) {
            if (strstr(path, "service=git-upload-pack")) {
                srv_handle_info_refs(&io, repo_for_request, "git-upload-pack");
            } else if (strstr(path, "service=git-receive-pack")) {
                srv_handle_info_refs(&io, repo_for_request, "git-receive-pack");
            } else {
                srv_send_status(&io, 400, "Bad Request");
            }
        } else if (strcmp(method, "POST") == 0 &&
                   strstr(path, "/git-upload-pack")) {
            srv_handle_upload_pack(&io, repo_for_request,
                                   req.data + body_start, body_len);
        } else if (strcmp(method, "POST") == 0 &&
                   strstr(path, "/git-receive-pack")) {
            srv_handle_receive_pack(&io, repo_for_request,
                                    req.data + body_start, body_len);
        } else if (strcmp(method, "GET") == 0 &&
                   srv_try_handle_rest(&io, repo_for_request, path)) {
            /* Handled by REST dispatcher. */
        } else {
            srv_send_status(&io, 404, "Not Found");
        }

        buf_destroy(&req);
        srv_io_close(&io);
        (void)have_per_request;
    }

    /* unreachable */
    return 0;
}

static int cmd_listen(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    unsigned long rc;
    u16 port = 7900;
    u64 poll_ms = 1000;
    const char *token = NULL;
    int auto_fetch_default = 0;
    int background = 0;
    int want_status = 0;
    int want_stop = 0;
    leech_outbound outbound[GUT_LISTEN_MAX_OUTBOUND];
    u64 outbound_count = 0;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (u16)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--poll") == 0 && i + 1 < argc) {
            poll_ms = (u64)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--auto-fetch") == 0) {
            auto_fetch_default = 1;
        } else if (strcmp(argv[i], "--background") == 0) {
            background = 1;
        } else if (strcmp(argv[i], "--status") == 0) {
            want_status = 1;
        } else if (strcmp(argv[i], "--stop") == 0) {
            want_stop = 1;
        } else if (strcmp(argv[i], "--leech") == 0 && i + 1 < argc) {
            if (outbound_count >= GUT_LISTEN_MAX_OUTBOUND) {
                fprintf(stderr, "error: too many --leech subscriptions\n");
                return 1;
            }
            outbound[outbound_count].url = argv[++i];
            outbound[outbound_count].token = NULL;
            outbound[outbound_count].name = NULL;
            outbound[outbound_count].auto_fetch = auto_fetch_default;
            outbound_count++;
        } else if (strcmp(argv[i], "--as") == 0 && i + 1 < argc && outbound_count > 0) {
            outbound[outbound_count - 1].name = argv[++i];
        } else if (strcmp(argv[i], "--leech-token") == 0 && i + 1 < argc && outbound_count > 0) {
            outbound[outbound_count - 1].token = argv[++i];
        }
    }

    if (want_status) return cmd_listen_status(port);
    if (want_stop)   return cmd_listen_stop(port);

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

    ensure_gut_home();

    /* Check if a previous instance is still alive. Skip when we're a
     * re-spawned child (parent sets GUT_DAEMON_CHILD env var). */
    if (!getenv("GUT_DAEMON_CHILD")) {
        long existing = read_pid_file(port);
        if (existing != 0 && pid_is_alive(existing)) {
            fprintf(stderr, "error: gut listen already running on port %u (pid %ld)\n",
                    (unsigned)port, existing);
            return 1;
        }
    }

    if (background) {
        char pid_path[1024];
        char log_path[1024];
        listen_pid_path(pid_path, sizeof(pid_path), port);
        listen_log_path(log_path, sizeof(log_path), port);

#ifdef _WIN32
        /* Windows: spawn a detached child that runs gut listen without --background */
        {
            char cmdline[4096];
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            HANDLE log_fh;
            SECURITY_ATTRIBUTES sa;
            char self_path[1024];
            int n;

            GetModuleFileNameA(NULL, self_path, sizeof(self_path));

            /* Build command-line, stripping --background from argv */
            n = snprintf(cmdline, sizeof(cmdline), "\"%s\" listen", self_path);
            for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "--background") == 0) continue;
                n += snprintf(cmdline + n, sizeof(cmdline) - n, " \"%s\"", argv[i]);
            }

            memset(&sa, 0, sizeof(sa));
            sa.nLength = sizeof(sa);
            sa.bInheritHandle = TRUE;
            log_fh = CreateFileA(log_path, GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (log_fh == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "error: cannot open log file %s\n", log_path);
                return 1;
            }

            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            si.hStdOutput = log_fh;
            si.hStdError = log_fh;

            /* Child inherits env — mark it as a daemon child so it skips the
             * "already running" check when it starts up. */
            _putenv("GUT_DAEMON_CHILD=1");

            if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                                CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                                NULL, cwd, &si, &pi)) {
                fprintf(stderr, "error: CreateProcess failed (%lu)\n", GetLastError());
                CloseHandle(log_fh);
                _putenv("GUT_DAEMON_CHILD=");
                return 1;
            }
            _putenv("GUT_DAEMON_CHILD=");
            CloseHandle(log_fh);

            {
                FILE *pf = fopen(pid_path, "w");
                if (pf) { fprintf(pf, "%lu\n", (unsigned long)pi.dwProcessId); fclose(pf); }
            }
            printf("gut listen started in background (pid %lu)\n  log: %s\n",
                   (unsigned long)pi.dwProcessId, log_path);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 0;
        }
#else
        /* POSIX: double-fork */
        {
            pid_t pid = fork();
            if (pid < 0) return 1;
            if (pid > 0) {
                /* Parent writes PID file and exits */
                FILE *pf = fopen(pid_path, "w");
                if (pf) { fprintf(pf, "%d\n", (int)pid); fclose(pf); }
                printf("gut listen started in background (pid %d)\n  log: %s\n",
                       (int)pid, log_path);
                return 0;
            }
            /* Child: detach from terminal, redirect I/O */
            setsid();
            {
                int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
            }
        }
#endif
    } else {
        /* Foreground: write our own PID for tooling */
        char pid_path[1024];
        FILE *pf;
        listen_pid_path(pid_path, sizeof(pid_path), port);
        pf = fopen(pid_path, "w");
        if (pf) {
#ifdef _WIN32
            fprintf(pf, "%lu\n", (unsigned long)GetCurrentProcessId());
#else
            fprintf(pf, "%d\n", (int)getpid());
#endif
            fclose(pf);
        }
    }

    g_op_repo = &repo;
    leech_listen_set_on_message(on_peer_op);

    rc = leech_listen(&repo, port, poll_ms, token, outbound, outbound_count);

    /* Remove PID file on clean exit */
    {
        char pid_path[1024];
        listen_pid_path(pid_path, sizeof(pid_path), port);
        remove(pid_path);
    }

    return rc ? 1 : 0;
}

/* ---- gut send ---- */
/* One-shot: connect, send a message, optionally wait for one reply, close. */
static int cmd_send(int argc, char **argv) {
    const char *url = NULL;
    const char *token = NULL;
    const char *text = NULL;
    int wait_reply = 0;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--reply") == 0) {
            wait_reply = 1;
        } else if (!url) {
            url = argv[i];
        } else if (!text) {
            text = argv[i];
        }
    }

    if (!url || !text) {
        fprintf(stderr, "usage: gut send <ws://host:port> <text> [--token <t>] [--reply]\n");
        return 1;
    }

    {
        char *reply = NULL;
        u64 reply_len = 0;
        unsigned long rc = leech_send_to(url, token, text, (u64)strlen(text),
                                         wait_reply ? &reply : NULL,
                                         wait_reply ? &reply_len : NULL);
        if (reply) {
            fwrite(reply, 1, (size_t)reply_len, stdout);
            printf("\n");
            free(reply);
        }
        return rc ? 1 : 0;
    }
}

/* ---- gut ask ---- */
/* Send { "op":"ask", "ref":"..." } to a peer, wait for the offer reply, then
 * fetch the pack at that OID and store it under refs/leech/<peer>/<ref>. */
static int cmd_ask(int argc, char **argv) {
    const char *url = NULL;
    const char *ref = NULL;
    const char *token = NULL;
    const char *peer_name = NULL;
    gut_repo repo;
    char cwd[2048];
    char msg[512];
    int msg_len;
    char *reply = NULL;
    u64 reply_len = 0;
    unsigned long rc;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) token = argv[++i];
        else if (strcmp(argv[i], "--as") == 0 && i + 1 < argc) peer_name = argv[++i];
        else if (!url) url = argv[i];
        else if (!ref) ref = argv[i];
    }
    if (!url || !ref) {
        fprintf(stderr, "usage: gut ask <ws://host:port> <ref> [--as <name>] [--token <t>]\n");
        return 1;
    }

    if (!getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    msg_len = snprintf(msg, sizeof(msg),
                       "{\"op\":\"ask\",\"ref\":\"%s\"}", ref);

    rc = leech_send_to(url, token, msg, (u64)msg_len, &reply, &reply_len);
    if (rc || !reply) {
        fprintf(stderr,
            "error: no reply from %s\n"
            "  is a broker listening there? try 'gut listen --background' on the peer\n",
            url);
        if (reply) free(reply);
        return 1;
    }

    {
        char op[32], oid_hex[GUT_OID_HEX_SIZE + 1], reply_ref[256];
        if (!op_json_str(op, sizeof(op), reply, "op") ||
            strcmp(op, "offer") != 0) {
            fprintf(stderr, "peer replied: %s\n", reply);
            free(reply);
            return 1;
        }
        if (!op_json_str(oid_hex, sizeof(oid_hex), reply, "oid") ||
            !op_json_str(reply_ref, sizeof(reply_ref), reply, "ref")) {
            fprintf(stderr, "malformed offer: %s\n", reply);
            free(reply);
            return 1;
        }
        printf("offer: %s @ %s\n", reply_ref, oid_hex);

        rc = leech_fetch(&repo, url,
                         peer_name ? peer_name : "peer",
                         oid_hex, reply_ref);
        free(reply);
        if (rc) {
            fprintf(stderr, "error: fetch failed (%lu)\n", rc);
            return 1;
        }
    }
    return 0;
}

/* ---- gut offer ---- */
/* Two modes:
 *   gut offer <url> <ref>                                   — ref-offer (branch tip)
 *   gut offer <url> <path> --patch [--as <name>]            — patch-offer (one file)
 *
 * Patch-offer wire format:
 *   { "op":"offer-patch", "path":"<rel>",
 *     "base_oid":"<40-hex>", "target_oid":"<40-hex>",
 *     "from":"<sender_name>", "content_b64":"<base64>" }
 *
 * We inline the blob bytes (base64) so the receiver can apply without a
 * round-trip. Cap at 512 KiB to keep WS frames modest; larger files
 * currently refuse and print a message (future: sidecar HTTP fetch). */

#define GUT_PATCH_INLINE_MAX (512u * 1024u)

static int cmd_offer_patch(const char *url, const char *path,
                           const char *token, const char *sender_name,
                           const char *fetch_url) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char idx_path_buf[2048];
    gut_oid target_oid;
    gut_oid base_oid;
    int have_base = 0;
    gut_object blob;
    char target_hex[GUT_OID_HEX_SIZE + 1];
    char base_hex[GUT_OID_HEX_SIZE + 1];
    buf b64;
    char *msg;
    u64 msg_cap;
    int msg_len;
    unsigned long rc;
    u64 i;
    int found_in_index = 0;

    if (!getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    /* target_oid = staged version from index */
    snprintf(idx_path_buf, sizeof(idx_path_buf), "%s/index", repo.git_dir);
    if (index_read(&idx, idx_path_buf) != 0) {
        fprintf(stderr, "error: cannot read index\n"); return 1;
    }
    for (i = 0; i < idx.count; i++) {
        if (strcmp(idx.entries[i].path, path) == 0) {
            target_oid = idx.entries[i].oid;
            found_in_index = 1;
            break;
        }
    }
    index_destroy(&idx);
    if (!found_in_index) {
        fprintf(stderr, "error: '%s' is not staged — run `gut add %s` first\n",
                path, path);
        return 1;
    }

    /* base_oid = HEAD's blob for this path (may not exist for new files) */
    {
        char head_ref[256];
        gut_oid head_oid;
        gut_object head_obj;
        gut_commit head_commit;
        if (repo_head_ref(head_ref, sizeof(head_ref), &repo) == 0 &&
            repo_resolve_ref(&head_oid, &repo, head_ref) == 0 &&
            odb_read(&head_obj, &repo.odb, &head_oid) == 0) {
            if (commit_parse(&head_commit, head_obj.data.data,
                             head_obj.data.len) == 0) {
                if (tree_lookup_path(&base_oid, &repo.odb,
                                     &head_commit.tree_oid, path) == 0) {
                    have_base = 1;
                }
                commit_destroy(&head_commit);
            }
            object_destroy(&head_obj);
        }
    }

    if (odb_read(&blob, &repo.odb, &target_oid) != 0) {
        fprintf(stderr, "error: cannot read staged blob for '%s'\n", path);
        return 1;
    }

    {
        int oversize = blob.data.len > GUT_PATCH_INLINE_MAX;
        if (oversize && !fetch_url) {
            fprintf(stderr,
                "error: '%s' is %llu bytes (cap %u) — pass --fetch-url "
                "<http://your-listener:port/> so the receiver can fetch it\n",
                path, (unsigned long long)blob.data.len, GUT_PATCH_INLINE_MAX);
            object_destroy(&blob);
            return 1;
        }

        if (!oversize) {
            if (buf_create(&b64, blob.data.len * 2 + 16) != 0 ||
                base64_encode(&b64, blob.data.data, blob.data.len) != 0) {
                object_destroy(&blob);
                fprintf(stderr, "error: base64_encode failed\n"); return 1;
            }
        } else {
            /* Oversize + fetch_url: sentinel empty b64 buf. */
            buf_create(&b64, 1);
        }
        oid_to_hex(target_hex, &target_oid);
        if (have_base) oid_to_hex(base_hex, &base_oid);

        msg_cap = b64.len + 2048;
        msg = (char *)malloc((size_t)msg_cap);
        if (!msg) {
            buf_destroy(&b64); object_destroy(&blob);
            fprintf(stderr, "error: oom\n"); return 1;
        }

        msg_len = snprintf(msg, msg_cap,
            "{\"op\":\"offer-patch\",\"path\":\"%s\","
            "\"base_oid\":\"%s\",\"target_oid\":\"%s\","
            "\"from\":\"%s\",\"fetch_url\":\"%s\","
            "\"content_b64\":\"%.*s\"}",
            path,
            have_base ? base_hex : "",
            target_hex,
            sender_name ? sender_name : "peer",
            fetch_url ? fetch_url : "",
            (int)b64.len, (const char *)b64.data);
    }

    /* Persist an outgoing-sent record before the wire so the listener
     * on our side (if we're running one) can detect a concurrent incoming
     * offer for the same path and apply tie-break. Record is keyed by
     * time + target_oid_short; the `path` inside drives matching. */
    char sent_rec_path[2048];
    {
        char sent_dir[2048];
        FILE *sfp;
        time_t now_ts = time(NULL);
        snprintf(sent_dir, sizeof(sent_dir), "%s/offers-sent", repo.git_dir);
#ifdef _WIN32
        _mkdir(sent_dir);
#else
        mkdir(sent_dir, 0755);
#endif
        snprintf(sent_rec_path, sizeof(sent_rec_path), "%s/%ld-%.8s.json",
                 sent_dir, (long)now_ts, target_hex);
        sfp = fopen(sent_rec_path, "w");
        if (sfp) {
            fprintf(sfp,
                    "{\"path\":\"%s\",\"as\":\"%s\",\"target_oid\":\"%s\","
                    "\"url\":\"%s\",\"sent_at\":%ld}\n",
                    path, sender_name ? sender_name : "peer",
                    target_hex, url, (long)now_ts);
            fclose(sfp);
        }
    }

    {
        char *reply = NULL;
        u64 reply_len = 0;
        rc = leech_send_to(url, token, msg, (u64)msg_len, &reply, &reply_len);
        free(msg);
        buf_destroy(&b64);
        object_destroy(&blob);

        /* Intentionally do NOT delete the outgoing-sent record here.
         * Cleanup-on-reply races with concurrent incoming offers:
         * if the peer sends us a patch for the same path a few ms
         * after our reply arrives, we need our record still on disk
         * so our listener can detect the collision and tie-break.
         * The listener treats records older than 60s as stale and
         * prunes them during scan; fresh ones stay load-bearing. */
        (void)sent_rec_path;

        if (rc) {
            fprintf(stderr,
            "error: cannot reach peer — is a broker listening at that URL? (line %lu)\n",
            rc);
            if (reply) free(reply);
            return 1;
        }

        if (!reply || reply_len == 0) {
            printf("offered patch for %s (%s) → %s (no ack)\n",
                   path, target_hex, url);
            if (reply) free(reply);
            return 0;
        }

        {
            char op[32] = {0};
            char reason[128] = {0};
            op_json_str(op, sizeof(op), reply, "op");
            op_json_str(reason, sizeof(reason), reply, "reason");
            if (strcmp(op, "offer-accepted") == 0) {
                printf("offered patch for %s (%s) → %s — ACCEPTED\n",
                       path, target_hex, url);
                free(reply);
                return 0;
            } else if (strcmp(op, "offer-rejected") == 0) {
                fprintf(stderr,
                        "offered patch for %s → %s — REJECTED: %s\n",
                        path, url, reason[0] ? reason : "unknown");
                free(reply);
                return 1;
            } else {
                printf("offered patch for %s → %s (unexpected reply: %s)\n",
                       path, url, reply);
                free(reply);
                return 0;
            }
        }
    }
}

static int cmd_offer(int argc, char **argv) {
    const char *url = NULL;
    const char *ref_or_path = NULL;
    const char *token = NULL;
    const char *sender_name = NULL;
    int patch_mode = 0;
    gut_repo repo;
    char cwd[2048];
    gut_oid oid;
    char oid_hex[GUT_OID_HEX_SIZE + 1];
    char msg[512];
    int msg_len;
    unsigned long rc;
    int i;

    const char *fetch_url = NULL;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) token = argv[++i];
        else if (strcmp(argv[i], "--as") == 0 && i + 1 < argc) sender_name = argv[++i];
        else if (strcmp(argv[i], "--patch") == 0) patch_mode = 1;
        else if (strcmp(argv[i], "--fetch-url") == 0 && i + 1 < argc)
            fetch_url = argv[++i];
        else if (!url) url = argv[i];
        else if (!ref_or_path) ref_or_path = argv[i];
    }
    if (!url || !ref_or_path) {
        fprintf(stderr,
            "usage: gut offer <ws://host:port> <ref>                              [--token <t>]\n"
            "       gut offer <ws://host:port> <path> --patch [--as <name>]       [--token <t>]\n"
            "                                 [--fetch-url <http://...>]  (required for blobs > 512 KiB)\n");
        return 1;
    }

    if (patch_mode) {
        return cmd_offer_patch(url, ref_or_path, token, sender_name, fetch_url);
    }

    if (!getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }
    if (repo_resolve_ref(&oid, &repo, ref_or_path) != 0) {
        fprintf(stderr, "error: cannot resolve ref '%s'\n", ref_or_path);
        return 1;
    }
    oid_to_hex(oid_hex, &oid);

    msg_len = snprintf(msg, sizeof(msg),
                       "{\"op\":\"offer\",\"ref\":\"%s\",\"oid\":\"%s\"}",
                       ref_or_path, oid_hex);

    rc = leech_send_to(url, token, msg, (u64)msg_len, NULL, NULL);
    if (rc) {
        fprintf(stderr,
            "error: cannot reach peer — is a broker listening at that URL? (line %lu)\n",
            rc);
        return 1;
    }
    printf("offered %s @ %s to %s\n", ref_or_path, oid_hex, url);
    return 0;
}

/* ---- gut offers ---- */
/* Subcommands:
 *   gut offers                   — list pending patch-offers
 *   gut offers apply <id>        — write target blob to working tree and stage
 *   gut offers reject <id>       — delete the offer record (blob stays in ODB)
 */

static int offers_read_record(const char *offers_dir, const char *id,
                              char *path_out, u64 path_cap,
                              char *target_hex_out, u64 target_cap,
                              char *from_out, u64 from_cap,
                              long *received_at_out) {
    char offer_path[2048];
    FILE *fp;
    char buf[4096];
    size_t n;
    snprintf(offer_path, sizeof(offer_path), "%s/%s.json", offers_dir, id);
    fp = fopen(offer_path, "r");
    if (!fp) return 0;
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    if (!op_json_str(path_out, path_cap, buf, "path")) return 0;
    if (!op_json_str(target_hex_out, target_cap, buf, "target_oid")) return 0;
    if (from_out) op_json_str(from_out, from_cap, buf, "from");
    if (received_at_out) {
        const char *p = strstr(buf, "\"received_at\":");
        if (p) *received_at_out = strtol(p + 14, NULL, 10);
        else   *received_at_out = 0;
    }
    return 1;
}

static int cmd_offers(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char offers_dir[2048];
    DIR *d;
    struct dirent *de;
    int count = 0;
    const char *sub = argc > 0 ? argv[0] : NULL;
    const char *arg_id = argc > 1 ? argv[1] : NULL;

    if (!getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }
    snprintf(offers_dir, sizeof(offers_dir), "%s/offers", repo.git_dir);

    /* Subcommand: apply */
    if (sub && strcmp(sub, "apply") == 0) {
        char path[512], target_hex[GUT_OID_HEX_SIZE + 1], from[128];
        long received_at = 0;
        gut_oid target_oid;
        gut_object blob;
        char wt_path[2048];
        FILE *wf;
        gut_index idx;
        char idx_path_buf[2048];

        if (!arg_id) {
            fprintf(stderr, "usage: gut offers apply <id>\n"); return 1;
        }
        if (!offers_read_record(offers_dir, arg_id,
                                path, sizeof(path),
                                target_hex, sizeof(target_hex),
                                from, sizeof(from), &received_at)) {
            fprintf(stderr, "error: no offer '%s'\n", arg_id); return 1;
        }
        if (oid_from_hex(&target_oid, target_hex) != 0) {
            fprintf(stderr, "error: bad target_oid in offer\n"); return 1;
        }
        if (odb_read(&blob, &repo.odb, &target_oid) != 0) {
            fprintf(stderr, "error: target blob not in ODB "
                            "(offer may predate a gc)\n");
            return 1;
        }

        /* Write to working tree */
        snprintf(wt_path, sizeof(wt_path), "%s/%s", repo.root_dir, path);
        wf = fopen(wt_path, "wb");
        if (!wf) {
            fprintf(stderr, "error: cannot write %s\n", wt_path);
            object_destroy(&blob); return 1;
        }
        fwrite(blob.data.data, 1, (size_t)blob.data.len, wf);
        fclose(wf);

        /* Stage it */
        snprintf(idx_path_buf, sizeof(idx_path_buf), "%s/index", repo.git_dir);
        if (index_read(&idx, idx_path_buf) == 0) {
            index_add(&idx, path, &target_oid, 0100644,
                      (u32)blob.data.len, (u32)time(NULL));
            index_write(&idx, idx_path_buf);
            index_destroy(&idx);
        }

        object_destroy(&blob);

        /* Delete the offer record so it doesn't re-appear */
        {
            char offer_path[2048];
            snprintf(offer_path, sizeof(offer_path), "%s/%s.json", offers_dir, arg_id);
            remove(offer_path);
        }

        printf("applied offer %s: wrote and staged %s (from %s)\n",
               arg_id, path, from);
        return 0;
    }

    /* Subcommand: reject */
    if (sub && strcmp(sub, "reject") == 0) {
        char offer_path[2048];
        if (!arg_id) {
            fprintf(stderr, "usage: gut offers reject <id>\n"); return 1;
        }
        snprintf(offer_path, sizeof(offer_path), "%s/%s.json", offers_dir, arg_id);
        if (remove(offer_path) != 0) {
            fprintf(stderr, "error: no offer '%s'\n", arg_id); return 1;
        }
        printf("rejected %s\n", arg_id);
        return 0;
    }

    /* Default: list */
    d = opendir(offers_dir);
    if (!d) {
        printf("no pending offers\n");
        return 0;
    }
    printf("pending patch-offers:\n");
    while ((de = readdir(d)) != NULL) {
        size_t L = strlen(de->d_name);
        char id[128], path[512], target_hex[GUT_OID_HEX_SIZE + 1], from[128];
        long received_at = 0;
        long age;
        char age_s[32];

        if (L < 6 || strcmp(de->d_name + L - 5, ".json") != 0) continue;
        if (L - 5 >= sizeof(id)) continue;
        memcpy(id, de->d_name, L - 5);
        id[L - 5] = '\0';

        if (!offers_read_record(offers_dir, id,
                                path, sizeof(path),
                                target_hex, sizeof(target_hex),
                                from, sizeof(from), &received_at)) continue;

        age = (long)time(NULL) - received_at;
        if (age < 60) snprintf(age_s, sizeof(age_s), "%lds", age);
        else if (age < 3600) snprintf(age_s, sizeof(age_s), "%ldm", age / 60);
        else if (age < 86400) snprintf(age_s, sizeof(age_s), "%ldh", age / 3600);
        else snprintf(age_s, sizeof(age_s), "%ldd", age / 86400);

        printf("  %s  %s (%s ago)  %s → %.8s\n",
               id, from, age_s, path, target_hex);
        count++;
    }
    closedir(d);
    if (count == 0) printf("  (none)\n");
    else printf("\napply: gut offers apply <id>   reject: gut offers reject <id>\n");
    return 0;
}

/* ---- gut sos ---- */
/* Send { "op":"sos", "file":"...", "message":"..." }. */
static int cmd_sos(int argc, char **argv) {
    const char *url = NULL;
    const char *file = NULL;
    const char *message = NULL;
    const char *token = NULL;
    char msg[1024];
    int msg_len;
    unsigned long rc;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) token = argv[++i];
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) message = argv[++i];
        else if (!url) url = argv[i];
        else if (!file) file = argv[i];
    }
    if (!url || !file) {
        fprintf(stderr, "usage: gut sos <ws://host:port> <file> [-m <msg>] [--token <t>]\n");
        return 1;
    }

    msg_len = snprintf(msg, sizeof(msg),
                       "{\"op\":\"sos\",\"file\":\"%s\"%s%s%s}",
                       file,
                       message ? ",\"message\":\"" : "",
                       message ? message           : "",
                       message ? "\""              : "");

    rc = leech_send_to(url, token, msg, (u64)msg_len, NULL, NULL);
    if (rc) {
        fprintf(stderr,
            "error: cannot reach peer — is a broker listening at that URL? (line %lu)\n",
            rc);
        return 1;
    }
    printf("SOS sent to %s for %s\n", url, file);
    return 0;
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
    const char *peer_name = NULL;
    int auto_fetch = 0;
    unsigned long rc;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            token = argv[++i];
        } else if (strcmp(argv[i], "--as") == 0 && i + 1 < argc) {
            peer_name = argv[++i];
        } else if (strcmp(argv[i], "--auto-fetch") == 0) {
            auto_fetch = 1;
        } else if (argv[i][0] != '-') {
            url = argv[i];
        }
    }

    if (!url) {
        fprintf(stderr, "usage: gut leech <ws://host:port> [--token <t>] [--as <name>] [--auto-fetch]\n");
        return 1;
    }

    if (auto_fetch) {
        gut_repo repo;
        char cwd[2048];
        if (!peer_name) peer_name = "peer";
        if (!gut_getcwd(cwd, sizeof(cwd))) {
            fprintf(stderr, "error: cannot get current directory\n");
            return 1;
        }
        rc = repo_open(&repo, cwd);
        if (rc) { fprintf(stderr, "error: --auto-fetch requires a gut repository\n"); return 1; }
        rc = leech_connect(url, token, &repo, peer_name);
    } else {
        rc = leech_connect(url, token, NULL, NULL);
    }
    return rc ? 1 : 0;
}

/* ---- gut repack ---- */
/* Collects all loose objects and packs them into a single .pack + .idx, then
 * deletes the loose objects. */
static int remote_read_file(char **out, u64 *len_out, const char *path);
static int remote_write_file(const char *path, const char *data, u64 len);

/* ---- gut config ---- */
/* Read or write .git/config keys using dot-path notation.
 *   gut config <section>.<name>                 — print value
 *   gut config <section>.<subsection>.<name>    — print value with subsection
 *   gut config <key> <value>                    — set (create if missing)
 *   gut config --list                           — dump all keys
 */

/* Split dot-key into (section, subsection, name). subsection may be "". */
static int config_split_key(const char *key,
                            char *sec, u64 sec_cap,
                            char *sub, u64 sub_cap,
                            char *nam, u64 nam_cap) {
    const char *first_dot = strchr(key, '.');
    const char *last_dot;
    if (!first_dot) return 0;
    last_dot = strrchr(key, '.');
    {
        u64 sec_len = (u64)(first_dot - key);
        u64 nam_len = (u64)(key + strlen(key) - (last_dot + 1));
        if (sec_len >= sec_cap || nam_len >= nam_cap) return 0;
        memcpy(sec, key, (size_t)sec_len); sec[sec_len] = 0;
        memcpy(nam, last_dot + 1, (size_t)nam_len); nam[nam_len] = 0;
    }
    if (first_dot == last_dot) {
        sub[0] = 0;
    } else {
        u64 sub_len = (u64)(last_dot - (first_dot + 1));
        if (sub_len >= sub_cap) return 0;
        memcpy(sub, first_dot + 1, (size_t)sub_len); sub[sub_len] = 0;
    }
    return 1;
}

static int cmd_config(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048], cfg_path[2048];
    int list_mode = 0;
    const char *key = NULL;
    const char *value = NULL;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--list") == 0) list_mode = 1;
        else if (!key) key = argv[i];
        else if (!value) value = argv[i];
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }
    snprintf(cfg_path, sizeof(cfg_path), "%s/config", repo.git_dir);

    /* --list: dump every key as section[.sub].name=value */
    if (list_mode) {
        char *data = NULL;
        u64 len = 0;
        if (!remote_read_file(&data, &len, cfg_path)) {
            printf("(no config)\n"); return 0;
        }
        {
            const char *p = data;
            const char *end = data + len;
            char cur_sec[128] = {0};
            char cur_sub[128] = {0};
            while (p < end) {
                const char *nl = memchr(p, '\n', (size_t)(end - p));
                u64 llen = nl ? (u64)(nl - p) : (u64)(end - p);
                if (llen > 0 && p[0] == '[') {
                    /* Parse section header */
                    const char *close = memchr(p, ']', (size_t)llen);
                    const char *q1 = memchr(p, '"', (size_t)llen);
                    cur_sec[0] = 0; cur_sub[0] = 0;
                    if (close && q1 && q1 < close) {
                        const char *q2 = memchr(q1 + 1, '"', (size_t)(close - (q1 + 1)));
                        const char *space = memchr(p + 1, ' ', (size_t)(q1 - p - 1));
                        u64 sec_len = space ? (u64)(space - (p + 1)) : (u64)(q1 - p - 2);
                        u64 sub_len = q2 ? (u64)(q2 - (q1 + 1)) : 0;
                        if (sec_len >= sizeof(cur_sec)) sec_len = sizeof(cur_sec) - 1;
                        if (sub_len >= sizeof(cur_sub)) sub_len = sizeof(cur_sub) - 1;
                        memcpy(cur_sec, p + 1, (size_t)sec_len);
                        cur_sec[sec_len] = 0;
                        memcpy(cur_sub, q1 + 1, (size_t)sub_len);
                        cur_sub[sub_len] = 0;
                    } else if (close) {
                        u64 sec_len = (u64)(close - (p + 1));
                        if (sec_len >= sizeof(cur_sec)) sec_len = sizeof(cur_sec) - 1;
                        memcpy(cur_sec, p + 1, (size_t)sec_len);
                        cur_sec[sec_len] = 0;
                    }
                } else if (llen > 0 && cur_sec[0]) {
                    const char *k = p;
                    const char *eq;
                    while (k < p + llen && (*k == ' ' || *k == '\t')) k++;
                    if (k >= p + llen || *k == '#' || *k == ';') {
                        p = nl ? nl + 1 : end; continue;
                    }
                    eq = memchr(k, '=', (size_t)(p + llen - k));
                    if (eq) {
                        const char *kend = eq;
                        const char *v = eq + 1;
                        while (kend > k && (kend[-1] == ' ' || kend[-1] == '\t')) kend--;
                        while (v < p + llen && (*v == ' ' || *v == '\t')) v++;
                        if (cur_sub[0]) {
                            printf("%s.%s.%.*s=%.*s\n",
                                   cur_sec, cur_sub,
                                   (int)(kend - k), k,
                                   (int)(p + llen - v), v);
                        } else {
                            printf("%s.%.*s=%.*s\n",
                                   cur_sec, (int)(kend - k), k,
                                   (int)(p + llen - v), v);
                        }
                    }
                }
                p = nl ? nl + 1 : end;
            }
        }
        free(data);
        return 0;
    }

    if (!key) {
        fprintf(stderr,
                "usage:\n"
                "  gut config <section>[.<sub>].<name>          get value\n"
                "  gut config <section>[.<sub>].<name> <value>  set value\n"
                "  gut config --list                           dump all keys\n");
        return 1;
    }

    /* Parse the key */
    char sec[128], sub[128], nam[128];
    if (!config_split_key(key, sec, sizeof(sec), sub, sizeof(sub),
                          nam, sizeof(nam))) {
        fprintf(stderr, "error: bad key '%s' (expected section[.sub].name)\n", key);
        return 1;
    }

    if (value) {
        /* Set */
        char *data = NULL;
        u64 len = 0;
        char header[256];
        char new_line[512];
        int nl_len;
        remote_read_file(&data, &len, cfg_path);

        if (sub[0]) snprintf(header, sizeof(header), "[%s \"%s\"]", sec, sub);
        else        snprintf(header, sizeof(header), "[%s]", sec);
        nl_len = snprintf(new_line, sizeof(new_line), "\t%s = %s\n", nam, value);

        {
            const char *p = data;
            const char *end = data ? data + len : NULL;
            int in_section = 0;
            int replaced = 0;
            char *out;
            u64 out_cap = len + (u64)nl_len + (u64)strlen(header) + 16;
            u64 out_len = 0;
            out = (char *)malloc((size_t)out_cap);
            if (!out) { free(data); return 1; }

            while (data && p < end) {
                const char *line_nl = memchr(p, '\n', (size_t)(end - p));
                u64 llen = line_nl ? (u64)(line_nl - p + 1) : (u64)(end - p);

                if (llen >= strlen(header) &&
                    strncmp(p, header, strlen(header)) == 0) {
                    in_section = 1;
                    memcpy(out + out_len, p, (size_t)llen);
                    out_len += llen;
                    p += llen;
                    continue;
                }

                if (in_section) {
                    const char *k = p;
                    while (k < p + llen && (*k == ' ' || *k == '\t')) k++;
                    if (llen > 0 && p[0] == '[') in_section = 0;
                    else if (k + strlen(nam) <= p + llen &&
                             strncmp(k, nam, strlen(nam)) == 0 &&
                             (k[strlen(nam)] == ' ' ||
                              k[strlen(nam)] == '\t' ||
                              k[strlen(nam)] == '=')) {
                        memcpy(out + out_len, new_line, (size_t)nl_len);
                        out_len += (u64)nl_len;
                        replaced = 1;
                        p += llen;
                        continue;
                    }
                }

                memcpy(out + out_len, p, (size_t)llen);
                out_len += llen;
                p += llen;
            }

            if (!replaced) {
                /* Need to append section + key */
                if (out_len > 0 && out[out_len - 1] != '\n') {
                    out[out_len++] = '\n';
                }
                /* See if section already exists in out — if so, append key
                 * inside. Simpler: always append a new section block. */
                {
                    int n = snprintf(out + out_len, (size_t)(out_cap - out_len),
                                     "%s\n%s", header, new_line);
                    out_len += (u64)n;
                }
            }

            if (!remote_write_file(cfg_path, out, out_len)) {
                free(out); free(data);
                fprintf(stderr,
                    "error: cannot write '%s' — check file permissions\n",
                    cfg_path);
                return 1;
            }
            free(out); free(data);
        }
        printf("set %s = %s\n", key, value);
        return 0;
    }

    /* Get */
    {
        gut_config cfg;
        const char *v = NULL;
        char section_header[256];
        if (config_read(&cfg, cfg_path) != 0) {
            fprintf(stderr, "error: cannot read config\n"); return 1;
        }
        if (sub[0]) snprintf(section_header, sizeof(section_header),
                              "%s \"%s\"", sec, sub);
        else        snprintf(section_header, sizeof(section_header), "%s", sec);
        if (config_get(&v, &cfg, section_header, nam) == 0 && v) {
            printf("%s\n", v);
            config_destroy(&cfg);
            return 0;
        }
        config_destroy(&cfg);
        fprintf(stderr, "error: '%s' not set\n", key);
        return 1;
    }
}

/* ---- gut remote ---- */
/* Manage [remote "<name>"] entries in .git/config. Subcommands:
 *   (none) or list          — list all remotes with their URLs
 *   add <name> <url>        — append a new remote
 *   remove <name>           — strip [remote "<name>"] and following keys
 *   set-url <name> <url>    — change existing remote's URL
 */

static int remote_read_file(char **out, u64 *len_out, const char *path) {
    FILE *fp = fopen(path, "rb");
    long sz;
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END); sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    *out = (char *)malloc((size_t)sz + 1);
    if (!*out) { fclose(fp); return 0; }
    fread(*out, 1, (size_t)sz, fp);
    (*out)[sz] = 0;
    *len_out = (u64)sz;
    fclose(fp);
    return 1;
}

static int remote_write_file(const char *path, const char *data, u64 len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    fwrite(data, 1, (size_t)len, fp);
    fclose(fp);
    return 1;
}

static int cmd_remote(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char cfg_path[2048];
    const char *sub = argc > 0 ? argv[0] : "list";

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }
    snprintf(cfg_path, sizeof(cfg_path), "%s/config", repo.git_dir);

    /* ---- list ---- */
    if (strcmp(sub, "list") == 0 || argc == 0) {
        char *data = NULL;
        u64 len = 0;
        if (!remote_read_file(&data, &len, cfg_path)) {
            printf("(no remotes — .git/config missing or unreadable)\n");
            return 0;
        }
        {
            const char *p = data;
            const char *end = data + len;
            int any = 0;
            while (p < end) {
                const char *nl = memchr(p, '\n', (size_t)(end - p));
                u64 llen = nl ? (u64)(nl - p) : (u64)(end - p);
                if (llen > 11 && strncmp(p, "[remote \"", 9) == 0) {
                    const char *quote = memchr(p + 9, '"', (size_t)(llen - 9));
                    if (quote) {
                        char name[128];
                        u64 nlen = (u64)(quote - (p + 9));
                        if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
                        memcpy(name, p + 9, (size_t)nlen);
                        name[nlen] = 0;
                        /* Look for following "\turl = ..." line */
                        {
                            const char *u = nl ? nl + 1 : end;
                            while (u < end) {
                                const char *u_nl = memchr(u, '\n', (size_t)(end - u));
                                u64 ulen = u_nl ? (u64)(u_nl - u) : (u64)(end - u);
                                if (ulen > 0 && u[0] == '[') break; /* next section */
                                {
                                    const char *k = u;
                                    while (k < u + ulen && (*k == ' ' || *k == '\t')) k++;
                                    if ((k + 4 <= u + ulen) && strncmp(k, "url", 3) == 0) {
                                        const char *eq = memchr(k, '=', (size_t)(u + ulen - k));
                                        if (eq) {
                                            const char *v = eq + 1;
                                            while (v < u + ulen && (*v == ' ' || *v == '\t')) v++;
                                            printf("%-12s  %.*s\n", name,
                                                   (int)(u + ulen - v), v);
                                            any = 1;
                                            break;
                                        }
                                    }
                                }
                                u = u_nl ? u_nl + 1 : end;
                            }
                        }
                    }
                }
                p = nl ? nl + 1 : end;
            }
            if (!any) printf("(no remotes)\n");
        }
        free(data);
        return 0;
    }

    /* ---- add <name> <url> ---- */
    if (strcmp(sub, "add") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: gut remote add <name> <url>\n"); return 1;
        }
        {
            char *data = NULL;
            u64 len = 0;
            char section[256];
            char append_block[1024];
            u64 total;
            char *combined;
            if (!remote_read_file(&data, &len, cfg_path)) {
                /* Fresh file */
                data = NULL;
                len = 0;
            }
            snprintf(section, sizeof(section), "[remote \"%s\"]", argv[1]);
            if (data && strstr(data, section)) {
                fprintf(stderr, "error: remote '%s' already exists\n", argv[1]);
                free(data); return 1;
            }
            snprintf(append_block, sizeof(append_block),
                     "%s[remote \"%s\"]\n\turl = %s\n",
                     (len > 0 && data[len - 1] != '\n') ? "\n" : "",
                     argv[1], argv[2]);
            total = len + (u64)strlen(append_block);
            combined = (char *)malloc((size_t)total);
            if (!combined) { free(data); return 1; }
            if (len > 0) memcpy(combined, data, (size_t)len);
            memcpy(combined + len, append_block, strlen(append_block));
            if (!remote_write_file(cfg_path, combined, total)) {
                free(combined); free(data);
                fprintf(stderr, "error: cannot write %s\n", cfg_path); return 1;
            }
            free(combined); free(data);
            printf("added remote '%s' → %s\n", argv[1], argv[2]);
            return 0;
        }
    }

    /* ---- remove <name> ---- */
    if (strcmp(sub, "remove") == 0 || strcmp(sub, "rm") == 0) {
        if (argc < 2) {
            fprintf(stderr, "usage: gut remote remove <name>\n"); return 1;
        }
        {
            char *data = NULL;
            u64 len = 0;
            char section[256];
            char *out;
            u64 out_len = 0;
            int removed = 0;
            if (!remote_read_file(&data, &len, cfg_path)) {
                fprintf(stderr, "error: no config\n"); return 1;
            }
            snprintf(section, sizeof(section), "[remote \"%s\"]", argv[1]);
            out = (char *)malloc((size_t)len + 1);
            {
                const char *p = data;
                const char *end = data + len;
                int skipping = 0;
                while (p < end) {
                    const char *nl = memchr(p, '\n', (size_t)(end - p));
                    u64 llen = nl ? (u64)(nl - p + 1) : (u64)(end - p);
                    if (llen >= strlen(section) &&
                        strncmp(p, section, strlen(section)) == 0) {
                        skipping = 1; removed = 1;
                        p += llen; continue;
                    }
                    if (skipping) {
                        if (llen > 0 && p[0] == '[') { skipping = 0; }
                        else { p += llen; continue; }
                    }
                    memcpy(out + out_len, p, (size_t)llen);
                    out_len += llen;
                    p += llen;
                }
            }
            if (!removed) {
                fprintf(stderr, "error: no remote named '%s'\n", argv[1]);
                free(out); free(data); return 1;
            }
            if (!remote_write_file(cfg_path, out, out_len)) {
                free(out); free(data);
                fprintf(stderr,
                    "error: cannot write '%s' — check file permissions\n",
                    cfg_path);
                return 1;
            }
            free(out); free(data);
            printf("removed remote '%s'\n", argv[1]);
            return 0;
        }
    }

    /* ---- set-url <name> <url> ---- */
    if (strcmp(sub, "set-url") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: gut remote set-url <name> <url>\n"); return 1;
        }
        {
            char *data = NULL;
            u64 len = 0;
            char section[256];
            char *out;
            u64 out_cap;
            u64 out_len = 0;
            int seen_section = 0;
            int updated = 0;
            if (!remote_read_file(&data, &len, cfg_path)) {
                fprintf(stderr, "error: no config\n"); return 1;
            }
            snprintf(section, sizeof(section), "[remote \"%s\"]", argv[1]);
            out_cap = len + (u64)strlen(argv[2]) + 64;
            out = (char *)malloc((size_t)out_cap);
            {
                const char *p = data;
                const char *end = data + len;
                while (p < end) {
                    const char *nl = memchr(p, '\n', (size_t)(end - p));
                    u64 llen = nl ? (u64)(nl - p + 1) : (u64)(end - p);
                    if (llen >= strlen(section) &&
                        strncmp(p, section, strlen(section)) == 0) {
                        seen_section = 1;
                        memcpy(out + out_len, p, (size_t)llen);
                        out_len += llen;
                        p += llen;
                        continue;
                    }
                    if (seen_section && !updated) {
                        const char *k = p;
                        while (k < p + llen && (*k == ' ' || *k == '\t')) k++;
                        if (k + 3 <= p + llen && strncmp(k, "url", 3) == 0) {
                            int wl = snprintf(out + out_len, (size_t)(out_cap - out_len),
                                              "\turl = %s\n", argv[2]);
                            out_len += (u64)wl;
                            updated = 1;
                            p += llen;
                            continue;
                        }
                        if (llen > 0 && p[0] == '[') seen_section = 0;
                    }
                    memcpy(out + out_len, p, (size_t)llen);
                    out_len += llen;
                    p += llen;
                }
            }
            if (!updated) {
                fprintf(stderr, "error: remote '%s' not found (or no url key)\n",
                        argv[1]);
                free(out); free(data); return 1;
            }
            if (!remote_write_file(cfg_path, out, out_len)) {
                free(out); free(data);
                fprintf(stderr,
                    "error: cannot write '%s' — check file permissions\n",
                    cfg_path);
                return 1;
            }
            free(out); free(data);
            printf("set '%s' url → %s\n", argv[1], argv[2]);
            return 0;
        }
    }

    fprintf(stderr, "usage:\n"
        "  gut remote                              list all remotes\n"
        "  gut remote add <name> <url>             add a new remote\n"
        "  gut remote remove <name>                remove a remote\n"
        "  gut remote set-url <name> <url>         update a remote's URL\n");
    return 1;
}

static int cmd_repack(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char objects_dir[2048];
    char pack_dir[2048];
    char pack_hex[GUT_OID_MAX_HEX_SIZE + 1];
    gut_oid *oids = NULL;
    u64 count = 0;
    u64 capacity = 128;
    unsigned long rc;
    DIR *d1, *d2;
    struct dirent *ent1, *ent2;
    unsigned hex_len;
    unsigned name_len;

    (void)argc;
    (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

    hex_len = gut_oid_hex_size(repo.hash_algo);
    name_len = hex_len - 2; /* filename = full hex minus 2-char dir prefix */

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
            char hex_full[GUT_OID_MAX_HEX_SIZE + 1];
            gut_oid oid;

            if (strlen(ent2->d_name) != name_len) continue;

            snprintf(hex_full, sizeof(hex_full), "%s%s", ent1->d_name, ent2->d_name);
            if (oid_from_hex_n(&oid, hex_full, hex_len) != 0) continue;

            if (count >= capacity) {
                gut_oid *tmp;
                capacity *= 2;
                tmp = (gut_oid *)realloc(oids, capacity * sizeof(gut_oid));
                if (!tmp) { free(oids); closedir(d2); closedir(d1); return 1; }
                oids = tmp;
            }
            memcpy(oids[count].bytes, oid.bytes, sizeof(oid.bytes));
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
            if (odb_object_path(path, sizeof(path), &repo.odb, &oids[i]) != 0) continue;
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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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

/* ---- gut index-pack ---- */
/* Build a .idx file for an existing .pack (replacement for git index-pack). */
static int cmd_index_pack(int argc, char **argv) {
    char pack_hex[GUT_OID_HEX_SIZE + 1];
    unsigned long rc;
    if (argc < 1) {
        fprintf(stderr, "usage: gut index-pack <pack-path>\n");
        return 1;
    }
    rc = pack_index_create(argv[0], pack_hex);
    if (rc) {
        fprintf(stderr, "error: pack_index_create failed (%lu)\n", rc);
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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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
            fprintf(stderr,
                "error: no remote configured\n"
                "  run 'gut remote add origin <url>' to set one, or pass the URL directly:\n"
                "      gut fetch <url>\n");
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
                memcpy(haves[have_count].bytes, oid.bytes, sizeof(oid.bytes));
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

        memcpy(wants[want_count].bytes, rid->bytes, sizeof(rid->bytes));
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
    rc = remote_fetch_pack_algo(url, wants, want_count, haves, have_count, pack_path,
                                0, NULL, NULL, repo.hash_algo);
    free(wants);
    free(haves);
    if (rc) {
        fprintf(stderr, "error: fetch failed (line %lu)\n", rc);
        return 1;
    }

    /* Index the pack */
    printf("Indexing pack...\n");
    if (pack_index_create_algo(pack_path, NULL, repo.hash_algo) != 0) {
        fprintf(stderr, "warning: pack indexing failed\n");
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
        unsigned hex_len = gut_oid_hex_size(repo.hash_algo);
        for (i = 0; i < remote_refs.count; i++) {
            const char *rname = remote_refs.refs[i].name;
            char ref_path[2048];
            char hex[GUT_OID_MAX_HEX_SIZE + 2];
            FILE *fp;
            if (strcmp(rname, "HEAD") == 0) continue;
            if (strncmp(rname, "refs/heads/", 11) != 0) continue;
            snprintf(ref_path, sizeof(ref_path), "%s/%s", ref_dir, rname + 11);
            oid_to_hex_n(hex, &remote_refs.refs[i].oid, hex_len);
            hex[hex_len] = '\n';
            hex[hex_len + 1] = '\0';
            fp = fopen(ref_path, "w");
            if (fp) { fputs(hex, fp); fclose(fp); }
        }
    }

    printf("done.\n");
    return 0;
}

/* ---- gut push ---- */

/* Object set: dynamic array with linear search dedup. Sufficient for MVP sizes.
 * `paths` is a parallel array of malloc'd strings, NULL per entry unless the
 * caller supplied one via oid_set_add_with_path (used by the push tree walk
 * to annotate blobs so pack_write_hinted can cluster by basename). */
typedef struct {
    gut_oid *items;
    char   **paths;
    u64 count;
    u64 capacity;
} oid_set;

static int oid_set_contains(oid_set *s, gut_oid *oid) {
    u64 i;
    for (i = 0; i < s->count; i++) {
        if (memcmp(s->items[i].bytes, oid->bytes, sizeof(oid->bytes)) == 0)
            return 1;
    }
    return 0;
}

static unsigned long oid_set_grow(oid_set *s) {
    if (s->count < s->capacity) return 0;
    u64 new_cap = s->capacity == 0 ? 64 : s->capacity * 2;
    gut_oid *ti = (gut_oid *)realloc(s->items, (size_t)(new_cap * sizeof(gut_oid)));
    if (!ti) return __LINE__;
    s->items = ti;
    char **tp = (char **)realloc(s->paths, (size_t)(new_cap * sizeof(char *)));
    if (!tp) return __LINE__;
    s->paths = tp;
    s->capacity = new_cap;
    return 0;
}

static unsigned long oid_set_add(oid_set *s, gut_oid *oid) {
    if (oid_set_contains(s, oid)) return 0;
    unsigned long rc = oid_set_grow(s);
    if (rc) return rc;
    memcpy(s->items[s->count].bytes, oid->bytes, sizeof(oid->bytes));
    s->paths[s->count] = NULL;
    s->count++;
    return 0;
}

static unsigned long oid_set_add_with_path(oid_set *s, gut_oid *oid,
                                            const char *path) {
    if (oid_set_contains(s, oid)) return 0;
    unsigned long rc = oid_set_grow(s);
    if (rc) return rc;
    memcpy(s->items[s->count].bytes, oid->bytes, sizeof(oid->bytes));
    s->paths[s->count] = path ? strdup(path) : NULL;
    s->count++;
    return 0;
}

static void oid_set_destroy(oid_set *s) {
    if (!s) return;
    if (s->paths) {
        u64 i;
        for (i = 0; i < s->count; i++) free(s->paths[i]);
        free(s->paths);
    }
    free(s->items);
    s->items = NULL;
    s->paths = NULL;
    s->count = 0;
    s->capacity = 0;
}

/* Walk a tree recursively, adding all referenced object OIDs to `result`. */
static unsigned long walk_tree_objects(oid_set *result, gut_odb *odb,
                                       gut_oid *tree_oid, const char *prefix) {
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

    rc = tree_parse_algo(&tree, obj.data.data, obj.data.len, odb->hash_algo);
    object_destroy(&obj);
    if (rc) return 0;

    for (i = 0; i < tree.count; i++) {
        if (tree.entries[i].mode == 040000) {
            char sub_prefix[2048];
            snprintf(sub_prefix, sizeof(sub_prefix), "%s%s/",
                     prefix ? prefix : "", tree.entries[i].name);
            walk_tree_objects(result, odb, &tree.entries[i].oid, sub_prefix);
        } else if (tree.entries[i].mode == 0160000) {
            /* Submodule gitlink — not in our ODB, don't try to pack it. */
            continue;
        } else {
            /* Blob: record its full path so pack_write_hinted can cluster
             * versions across commits by basename. */
            char full[2048];
            snprintf(full, sizeof(full), "%s%s",
                     prefix ? prefix : "", tree.entries[i].name);
            oid_set_add_with_path(result, &tree.entries[i].oid, full);
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

        /* Walk this commit's tree (empty prefix — tree entries are
         * relative to the repo root). */
        walk_tree_objects(result, odb, &commit.tree_oid, "");

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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

    /* Run pre-push hook — abort on non-zero exit */
    if (run_hook(&repo, "pre-push", 1) != 0) return 1;

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
            fprintf(stderr,
                "error: no remote configured\n"
                "  run 'gut remote add origin <url>' to set one, or pass the URL directly:\n"
                "      gut push <url> [--token <t>]\n");
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
    if (rc) {
        fprintf(stderr,
            "error: cannot resolve %s — make at least one commit before pushing\n",
            head_ref);
        return 1;
    }

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
                memcpy(remote_oid.bytes, remote_refs.refs[j].oid.bytes,
                       sizeof(remote_refs.refs[j].oid.bytes));
                has_remote_oid = 1;
                break;
            }
        }
    }

    /* Remote/local algo mismatch: abort with clear message. */
    if (remote_refs.count > 0 && remote_refs.hash_algo != repo.hash_algo) {
        fprintf(stderr, "error: remote hash algorithm (%s) does not match "
                        "local (%s)\n",
                remote_refs.hash_algo == GUT_HASH_SHA256 ? "sha256" : "sha1",
                repo.hash_algo == GUT_HASH_SHA256 ? "sha256" : "sha1");
        return 1;
    }

    /* Already up to date? */
    if (has_remote_oid &&
        memcmp(local_oid.bytes, remote_oid.bytes, sizeof(local_oid.bytes)) == 0) {
        printf("Already up to date.\n");
        return 0;
    }

    /* Compute object closure: walk from local_oid, stopping at remote_oid */
    {
        oid_set objects;
        char pack_dir[2048];
        char pack_hex[GUT_OID_MAX_HEX_SIZE + 1];
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
            oid_set_destroy(&objects);
            fprintf(stderr, "error: no objects to push\n");
            return 1;
        }

        printf("Packing %llu objects...\n", (unsigned long long)objects.count);

        /* Write pack to pack dir with path hints so basename clustering
         * improves delta compression across same-file versions. */
        snprintf(pack_dir, sizeof(pack_dir), "%s/objects/pack", repo.git_dir);
        rc = pack_write_hinted(pack_hex, pack_dir, &repo.odb,
                               objects.items, (const char **)objects.paths,
                               objects.count);
        oid_set_destroy(&objects);
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
        memset(update.old_oid.bytes, 0, sizeof(update.old_oid.bytes));
        memset(update.new_oid.bytes, 0, sizeof(update.new_oid.bytes));
        if (has_remote_oid) {
            memcpy(update.old_oid.bytes, remote_oid.bytes,
                   sizeof(remote_oid.bytes));
        }
        memcpy(update.new_oid.bytes, local_oid.bytes, sizeof(local_oid.bytes));
        snprintf(update.ref_name, sizeof(update.ref_name), "%s", head_ref);

        printf("Sending pack (%llu bytes) and update command...\n",
               (unsigned long long)pack_len);

        rc = remote_send_pack_algo(&server_msg, url, token, &update, 1,
                                   pack_data, pack_len, repo.hash_algo);
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

    /* Update local remote tracking ref so listeners can broadcast push events */
    {
        char ref_path[2048];
        char ref_dir[2048];
        char hex[GUT_OID_MAX_HEX_SIZE + 2];
        FILE *fp;
        unsigned hex_len = gut_oid_hex_size(repo.hash_algo);

        snprintf(ref_dir, sizeof(ref_dir), "%s/refs/remotes/origin", repo.git_dir);
#ifdef _WIN32
        {
            char tmp[2048];
            snprintf(tmp, sizeof(tmp), "%s/refs/remotes", repo.git_dir);
            _mkdir(tmp);
            _mkdir(ref_dir);
        }
#else
        {
            char tmp[2048];
            snprintf(tmp, sizeof(tmp), "%s/refs/remotes", repo.git_dir);
            mkdir(tmp, 0755);
            mkdir(ref_dir, 0755);
        }
#endif
        snprintf(ref_path, sizeof(ref_path), "%s/%s", ref_dir, branch_name);
        oid_to_hex_n(hex, &local_oid, hex_len);
        hex[hex_len] = '\n';
        hex[hex_len + 1] = '\0';
        fp = fopen(ref_path, "w");
        if (fp) { fputs(hex, fp); fclose(fp); }
    }

    printf("done.\n");
    return 0;
}

static int cmd_hash_object(int argc, char **argv) {
    gut_repo repo;
    gut_oid oid;
    char hex[GUT_OID_MAX_HEX_SIZE + 1];
    unsigned long rc;
    int do_write = 0;
    const char *file_path = NULL;
    char cwd[2048];
    gut_hash_algo algo = GUT_HASH_SHA1;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            do_write = 1;
        } else if (strcmp(argv[i], "--object-format") == 0 && i + 1 < argc) {
            const char *f = argv[++i];
            if      (strcmp(f, "sha1")   == 0) algo = GUT_HASH_SHA1;
            else if (strcmp(f, "sha256") == 0) algo = GUT_HASH_SHA256;
            else {
                fprintf(stderr, "error: unknown --object-format '%s' "
                                "(expected sha1 or sha256)\n", f);
                return 1;
            }
        } else {
            file_path = argv[i];
        }
    }

    if (!file_path) {
        fprintf(stderr, "usage: gut hash-object [-w] [--object-format sha1|sha256] <file>\n");
        return 1;
    }

    if (do_write) {
        /* -w currently only makes sense for SHA-1 (matches the repo's
         * on-disk format). SHA-256 object storage is Phase 2. */
        if (algo == GUT_HASH_SHA256) {
            fprintf(stderr, "error: -w with --object-format sha256 not yet "
                            "supported (storage pending Phase 2)\n");
            return 1;
        }
        if (!gut_getcwd(cwd, sizeof(cwd))) {
            fprintf(stderr, "error: cannot get current directory\n");
            return 1;
        }
        rc = repo_open(&repo, cwd);
        if (rc) {
            fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
            return 1;
        }

        rc = odb_write_file(&oid, &repo.odb, file_path);
        if (rc) {
            fprintf(stderr, "error: failed to hash file (line %lu)\n", rc);
            return 1;
        }
    } else {
        FILE *fp = fopen(file_path, "rb");
        long size;
        u8 *data;

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
                free(data); fclose(fp); return 1;
            }
        }
        fclose(fp);

        rc = obj_hash_algo(&oid, algo, GUT_OBJ_BLOB, data, (u64)size);
        free(data);
        if (rc) return 1;
    }

    rc = oid_to_hex_n(hex, &oid, gut_oid_hex_size(algo));
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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    if (resolve_object(&oid, &repo, object_ref)) {
        fprintf(stderr, "error: invalid object name '%s'\n", object_ref);
        return 1;
    }

    rc = odb_read(&obj, &repo.odb, &oid);
    if (rc) {
        fprintf(stderr,
            "error: object '%s' not in repository (loose + pack lookup failed, line %lu)\n",
            object_ref, rc);
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
            unsigned hex_len = gut_oid_hex_size(repo.hash_algo);
            rc = tree_parse_algo(&tree, obj.data.data, obj.data.len,
                                 repo.hash_algo);
            if (rc) { object_destroy(&obj); return 1; }
            for (u64 j = 0; j < tree.count; j++) {
                char entry_hex[GUT_OID_MAX_HEX_SIZE + 1];
                const char *entry_type = (tree.entries[j].mode == 040000) ? "tree" : "blob";
                oid_to_hex_n(entry_hex, &tree.entries[j].oid, hex_len);
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
    unsigned full_hex = gut_oid_hex_size(repo->hash_algo);

    /* Try as full hex OID (width depends on repo's algo) */
    if (strlen(ref) == full_hex) {
        rc = oid_from_hex_n(out, ref, full_hex);
        if (rc == 0) return 0;
    }

    /* Try as short SHA prefix */
    if (strlen(ref) >= 4 && strlen(ref) < full_hex) {
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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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

/* ---- gut ls-files ---- */
/* List every tracked path, one per line. Useful for scripting. */
static int cmd_ls_files(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048], index_path[2048];
    u64 i;
    (void)argc; (void)argv;

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }
    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    if (index_read(&idx, index_path) != 0) {
        fprintf(stderr, "error: cannot read index\n"); return 1;
    }
    for (i = 0; i < idx.count; i++) {
        printf("%s\n", idx.entries[i].path);
    }
    index_destroy(&idx);
    return 0;
}

/* ---- gut mv <old> <new> ---- */
/* Rename a tracked file on disk and move its index entry. Atomic vs
 * working-tree: rename the file first, then update the index. Refuses
 * if old isn't tracked, if new exists, or if old is missing on disk. */
static int cmd_mv(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    char old_wt[2048], new_wt[2048];
    struct stat st;
    u64 i, old_idx_pos = 0;
    int found = 0;
    gut_oid blob_oid;
    u32 mode, fsize, mtime;

    if (argc < 2) {
        fprintf(stderr, "usage: gut mv <old> <new>\n"); return 1;
    }
    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    if (index_read(&idx, index_path) != 0) {
        fprintf(stderr, "error: cannot read index\n"); return 1;
    }

    for (i = 0; i < idx.count; i++) {
        if (strcmp(idx.entries[i].path, argv[0]) == 0) {
            found = 1;
            old_idx_pos = i;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "error: '%s' is not tracked\n", argv[0]);
        index_destroy(&idx); return 1;
    }

    /* Reject if target already in index */
    for (i = 0; i < idx.count; i++) {
        if (strcmp(idx.entries[i].path, argv[1]) == 0) {
            fprintf(stderr, "error: '%s' is already tracked\n", argv[1]);
            index_destroy(&idx); return 1;
        }
    }

    /* Snapshot fields from old entry before removing */
    blob_oid = idx.entries[old_idx_pos].oid;
    mode = idx.entries[old_idx_pos].mode;
    fsize = idx.entries[old_idx_pos].file_size;
    mtime = idx.entries[old_idx_pos].mtime_sec;

    /* Working-tree rename (if file exists) */
    snprintf(old_wt, sizeof(old_wt), "%s/%s", repo.root_dir, argv[0]);
    snprintf(new_wt, sizeof(new_wt), "%s/%s", repo.root_dir, argv[1]);
    if (stat(new_wt, &st) == 0) {
        fprintf(stderr, "error: '%s' exists in working tree\n", argv[1]);
        index_destroy(&idx); return 1;
    }
    if (stat(old_wt, &st) == 0) {
        if (rename(old_wt, new_wt) != 0) {
            fprintf(stderr, "error: cannot rename %s → %s\n", old_wt, new_wt);
            index_destroy(&idx); return 1;
        }
    }

    /* Update index: remove old, add new with same blob_oid */
    index_remove(&idx, argv[0]);
    index_add(&idx, argv[1], &blob_oid, mode, fsize, mtime);

    if (index_write(&idx, index_path) != 0) {
        fprintf(stderr, "error: cannot write index\n");
        /* try to undo the rename */
        rename(new_wt, old_wt);
        index_destroy(&idx); return 1;
    }
    index_destroy(&idx);
    printf("renamed %s → %s\n", argv[0], argv[1]);
    return 0;
}

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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
    /* Pre-checkout HEAD snapshot — used to record the transition in
     * .git/logs/HEAD after the switch succeeds. */
    char old_head_ref[256] = "";
    gut_oid old_head_oid;
    int have_old_head = 0;

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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    /* Snapshot HEAD's current branch + OID so we can record the checkout
     * transition in .git/logs/HEAD once the switch is complete. */
    memset(&old_head_oid, 0, sizeof(old_head_oid));
    if (repo_head_ref(old_head_ref, sizeof(old_head_ref), &repo) == 0 &&
        repo_resolve_ref(&old_head_oid, &repo, old_head_ref) == 0) {
        have_old_head = 1;
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

    /* Record the transition in .git/logs/HEAD. Best-effort: reflog
     * failure doesn't roll back the checkout itself. */
    if (have_old_head) {
        char reason[256];
        const char *from_name = old_head_ref;
        if (strncmp(from_name, "refs/heads/", 11) == 0) from_name += 11;
        snprintf(reason, sizeof(reason),
                 "checkout: moving from %s to %s", from_name, argv[0]);
        (void)repo_reflog_head(&repo, &old_head_oid, &target_oid, reason);
    }

    printf("Switched to branch '%s'\n", argv[0]);
    return 0;
}

/* ---- gut add ---- */

/* ====================================================================
 *  gut feeling — predict merge conflicts from leeched peer state.
 *
 *  Walks refs/leech/<peer>/<branch> and for every staged file checks
 *  whether any peer has also modified it. Runs a 3-way merge for
 *  divergent cases: CLEAN (no peer touched it), MATCH (same change as a
 *  peer — deduplicate!), OVERLAP (both touched but merges cleanly), or
 *  CONFLICT (3-way merge emits conflict markers).
 * ==================================================================== */

typedef struct {
    char    peer_name[64];
    char    branch[256];
    gut_oid commit_oid;
    gut_oid tree_oid;
    long    commit_ts;  /* Unix seconds parsed from committer line; 0 if unknown */
} feeling_peer;

/* Parse "name <email> <ts> <tz>" → ts. Returns 0 on failure. */
static long feeling_parse_commit_ts(const char *committer_line) {
    const char *end;
    const char *space_before_tz;
    const char *space_before_ts;
    size_t len;
    if (!committer_line) return 0;
    len = strlen(committer_line);
    if (len < 2) return 0;
    end = committer_line + len;
    /* Skip trailing whitespace */
    while (end > committer_line && (end[-1] == '\n' || end[-1] == ' ')) end--;
    /* Find last space — before the timezone */
    space_before_tz = end;
    while (space_before_tz > committer_line && space_before_tz[-1] != ' ')
        space_before_tz--;
    if (space_before_tz == committer_line) return 0;
    /* Find space before that — between email> and timestamp */
    space_before_ts = space_before_tz - 1;
    while (space_before_ts > committer_line && space_before_ts[-1] != ' ')
        space_before_ts--;
    if (space_before_ts == committer_line) return 0;
    return strtol(space_before_ts, NULL, 10);
}

/* Parse "2h" | "30m" | "1d" | "45s" | "90" (seconds) → seconds.
 * Returns -1 on parse failure. */
static long feeling_parse_duration(const char *s) {
    char *end;
    long v;
    long mult = 1;
    if (!s || !*s) return -1;
    v = strtol(s, &end, 10);
    if (end == s || v < 0) return -1;
    if (*end == 'h' && end[1] == 0) mult = 3600;
    else if (*end == 'm' && end[1] == 0) mult = 60;
    else if (*end == 'd' && end[1] == 0) mult = 86400;
    else if ((*end == 's' && end[1] == 0) || *end == 0) mult = 1;
    else return -1;
    return v * mult;
}

/* Recursively descend refs/leech/<peer>/... collecting (peer, branch, oid). */
static unsigned long feeling_collect_walk(feeling_peer **out, u64 *count,
                                          u64 *cap, gut_repo *repo,
                                          const char *rel_dir_after_leech,
                                          const char *peer_name_or_null) {
    char full_dir[2048];
    DIR *d;
    struct dirent *de;

    if (rel_dir_after_leech && *rel_dir_after_leech) {
        snprintf(full_dir, sizeof(full_dir), "%s/refs/leech/%s",
                 repo->git_dir, rel_dir_after_leech);
    } else {
        snprintf(full_dir, sizeof(full_dir), "%s/refs/leech", repo->git_dir);
    }

    d = opendir(full_dir);
    if (!d) return 0; /* no leech refs at all */

    while ((de = readdir(d)) != NULL) {
        struct stat st;
        char child_path[2048];
        char child_rel[1024];

        if (de->d_name[0] == '.' &&
            (de->d_name[1] == 0 || (de->d_name[1] == '.' && de->d_name[2] == 0)))
            continue;

        snprintf(child_path, sizeof(child_path), "%s/%s", full_dir, de->d_name);
        if (stat(child_path, &st) != 0) continue;

        if (rel_dir_after_leech && *rel_dir_after_leech) {
            snprintf(child_rel, sizeof(child_rel), "%s/%s",
                     rel_dir_after_leech, de->d_name);
        } else {
            snprintf(child_rel, sizeof(child_rel), "%s", de->d_name);
        }

        if (S_ISDIR(st.st_mode)) {
            const char *next_peer = peer_name_or_null ? peer_name_or_null : de->d_name;
            feeling_collect_walk(out, count, cap, repo, child_rel, next_peer);
        } else if (S_ISREG(st.st_mode) && peer_name_or_null) {
            /* Read OID from the ref file */
            FILE *rf = fopen(child_path, "r");
            char hex[GUT_OID_HEX_SIZE + 2];
            if (!rf) continue;
            if (fgets(hex, sizeof(hex), rf) != NULL) {
                size_t L = strlen(hex);
                while (L > 0 && (hex[L - 1] == '\n' || hex[L - 1] == '\r' ||
                                 hex[L - 1] == ' '  || hex[L - 1] == '\t')) {
                    hex[--L] = 0;
                }
                if (L == GUT_OID_HEX_SIZE) {
                    feeling_peer p;
                    gut_object commit_obj;
                    gut_commit  commit;
                    memset(&p, 0, sizeof(p));
                    if (oid_from_hex(&p.commit_oid, hex) != 0) { fclose(rf); continue; }
                    if (odb_read(&commit_obj, &repo->odb, &p.commit_oid) != 0) {
                        fclose(rf); continue;
                    }
                    if (commit_parse(&commit, commit_obj.data.data, commit_obj.data.len) != 0) {
                        object_destroy(&commit_obj);
                        fclose(rf); continue;
                    }
                    p.tree_oid = commit.tree_oid;
                    p.commit_ts = feeling_parse_commit_ts(commit.committer);
                    commit_destroy(&commit);
                    object_destroy(&commit_obj);

                    snprintf(p.peer_name, sizeof(p.peer_name), "%s", peer_name_or_null);
                    /* branch = child_rel minus the leading "<peer>/" */
                    {
                        const char *br = child_rel;
                        size_t pnl = strlen(peer_name_or_null);
                        if (strncmp(br, peer_name_or_null, pnl) == 0 && br[pnl] == '/') {
                            br = br + pnl + 1;
                        }
                        snprintf(p.branch, sizeof(p.branch), "%s", br);
                    }

                    if (*count == *cap) {
                        *cap = *cap ? *cap * 2 : 8;
                        *out = (feeling_peer *)realloc(*out, *cap * sizeof(feeling_peer));
                        if (!*out) { fclose(rf); closedir(d); return __LINE__; }
                    }
                    (*out)[(*count)++] = p;
                }
            }
            fclose(rf);
        }
    }
    closedir(d);
    return 0;
}

static unsigned long feeling_collect(feeling_peer **out, u64 *out_count,
                                     gut_repo *repo) {
    u64 cap = 0;
    *out = NULL;
    *out_count = 0;
    return feeling_collect_walk(out, out_count, &cap, repo, "", NULL);
}

typedef enum {
    FEELING_CLEAN    = 0,
    FEELING_MATCH    = 1,  /* peer made the same change */
    FEELING_OVERLAP  = 2,  /* both changed, auto-merge clean */
    FEELING_CONFLICT = 3   /* 3-way merge produces conflict markers */
} feeling_level;

/* Print the first conflict hunk from a diff3-merged text, indented. */
static void feeling_print_first_conflict(const char *merged, u64 len) {
    const char *start = NULL;
    const char *end = NULL;
    const char *p;
    u64 i;

    for (i = 0; i + 7 <= len; i++) {
        if (merged[i] == '<' && memcmp(merged + i, "<<<<<<<", 7) == 0) {
            start = merged + i;
            while (start > merged && start[-1] != '\n') start--;
            break;
        }
    }
    if (!start) return;

    for (i = (u64)(start - merged); i + 7 <= len; i++) {
        if (merged[i] == '>' && memcmp(merged + i, ">>>>>>>", 7) == 0) {
            p = merged + i + 7;
            while (p < merged + len && *p != '\n') p++;
            if (p < merged + len) p++;
            end = p;
            break;
        }
    }
    if (!end) end = merged + len;

    printf("      |");
    for (p = start; p < end; p++) {
        putchar(*p);
        if (*p == '\n' && p + 1 < end) printf("      |");
    }
    if (end > start && end[-1] != '\n') putchar('\n');
}

/* Core check: iterate staged files against all leech peers.
 *
 *   verbose_all:   print MATCH / OVERLAP rows too (not just CONFLICT)
 *   show_preview:  on CONFLICT rows, print the first conflict hunk
 *   only_path:     NULL means check everything; else restrict to this path
 *   out_*_counts:  receive totals (all optional, may be NULL)
 *
 * Returns 0 on success; non-zero on setup failure. Peer/file errors are
 * swallowed (the check is advisory).
 */
static int cmd_offer_patch(const char *url, const char *path,
                           const char *token, const char *sender_name,
                           const char *fetch_url);

static unsigned long feeling_check_index(gut_repo *repo, gut_index *idx,
                                         int verbose_all, int show_preview,
                                         const char *only_path,
                                         long min_commit_ts,
                                         const char *offer_to_url,
                                         const char *offer_as_name,
                                         int *out_conflicts, int *out_overlaps,
                                         int *out_matches,   int *out_checked) {
    char head_ref[256];
    gut_oid head_oid;
    gut_object head_obj;
    gut_commit head_commit;
    int have_head = 0;
    feeling_peer *peers = NULL;
    u64 peer_count = 0;
    u64 i;
    int n_conflict = 0, n_overlap = 0, n_match = 0, n_checked = 0;

    if (out_conflicts) *out_conflicts = 0;
    if (out_overlaps)  *out_overlaps  = 0;
    if (out_matches)   *out_matches   = 0;
    if (out_checked)   *out_checked   = 0;

    if (repo_head_ref(head_ref, sizeof(head_ref), repo) == 0 &&
        repo_resolve_ref(&head_oid, repo, head_ref) == 0 &&
        odb_read(&head_obj, &repo->odb, &head_oid) == 0) {
        if (commit_parse(&head_commit, head_obj.data.data, head_obj.data.len) == 0) {
            have_head = 1;
        }
        object_destroy(&head_obj);
    }

    feeling_collect(&peers, &peer_count, repo);
    if (peer_count == 0) {
        if (have_head) commit_destroy(&head_commit);
        free(peers);
        return 0; /* no peers — silently successful */
    }

    for (i = 0; i < idx->count; i++) {
        const char *path = idx->entries[i].path;
        gut_oid *my_blob = &idx->entries[i].oid;
        gut_oid  head_blob;
        int have_head_blob = 0;
        u64 pi;

        if (only_path && strcmp(only_path, path) != 0) continue;

        if (have_head) {
            if (tree_lookup_path(&head_blob, &repo->odb,
                                 &head_commit.tree_oid, path) == 0) {
                have_head_blob = 1;
            }
        }

        if (have_head_blob) {
            long cmp;
            oid_compare(&cmp, &head_blob, my_blob);
            if (cmp == 0) continue; /* no staged change */
        }

        n_checked++;

        for (pi = 0; pi < peer_count; pi++) {
            feeling_peer *p = &peers[pi];
            gut_oid peer_blob;
            long c_my_peer, c_head_peer;
            feeling_level level = FEELING_CLEAN;
            diff_merge_result mr_saved;
            int have_mr = 0;

            if (min_commit_ts > 0 && p->commit_ts > 0 &&
                p->commit_ts < min_commit_ts) continue; /* too old */

            if (tree_lookup_path(&peer_blob, &repo->odb,
                                 &p->tree_oid, path) != 0) continue;

            if (have_head_blob) {
                oid_compare(&c_head_peer, &head_blob, &peer_blob);
                if (c_head_peer == 0) continue; /* peer on same version */
            }

            oid_compare(&c_my_peer, my_blob, &peer_blob);
            if (c_my_peer == 0) {
                level = FEELING_MATCH;
            } else if (have_head_blob) {
                gut_object b_obj, o_obj, t_obj;
                int read_ok = 1;
                if (odb_read(&b_obj, &repo->odb, &head_blob) != 0) read_ok = 0;
                if (read_ok && odb_read(&o_obj, &repo->odb, my_blob) != 0) {
                    object_destroy(&b_obj); read_ok = 0;
                }
                if (read_ok && odb_read(&t_obj, &repo->odb, &peer_blob) != 0) {
                    object_destroy(&b_obj); object_destroy(&o_obj); read_ok = 0;
                }
                if (!read_ok) { level = FEELING_OVERLAP; }
                else {
                    char theirs_label[128];
                    snprintf(theirs_label, sizeof(theirs_label),
                             "%s/%s", p->peer_name, p->branch);
                    if (diff_three_way(&mr_saved,
                            (const char *)b_obj.data.data, b_obj.data.len,
                            (const char *)o_obj.data.data, o_obj.data.len,
                            (const char *)t_obj.data.data, t_obj.data.len,
                            "me", theirs_label,
                            DIFF_MERGE_STYLE_STANDARD) == 0) {
                        level = mr_saved.has_conflicts ? FEELING_CONFLICT
                                                       : FEELING_OVERLAP;
                        have_mr = 1;
                    } else {
                        level = FEELING_OVERLAP;
                    }
                    object_destroy(&b_obj);
                    object_destroy(&o_obj);
                    object_destroy(&t_obj);
                }
            } else {
                level = FEELING_CONFLICT; /* both newly added with different content */
            }

            switch (level) {
            case FEELING_MATCH:
                if (verbose_all) {
                    printf("  [MATCH]    %-40s  same change as %s/%s\n",
                           path, p->peer_name, p->branch);
                }
                n_match++;
                break;
            case FEELING_OVERLAP:
                if (verbose_all) {
                    printf("  [OVERLAP]  %-40s  touched by %s/%s (auto-merges)\n",
                           path, p->peer_name, p->branch);
                }
                n_overlap++;
                break;
            case FEELING_CONFLICT:
                if (verbose_all || show_preview) {
                    printf("  [CONFLICT] %-40s  conflicts with %s/%s\n",
                           path, p->peer_name, p->branch);
                }
                n_conflict++;
                if (show_preview && have_mr) {
                    feeling_print_first_conflict(mr_saved.data, mr_saved.len);
                }
                if (offer_to_url) {
                    printf("  → auto-offering %s to %s\n", path, offer_to_url);
                    cmd_offer_patch(offer_to_url, path, NULL,
                                    offer_as_name ? offer_as_name : "peer",
                                    NULL /* inline only from feeling auto-offer */);
                }
                break;
            case FEELING_CLEAN:
                break;
            }

            if (have_mr) diff_merge_destroy(&mr_saved);
        }
    }

    if (out_conflicts) *out_conflicts = n_conflict;
    if (out_overlaps)  *out_overlaps  = n_overlap;
    if (out_matches)   *out_matches   = n_match;
    if (out_checked)   *out_checked   = n_checked;

    if (have_head) commit_destroy(&head_commit);
    free(peers);
    return 0;
}

/* Lightweight wrapper used by cmd_add — prints a terse heads-up only when
 * at least one conflict is found. Silent otherwise. Called with the index
 * already loaded so we don't re-read it. */
static void feeling_post_add_hint(gut_repo *repo, gut_index *idx) {
    int n_conflict = 0, n_overlap = 0, n_match = 0, n_checked = 0;
    /* Silent mode: only CONFLICT lines get printed, no MATCH/OVERLAP noise. */
    feeling_check_index(repo, idx, 0, 0, NULL, 0, NULL, NULL,
                        &n_conflict, &n_overlap, &n_match, &n_checked);
    if (n_conflict > 0) {
        printf("gut feeling: %d conflict(s) detected — "
               "run `gut feeling` for preview\n", n_conflict);
    }
}

/* For `gut status` peer section: print each peer's branch tip and up to
 * MAX_LIST files that differ from HEAD's tree. */
static void feeling_print_status_peers(gut_repo *repo, long min_commit_ts) {
    feeling_peer *peers = NULL;
    u64 peer_count = 0;
    char head_ref[256];
    gut_oid head_oid;
    gut_object head_obj;
    gut_commit head_commit;
    int have_head = 0;
    u64 pi;
    int any_printed = 0;
    enum { MAX_LIST = 10 };

    if (feeling_collect(&peers, &peer_count, repo) != 0) { free(peers); return; }
    if (peer_count == 0) { free(peers); return; }

    if (repo_head_ref(head_ref, sizeof(head_ref), repo) == 0 &&
        repo_resolve_ref(&head_oid, repo, head_ref) == 0 &&
        odb_read(&head_obj, &repo->odb, &head_oid) == 0) {
        if (commit_parse(&head_commit, head_obj.data.data, head_obj.data.len) == 0) {
            have_head = 1;
        }
        object_destroy(&head_obj);
    }

    for (pi = 0; pi < peer_count; pi++) {
        feeling_peer *p = &peers[pi];
        gut_index peer_idx;
        u64 i;
        int shown = 0;
        u64 diff_count = 0;

        if (min_commit_ts > 0 && p->commit_ts > 0 &&
            p->commit_ts < min_commit_ts) continue;

        if (index_read_tree(&peer_idx, &repo->odb, &p->tree_oid) != 0) continue;

        for (i = 0; i < peer_idx.count; i++) {
            gut_oid head_blob;
            int same_in_head = 0;
            if (have_head &&
                tree_lookup_path(&head_blob, &repo->odb,
                                 &head_commit.tree_oid,
                                 peer_idx.entries[i].path) == 0) {
                long cmp;
                oid_compare(&cmp, &head_blob, &peer_idx.entries[i].oid);
                if (cmp == 0) same_in_head = 1;
            }
            if (same_in_head) continue;
            diff_count++;
        }

        if (diff_count == 0) { index_destroy(&peer_idx); continue; }

        if (!any_printed) {
            printf("\nPeer activity (leech refs diverged from HEAD):\n");
            any_printed = 1;
        }

        if (p->commit_ts > 0) {
            long age = (long)time(NULL) - p->commit_ts;
            char age_s[32];
            if (age < 60) snprintf(age_s, sizeof(age_s), "%lds", age);
            else if (age < 3600) snprintf(age_s, sizeof(age_s), "%ldm", age / 60);
            else if (age < 86400) snprintf(age_s, sizeof(age_s), "%ldh", age / 3600);
            else snprintf(age_s, sizeof(age_s), "%ldd", age / 86400);
            printf("  %s/%s  (%s ago, %llu file%s changed)\n",
                   p->peer_name, p->branch, age_s,
                   (unsigned long long)diff_count,
                   diff_count == 1 ? "" : "s");
        } else {
            printf("  %s/%s  (%llu file%s changed)\n",
                   p->peer_name, p->branch,
                   (unsigned long long)diff_count,
                   diff_count == 1 ? "" : "s");
        }

        for (i = 0; i < peer_idx.count && shown < MAX_LIST; i++) {
            gut_oid head_blob;
            int same_in_head = 0;
            if (have_head &&
                tree_lookup_path(&head_blob, &repo->odb,
                                 &head_commit.tree_oid,
                                 peer_idx.entries[i].path) == 0) {
                long cmp;
                oid_compare(&cmp, &head_blob, &peer_idx.entries[i].oid);
                if (cmp == 0) same_in_head = 1;
            }
            if (same_in_head) continue;
            printf("      %s\n", peer_idx.entries[i].path);
            shown++;
        }
        if (diff_count > (u64)MAX_LIST) {
            printf("      ... and %llu more\n",
                   (unsigned long long)(diff_count - MAX_LIST));
        }

        index_destroy(&peer_idx);
    }

    if (have_head) commit_destroy(&head_commit);
    free(peers);
}

static int cmd_feeling(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char idx_path[2048];
    const char *only_path = NULL;
    const char *offer_to_url = NULL;
    const char *offer_as_name = NULL;
    int n_conflict = 0, n_overlap = 0, n_match = 0, n_checked = 0;
    feeling_peer *peers_tmp = NULL;
    u64 peers_tmp_count = 0;
    long min_commit_ts = 0;
    int ai;

    for (ai = 0; ai < argc; ai++) {
        if (strcmp(argv[ai], "--since") == 0 && ai + 1 < argc) {
            long sec = feeling_parse_duration(argv[++ai]);
            if (sec < 0) {
                fprintf(stderr, "error: bad --since duration '%s' (try 2h, 1d, 30m, 45s)\n",
                        argv[ai]);
                return 1;
            }
            min_commit_ts = (long)time(NULL) - sec;
        } else if (strcmp(argv[ai], "--offer-to") == 0 && ai + 1 < argc) {
            offer_to_url = argv[++ai];
        } else if (strcmp(argv[ai], "--as") == 0 && ai + 1 < argc) {
            offer_as_name = argv[++ai];
        } else if (argv[ai][0] != '-') {
            only_path = argv[ai];
        }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get cwd\n"); return 1;
    }
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    snprintf(idx_path, sizeof(idx_path), "%s/index", repo.git_dir);
    if (index_read(&idx, idx_path) != 0) {
        fprintf(stderr, "error: cannot read index\n"); return 1;
    }

    /* Peek at peer count for a meaningful banner (after --since filter) */
    feeling_collect(&peers_tmp, &peers_tmp_count, &repo);
    {
        u64 filtered = 0;
        if (min_commit_ts > 0) {
            u64 j;
            for (j = 0; j < peers_tmp_count; j++) {
                if (peers_tmp[j].commit_ts == 0 ||
                    peers_tmp[j].commit_ts >= min_commit_ts) filtered++;
            }
        } else {
            filtered = peers_tmp_count;
        }
        if (filtered == 0) {
            if (peers_tmp_count == 0) {
                printf("no leech refs found under refs/leech/\n");
                printf("  start `gut listen` and have peers run `gut leech ws://you...`\n");
            } else {
                printf("no peer activity within --since window\n");
            }
            index_destroy(&idx);
            free(peers_tmp);
            return 0;
        }
        printf("gut feeling — checking %llu staged path(s) against %llu peer ref(s)\n\n",
               (unsigned long long)idx.count, (unsigned long long)filtered);
    }
    free(peers_tmp);

    feeling_check_index(&repo, &idx, 1, 1, only_path, min_commit_ts,
                        offer_to_url, offer_as_name,
                        &n_conflict, &n_overlap, &n_match, &n_checked);

    printf("\n");
    if (n_checked == 0) {
        printf("no staged changes to check\n");
    } else if (n_conflict + n_overlap + n_match == 0) {
        printf("looks good — none of %d staged path(s) overlap with any peer\n",
               n_checked);
    } else {
        printf("summary: %d conflict, %d overlap, %d match (across %d staged path(s))\n",
               n_conflict, n_overlap, n_match, n_checked);
    }

    index_destroy(&idx);
    return n_conflict > 0 ? 2 : 0;
}

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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    idx.hash_algo = repo.hash_algo;
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
    if (rc) {
        index_destroy(&idx);
        fprintf(stderr, "error: cannot write index (line %lu)\n", rc);
        return 1;
    }

    /* Post-add feeling check: terse warning only when a peer's work
     * collides with what we just staged. Silenced by GUT_NO_FEELING=1
     * for users who don't want this (e.g. in scripts). */
    if (!getenv("GUT_NO_FEELING")) {
        feeling_post_add_hint(&repo, &idx);
    }
    index_destroy(&idx);

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
    char hex[GUT_OID_MAX_HEX_SIZE + 1];
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
    unsigned hex_len;

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
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    /* Run pre-commit hook; abort if it fails */
    if (run_hook(&repo, "pre-commit", 1) != 0) return 1;

    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    idx.hash_algo = repo.hash_algo;
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

    hex_len = gut_oid_hex_size(repo.hash_algo);

    /* tree <hex>\n */
    oid_to_hex_n(hex, &tree_oid, hex_len);
    buf_append(&commit_buf, (u8 *)"tree ", 5);
    buf_append(&commit_buf, (u8 *)hex, hex_len);
    buf_append_byte(&commit_buf, '\n');

    /* parent <hex>\n (if exists) */
    if (has_parent) {
        oid_to_hex_n(hex, &parent_oid, hex_len);
        buf_append(&commit_buf, (u8 *)"parent ", 7);
        buf_append(&commit_buf, (u8 *)hex, hex_len);
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
    {
        char reflog_reason[512];
        snprintf(reflog_reason, sizeof(reflog_reason),
                 has_parent ? "commit: %s" : "commit (initial): %s",
                 message);
        rc = repo_update_ref(&repo, head_ref, &commit_oid, reflog_reason);
    }
    if (rc) {
        fprintf(stderr, "error: cannot update ref (line %lu)\n", rc);
        return 1;
    }

    oid_to_hex_n(hex, &commit_oid, hex_len);
    printf("[%s %.*s] %s\n",
           has_parent ? "main" : "(root-commit)",
           7, hex, message);

    /* Post-commit hook — advisory, can't abort (we've already committed). */
    run_hook(&repo, "post-commit", 0);

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
    int oneline = 0;
    int graph = 0;
    int ai;

    for (ai = 0; ai < argc; ai++) {
        if (strcmp(argv[ai], "--oneline") == 0) oneline = 1;
        else if (strcmp(argv[ai], "--graph") == 0) graph = 1;
        else if (strcmp(argv[ai], "-n") == 0 && ai + 1 < argc) {
            max_count = atoi(argv[++ai]);
        }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) {
        fprintf(stderr, "error: cannot read HEAD\n");
        return 1;
    }

    rc = repo_resolve_ref(&current_oid, &repo, head_ref);
    if (rc) {
        fprintf(stderr, "fatal: HEAD points to an unborn branch — no commits yet (run 'gut commit' first)\n");
        return 1;
    }

    /* Load .git/shallow list — commits that should be treated as parentless. */
    gut_oid *shallow_list = NULL;
    u64 shallow_count = 0;
    {
        char sh_path[2048];
        FILE *sf;
        snprintf(sh_path, sizeof(sh_path), "%s/shallow", repo.git_dir);
        sf = fopen(sh_path, "r");
        if (sf) {
            char line[128];
            u64 cap = 0;
            while (fgets(line, sizeof(line), sf)) {
                size_t L = strlen(line);
                while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r'))
                    line[--L] = 0;
                if (L != GUT_OID_HEX_SIZE) continue;
                if (shallow_count == cap) {
                    cap = cap ? cap * 2 : 8;
                    shallow_list = (gut_oid *)realloc(shallow_list,
                                                      cap * sizeof(gut_oid));
                }
                if (shallow_list && oid_from_hex(&shallow_list[shallow_count],
                                                 line) == 0) {
                    shallow_count++;
                }
            }
            fclose(sf);
        }
    }

    while (1) {
        gut_object obj;
        gut_commit commit;
        char hex[GUT_OID_MAX_HEX_SIZE + 1];
        int at_boundary = 0;
        u64 k;
        unsigned hex_len = gut_oid_hex_size(repo.hash_algo);

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

        oid_to_hex_n(hex, &current_oid, hex_len);

        for (k = 0; k < shallow_count; k++) {
            long cmp;
            oid_compare(&cmp, &current_oid, &shallow_list[k]);
            if (cmp == 0) { at_boundary = 1; break; }
        }

        if (oneline) {
            const char *subject = commit.message ? commit.message : "";
            const char *nl = strchr(subject, '\n');
            int subj_len = nl ? (int)(nl - subject) : (int)strlen(subject);
            if (graph) printf("* ");
            printf("%.7s %.*s%s\n",
                   hex, subj_len, subject,
                   at_boundary ? "  [shallow]" : "");
        } else {
            if (graph) printf("* ");
            printf("commit %s%s\n", hex, at_boundary ? "  [shallow]" : "");
            if (commit.author) printf("%sAuthor: %s\n", graph ? "| " : "", commit.author);
            printf("%s\n", graph ? "|" : "");
            if (commit.message) printf("%s    %s\n", graph ? "| " : "", commit.message);
            printf("%s\n", graph ? "|" : "");
        }

        shown++;

        if (at_boundary || commit.parent_count == 0) {
            commit_destroy(&commit);
            break;
        }
        memcpy(current_oid.bytes, commit.parent_oids[0].bytes,
               sizeof(current_oid.bytes));
        commit_destroy(&commit);
    }

    free(shallow_list);

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

/* Accumulate insert/delete line counts for a file pair into (ins, del). */
static void diff_tally(int *ins, int *del,
                       const u8 *a, u64 al, const u8 *b, u64 bl) {
    diff_result r;
    u64 i;
    if (diff_patience(&r, (const char *)a, al, (const char *)b, bl) != 0) return;
    for (i = 0; i < r.len; i++) {
        if (r.edits[i].op == DIFF_INSERT) *ins += (int)r.edits[i].len;
        else if (r.edits[i].op == DIFF_DELETE) *del += (int)r.edits[i].len;
    }
    diff_destroy(&r);
}

typedef struct {
    char *path;
    int   ins;
    int   del;
} stat_row;

/* Either emit a unified hunk or tally lines, depending on stat_mode. */
static void diff_emit(int stat_mode, stat_row **rows, int *n_rows,
                      const char *path,
                      const u8 *a, u64 al, const u8 *b, u64 bl) {
    if (!stat_mode) {
        diff_file_pair(path, a, al, b, bl);
        return;
    }
    {
        stat_row r;
        r.ins = 0; r.del = 0;
        diff_tally(&r.ins, &r.del, a, al, b, bl);
        if (r.ins + r.del == 0) return;
        {
            size_t n = (size_t)strlen(path) + 1;
            r.path = (char *)malloc(n);
            if (!r.path) return;
            memcpy(r.path, path, n);
        }
        *rows = (stat_row *)realloc(*rows, (*n_rows + 1) * sizeof(stat_row));
        if (!*rows) { free(r.path); return; }
        (*rows)[(*n_rows)++] = r;
    }
}

/* Print stat summary — paths left-aligned, change count, proportional
 * +/- bars. Mirrors git's layout. */
static void diff_stat_print(const stat_row *rows, int n_rows) {
    int i;
    int max_path_len = 0;
    int max_change = 1;
    int total_ins = 0, total_del = 0;
    const int BAR_WIDTH = 40;

    for (i = 0; i < n_rows; i++) {
        int pl = (int)strlen(rows[i].path);
        if (pl > max_path_len) max_path_len = pl;
        if (rows[i].ins + rows[i].del > max_change) max_change = rows[i].ins + rows[i].del;
        total_ins += rows[i].ins;
        total_del += rows[i].del;
    }

    for (i = 0; i < n_rows; i++) {
        int total = rows[i].ins + rows[i].del;
        int bar = total * BAR_WIDTH / max_change;
        int pluses = total > 0 ? (rows[i].ins * bar + total / 2) / total : 0;
        int minuses = bar - pluses;
        if (total > 0 && bar == 0) bar = 1;
        if (rows[i].ins > 0 && pluses == 0) pluses = 1;
        if (rows[i].del > 0 && minuses == 0) minuses = 1;
        printf(" %-*s | %4d ", max_path_len, rows[i].path, total);
        {
            int k;
            for (k = 0; k < pluses; k++) putchar('+');
            for (k = 0; k < minuses; k++) putchar('-');
        }
        putchar('\n');
    }
    if (n_rows > 0) {
        printf(" %d file%s changed, %d insertion%s(+), %d deletion%s(-)\n",
               n_rows, n_rows == 1 ? "" : "s",
               total_ins, total_ins == 1 ? "" : "s",
               total_del, total_del == 1 ? "" : "s");
    }
}

/* ---- gut reflog ---- */

/* Read `.git/logs/<ref>` and print one line per entry in reverse order
 * (newest first), indexed as <ref>@{0}, <ref>@{1}, ....
 *
 * Each stored line is:
 *   <old-hex> SP <new-hex> SP <name> SP "<" email ">" SP
 *   <unix-ts> SP <tz-offset> TAB <reason> LF
 *
 * We print the git-style compact form:
 *   <short-new> <ref>@{N}: <reason>
 *
 * For each line except the very first (which records creation), the
 * "new" hex is what HEAD/ref pointed at after that update — which is
 * the useful OID to dereference if the user wants to undo.
 *
 * With -n <count> we cap output; with no args the ref defaults to HEAD. */
static int cmd_reflog(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char log_path[2048];
    const char *ref = "HEAD";
    int max_count = -1;
    int ai;
    unsigned long rc;
    FILE *fp;
    long fsize;
    char *buf_all = NULL;
    size_t n_read;
    long *line_starts = NULL;
    int n_lines = 0;
    int cap = 0;
    long i_scan;
    int i_emit;
    int shown = 0;
    unsigned hex_len;

    for (ai = 0; ai < argc; ai++) {
        if (strcmp(argv[ai], "-n") == 0 && ai + 1 < argc) {
            max_count = atoi(argv[++ai]);
        } else if (argv[ai][0] != '-') {
            ref = argv[ai];
        }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    hex_len = gut_oid_hex_size(repo.hash_algo);

    snprintf(log_path, sizeof(log_path), "%s/logs/%s", repo.git_dir, ref);

    fp = fopen(log_path, "rb");
    if (!fp) {
        /* No reflog yet — not an error, just empty. Match git's behavior
         * when the log file simply hasn't been created. */
        return 0;
    }

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 1; }
    fsize = ftell(fp);
    if (fsize < 0) { fclose(fp); return 1; }
    if (fsize == 0) { fclose(fp); return 0; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return 1; }

    buf_all = (char *)malloc((size_t)fsize);
    if (!buf_all) { fclose(fp); return 1; }
    n_read = fread(buf_all, 1, (size_t)fsize, fp);
    fclose(fp);
    if (n_read != (size_t)fsize) { free(buf_all); return 1; }

    /* Index start of each line (byte after previous '\n', or 0 for the
     * first). We'll walk the list in reverse to emit newest-first. */
    for (i_scan = 0; i_scan < fsize; ) {
        long start = i_scan;
        while (i_scan < fsize && buf_all[i_scan] != '\n') i_scan++;
        if (i_scan < fsize) i_scan++;   /* past the LF */
        if (n_lines == cap) {
            int new_cap = cap ? cap * 2 : 64;
            long *grown = (long *)realloc(line_starts,
                                          (size_t)new_cap * sizeof(long));
            if (!grown) { free(buf_all); free(line_starts); return 1; }
            line_starts = grown;
            cap = new_cap;
        }
        line_starts[n_lines++] = start;
    }

    /* Emit newest-first as <short-new> <ref>@{N}: <reason>. */
    for (i_emit = n_lines - 1; i_emit >= 0; i_emit--) {
        long start = line_starts[i_emit];
        long end = (i_emit + 1 < n_lines) ? line_starts[i_emit + 1] : fsize;
        long lineno_from_newest = (n_lines - 1) - i_emit;
        const char *line = buf_all + start;
        long llen = end - start;
        const char *p;
        const char *tab;
        const char *new_hex;
        const char *reason;
        long reason_len;

        /* Trim trailing LF/CR. */
        while (llen > 0 && (line[llen - 1] == '\n' || line[llen - 1] == '\r'))
            llen--;
        if (llen <= (long)(hex_len * 2 + 2)) continue;   /* malformed */

        /* Positions: old-hex starts at 0, new-hex at hex_len + 1.
         * Reason follows a TAB; everything up to the TAB is the prefix. */
        new_hex = line + hex_len + 1;

        tab = NULL;
        for (p = line; p < line + llen; p++) {
            if (*p == '\t') { tab = p; break; }
        }
        if (!tab) continue;
        reason = tab + 1;
        reason_len = (line + llen) - reason;

        printf("%.7s %s@{%ld}: %.*s\n",
               new_hex, ref, lineno_from_newest,
               (int)reason_len, reason);

        shown++;
        if (max_count > 0 && shown >= max_count) break;
    }

    free(line_starts);
    free(buf_all);
    return 0;
}

static int cmd_diff(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    char cwd[2048];
    char index_path[2048];
    unsigned long rc;
    int staged = 0;
    int stat_mode = 0;
    stat_row *rows = NULL;
    int n_rows = 0;
    u64 i;

    for (i = 0; i < (u64)argc; i++) {
        if (strcmp(argv[i], "--staged") == 0 || strcmp(argv[i], "--cached") == 0)
            staged = 1;
        else if (strcmp(argv[i], "--stat") == 0)
            stat_mode = 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
                    diff_emit(stat_mode, &rows, &n_rows,
                              idx.entries[i].path, NULL, 0,
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

                diff_emit(stat_mode, &rows, &n_rows,
                          idx.entries[i].path,
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

                diff_emit(stat_mode, &rows, &n_rows,
                          idx.entries[i].path,
                          old_blob.data.data, old_blob.data.len,
                          new_data, (u64)(size > 0 ? size : 0));
                free(new_data);
                object_destroy(&old_blob);
            }
        }
    }

    if (stat_mode) {
        int r;
        diff_stat_print(rows, n_rows);
        for (r = 0; r < n_rows; r++) free(rows[r].path);
        free(rows);
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
    long min_commit_ts = 0;
    int ai;

    for (ai = 0; ai < argc; ai++) {
        if (strcmp(argv[ai], "--since") == 0 && ai + 1 < argc) {
            long sec = feeling_parse_duration(argv[++ai]);
            if (sec < 0) {
                fprintf(stderr, "error: bad --since duration '%s' (try 2h, 1d, 30m)\n",
                        argv[ai]);
                return 1;
            }
            min_commit_ts = (long)time(NULL) - sec;
        }
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
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
    idx.hash_algo = repo.hash_algo;
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

    /* Peer activity section (leech-derived). Silent if no peers. */
    feeling_print_status_peers(&repo, min_commit_ts);

    printf("\n");
    return 0;
}

/* ---- gut last ---- */

/* ---- gut wip ---- */
/* Convenience: `gut wip [<note>]` commits currently-staged changes with
 * a "WIP:" message prefix. If no note, uses the current timestamp. */
static int cmd_wip(int argc, char **argv) {
    char msg[256];
    char *sub_argv[2];
    if (argc > 0 && argv[0][0] != '-') {
        snprintf(msg, sizeof(msg), "WIP: %s", argv[0]);
    } else {
        time_t now = time(NULL);
        struct tm *lt = localtime(&now);
        strftime(msg, sizeof(msg), "WIP: %Y-%m-%d %H:%M:%S", lt);
    }
    sub_argv[0] = (char *)"-m";
    sub_argv[1] = msg;
    return cmd_commit(2, sub_argv);
}

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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }

    rc = repo_resolve_ref(&head_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "fatal: HEAD points to an unborn branch — no commits yet (run 'gut commit' first)\n"); return 1; }

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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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

    {
        char reflog_reason[512];
        snprintf(reflog_reason, sizeof(reflog_reason),
                 "commit (amend): %s", message);
        rc = repo_update_ref(&repo, head_ref, &new_commit_oid, reflog_reason);
    }
    if (rc) { fprintf(stderr, "error: cannot update ref\n"); return 1; }

    oid_to_hex(hex, &new_commit_oid);
    printf("[%.*s] %s\n", 7, hex, message);
    return 0;
}

/* ---- gut squash ---- */
/* Collapse the last N commits into one. New commit has HEAD's tree
 * (no changes discarded) and the Nth ancestor's parent as its parent.
 * Message defaults to a concatenation of the squashed subjects; -m
 * overrides. Refuses if any of the squashed commits is a merge. */
static int cmd_squash(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    gut_oid tree_oid, new_commit_oid, head_oid;
    char cwd[2048], index_path[2048], obj_dir[2048], head_ref[256];
    char hex[GUT_OID_HEX_SIZE + 1];
    const char *message_arg = NULL;
    unsigned long rc;
    int n = 0;
    int i;
    gut_oid cursor;
    gut_oid squash_parent;
    int have_parent = 0;
    buf msg_buf;
    buf commit_buf;
    gut_object head_obj;
    gut_commit head_commit;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            message_arg = argv[++i];
        } else if (argv[i][0] != '-') {
            n = atoi(argv[i]);
        }
    }

    if (n <= 0) {
        fprintf(stderr, "usage: gut squash <N> [-m <msg>]\n"
                        "  N must be >= 1 (number of HEAD commits to collapse)\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) { fprintf(stderr, "error: cwd\n"); return 1; }
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    if (repo_head_ref(head_ref, sizeof(head_ref), &repo) != 0) {
        fprintf(stderr, "error: cannot read HEAD\n"); return 1;
    }
    if (repo_resolve_ref(&head_oid, &repo, head_ref) != 0) {
        fprintf(stderr, "fatal: nothing to squash\n"); return 1;
    }

    /* Walk N commits back from HEAD, collecting messages.
     * Refuse if any is a merge commit. */
    if (buf_create(&msg_buf, 512) != 0) { return 1; }
    memcpy(cursor.bytes, head_oid.bytes, GUT_OID_RAW_SIZE);
    for (i = 0; i < n; i++) {
        gut_object o; gut_commit c;
        if (odb_read(&o, &repo.odb, &cursor) != 0) {
            fprintf(stderr, "error: cannot read commit %d of %d\n", i + 1, n);
            buf_destroy(&msg_buf); return 1;
        }
        if (commit_parse(&c, o.data.data, o.data.len) != 0) {
            object_destroy(&o);
            fprintf(stderr, "error: cannot parse commit\n");
            buf_destroy(&msg_buf); return 1;
        }
        object_destroy(&o);

        if (c.parent_count > 1) {
            fprintf(stderr, "error: commit %d of %d is a merge — refusing to squash\n",
                    i + 1, n);
            commit_destroy(&c); buf_destroy(&msg_buf); return 1;
        }

        if (!message_arg) {
            /* Accumulate subject lines (first line of each message), oldest last */
            const char *s = c.message ? c.message : "";
            const char *nl = strchr(s, '\n');
            u64 slen = nl ? (u64)(nl - s) : (u64)strlen(s);
            if (msg_buf.len > 0) buf_append_byte(&msg_buf, '\n');
            buf_append(&msg_buf, (u8 *)"* ", 2);
            buf_append(&msg_buf, (u8 *)s, slen);
        }

        if (c.parent_count == 0) {
            if (i < n - 1) {
                fprintf(stderr,
                        "error: only %d commit(s) reachable from HEAD, asked to squash %d\n",
                        i + 1, n);
                commit_destroy(&c); buf_destroy(&msg_buf); return 1;
            }
            /* Root commit — squash parent is none */
            have_parent = 0;
        } else {
            memcpy(cursor.bytes, c.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
            if (i == n - 1) {
                memcpy(squash_parent.bytes, c.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
                have_parent = 1;
            }
        }
        commit_destroy(&c);
    }

    /* Read HEAD commit (to reuse author/committer fields) */
    if (odb_read(&head_obj, &repo.odb, &head_oid) != 0) {
        fprintf(stderr, "error: cannot re-read HEAD\n");
        buf_destroy(&msg_buf); return 1;
    }
    if (commit_parse(&head_commit, head_obj.data.data, head_obj.data.len) != 0) {
        object_destroy(&head_obj);
        fprintf(stderr, "error: cannot parse HEAD commit\n");
        buf_destroy(&msg_buf); return 1;
    }
    object_destroy(&head_obj);

    /* Build tree from current index (preserves working changes) */
    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    if (index_read(&idx, index_path) != 0) {
        commit_destroy(&head_commit); buf_destroy(&msg_buf); return 1;
    }
    snprintf(obj_dir, sizeof(obj_dir), "%s/objects", repo.git_dir);
    rc = index_write_tree(&tree_oid, &idx, obj_dir);
    index_destroy(&idx);
    if (rc) { commit_destroy(&head_commit); buf_destroy(&msg_buf); return 1; }

    /* Compose the new commit object */
    if (buf_create(&commit_buf, 512) != 0) {
        commit_destroy(&head_commit); buf_destroy(&msg_buf); return 1;
    }
    oid_to_hex(hex, &tree_oid);
    buf_append(&commit_buf, (u8 *)"tree ", 5);
    buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
    buf_append_byte(&commit_buf, '\n');

    if (have_parent) {
        oid_to_hex(hex, &squash_parent);
        buf_append(&commit_buf, (u8 *)"parent ", 7);
        buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
        buf_append_byte(&commit_buf, '\n');
    }

    {
        char line[512];
        int k;
        k = snprintf(line, sizeof(line), "author %s\n", head_commit.author);
        buf_append(&commit_buf, (u8 *)line, (u64)k);
        k = snprintf(line, sizeof(line), "committer %s\n", head_commit.committer);
        buf_append(&commit_buf, (u8 *)line, (u64)k);
    }
    buf_append_byte(&commit_buf, '\n');

    if (message_arg) {
        buf_append(&commit_buf, (u8 *)message_arg, (u64)strlen(message_arg));
        if (message_arg[strlen(message_arg) - 1] != '\n')
            buf_append_byte(&commit_buf, '\n');
    } else {
        char header[64];
        int hl = snprintf(header, sizeof(header), "squash: %d commits\n\n", n);
        buf_append(&commit_buf, (u8 *)header, (u64)hl);
        buf_append(&commit_buf, msg_buf.data, msg_buf.len);
        buf_append_byte(&commit_buf, '\n');
    }
    buf_destroy(&msg_buf);

    rc = odb_write(&new_commit_oid, &repo.odb, GUT_OBJ_COMMIT,
                   commit_buf.data, commit_buf.len);
    buf_destroy(&commit_buf);
    commit_destroy(&head_commit);
    if (rc) { fprintf(stderr, "error: cannot write commit\n"); return 1; }

    {
        char reflog_reason[128];
        snprintf(reflog_reason, sizeof(reflog_reason),
                 "squash: %d commits", n);
        if (repo_update_ref(&repo, head_ref, &new_commit_oid, reflog_reason) != 0) {
            fprintf(stderr, "error: cannot update ref\n"); return 1;
        }
    }

    oid_to_hex(hex, &new_commit_oid);
    printf("[%.*s] squashed %d commits\n", 7, hex, n);
    return 0;
}

/* ---- gut show ---- */
/* Pretty-print a commit and the diff from its first parent (or the
 * empty tree for a root commit). Shape mirrors git: header, then
 * per-file diff body. */

/* Diff two trees (either may be NULL to mean empty). For each path
 * that differs, call diff_emit with the (path, old, new) blobs. */
static void show_diff_trees(gut_repo *repo,
                            gut_oid *a_tree, gut_oid *b_tree,
                            int stat_mode, stat_row **rows, int *n_rows) {
    gut_index a_idx, b_idx;
    int have_a = 0, have_b = 0;
    u64 i;

    if (a_tree && index_read_tree(&a_idx, &repo->odb, a_tree) == 0) have_a = 1;
    if (b_tree && index_read_tree(&b_idx, &repo->odb, b_tree) == 0) have_b = 1;

    /* Modified / added files: iterate b */
    if (have_b) {
        for (i = 0; i < b_idx.count; i++) {
            const char *path = b_idx.entries[i].path;
            gut_oid *new_oid = &b_idx.entries[i].oid;
            gut_oid old_oid_tmp;
            int have_old = 0;

            if (have_a) {
                u64 j;
                for (j = 0; j < a_idx.count; j++) {
                    if (strcmp(a_idx.entries[j].path, path) == 0) {
                        old_oid_tmp = a_idx.entries[j].oid;
                        have_old = 1;
                        break;
                    }
                }
            }

            if (have_old) {
                long cmp;
                oid_compare(&cmp, &old_oid_tmp, new_oid);
                if (cmp == 0) continue; /* unchanged */
            }

            {
                gut_object new_blob, old_blob;
                int read_old = 0;
                if (odb_read(&new_blob, &repo->odb, new_oid) != 0) continue;
                if (have_old) {
                    if (odb_read(&old_blob, &repo->odb, &old_oid_tmp) == 0)
                        read_old = 1;
                }
                diff_emit(stat_mode, rows, n_rows, path,
                          read_old ? old_blob.data.data : NULL,
                          read_old ? old_blob.data.len  : 0,
                          new_blob.data.data, new_blob.data.len);
                if (read_old) object_destroy(&old_blob);
                object_destroy(&new_blob);
            }
        }
    }

    /* Deleted files: iterate a, look up in b */
    if (have_a) {
        for (i = 0; i < a_idx.count; i++) {
            const char *path = a_idx.entries[i].path;
            int in_b = 0;
            if (have_b) {
                u64 j;
                for (j = 0; j < b_idx.count; j++) {
                    if (strcmp(b_idx.entries[j].path, path) == 0) { in_b = 1; break; }
                }
            }
            if (in_b) continue;
            {
                gut_object old_blob;
                if (odb_read(&old_blob, &repo->odb, &a_idx.entries[i].oid) != 0) continue;
                diff_emit(stat_mode, rows, n_rows, path,
                          old_blob.data.data, old_blob.data.len, NULL, 0);
                object_destroy(&old_blob);
            }
        }
    }

    if (have_a) index_destroy(&a_idx);
    if (have_b) index_destroy(&b_idx);
}

static int cmd_show(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    gut_oid commit_oid;
    gut_object obj;
    gut_commit commit;
    const char *spec = argc > 0 ? argv[0] : "HEAD";
    char hex[GUT_OID_HEX_SIZE + 1];

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    if (strcmp(spec, "HEAD") == 0) {
        char head_ref[256];
        if (repo_head_ref(head_ref, sizeof(head_ref), &repo) != 0 ||
            repo_resolve_ref(&commit_oid, &repo, head_ref) != 0) {
            fprintf(stderr, "error: cannot resolve HEAD\n"); return 1;
        }
    } else if (oid_from_hex(&commit_oid, spec) != 0) {
        if (odb_resolve_prefix(&commit_oid, &repo.odb, spec) != 0) {
            fprintf(stderr, "error: cannot resolve '%s'\n", spec); return 1;
        }
    }

    if (odb_read(&obj, &repo.odb, &commit_oid) != 0) {
        fprintf(stderr, "error: cannot read object\n"); return 1;
    }
    if (obj.type != GUT_OBJ_COMMIT) {
        fprintf(stderr, "error: '%s' is not a commit\n", spec);
        object_destroy(&obj); return 1;
    }
    if (commit_parse(&commit, obj.data.data, obj.data.len) != 0) {
        object_destroy(&obj); return 1;
    }
    object_destroy(&obj);

    oid_to_hex(hex, &commit_oid);
    printf("commit %s\n", hex);
    if (commit.parent_count > 1) {
        u64 pi;
        printf("Merge:");
        for (pi = 0; pi < commit.parent_count; pi++) {
            oid_to_hex(hex, &commit.parent_oids[pi]);
            printf(" %.7s", hex);
        }
        printf("\n");
    }
    if (commit.author) printf("Author: %s\n", commit.author);
    printf("\n");
    if (commit.message) printf("    %s\n", commit.message);
    printf("\n");

    /* Diff vs first parent (or empty tree if root) */
    if (commit.parent_count > 0) {
        gut_object p_obj;
        gut_commit p;
        if (odb_read(&p_obj, &repo.odb, &commit.parent_oids[0]) == 0 &&
            commit_parse(&p, p_obj.data.data, p_obj.data.len) == 0) {
            show_diff_trees(&repo, &p.tree_oid, &commit.tree_oid, 0, NULL, NULL);
            commit_destroy(&p);
        }
        object_destroy(&p_obj);
    } else {
        show_diff_trees(&repo, NULL, &commit.tree_oid, 0, NULL, NULL);
    }

    commit_destroy(&commit);
    return 0;
}

/* ---- gut bisect ---- */
/* State kept under .git/bisect/:
 *   start — exact contents of HEAD at bisect-start (either "ref: refs/..."
 *            or a raw OID hex for detached HEADs), so we can restore it
 *   bad   — 40-hex OID of known-bad
 *   good  — 40-hex OID of known-good
 *
 * Linear-history MVP: walks bad → parent → ... → good and counts the
 * commits in between. Picks the middle one and checks out a detached
 * HEAD on that commit. Refuses if the path includes merges or if good
 * is not an ancestor of bad. */

static int bisect_read_head(gut_repo *repo, char *out, u64 cap) {
    char path[2048];
    FILE *fp;
    size_t n;
    snprintf(path, sizeof(path), "%s/HEAD", repo->git_dir);
    fp = fopen(path, "r");
    if (!fp) return 0;
    n = fread(out, 1, cap - 1, fp);
    fclose(fp);
    out[n] = 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = 0;
    return 1;
}

static int bisect_write_head(gut_repo *repo, const char *contents) {
    char path[2048];
    FILE *fp;
    snprintf(path, sizeof(path), "%s/HEAD", repo->git_dir);
    fp = fopen(path, "w");
    if (!fp) return 0;
    fprintf(fp, "%s\n", contents);
    fclose(fp);
    return 1;
}

static int bisect_reset_tree(gut_repo *repo, gut_oid *commit_oid) {
    gut_object obj;
    gut_commit c;
    gut_index new_idx, old_idx;
    char index_path[2048];

    if (odb_read(&obj, &repo->odb, commit_oid) != 0) return 0;
    if (commit_parse(&c, obj.data.data, obj.data.len) != 0) {
        object_destroy(&obj); return 0;
    }
    object_destroy(&obj);

    if (index_read_tree(&new_idx, &repo->odb, &c.tree_oid) != 0) {
        commit_destroy(&c); return 0;
    }
    commit_destroy(&c);

    snprintf(index_path, sizeof(index_path), "%s/index", repo->git_dir);
    if (index_read(&old_idx, index_path) == 0) {
        workdir_remove_stale(repo, &old_idx, &new_idx);
        index_destroy(&old_idx);
    }
    workdir_write_from_index(repo, &new_idx);
    index_write(&new_idx, index_path);
    index_destroy(&new_idx);
    return 1;
}

static int bisect_write_state(const char *path, const char *hex) {
    FILE *fp = fopen(path, "w");
    if (!fp) return 0;
    fprintf(fp, "%s\n", hex);
    fclose(fp);
    return 1;
}

static int bisect_read_state(const char *path, char *out, u64 cap) {
    FILE *fp = fopen(path, "r");
    size_t n;
    if (!fp) return 0;
    n = fread(out, 1, cap - 1, fp);
    fclose(fp);
    out[n] = 0;
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = 0;
    return n > 0;
}

/* Walk from bad toward good via first-parent. Returns candidate count
 * (-1 on error). If out_mid is non-NULL, sets it to the midpoint commit. */
static int bisect_walk(gut_repo *repo, gut_oid *bad, gut_oid *good,
                       gut_oid *out_mid) {
    gut_oid *cands = NULL;
    int n = 0, cap = 0;
    gut_oid cursor;
    memcpy(cursor.bytes, bad->bytes, GUT_OID_RAW_SIZE);

    for (;;) {
        long cmp;
        gut_object obj;
        gut_commit c;

        oid_compare(&cmp, &cursor, good);
        if (cmp == 0) break; /* reached good */

        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            cands = (gut_oid *)realloc(cands, cap * sizeof(gut_oid));
            if (!cands) return -1;
        }
        memcpy(cands[n++].bytes, cursor.bytes, GUT_OID_RAW_SIZE);

        if (odb_read(&obj, &repo->odb, &cursor) != 0) {
            free(cands); return -1;
        }
        if (commit_parse(&c, obj.data.data, obj.data.len) != 0) {
            object_destroy(&obj); free(cands); return -1;
        }
        object_destroy(&obj);

        if (c.parent_count == 0) {
            fprintf(stderr,
                "error: good commit is not an ancestor of bad (walked past root)\n");
            commit_destroy(&c); free(cands); return -1;
        }
        if (c.parent_count > 1) {
            fprintf(stderr,
                "error: merge commit encountered — linear-history bisect only for now\n");
            commit_destroy(&c); free(cands); return -1;
        }
        memcpy(cursor.bytes, c.parent_oids[0].bytes, GUT_OID_RAW_SIZE);
        commit_destroy(&c);
    }

    if (out_mid && n > 0) {
        memcpy(out_mid->bytes, cands[n / 2].bytes, GUT_OID_RAW_SIZE);
    }
    free(cands);
    return n;
}

static int cmd_bisect(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char bisect_dir[2048], start_path[2048], bad_path[2048], good_path[2048];
    const char *sub = argc > 0 ? argv[0] : NULL;

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    snprintf(bisect_dir, sizeof(bisect_dir), "%s/bisect", repo.git_dir);
    snprintf(start_path, sizeof(start_path), "%s/start", bisect_dir);
    snprintf(bad_path,   sizeof(bad_path),   "%s/bad",   bisect_dir);
    snprintf(good_path,  sizeof(good_path),  "%s/good",  bisect_dir);

    if (!sub || strcmp(sub, "start") == 0) {
        char head[1024];
#ifdef _WIN32
        _mkdir(bisect_dir);
#else
        mkdir(bisect_dir, 0755);
#endif
        if (!bisect_read_head(&repo, head, sizeof(head))) {
            fprintf(stderr, "error: cannot read HEAD\n"); return 1;
        }
        {
            FILE *fp = fopen(start_path, "w");
            if (!fp) { fprintf(stderr, "error: cannot write %s\n", start_path); return 1; }
            fprintf(fp, "%s\n", head);
            fclose(fp);
        }
        remove(bad_path);
        remove(good_path);
        printf("bisect started — mark a bad commit (`gut bisect bad`) "
               "and a good commit (`gut bisect good <oid>`)\n");
        return 0;
    }

    if (strcmp(sub, "reset") == 0) {
        char saved[1024];
        gut_oid oid;
        if (!bisect_read_state(start_path, saved, sizeof(saved))) {
            fprintf(stderr, "no bisect in progress\n"); return 1;
        }
        if (strncmp(saved, "ref: ", 5) == 0) {
            if (repo_resolve_ref(&oid, &repo, saved + 5) != 0) {
                fprintf(stderr, "error: cannot resolve saved ref %s\n", saved); return 1;
            }
        } else if (oid_from_hex(&oid, saved) != 0) {
            fprintf(stderr, "error: corrupt bisect/start\n"); return 1;
        }
        bisect_write_head(&repo, saved);
        bisect_reset_tree(&repo, &oid);
        remove(start_path);
        remove(bad_path);
        remove(good_path);
#ifdef _WIN32
        _rmdir(bisect_dir);
#else
        rmdir(bisect_dir);
#endif
        printf("bisect reset — HEAD restored to %s\n", saved);
        return 0;
    }

    if (strcmp(sub, "bad") == 0 || strcmp(sub, "good") == 0) {
        gut_oid mark_oid;
        char hex[GUT_OID_HEX_SIZE + 1];
        const char *target_path = (strcmp(sub, "bad") == 0) ? bad_path : good_path;
        const char *oid_arg = argc > 1 ? argv[1] : NULL;

        if (oid_arg) {
            if (oid_from_hex(&mark_oid, oid_arg) != 0 &&
                odb_resolve_prefix(&mark_oid, &repo.odb, oid_arg) != 0) {
                fprintf(stderr, "error: cannot resolve '%s'\n", oid_arg); return 1;
            }
        } else {
            /* default HEAD */
            char head_ref[256];
            if (repo_head_ref(head_ref, sizeof(head_ref), &repo) == 0 &&
                repo_resolve_ref(&mark_oid, &repo, head_ref) == 0) {
                /* ok */
            } else {
                /* Detached HEAD: read file raw */
                char head[256];
                if (!bisect_read_head(&repo, head, sizeof(head)) ||
                    oid_from_hex(&mark_oid, head) != 0) {
                    fprintf(stderr, "error: cannot resolve HEAD\n"); return 1;
                }
            }
        }

        oid_to_hex(hex, &mark_oid);
        if (!bisect_write_state(target_path, hex)) {
            fprintf(stderr, "error: cannot persist bisect state\n"); return 1;
        }
        printf("marked %s as %s\n", hex, sub);

        /* If both marks exist, advance. */
        {
            char bad_hex[GUT_OID_HEX_SIZE + 2];
            char good_hex[GUT_OID_HEX_SIZE + 2];
            if (bisect_read_state(bad_path,  bad_hex,  sizeof(bad_hex)) &&
                bisect_read_state(good_path, good_hex, sizeof(good_hex))) {
                gut_oid bad, good, mid;
                int n;
                oid_from_hex(&bad,  bad_hex);
                oid_from_hex(&good, good_hex);
                n = bisect_walk(&repo, &bad, &good, &mid);
                if (n < 0) return 1;
                if (n == 0) {
                    printf("\nbisect: bad == good — nothing to search\n");
                    return 0;
                }
                if (n == 1) {
                    printf("\nfirst bad commit: %s\n", bad_hex);
                    printf("  (run `gut bisect reset` to restore HEAD)\n");
                    return 0;
                }
                /* Check out midpoint as detached HEAD */
                {
                    char mid_hex[GUT_OID_HEX_SIZE + 1];
                    oid_to_hex(mid_hex, &mid);
                    bisect_write_head(&repo, mid_hex);
                    bisect_reset_tree(&repo, &mid);
                    printf("\n%d commits left to test — now on %.7s (detached)\n"
                           "  mark it with `gut bisect good` or `gut bisect bad`\n",
                           n, mid_hex);
                }
                return 0;
            }
        }
        return 0;
    }

    fprintf(stderr, "usage:\n"
        "  gut bisect start            # begin a bisect session\n"
        "  gut bisect bad [<oid>]      # mark commit as bad (default HEAD)\n"
        "  gut bisect good <oid>       # mark commit as good\n"
        "  gut bisect reset            # restore HEAD and exit bisect\n");
    return 1;
}

/* ---- gut blame ---- */
/* For each line in the HEAD version of a file, find the oldest commit
 * where that exact line was present — attributing the line to the newest
 * commit that introduced it. This is a content-equality blame (no
 * rename-detection, no intra-line granularity) but works well for the
 * common case of text files. */

typedef struct {
    const char *start;   /* pointer into file buffer */
    u64         len;     /* line length, not including trailing \n */
    gut_oid     blame;   /* commit that introduced this line */
    int         done;    /* 1 once we've walked past its introduction */
} blame_line;

/* Split a buffer into lines, NOT copying — just storing pointers. */
static blame_line *blame_split(const char *data, u64 len, u64 *n_out) {
    blame_line *lines = NULL;
    u64 cap = 0, n = 0;
    u64 i, line_start = 0;
    for (i = 0; i <= len; i++) {
        if (i == len || data[i] == '\n') {
            if (n == cap) {
                cap = cap ? cap * 2 : 64;
                lines = (blame_line *)realloc(lines, cap * sizeof(blame_line));
            }
            lines[n].start = data + line_start;
            lines[n].len = i - line_start;
            lines[n].done = 0;
            memset(lines[n].blame.bytes, 0, GUT_OID_RAW_SIZE);
            n++;
            line_start = i + 1;
        }
    }
    /* If the file ended with \n, we added an empty trailing line; drop it. */
    if (n > 0 && lines[n - 1].len == 0 && len > 0 && data[len - 1] == '\n') n--;
    *n_out = n;
    return lines;
}

/* Check if `line` (with length ll) appears as a complete line in `data`. */
static int blame_contains(const char *data, u64 data_len,
                          const char *line, u64 ll) {
    u64 i, line_start = 0;
    for (i = 0; i <= data_len; i++) {
        if (i == data_len || data[i] == '\n') {
            u64 cur_len = i - line_start;
            if (cur_len == ll &&
                memcmp(data + line_start, line, (size_t)ll) == 0) return 1;
            line_start = i + 1;
        }
    }
    return 0;
}

static int cmd_blame(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    char head_ref[256];
    gut_oid cursor_oid, head_oid;
    gut_object head_blob_obj;
    gut_oid head_blob_oid;
    blame_line *lines = NULL;
    u64 n_lines = 0;
    u64 i;
    const char *path;
    char head_commit_ref_init[GUT_OID_RAW_SIZE]; (void)head_commit_ref_init;

    if (argc < 1) {
        fprintf(stderr, "usage: gut blame <path>\n"); return 1;
    }
    path = argv[0];

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }
    if (repo_head_ref(head_ref, sizeof(head_ref), &repo) != 0 ||
        repo_resolve_ref(&head_oid, &repo, head_ref) != 0) {
        fprintf(stderr, "error: cannot resolve HEAD\n"); return 1;
    }

    /* Read HEAD's version of the file via HEAD tree */
    {
        gut_object commit_obj;
        gut_commit commit;
        if (odb_read(&commit_obj, &repo.odb, &head_oid) != 0) return 1;
        if (commit_parse(&commit, commit_obj.data.data, commit_obj.data.len) != 0) {
            object_destroy(&commit_obj); return 1;
        }
        object_destroy(&commit_obj);
        if (tree_lookup_path(&head_blob_oid, &repo.odb,
                             &commit.tree_oid, path) != 0) {
            commit_destroy(&commit);
            fprintf(stderr, "error: '%s' not in HEAD\n", path); return 1;
        }
        commit_destroy(&commit);
    }
    if (odb_read(&head_blob_obj, &repo.odb, &head_blob_oid) != 0) return 1;

    lines = blame_split((const char *)head_blob_obj.data.data,
                        head_blob_obj.data.len, &n_lines);
    /* Initial blame: HEAD (refined as we walk back) */
    for (i = 0; i < n_lines; i++) {
        memcpy(lines[i].blame.bytes, head_oid.bytes, GUT_OID_RAW_SIZE);
    }

    /* Walk parents. At each commit C where the file exists, for each line
     * still "in play": if C's file also contains that exact line, move
     * the blame back to C. Otherwise mark the line done — its blame is
     * the most-recent commit where it was present (already set). */
    memcpy(cursor_oid.bytes, head_oid.bytes, GUT_OID_RAW_SIZE);
    for (;;) {
        gut_object c_obj;
        gut_commit c;
        gut_oid parent_oid;
        gut_oid c_blob_oid;
        gut_object c_blob;
        int all_done = 1;
        int has_file;

        for (i = 0; i < n_lines; i++) {
            if (!lines[i].done) { all_done = 0; break; }
        }
        if (all_done) break;

        if (odb_read(&c_obj, &repo.odb, &cursor_oid) != 0) break;
        if (commit_parse(&c, c_obj.data.data, c_obj.data.len) != 0) {
            object_destroy(&c_obj); break;
        }
        object_destroy(&c_obj);

        if (c.parent_count == 0) {
            /* Root commit — any line present here blames to root. */
            has_file = tree_lookup_path(&c_blob_oid, &repo.odb,
                                        &c.tree_oid, path) == 0;
            if (has_file && odb_read(&c_blob, &repo.odb, &c_blob_oid) == 0) {
                for (i = 0; i < n_lines; i++) {
                    if (lines[i].done) continue;
                    if (blame_contains((const char *)c_blob.data.data,
                                       c_blob.data.len,
                                       lines[i].start, lines[i].len)) {
                        memcpy(lines[i].blame.bytes, cursor_oid.bytes,
                               GUT_OID_RAW_SIZE);
                    }
                    lines[i].done = 1; /* can't go further than root */
                }
                object_destroy(&c_blob);
            } else {
                /* No file at root → no change — mark all remaining done */
                for (i = 0; i < n_lines; i++) lines[i].done = 1;
            }
            commit_destroy(&c);
            break;
        }

        memcpy(parent_oid.bytes, c.parent_oids[0].bytes, GUT_OID_RAW_SIZE);

        /* Look at parent's file. If a line is present in parent, blame
         * moves to parent. Else it's introduced in `cursor_oid` — done. */
        {
            gut_object p_obj;
            gut_commit p;
            int parent_has_file = 0;

            if (odb_read(&p_obj, &repo.odb, &parent_oid) == 0) {
                if (commit_parse(&p, p_obj.data.data, p_obj.data.len) == 0) {
                    gut_oid p_blob_oid;
                    if (tree_lookup_path(&p_blob_oid, &repo.odb,
                                         &p.tree_oid, path) == 0) {
                        gut_object p_blob;
                        if (odb_read(&p_blob, &repo.odb, &p_blob_oid) == 0) {
                            parent_has_file = 1;
                            for (i = 0; i < n_lines; i++) {
                                if (lines[i].done) continue;
                                if (blame_contains((const char *)p_blob.data.data,
                                                   p_blob.data.len,
                                                   lines[i].start, lines[i].len)) {
                                    memcpy(lines[i].blame.bytes,
                                           parent_oid.bytes,
                                           GUT_OID_RAW_SIZE);
                                } else {
                                    lines[i].done = 1; /* introduced at cursor */
                                }
                            }
                            object_destroy(&p_blob);
                        }
                    }
                    commit_destroy(&p);
                }
                object_destroy(&p_obj);
            }
            if (!parent_has_file) {
                /* File didn't exist in parent — everything still-alive
                 * is introduced at cursor. */
                for (i = 0; i < n_lines; i++) {
                    if (lines[i].done) continue;
                    memcpy(lines[i].blame.bytes, cursor_oid.bytes,
                           GUT_OID_RAW_SIZE);
                    lines[i].done = 1;
                }
            }
        }

        commit_destroy(&c);
        memcpy(cursor_oid.bytes, parent_oid.bytes, GUT_OID_RAW_SIZE);
    }

    /* Print. Cache commit -> "author-name + date" map as we go. */
    for (i = 0; i < n_lines; i++) {
        char hex[GUT_OID_HEX_SIZE + 1];
        gut_object obj;
        gut_commit c;
        char author_name[64] = "???";
        char date[16] = "?";
        oid_to_hex(hex, &lines[i].blame);
        if (odb_read(&obj, &repo.odb, &lines[i].blame) == 0) {
            if (commit_parse(&c, obj.data.data, obj.data.len) == 0) {
                if (c.author) {
                    const char *lt = strchr(c.author, '<');
                    u64 name_len = lt ? (u64)(lt - c.author) : strlen(c.author);
                    if (name_len > 0 && c.author[name_len - 1] == ' ') name_len--;
                    if (name_len > sizeof(author_name) - 1) name_len = sizeof(author_name) - 1;
                    memcpy(author_name, c.author, (size_t)name_len);
                    author_name[name_len] = 0;

                    /* timestamp: second-to-last space-separated token */
                    {
                        long ts = feeling_parse_commit_ts(c.author);
                        if (ts > 0) {
                            time_t t = (time_t)ts;
                            struct tm *lt2 = localtime(&t);
                            strftime(date, sizeof(date), "%Y-%m-%d", lt2);
                        }
                    }
                }
                commit_destroy(&c);
            }
            object_destroy(&obj);
        }
        printf("%.7s (%-20s %s) %4llu  %.*s\n",
               hex, author_name, date,
               (unsigned long long)(i + 1),
               (int)lines[i].len, lines[i].start);
    }

    free(lines);
    object_destroy(&head_blob_obj);
    return 0;
}

/* ---- Hook executor ---- */
/* Runs .git/hooks/<name>. If the file starts with a shebang (`#!`) it's
 * executed via `bash`, which works both on POSIX and on Windows whenever
 * Git-Bash / MSYS is installed (very common). Binaries / .bat files run
 * directly. Env var GUT_SKIP_HOOKS=1 bypasses all hooks.
 *
 * Returns 0 on success/no-hook, 1 when abort_on_fail=1 and the hook
 * failed. post-* hooks pass abort_on_fail=0 (advisory only). */
static int run_hook(gut_repo *repo, const char *name, int abort_on_fail) {
    char path[2048];
    char cmd[4096];
    struct stat st;
    int ret;
    int use_bash = 0;
    FILE *fp;

    if (getenv("GUT_SKIP_HOOKS")) return 0;

    snprintf(path, sizeof(path), "%s/hooks/%s", repo->git_dir, name);
    if (stat(path, &st) != 0) return 0;
#ifndef _WIN32
    if (!(st.st_mode & S_IXUSR)) return 0;
#endif

    /* Peek first two bytes — shebang means "script, needs an interpreter". */
    fp = fopen(path, "rb");
    if (fp) {
        int c1 = fgetc(fp);
        int c2 = fgetc(fp);
        if (c1 == '#' && c2 == '!') use_bash = 1;
        fclose(fp);
    }

    if (use_bash) {
        snprintf(cmd, sizeof(cmd), "bash \"%s\"", path);
    } else {
        snprintf(cmd, sizeof(cmd), "\"%s\"", path);
    }

    /* Flush our buffer so hook output doesn't interleave weirdly */
    fflush(stdout);
    ret = system(cmd);
    if (ret != 0 && abort_on_fail) {
        fprintf(stderr, "gut: %s hook exited %d — aborting "
                        "(override with GUT_SKIP_HOOKS=1)\n",
                name, ret);
        return 1;
    }
    return 0;
}

/* ---- gut stash / stash pop / stash list ---- */
/* Stash captures working-tree + index state as a commit on refs/stashes/<ts>
 * and returns the tree to HEAD. Pop restores the most recent stash. */

static int stash_save(gut_repo *repo) {
    gut_index idx;
    gut_oid tree_oid, commit_oid, head_oid;
    char head_ref[256];
    char index_path[2048], obj_dir[2048], stash_dir[2048], stash_ref_path[2048];
    char hex[GUT_OID_HEX_SIZE + 1];
    char timestamp[64];
    time_t now;
    gut_object head_obj;
    gut_commit head_commit;
    buf commit_buf;
    u64 i;
    unsigned long rc;
    int have_head = 0;

    if (repo_head_ref(head_ref, sizeof(head_ref), repo) != 0 ||
        repo_resolve_ref(&head_oid, repo, head_ref) != 0) {
        fprintf(stderr, "error: nothing to stash (no HEAD)\n"); return 1;
    }
    if (odb_read(&head_obj, &repo->odb, &head_oid) == 0) {
        if (commit_parse(&head_commit, head_obj.data.data, head_obj.data.len) == 0)
            have_head = 1;
        object_destroy(&head_obj);
    }
    if (!have_head) { fprintf(stderr, "error: bad HEAD\n"); return 1; }

    /* Pick up working-tree state on top of current index: re-hash any
     * tracked file whose mtime/size changed; drop any deleted entry. */
    snprintf(index_path, sizeof(index_path), "%s/index", repo->git_dir);
    if (index_read(&idx, index_path) != 0) {
        commit_destroy(&head_commit);
        fprintf(stderr, "error: cannot read index\n"); return 1;
    }

    {
        u64 keep = 0;
        for (i = 0; i < idx.count; i++) {
            char full[2048];
            struct stat st;
            gut_oid fresh_oid;

            snprintf(full, sizeof(full), "%s/%s", repo->root_dir, idx.entries[i].path);
            if (stat(full, &st) != 0) {
                /* file removed — drop it */
                free(idx.entries[i].path);
                continue;
            }
            if ((u32)st.st_mtime != idx.entries[i].mtime_sec ||
                (u32)st.st_size != idx.entries[i].file_size) {
                if (odb_write_file(&fresh_oid, &repo->odb, full) == 0) {
                    idx.entries[i].oid = fresh_oid;
                    idx.entries[i].file_size = (u32)st.st_size;
                    idx.entries[i].mtime_sec = (u32)st.st_mtime;
                }
            }
            if (keep != i) idx.entries[keep] = idx.entries[i];
            keep++;
        }
        idx.count = keep;
    }

    /* Check: if snapshot tree equals HEAD tree, nothing to stash. */
    snprintf(obj_dir, sizeof(obj_dir), "%s/objects", repo->git_dir);
    rc = index_write_tree(&tree_oid, &idx, obj_dir);
    if (rc) {
        index_destroy(&idx); commit_destroy(&head_commit);
        fprintf(stderr, "error: cannot build tree\n"); return 1;
    }
    {
        long cmp;
        oid_compare(&cmp, &tree_oid, &head_commit.tree_oid);
        if (cmp == 0) {
            index_destroy(&idx); commit_destroy(&head_commit);
            printf("nothing to stash — working tree matches HEAD\n");
            return 0;
        }
    }

    /* Build and write the stash commit */
    if (buf_create(&commit_buf, 512) != 0) {
        index_destroy(&idx); commit_destroy(&head_commit); return 1;
    }
    oid_to_hex(hex, &tree_oid);
    buf_append(&commit_buf, (u8 *)"tree ", 5);
    buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
    buf_append_byte(&commit_buf, '\n');
    oid_to_hex(hex, &head_oid);
    buf_append(&commit_buf, (u8 *)"parent ", 7);
    buf_append(&commit_buf, (u8 *)hex, GUT_OID_HEX_SIZE);
    buf_append_byte(&commit_buf, '\n');
    {
        char line[512];
        int n = snprintf(line, sizeof(line), "author %s\n", head_commit.author);
        buf_append(&commit_buf, (u8 *)line, (u64)n);
        n = snprintf(line, sizeof(line), "committer %s\n", head_commit.committer);
        buf_append(&commit_buf, (u8 *)line, (u64)n);
    }
    buf_append_byte(&commit_buf, '\n');
    now = time(NULL);
    {
        struct tm *lt = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", lt);
    }
    {
        char msg[128];
        int n = snprintf(msg, sizeof(msg), "stash: %s\n", timestamp);
        buf_append(&commit_buf, (u8 *)msg, (u64)n);
    }

    rc = odb_write(&commit_oid, &repo->odb, GUT_OBJ_COMMIT,
                   commit_buf.data, commit_buf.len);
    buf_destroy(&commit_buf);
    commit_destroy(&head_commit);
    if (rc) {
        index_destroy(&idx);
        fprintf(stderr, "error: cannot write stash commit\n"); return 1;
    }

    /* Write refs/stashes/<ts> */
    snprintf(stash_dir, sizeof(stash_dir), "%s/refs/stashes", repo->git_dir);
#ifdef _WIN32
    _mkdir(stash_dir);
#else
    mkdir(stash_dir, 0755);
#endif
    snprintf(stash_ref_path, sizeof(stash_ref_path),
             "refs/stashes/%ld", (long)now);
    if (repo_update_ref(repo, stash_ref_path, &commit_oid, "stash: snapshot") != 0) {
        index_destroy(&idx);
        fprintf(stderr, "error: cannot write stash ref\n"); return 1;
    }

    /* Reset working tree + index to HEAD */
    {
        gut_index head_idx, old_idx;
        gut_object obj;
        gut_commit c;

        if (odb_read(&obj, &repo->odb, &head_oid) == 0 &&
            commit_parse(&c, obj.data.data, obj.data.len) == 0) {
            object_destroy(&obj);
            if (index_read_tree(&head_idx, &repo->odb, &c.tree_oid) == 0) {
                if (index_read(&old_idx, index_path) == 0) {
                    workdir_remove_stale(repo, &old_idx, &head_idx);
                    index_destroy(&old_idx);
                }
                workdir_write_from_index(repo, &head_idx);
                index_write(&head_idx, index_path);
                index_destroy(&head_idx);
            }
            commit_destroy(&c);
        } else {
            object_destroy(&obj);
        }
    }
    index_destroy(&idx);

    oid_to_hex(hex, &commit_oid);
    printf("stashed as %s (%.7s) — working tree reset to HEAD\n",
           stash_ref_path, hex);
    return 0;
}

/* Find the most recent stash (largest timestamp in refs/stashes). Returns
 * 1 on success, 0 if none found. */
static int stash_find_latest(gut_repo *repo, char *name_out, u64 name_cap,
                             gut_oid *oid_out) {
    char stash_dir[2048];
    DIR *d;
    struct dirent *de;
    long best_ts = -1;
    char best_name[128] = {0};

    snprintf(stash_dir, sizeof(stash_dir), "%s/refs/stashes", repo->git_dir);
    d = opendir(stash_dir);
    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        long ts;
        if (de->d_name[0] == '.') continue;
        ts = strtol(de->d_name, NULL, 10);
        if (ts > best_ts) {
            best_ts = ts;
            snprintf(best_name, sizeof(best_name), "%s", de->d_name);
        }
    }
    closedir(d);
    if (best_ts < 0) return 0;
    {
        char ref[256];
        snprintf(ref, sizeof(ref), "refs/stashes/%s", best_name);
        if (repo_resolve_ref(oid_out, repo, ref) != 0) return 0;
        snprintf(name_out, name_cap, "%s", best_name);
    }
    return 1;
}

static int stash_pop(gut_repo *repo) {
    char name[128];
    gut_oid commit_oid;
    gut_object obj;
    gut_commit commit;
    gut_index stash_idx, old_idx;
    char index_path[2048];
    char ref_file[2048];
    char ref_lock[2048];
    (void)ref_lock;

    if (!stash_find_latest(repo, name, sizeof(name), &commit_oid)) {
        fprintf(stderr, "no stash to pop\n"); return 1;
    }
    if (odb_read(&obj, &repo->odb, &commit_oid) != 0) {
        fprintf(stderr, "error: cannot read stash commit\n"); return 1;
    }
    if (commit_parse(&commit, obj.data.data, obj.data.len) != 0) {
        object_destroy(&obj);
        fprintf(stderr, "error: cannot parse stash commit\n"); return 1;
    }
    object_destroy(&obj);

    if (index_read_tree(&stash_idx, &repo->odb, &commit.tree_oid) != 0) {
        commit_destroy(&commit);
        fprintf(stderr, "error: cannot materialize stash tree\n"); return 1;
    }
    commit_destroy(&commit);

    snprintf(index_path, sizeof(index_path), "%s/index", repo->git_dir);
    if (index_read(&old_idx, index_path) == 0) {
        workdir_remove_stale(repo, &old_idx, &stash_idx);
        index_destroy(&old_idx);
    }
    workdir_write_from_index(repo, &stash_idx);
    index_write(&stash_idx, index_path);
    index_destroy(&stash_idx);

    /* Delete the stash ref */
    snprintf(ref_file, sizeof(ref_file), "%s/refs/stashes/%s",
             repo->git_dir, name);
    remove(ref_file);

    printf("popped stash %s — restored to working tree + index\n", name);
    return 0;
}

static int stash_list(gut_repo *repo) {
    char stash_dir[2048];
    DIR *d;
    struct dirent *de;
    int count = 0;

    snprintf(stash_dir, sizeof(stash_dir), "%s/refs/stashes", repo->git_dir);
    d = opendir(stash_dir);
    if (!d) { printf("no stashes\n"); return 0; }
    while ((de = readdir(d)) != NULL) {
        char ref[256];
        gut_oid oid;
        gut_object obj;
        gut_commit c;
        char hex[GUT_OID_HEX_SIZE + 1];
        long ts;
        time_t t;
        char when[32];
        struct tm *lt;

        if (de->d_name[0] == '.') continue;
        snprintf(ref, sizeof(ref), "refs/stashes/%s", de->d_name);
        if (repo_resolve_ref(&oid, repo, ref) != 0) continue;
        if (odb_read(&obj, &repo->odb, &oid) != 0) continue;
        if (commit_parse(&c, obj.data.data, obj.data.len) == 0) {
            oid_to_hex(hex, &oid);
            ts = strtol(de->d_name, NULL, 10);
            t = (time_t)ts;
            lt = localtime(&t);
            strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", lt);
            printf("  %s  %.7s  %s\n", de->d_name, hex, when);
            commit_destroy(&c);
            count++;
        }
        object_destroy(&obj);
    }
    closedir(d);
    if (count == 0) printf("  (empty)\n");
    return 0;
}

static int cmd_stash(int argc, char **argv) {
    gut_repo repo;
    char cwd[2048];
    const char *sub;

    if (!gut_getcwd(cwd, sizeof(cwd))) return 1;
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    sub = argc > 0 ? argv[0] : "save";
    if (strcmp(sub, "pop")  == 0) return stash_pop(&repo);
    if (strcmp(sub, "list") == 0) return stash_list(&repo);
    if (strcmp(sub, "save") == 0) return stash_save(&repo);
    return stash_save(&repo); /* bare `gut stash` */
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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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
    rc = repo_update_ref(&repo, head_ref, &commit.parent_oids[0],
                         "undo: moving to HEAD^");
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

/* ---- gut revert-file ---- */
/* Pull a single file's contents from a past commit into the working tree,
 * and stage it. Useful for "give me back the old version of this one file"
 * without doing a full checkout. */
static int cmd_revert_file(int argc, char **argv) {
    gut_repo repo;
    gut_index idx;
    gut_oid commit_oid;
    gut_object commit_obj;
    gut_commit commit;
    gut_oid blob_oid;
    gut_object blob;
    char cwd[2048];
    char index_path[2048];
    char wt_path[2048];
    FILE *fp;
    unsigned long rc;

    if (argc < 2) {
        fprintf(stderr, "usage: gut revert-file <commit> <path>\n");
        return 1;
    }

    if (!gut_getcwd(cwd, sizeof(cwd))) { fprintf(stderr, "error: cwd\n"); return 1; }
    if (repo_open(&repo, cwd) != 0) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1;
    }

    /* Resolve commit (supports short prefix via odb_resolve_prefix) */
    if (oid_from_hex(&commit_oid, argv[0]) != 0) {
        if (odb_resolve_prefix(&commit_oid, &repo.odb, argv[0]) != 0) {
            fprintf(stderr, "error: cannot resolve commit '%s'\n", argv[0]);
            return 1;
        }
    }

    if (odb_read(&commit_obj, &repo.odb, &commit_oid) != 0) {
        fprintf(stderr, "error: cannot read commit object\n"); return 1;
    }
    if (commit_obj.type != GUT_OBJ_COMMIT) {
        fprintf(stderr, "error: '%s' is not a commit\n", argv[0]);
        object_destroy(&commit_obj); return 1;
    }
    if (commit_parse(&commit, commit_obj.data.data, commit_obj.data.len) != 0) {
        fprintf(stderr, "error: cannot parse commit\n");
        object_destroy(&commit_obj); return 1;
    }
    object_destroy(&commit_obj);

    /* Walk the tree to find the path */
    if (tree_lookup_path(&blob_oid, &repo.odb, &commit.tree_oid, argv[1]) != 0) {
        fprintf(stderr, "error: '%s' not in commit %s\n", argv[1], argv[0]);
        commit_destroy(&commit); return 1;
    }
    commit_destroy(&commit);

    if (odb_read(&blob, &repo.odb, &blob_oid) != 0) {
        fprintf(stderr, "error: cannot read blob\n"); return 1;
    }

    /* Write to working tree */
    snprintf(wt_path, sizeof(wt_path), "%s/%s", repo.root_dir, argv[1]);
    fp = fopen(wt_path, "wb");
    if (!fp) {
        fprintf(stderr, "error: cannot write '%s'\n", wt_path);
        object_destroy(&blob); return 1;
    }
    fwrite(blob.data.data, 1, (size_t)blob.data.len, fp);
    fclose(fp);

    /* Stage it */
    snprintf(index_path, sizeof(index_path), "%s/index", repo.git_dir);
    rc = index_read(&idx, index_path);
    if (rc == 0) {
        index_add(&idx, argv[1], &blob_oid, 0100644,
                  (u32)blob.data.len, (u32)time(NULL));
        index_write(&idx, index_path);
        index_destroy(&idx);
    }

    {
        char hex[GUT_OID_HEX_SIZE + 1];
        oid_to_hex(hex, &blob_oid);
        printf("reverted %s to %s (blob %.8s) — staged\n",
               argv[1], argv[0], hex);
    }
    object_destroy(&blob);
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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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

        {
            char reflog_reason[256];
            snprintf(reflog_reason, sizeof(reflog_reason),
                     "reset: moving to %s", rev_spec);
            rc = repo_update_ref(&repo, head_ref, &target_oid, reflog_reason);
        }
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
    if (rc) { fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n"); return 1; }

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

        {
            char reflog_reason[256];
            snprintf(reflog_reason, sizeof(reflog_reason),
                     "merge %s: Fast-forward", branch_name);
            repo_update_ref(&repo, head_ref, &their_oid, reflog_reason);
        }

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

        {
            char reflog_reason[256];
            snprintf(reflog_reason, sizeof(reflog_reason),
                     "merge %s", branch_name);
            repo_update_ref(&repo, head_ref, &merge_commit_oid, reflog_reason);
        }

        oid_to_hex(hex, &merge_commit_oid);
        printf("Merge made by the 'recursive' strategy.\n");
    }

    return 0;
}

/* ---- gut cherry-pick ---- */

/* Extract the first line of `message` into `subject` (bounded). Used to
 * build a one-line reflog reason and a short status print. */
static void commit_subject(char *subject, u64 subject_sz, const char *message) {
    u64 i = 0;
    if (!message) { subject[0] = '\0'; return; }
    while (message[i] && message[i] != '\n' && i + 1 < subject_sz) {
        subject[i] = message[i];
        i++;
    }
    subject[i] = '\0';
}

/* Apply the diff introduced by `pick` (pick - parent(pick)) onto HEAD,
 * then record a new commit with pick's message + author + a
 * "(cherry picked from commit <oid>)" trailer. HEAD becomes the only
 * parent of the new commit.
 *
 * Conflict handling mirrors cmd_merge: on content conflict we write the
 * diff3 markers into the blob, stage the file anyway, and refuse to
 * commit — letting the user resolve, re-add, and `gut commit` manually. */
static int cmd_cherry_pick(int argc, char **argv) {
    gut_repo repo;
    gut_oid our_oid, their_oid, base_oid;
    char cwd[2048];
    char head_ref[256];
    char hex[GUT_OID_MAX_HEX_SIZE + 1];
    unsigned long rc;
    const char *rev_spec;
    unsigned hex_len;

    if (argc < 1) {
        fprintf(stderr, "usage: gut cherry-pick <commit>\n");
        return 1;
    }
    rev_spec = argv[0];

    if (!gut_getcwd(cwd, sizeof(cwd))) {
        fprintf(stderr, "error: cannot get current directory\n");
        return 1;
    }

    rc = repo_open(&repo, cwd);
    if (rc) {
        fprintf(stderr, "error: not a gut repository (run 'gut init' to create one)\n");
        return 1;
    }

    hex_len = gut_oid_hex_size(repo.hash_algo);

    /* Resolve HEAD */
    rc = repo_head_ref(head_ref, sizeof(head_ref), &repo);
    if (rc) { fprintf(stderr, "error: cannot read HEAD\n"); return 1; }
    rc = repo_resolve_ref(&our_oid, &repo, head_ref);
    if (rc) { fprintf(stderr, "fatal: HEAD is unborn — run 'gut commit' first\n"); return 1; }

    /* Resolve the commit to pick (short SHA, full SHA, ref name) */
    if (resolve_object(&their_oid, &repo, rev_spec)) {
        fprintf(stderr, "fatal: invalid revision '%s'\n", rev_spec);
        return 1;
    }

    /* Load pick and its first parent (= base for the 3-way merge) */
    {
        gut_object their_obj;
        gut_commit their_commit;
        gut_oid their_tree;
        char *pick_author = NULL;
        char *pick_message = NULL;
        u64 pick_author_len = 0;
        u64 pick_message_len = 0;

        rc = odb_read(&their_obj, &repo.odb, &their_oid);
        if (rc) { fprintf(stderr, "error: cannot read commit %s\n", rev_spec); return 1; }
        rc = commit_parse(&their_commit, their_obj.data.data, their_obj.data.len);
        object_destroy(&their_obj);
        if (rc) { fprintf(stderr, "error: cannot parse commit\n"); return 1; }

        if (their_commit.parent_count == 0) {
            /* Root-commit cherry-picks are rare and require a null-tree
             * diff base. MVP defers them until a user actually asks. */
            commit_destroy(&their_commit);
            fprintf(stderr, "error: cherry-picking a root commit is not supported yet\n");
            return 1;
        }

        memcpy(their_tree.bytes, their_commit.tree_oid.bytes, GUT_OID_MAX_RAW_SIZE);
        memcpy(base_oid.bytes,
               their_commit.parent_oids[0].bytes, GUT_OID_MAX_RAW_SIZE);

        /* Snapshot author line and full message so we can build the new
         * commit after tearing down the parsed `their_commit`. */
        if (their_commit.author) {
            pick_author_len = strlen(their_commit.author);
            pick_author = (char *)malloc(pick_author_len + 1);
            if (!pick_author) { commit_destroy(&their_commit); return 1; }
            memcpy(pick_author, their_commit.author, pick_author_len + 1);
        }
        if (their_commit.message) {
            pick_message_len = strlen(their_commit.message);
            pick_message = (char *)malloc(pick_message_len + 1);
            if (!pick_message) {
                free(pick_author);
                commit_destroy(&their_commit);
                return 1;
            }
            memcpy(pick_message, their_commit.message, pick_message_len + 1);
        }

        commit_destroy(&their_commit);

        /* Already-applied check: if HEAD's tree and pick's tree are
         * identical, this is a no-op. Don't bother with the merge. */
        {
            gut_object our_obj;
            gut_commit our_commit;
            long c;
            if (odb_read(&our_obj, &repo.odb, &our_oid) == 0 &&
                commit_parse(&our_commit, our_obj.data.data, our_obj.data.len) == 0) {
                oid_compare(&c, &our_commit.tree_oid, &their_tree);
                commit_destroy(&our_commit);
                object_destroy(&our_obj);
                if (c == 0) {
                    free(pick_author); free(pick_message);
                    printf("Already applied: %s\n", rev_spec);
                    return 0;
                }
            } else {
                object_destroy(&our_obj);
            }
        }

        /* Three-way merge: base = parent(pick), ours = HEAD, theirs = pick. */
        {
            gut_object our_commit_obj, base_commit_obj;
            gut_commit our_commit, base_commit;
            gut_oid our_tree, base_tree;
            gut_index base_idx, our_idx, their_idx, merged_idx;
            char index_path[2048];
            char obj_dir[2048];
            gut_oid merge_tree_oid, new_commit_oid;
            int has_conflicts = 0;
            u64 i;

            if (odb_read(&our_commit_obj, &repo.odb, &our_oid) ||
                commit_parse(&our_commit,
                             our_commit_obj.data.data,
                             our_commit_obj.data.len)) {
                free(pick_author); free(pick_message);
                fprintf(stderr, "error: cannot read HEAD commit\n");
                return 1;
            }
            memcpy(our_tree.bytes, our_commit.tree_oid.bytes, GUT_OID_MAX_RAW_SIZE);
            commit_destroy(&our_commit);
            object_destroy(&our_commit_obj);

            if (odb_read(&base_commit_obj, &repo.odb, &base_oid) ||
                commit_parse(&base_commit,
                             base_commit_obj.data.data,
                             base_commit_obj.data.len)) {
                free(pick_author); free(pick_message);
                fprintf(stderr, "error: cannot read parent of pick\n");
                return 1;
            }
            memcpy(base_tree.bytes, base_commit.tree_oid.bytes, GUT_OID_MAX_RAW_SIZE);
            commit_destroy(&base_commit);
            object_destroy(&base_commit_obj);

            index_read_tree(&base_idx, &repo.odb, &base_tree);
            index_read_tree(&our_idx, &repo.odb, &our_tree);
            index_read_tree(&their_idx, &repo.odb, &their_tree);
            index_init(&merged_idx);

            /* Same three-way merge loop as cmd_merge. */
            for (i = 0; i < our_idx.count; i++) {
                const char *path = our_idx.entries[i].path;
                u64 base_pos, their_pos;
                int in_base, in_theirs;
                gut_oid *our_blob = &our_idx.entries[i].oid;

                index_find(&base_pos, &base_idx, path);
                in_base = (base_pos < base_idx.count &&
                           strcmp(base_idx.entries[base_pos].path, path) == 0);
                index_find(&their_pos, &their_idx, path);
                in_theirs = (their_pos < their_idx.count &&
                             strcmp(their_idx.entries[their_pos].path, path) == 0);

                if (!in_theirs) {
                    if (in_base) {
                        long c;
                        oid_compare(&c, our_blob, &base_idx.entries[base_pos].oid);
                        if (c == 0) continue;   /* pick deleted a file we didn't touch */
                        fprintf(stderr, "CONFLICT (modify/delete): %s\n", path);
                        has_conflicts = 1;
                        index_add(&merged_idx, path, our_blob,
                                  our_idx.entries[i].mode, 0, 0);
                    } else {
                        index_add(&merged_idx, path, our_blob,
                                  our_idx.entries[i].mode, 0, 0);
                    }
                    continue;
                }

                {
                    gut_oid *their_blob = &their_idx.entries[their_pos].oid;
                    long c_ours_theirs, c_ours_base;

                    oid_compare(&c_ours_theirs, our_blob, their_blob);
                    if (c_ours_theirs == 0) {
                        index_add(&merged_idx, path, our_blob,
                                  our_idx.entries[i].mode, 0, 0);
                        continue;
                    }

                    if (!in_base) {
                        fprintf(stderr, "CONFLICT (add/add): %s\n", path);
                        has_conflicts = 1;
                        index_add(&merged_idx, path, our_blob,
                                  our_idx.entries[i].mode, 0, 0);
                        continue;
                    }

                    oid_compare(&c_ours_base, our_blob, &base_idx.entries[base_pos].oid);
                    if (c_ours_base == 0) {
                        index_add(&merged_idx, path, their_blob,
                                  their_idx.entries[their_pos].mode, 0, 0);
                        continue;
                    }

                    {
                        long c_theirs_base;
                        oid_compare(&c_theirs_base, their_blob,
                                    &base_idx.entries[base_pos].oid);
                        if (c_theirs_base == 0) {
                            index_add(&merged_idx, path, our_blob,
                                      our_idx.entries[i].mode, 0, 0);
                            continue;
                        }
                    }

                    {
                        gut_object b_obj, o_obj, t_obj;
                        diff_merge_result mr;

                        if (odb_read(&b_obj, &repo.odb,
                                     &base_idx.entries[base_pos].oid) ||
                            odb_read(&o_obj, &repo.odb, our_blob) ||
                            odb_read(&t_obj, &repo.odb, their_blob)) {
                            fprintf(stderr, "error: cannot read blobs for %s\n", path);
                            has_conflicts = 1;
                            index_add(&merged_idx, path, our_blob,
                                      our_idx.entries[i].mode, 0, 0);
                            continue;
                        }

                        rc = diff_three_way(&mr,
                            (const char *)b_obj.data.data, b_obj.data.len,
                            (const char *)o_obj.data.data, o_obj.data.len,
                            (const char *)t_obj.data.data, t_obj.data.len,
                            "HEAD", "cherry-pick",
                            DIFF_MERGE_STYLE_STANDARD);

                        object_destroy(&b_obj);
                        object_destroy(&o_obj);
                        object_destroy(&t_obj);

                        if (rc) {
                            fprintf(stderr, "error: merge failed for %s\n", path);
                            has_conflicts = 1;
                            index_add(&merged_idx, path, our_blob,
                                      our_idx.entries[i].mode, 0, 0);
                        } else {
                            gut_oid merged_blob;
                            odb_write(&merged_blob, &repo.odb, GUT_OBJ_BLOB,
                                      (u8 *)mr.data, mr.len);
                            index_add(&merged_idx, path, &merged_blob,
                                      our_idx.entries[i].mode, 0, 0);
                            if (mr.has_conflicts) {
                                fprintf(stderr,
                                        "CONFLICT (content): merge conflict in %s\n",
                                        path);
                                has_conflicts = 1;
                            }
                            diff_merge_destroy(&mr);
                        }
                    }
                }
            }

            /* Files new in the pick (added by pick, absent from HEAD). */
            for (i = 0; i < their_idx.count; i++) {
                const char *path = their_idx.entries[i].path;
                u64 our_pos;
                index_find(&our_pos, &our_idx, path);
                if (our_pos < our_idx.count &&
                    strcmp(our_idx.entries[our_pos].path, path) == 0)
                    continue;
                index_add(&merged_idx, path, &their_idx.entries[i].oid,
                          their_idx.entries[i].mode, 0, 0);
            }

            index_destroy(&base_idx);
            index_destroy(&our_idx);
            index_destroy(&their_idx);

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
                free(pick_author); free(pick_message);
                fprintf(stderr,
                        "error: could not apply %s cleanly; resolve conflicts and "
                        "commit.\n", rev_spec);
                return 1;
            }

            snprintf(obj_dir, sizeof(obj_dir), "%s/objects", repo.git_dir);
            index_write_tree(&merge_tree_oid, &merged_idx, obj_dir);
            index_write(&merged_idx, index_path);
            index_destroy(&merged_idx);

            /* Build the new commit: single parent (HEAD), preserved author
             * (as a full "Name <email> ts tz" line from the picked commit),
             * current-user committer, message + trailer. */
            {
                buf commit_buf;
                const char *committer_name = NULL;
                const char *committer_email = NULL;
                char timestamp[128];
                time_t now = time(NULL);
                char committer_name_buf[256];
                char committer_email_buf[256];
                gut_config cfg;
                int have_cfg = 0;
                char pick_oid_hex[GUT_OID_MAX_HEX_SIZE + 1];
                char subject[256];

                committer_name = getenv("GUT_COMMITTER_NAME");
                if (!committer_name) committer_name = getenv("GUT_AUTHOR_NAME");
                if (!committer_name) committer_name = getenv("GIT_COMMITTER_NAME");
                if (!committer_name) committer_name = getenv("GIT_AUTHOR_NAME");
                committer_email = getenv("GUT_COMMITTER_EMAIL");
                if (!committer_email) committer_email = getenv("GUT_AUTHOR_EMAIL");
                if (!committer_email) committer_email = getenv("GIT_COMMITTER_EMAIL");
                if (!committer_email) committer_email = getenv("GIT_AUTHOR_EMAIL");
                if (!committer_name || !committer_email) {
                    char config_path[2048];
                    snprintf(config_path, sizeof(config_path), "%s/config", repo.git_dir);
                    if (config_read(&cfg, config_path) == 0) {
                        const char *v;
                        have_cfg = 1;
                        if (!committer_name && config_get(&v, &cfg, "user", "name") == 0)
                            committer_name = v;
                        if (!committer_email && config_get(&v, &cfg, "user", "email") == 0)
                            committer_email = v;
                    }
                }
                if (!committer_name) committer_name = "Unknown";
                if (!committer_email) committer_email = "unknown@example.com";
                snprintf(committer_name_buf, sizeof(committer_name_buf),
                         "%s", committer_name);
                snprintf(committer_email_buf, sizeof(committer_email_buf),
                         "%s", committer_email);
                if (have_cfg) config_destroy(&cfg);

                {
                    long tz_offset = 0;
#ifdef _WIN32
                    TIME_ZONE_INFORMATION tzi;
                    if (GetTimeZoneInformation(&tzi) != TIME_ZONE_ID_INVALID)
                        tz_offset = -(long)tzi.Bias;
#else
                    struct tm *lt = localtime(&now);
                    if (lt) tz_offset = lt->tm_gmtoff / 60;
#endif
                    snprintf(timestamp, sizeof(timestamp), "%lld %+03ld%02ld",
                             (long long)now, tz_offset / 60, labs(tz_offset) % 60);
                }

                buf_create(&commit_buf, 512);

                oid_to_hex_n(hex, &merge_tree_oid, hex_len);
                buf_append(&commit_buf, (u8 *)"tree ", 5);
                buf_append(&commit_buf, (u8 *)hex, hex_len);
                buf_append_byte(&commit_buf, '\n');

                oid_to_hex_n(hex, &our_oid, hex_len);
                buf_append(&commit_buf, (u8 *)"parent ", 7);
                buf_append(&commit_buf, (u8 *)hex, hex_len);
                buf_append_byte(&commit_buf, '\n');

                /* Preserve the pick's author line verbatim. Fallback to the
                 * current committer if the original was missing. */
                if (pick_author) {
                    buf_append(&commit_buf, (u8 *)"author ", 7);
                    buf_append(&commit_buf, (u8 *)pick_author, pick_author_len);
                    buf_append_byte(&commit_buf, '\n');
                } else {
                    char line[512];
                    int n = snprintf(line, sizeof(line), "author %s <%s> %s\n",
                                     committer_name_buf, committer_email_buf,
                                     timestamp);
                    buf_append(&commit_buf, (u8 *)line, (u64)n);
                }
                {
                    char line[512];
                    int n = snprintf(line, sizeof(line), "committer %s <%s> %s\n",
                                     committer_name_buf, committer_email_buf,
                                     timestamp);
                    buf_append(&commit_buf, (u8 *)line, (u64)n);
                }

                buf_append_byte(&commit_buf, '\n');

                if (pick_message) {
                    buf_append(&commit_buf, (u8 *)pick_message, pick_message_len);
                    /* Ensure a separating blank line before the trailer. */
                    if (pick_message_len == 0 ||
                        pick_message[pick_message_len - 1] != '\n')
                        buf_append_byte(&commit_buf, '\n');
                    buf_append_byte(&commit_buf, '\n');
                }

                oid_to_hex_n(pick_oid_hex, &their_oid, hex_len);
                pick_oid_hex[hex_len] = '\0';
                {
                    char trailer[128];
                    int n = snprintf(trailer, sizeof(trailer),
                                     "(cherry picked from commit %s)\n",
                                     pick_oid_hex);
                    buf_append(&commit_buf, (u8 *)trailer, (u64)n);
                }

                odb_write(&new_commit_oid, &repo.odb, GUT_OBJ_COMMIT,
                          commit_buf.data, commit_buf.len);
                buf_destroy(&commit_buf);

                commit_subject(subject, sizeof(subject), pick_message);
                {
                    char reflog_reason[512];
                    snprintf(reflog_reason, sizeof(reflog_reason),
                             "cherry-pick: %s", subject);
                    repo_update_ref(&repo, head_ref, &new_commit_oid,
                                    reflog_reason);
                }

                oid_to_hex_n(hex, &new_commit_oid, hex_len);
                hex[hex_len] = '\0';
                printf("[cherry-pick %.*s] %s\n", 7, hex, subject);
            }

            free(pick_author);
            free(pick_message);
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 0;
    }

    if (strcmp(argv[1], "help") == 0 ||
        strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0) {
        usage();
        return 0;
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
    if (strcmp(argv[1], "index-pack") == 0) {
        return cmd_index_pack(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "repack") == 0) {
        return cmd_repack(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "remote") == 0) {
        return cmd_remote(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "submodule") == 0) {
        return cmd_submodule(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "config") == 0) {
        return cmd_config(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "listen") == 0) {
        return cmd_listen(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "server") == 0) {
        return cmd_server(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "leech") == 0) {
        return cmd_leech(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "send") == 0) {
        return cmd_send(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "leechers") == 0) {
        return cmd_leechers(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "ask") == 0) {
        return cmd_ask(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "offer") == 0) {
        return cmd_offer(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "offers") == 0) {
        return cmd_offers(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "sos") == 0) {
        return cmd_sos(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "feeling") == 0) {
        return cmd_feeling(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "login") == 0) {
        return cmd_login(argc - 2, argv + 2);
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
    if (strcmp(argv[1], "mv") == 0) {
        return cmd_mv(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "ls-files") == 0) {
        return cmd_ls_files(argc - 2, argv + 2);
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
    if (strcmp(argv[1], "cherry-pick") == 0) {
        return cmd_cherry_pick(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "diff") == 0) {
        return cmd_diff(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "commit") == 0) {
        return cmd_commit(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "wip") == 0) {
        return cmd_wip(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "squash") == 0) {
        return cmd_squash(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "revert-file") == 0) {
        return cmd_revert_file(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "stash") == 0) {
        return cmd_stash(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "blame") == 0) {
        return cmd_blame(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "show") == 0) {
        return cmd_show(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "bisect") == 0) {
        return cmd_bisect(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "log") == 0) {
        return cmd_log(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "reflog") == 0) {
        return cmd_reflog(argc - 2, argv + 2);
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
    suggest_command(argv[1]);
    fprintf(stderr, "  (run `gut help` for the full list)\n");
    return 1;
}
