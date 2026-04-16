#include "gut/repo.h"
#include "gut/oid.h"
#include "gut/object.h"
#include "gut/index.h"
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
        "   add         Add file contents to the index\n"
        "   commit      Record changes to the repository\n"
        "   log         Show commit logs\n"
        "   status      Show the working tree status\n"
        "   hash-object Hash a file and optionally write to object database\n"
        "   cat-file    Display object contents\n"
    );
}

/* Normalize path separators to forward slashes and make relative to repo root */
static void normalize_path(char *path) {
    char *p;
    for (p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
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

    rc = oid_from_hex(&oid, object_ref);
    if (rc) {
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

        /* Build full path */
        if (argv[i][0] == '/' || (argv[i][0] != '\0' && argv[i][1] == ':')) {
            snprintf(full_path, sizeof(full_path), "%s", argv[i]);
        } else {
            snprintf(full_path, sizeof(full_path), "%s/%s", cwd, argv[i]);
        }
        normalize_path(full_path);

        if (stat(full_path, &st) != 0) {
            fprintf(stderr, "error: pathspec '%s' did not match any files\n", argv[i]);
            index_destroy(&idx);
            return 1;
        }

        /* Compute relative path from repo root */
        {
            size_t root_len = strlen(repo.root_dir);
            if (strncmp(full_path, repo.root_dir, root_len) == 0) {
                const char *rel = full_path + root_len;
                if (*rel == '/' || *rel == '\\') rel++;
                snprintf(rel_path, sizeof(rel_path), "%s", rel);
            } else {
                snprintf(rel_path, sizeof(rel_path), "%s", argv[i]);
            }
        }
        normalize_path(rel_path);

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

    /* Build commit object */
    author_name = getenv("GUT_AUTHOR_NAME");
    if (!author_name) author_name = getenv("GIT_AUTHOR_NAME");
    if (!author_name) author_name = "Unknown";

    author_email = getenv("GUT_AUTHOR_EMAIL");
    if (!author_email) author_email = getenv("GIT_AUTHOR_EMAIL");
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

    index_destroy(&idx);
    printf("\n");
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
    if (strcmp(argv[1], "add") == 0) {
        return cmd_add(argc - 2, argv + 2);
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
