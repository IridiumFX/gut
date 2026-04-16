#include "gut/repo.h"
#include "gut/oid.h"
#include "gut/object.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
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
        "   init       Create an empty gut repository\n"
        "   hash-object Hash a file and optionally write to object database\n"
        "   cat-file   Display object contents\n"
    );
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

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "init") == 0) {
        return cmd_init(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "hash-object") == 0) {
        return cmd_hash_object(argc - 2, argv + 2);
    }
    if (strcmp(argv[1], "cat-file") == 0) {
        return cmd_cat_file(argc - 2, argv + 2);
    }

    fprintf(stderr, "gut: '%s' is not a gut command\n", argv[1]);
    return 1;
}
