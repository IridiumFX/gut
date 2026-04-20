/*
 * Credential-helper protocol client. See the header for scope.
 *
 * Subprocess architecture:
 *   We need a bidirectional pipe to the child: write the key=value
 *   request to its stdin, read key=value reply from its stdout. This
 *   is enough of a common pattern that we implement both POSIX and
 *   Windows versions inline rather than pulling in a full process
 *   abstraction.
 *
 *   POSIX: pipe() + fork() + exec() — standard.
 *   Windows: CreatePipe() + CreateProcess() with redirected handles.
 *
 * We don't time out the child. If `manager-core` hangs on a UI prompt
 * and the user backgrounded the shell, that's on them — gut will wait
 * indefinitely, same as git does. A timeout opt-in can come later if
 * any CI environment reports it matters.
 */

#include "gut/cred_helper.h"
#include "gut/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#endif

/* ====================================================================
 *  URL parser
 * ==================================================================== */

unsigned long cred_request_from_url(gut_cred_request *out, const char *url) {
    const char *p;
    const char *scheme_end;
    const char *authority;
    const char *at;
    const char *host_start;
    const char *host_end;
    const char *path_start;

    if (!out) return __LINE__;
    if (!url) return __LINE__;

    memset(out, 0, sizeof(*out));

    /* scheme */
    scheme_end = strstr(url, "://");
    if (!scheme_end) return __LINE__;
    {
        u64 slen = (u64)(scheme_end - url);
        if (slen >= sizeof(out->protocol)) return __LINE__;
        memcpy(out->protocol, url, slen);
        out->protocol[slen] = '\0';
    }
    authority = scheme_end + 3;

    /* Optional user@host prefix. */
    at = authority;
    p = authority;
    while (*p && *p != '/' && *p != '@') p++;
    if (*p == '@') {
        u64 ulen = (u64)(p - at);
        if (ulen >= sizeof(out->username)) return __LINE__;
        memcpy(out->username, at, ulen);
        out->username[ulen] = '\0';
        host_start = p + 1;
    } else {
        host_start = authority;
    }

    /* Host runs to the first '/' or the end. Port (:N) is retained
     * verbatim — some helpers accept it, others ignore. */
    host_end = host_start;
    while (*host_end && *host_end != '/') host_end++;
    {
        u64 hlen = (u64)(host_end - host_start);
        if (hlen >= sizeof(out->host)) return __LINE__;
        memcpy(out->host, host_start, hlen);
        out->host[hlen] = '\0';
    }

    /* Path: everything after the first '/', minus a leading slash so
     * it reads as "owner/repo" for github-style URLs. */
    if (*host_end == '/') {
        path_start = host_end + 1;
        {
            u64 plen = strlen(path_start);
            if (plen >= sizeof(out->path)) return __LINE__;
            memcpy(out->path, path_start, plen);
            out->path[plen] = '\0';
        }
    }

    return 0;
}

/* ====================================================================
 *  Config lookup
 * ==================================================================== */

unsigned long cred_helper_from_config(char *out, u64 out_sz,
                                      const char *common_dir) {
    char cp[2048];
    gut_config cfg;
    const char *v = NULL;

    if (!out) return __LINE__;
    if (!common_dir) return __LINE__;

    snprintf(cp, sizeof(cp), "%s/config", common_dir);
    if (config_read(&cfg, cp)) return __LINE__;

    if (config_get(&v, &cfg, "credential", "helper") != 0 || !v) {
        config_destroy(&cfg);
        return __LINE__;
    }
    if (strlen(v) >= out_sz) {
        config_destroy(&cfg);
        return __LINE__;
    }
    snprintf(out, (size_t)out_sz, "%s", v);
    config_destroy(&cfg);
    return 0;
}

/* ====================================================================
 *  Resolve helper name → program to run
 * ==================================================================== */

/* Returns 0 on success with the full command line written to `out`.
 * Rejects shell-exec ("!cmd") forms for now. */
static unsigned long resolve_helper_command(char *out, u64 out_sz,
                                            const char *name) {
    if (!name || !*name) return __LINE__;
    if (name[0] == '!') {
        fprintf(stderr,
                "error: shell-exec credential helpers (\"!<cmd>\") are not "
                "supported by gut yet — configure a named helper instead\n");
        return __LINE__;
    }
    /* Absolute path (POSIX) or drive-letter path (Windows). */
    if (name[0] == '/' || name[0] == '\\' ||
        (name[0] != '\0' && name[1] == ':')) {
        if ((u64)snprintf(out, (size_t)out_sz, "%s", name) >= out_sz)
            return __LINE__;
        return 0;
    }
    /* Bare name: prefix with git-credential-. Common helpers:
     *   manager-core, manager, osxkeychain, libsecret, cache, store */
    if ((u64)snprintf(out, (size_t)out_sz, "git-credential-%s", name)
        >= out_sz) return __LINE__;
    return 0;
}

/* ====================================================================
 *  Build the stdin payload
 * ==================================================================== */

static void build_payload(char *out, u64 out_sz, const gut_cred_request *req) {
    u64 off = 0;
    int n;
    if (req->protocol[0]) {
        n = snprintf(out + off, (size_t)(out_sz - off),
                     "protocol=%s\n", req->protocol);
        off += (n > 0) ? (u64)n : 0;
    }
    if (req->host[0]) {
        n = snprintf(out + off, (size_t)(out_sz - off),
                     "host=%s\n", req->host);
        off += (n > 0) ? (u64)n : 0;
    }
    if (req->path[0]) {
        n = snprintf(out + off, (size_t)(out_sz - off),
                     "path=%s\n", req->path);
        off += (n > 0) ? (u64)n : 0;
    }
    if (req->username[0]) {
        n = snprintf(out + off, (size_t)(out_sz - off),
                     "username=%s\n", req->username);
        off += (n > 0) ? (u64)n : 0;
    }
    /* Terminating blank line — protocol sentinel. */
    if (out_sz - off >= 2) {
        out[off++] = '\n';
        out[off] = '\0';
    }
}

/* ====================================================================
 *  Parse helper's reply
 * ==================================================================== */

static int parse_reply(gut_cred_response *out, const char *buf, u64 len) {
    u64 i = 0;
    int got_user = 0, got_pass = 0;

    memset(out, 0, sizeof(*out));

    while (i < len) {
        u64 line_start = i;
        u64 line_end;
        const char *key;
        const char *eq;
        while (i < len && buf[i] != '\n') i++;
        line_end = i;
        if (i < len) i++;   /* skip \n */

        /* Trim trailing \r */
        while (line_end > line_start && buf[line_end - 1] == '\r') line_end--;

        if (line_start == line_end) continue;   /* blank — end marker */

        key = buf + line_start;
        eq = memchr(key, '=', (size_t)(line_end - line_start));
        if (!eq) continue;

        {
            u64 klen = (u64)(eq - key);
            const char *val = eq + 1;
            u64 vlen = (u64)(line_end - line_start) - klen - 1;

            if (klen == 8 && memcmp(key, "username", 8) == 0) {
                if (vlen >= sizeof(out->username)) vlen = sizeof(out->username) - 1;
                memcpy(out->username, val, vlen);
                out->username[vlen] = '\0';
                got_user = 1;
            } else if (klen == 8 && memcmp(key, "password", 8) == 0) {
                if (vlen >= sizeof(out->password)) vlen = sizeof(out->password) - 1;
                memcpy(out->password, val, vlen);
                out->password[vlen] = '\0';
                got_pass = 1;
            }
            /* Other keys (protocol, host, path, quit, etc.) are ignored. */
        }
    }

    /* A successful get returns BOTH username and password. Some helpers
     * return only one or neither when they have no credential stored —
     * we report that as a non-success so the caller falls through to
     * whatever the next fallback is (e.g. `gut login`, or prompt). */
    return (got_user && got_pass) ? 0 : 1;
}

/* ====================================================================
 *  Subprocess invocation — platform-specific
 * ==================================================================== */

#ifdef _WIN32

static unsigned long run_helper_win(const char *cmd, const char *subcmd,
                                    const char *input, u64 input_len,
                                    char *output, u64 output_cap,
                                    u64 *output_len) {
    HANDLE stdin_r = NULL, stdin_w = NULL;
    HANDLE stdout_r = NULL, stdout_w = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char full_cmd[4096];
    DWORD exit_code = 0;
    DWORD written = 0;
    DWORD total_read = 0;

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&stdin_r, &stdin_w, &sa, 0)) return __LINE__;
    if (!SetHandleInformation(stdin_w, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(stdin_r); CloseHandle(stdin_w);
        return __LINE__;
    }
    if (!CreatePipe(&stdout_r, &stdout_w, &sa, 0)) {
        CloseHandle(stdin_r); CloseHandle(stdin_w);
        return __LINE__;
    }
    if (!SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(stdin_r); CloseHandle(stdin_w);
        CloseHandle(stdout_r); CloseHandle(stdout_w);
        return __LINE__;
    }

    snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd, subcmd);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdOutput = stdout_w;
    si.hStdInput = stdin_r;
    si.dwFlags |= STARTF_USESTDHANDLES;

    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE, 0,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(stdin_r); CloseHandle(stdin_w);
        CloseHandle(stdout_r); CloseHandle(stdout_w);
        return __LINE__;
    }

    /* Parent closes its end of the child's inherited handles so the
     * child can see EOF on stdin when we close `stdin_w`. */
    CloseHandle(stdin_r);
    CloseHandle(stdout_w);

    /* Write the payload then close stdin so the helper gets EOF. */
    if (input_len > 0) {
        DWORD off = 0;
        while (off < (DWORD)input_len) {
            if (!WriteFile(stdin_w, input + off,
                           (DWORD)input_len - off, &written, NULL)) break;
            if (written == 0) break;
            off += written;
        }
    }
    CloseHandle(stdin_w);

    /* Read stdout until EOF or buffer fills. */
    while (total_read + 1 < output_cap) {
        DWORD got = 0;
        if (!ReadFile(stdout_r, output + total_read,
                      (DWORD)(output_cap - 1 - total_read), &got, NULL)) break;
        if (got == 0) break;
        total_read += got;
    }
    output[total_read] = '\0';
    *output_len = total_read;
    CloseHandle(stdout_r);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != 0) return __LINE__;
    return 0;
}

#else

static unsigned long run_helper_posix(const char *cmd, const char *subcmd,
                                      const char *input, u64 input_len,
                                      char *output, u64 output_cap,
                                      u64 *output_len) {
    int in_pipe[2];
    int out_pipe[2];
    pid_t pid;
    int status;
    u64 total_read = 0;

    if (pipe(in_pipe)  != 0) return __LINE__;
    if (pipe(out_pipe) != 0) {
        close(in_pipe[0]); close(in_pipe[1]);
        return __LINE__;
    }

    pid = fork();
    if (pid < 0) {
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return __LINE__;
    }
    if (pid == 0) {
        /* Child: hook pipes up to stdin/stdout, exec the helper. */
        dup2(in_pipe[0], 0);
        dup2(out_pipe[1], 1);
        close(in_pipe[0]);  close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        execlp(cmd, cmd, subcmd, (char *)NULL);
        _exit(127);
    }

    /* Parent */
    close(in_pipe[0]);
    close(out_pipe[1]);

    if (input_len > 0) {
        u64 off = 0;
        while (off < input_len) {
            ssize_t w = write(in_pipe[1], input + off, (size_t)(input_len - off));
            if (w <= 0) break;
            off += (u64)w;
        }
    }
    close(in_pipe[1]);

    while (total_read + 1 < output_cap) {
        ssize_t r = read(out_pipe[0], output + total_read,
                         (size_t)(output_cap - 1 - total_read));
        if (r <= 0) break;
        total_read += (u64)r;
    }
    output[total_read] = '\0';
    *output_len = total_read;
    close(out_pipe[0]);

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return __LINE__;
    return 0;
}

#endif

/* ====================================================================
 *  Public entry
 * ==================================================================== */

unsigned long cred_helper_get(gut_cred_response *out,
                              const char *helper_name,
                              const gut_cred_request *req) {
    char command[1024];
    char payload[2048];
    char reply[4096];
    u64 reply_len = 0;
    unsigned long rc;

    if (!out) return __LINE__;
    if (!req) return __LINE__;

    rc = resolve_helper_command(command, sizeof(command), helper_name);
    if (rc) return rc;

    build_payload(payload, sizeof(payload), req);

#ifdef _WIN32
    rc = run_helper_win(command, "get",
                        payload, strlen(payload),
                        reply, sizeof(reply), &reply_len);
#else
    rc = run_helper_posix(command, "get",
                          payload, strlen(payload),
                          reply, sizeof(reply), &reply_len);
#endif
    if (rc) return rc;

    if (parse_reply(out, reply, reply_len) != 0) return __LINE__;
    return 0;
}

/* Shared by store + erase. Build the payload including the username/
 * password (for store) or just the identifying fields (for erase),
 * spawn the helper with the given subcommand, expect no output. */
static unsigned long run_sideeffect(const char *helper_name,
                                    const char *subcmd,
                                    const gut_cred_request *req,
                                    const char *username,
                                    const char *password) {
    char command[1024];
    char payload[2560];
    char reply[256];   /* Store/erase produce no output, but keep a
                        * small buffer so stdout isn't blocked. */
    u64 reply_len = 0;
    unsigned long rc;

    rc = resolve_helper_command(command, sizeof(command), helper_name);
    if (rc) return rc;

    /* Start from the standard request payload, then append
     * username/password if given (store). erase sends only the
     * request fields + blank line. */
    build_payload(payload, sizeof(payload), req);
    if (username && *username) {
        u64 off = strlen(payload);
        /* build_payload already wrote the terminating blank line —
         * we need to back up over the trailing "\n" to insert more
         * fields before it. */
        if (off >= 1 && payload[off - 1] == '\n') {
            off -= 1;
            if (off >= 1 && payload[off - 1] == '\n') off -= 1;
            /* Now off points at the start of the blank terminator. */
        }
        off += (u64)snprintf(payload + off, sizeof(payload) - off,
                             "username=%s\n", username);
        if (password) {
            off += (u64)snprintf(payload + off, sizeof(payload) - off,
                                 "password=%s\n", password);
        }
        /* Re-terminate. */
        if (off + 1 < sizeof(payload)) {
            payload[off++] = '\n';
            payload[off] = '\0';
        }
    }

#ifdef _WIN32
    rc = run_helper_win(command, subcmd,
                        payload, strlen(payload),
                        reply, sizeof(reply), &reply_len);
#else
    rc = run_helper_posix(command, subcmd,
                          payload, strlen(payload),
                          reply, sizeof(reply), &reply_len);
#endif
    (void)reply_len;
    return rc;
}

unsigned long cred_helper_store(const char *helper_name,
                                const gut_cred_request *req,
                                const char *username,
                                const char *password) {
    if (!req) return __LINE__;
    if (!username || !password) return __LINE__;
    return run_sideeffect(helper_name, "store", req, username, password);
}

unsigned long cred_helper_erase(const char *helper_name,
                                const gut_cred_request *req) {
    if (!req) return __LINE__;
    return run_sideeffect(helper_name, "erase", req, NULL, NULL);
}
