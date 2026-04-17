#include "gut/login.h"
#include "apennines/oidc.h"
#include "apennines/oauth2.h"
#include "apennines/oauth2_client.h"
#include "apennines/https_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define gut_mkdir(p) _mkdir(p)
#define gut_sleep_s(s) Sleep((s) * 1000)
#define gut_getenv_home() (getenv("USERPROFILE") ? getenv("USERPROFILE") : "C:")
#else
#include <unistd.h>
#define gut_mkdir(p) mkdir(p, 0700)
#define gut_sleep_s(s) sleep(s)
#define gut_getenv_home() (getenv("HOME") ? getenv("HOME") : "/tmp")
#endif

/* Build the path to ~/.gut/credentials (also ensures ~/.gut exists) */
static unsigned long credentials_path(char *out, size_t out_size) {
    const char *home = gut_getenv_home();
    char dir[1024];
    int n;

    n = snprintf(dir, sizeof(dir), "%s/.gut", home);
    if (n < 0 || (size_t)n >= sizeof(dir)) return __LINE__;
    gut_mkdir(dir);

    n = snprintf(out, out_size, "%s/.gut/credentials", home);
    if (n < 0 || (size_t)n >= out_size) return __LINE__;
    return 0;
}

/* Write/replace the credential block for `issuer`. Other blocks preserved. */
static unsigned long credentials_write(const char *issuer,
                                       const oauth2_token *tok,
                                       const char *client_id) {
    char path[1024];
    char tmp_path[1024];
    char section_marker[512];
    FILE *in;
    FILE *out;
    char line[1024];
    int in_target_section = 0;
    int wrote_block = 0;
    unsigned long rc;

    rc = credentials_path(path, sizeof(path));
    if (rc) return __LINE__;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    snprintf(section_marker, sizeof(section_marker),
             "[credential \"%s\"]", issuer);

    out = fopen(tmp_path, "w");
    if (!out) return __LINE__;

    /* Write our block */
    {
        u64 expires_at = tok->obtained_at + tok->expires_in;
        fprintf(out, "%s\n", section_marker);
        fprintf(out, "    access_token = %s\n", tok->access_token);
        if (tok->refresh_token)
            fprintf(out, "    refresh_token = %s\n", tok->refresh_token);
        fprintf(out, "    token_type = %s\n", tok->token_type ? tok->token_type : "Bearer");
        fprintf(out, "    expires_at = %llu\n", (unsigned long long)expires_at);
        if (client_id)
            fprintf(out, "    client_id = %s\n", client_id);
        if (tok->scope)
            fprintf(out, "    scope = %s\n", tok->scope);
        fputc('\n', out);
        wrote_block = 1;
    }

    /* Copy other sections from the existing file (skipping any old block for this issuer) */
    in = fopen(path, "r");
    if (in) {
        while (fgets(line, sizeof(line), in)) {
            if (line[0] == '[') {
                /* Section header */
                if (strstr(line, section_marker)) {
                    in_target_section = 1;
                    continue;
                } else {
                    in_target_section = 0;
                }
            }
            if (!in_target_section) {
                fputs(line, out);
            }
        }
        fclose(in);
    }
    (void)wrote_block;

    fclose(out);

    /* Atomic replace */
    remove(path);
    if (rename(tmp_path, path) != 0) {
        remove(tmp_path);
        return __LINE__;
    }

#ifndef _WIN32
    chmod(path, 0600);
#endif
    return 0;
}

/* Trim leading/trailing whitespace in place */
static char *trim(char *s) {
    char *end;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\n' || end[-1] == '\r')) end--;
    *end = '\0';
    return s;
}

unsigned long login_get_token(char **out, const char *issuer) {
    char path[1024];
    char section_marker[512];
    FILE *fp;
    char line[1024];
    int in_target_section = 0;
    char *access_token = NULL;
    u64 expires_at = 0;
    unsigned long rc;

    if (!out || !issuer) return __LINE__;
    *out = NULL;

    rc = credentials_path(path, sizeof(path));
    if (rc) return __LINE__;

    snprintf(section_marker, sizeof(section_marker),
             "[credential \"%s\"]", issuer);

    fp = fopen(path, "r");
    if (!fp) return __LINE__;

    while (fgets(line, sizeof(line), fp)) {
        char *t = trim(line);
        if (t[0] == '[') {
            in_target_section = (strcmp(t, section_marker) == 0);
            continue;
        }
        if (!in_target_section || t[0] == '\0' || t[0] == '#') continue;

        {
            char *eq = strchr(t, '=');
            if (eq) {
                char *key, *val;
                *eq = '\0';
                key = trim(t);
                val = trim(eq + 1);
                if (strcmp(key, "access_token") == 0) {
                    free(access_token);
                    access_token = (char *)malloc(strlen(val) + 1);
                    if (access_token) memcpy(access_token, val, strlen(val) + 1);
                } else if (strcmp(key, "expires_at") == 0) {
                    expires_at = (u64)strtoull(val, NULL, 10);
                }
            }
        }
    }
    fclose(fp);

    if (!access_token) return __LINE__;

    /* Check expiry (allow 60s skew) */
    if (expires_at != 0 && (u64)time(NULL) + 60 >= expires_at) {
        free(access_token);
        return __LINE__;
    }

    *out = access_token;
    return 0;
}

unsigned long login_device_flow(const char *issuer,
                                const char *client_id,
                                const char *scope) {
    https_client *c = NULL;
    oidc_config oc;
    oauth2_config ocfg;
    oauth2_device_authz authz;
    oauth2_token tok;
    unsigned long rc;
    int memset_done = 0;

    if (!issuer || !client_id) return __LINE__;

    memset(&oc, 0, sizeof(oc));
    memset(&authz, 0, sizeof(authz));
    memset(&tok, 0, sizeof(tok));

    rc = https_client_create(&c);
    if (rc) { fprintf(stderr, "error: cannot create HTTPS client\n"); return __LINE__; }

    /* 1. OIDC discovery */
    printf("Discovering OIDC config from %s ...\n", issuer);
    fflush(stdout);
    rc = oidc_discover(&oc, c, issuer);
    if (rc) {
        fprintf(stderr, "error: OIDC discovery failed (rc=%lu)\n", rc);
        fprintf(stderr, "  (likely TLS handshake — issuer's CA may not be in trust store)\n");
        https_client_destroy(c);
        return __LINE__;
    }

    if (!oc.device_authorization_endpoint) {
        fprintf(stderr, "error: issuer does not advertise device authorization endpoint\n");
        oidc_config_free(&oc);
        https_client_destroy(c);
        return __LINE__;
    }

    /* 2. Device authorization */
    memset(&ocfg, 0, sizeof(ocfg));
    ocfg.token_endpoint = oc.token_endpoint;
    ocfg.client_id = client_id;
    ocfg.scope = scope;
    memset_done = 1;
    (void)memset_done;

    printf("Requesting device authorization ...\n");
    fflush(stdout);
    rc = oauth2_client_device_authorize(&authz, c,
                                         oc.device_authorization_endpoint,
                                         &ocfg);
    if (rc) {
        fprintf(stderr, "error: device authorize failed (rc=%lu)\n", rc);
        oidc_config_free(&oc);
        https_client_destroy(c);
        return __LINE__;
    }

    /* 3. Display verification URL + user code */
    printf("\n");
    printf("================================================================\n");
    printf(" To complete sign-in:\n");
    printf("\n");
    if (authz.verification_uri_complete) {
        printf("   %s\n", authz.verification_uri_complete);
    } else {
        printf("   1. Open: %s\n", authz.verification_uri);
        printf("   2. Enter code: %s\n", authz.user_code);
    }
    printf("\n");
    printf("================================================================\n");
    printf("\n");
    printf("Waiting for authorization (poll interval %llus)...\n",
           (unsigned long long)authz.interval);
    fflush(stdout);

    /* 4. Poll for token */
    {
        u64 interval = authz.interval > 0 ? authz.interval : 5;
        u64 elapsed = 0;
        u64 max_wait = authz.expires_in > 0 ? authz.expires_in : 600;

        for (;;) {
            gut_sleep_s(interval);
            elapsed += interval;

            rc = oauth2_client_device_poll(&tok, c, &ocfg, authz.device_code);
            if (rc == 0) break;
            if (rc == 11) { printf("."); fflush(stdout); continue; } /* pending */
            if (rc == 12) { interval += 5; printf(":"); fflush(stdout); continue; } /* slow_down */
            if (rc == 13) {
                fprintf(stderr, "\nerror: user denied authorization\n");
                oauth2_device_authz_free(&authz);
                oidc_config_free(&oc);
                https_client_destroy(c);
                return __LINE__;
            }
            if (rc == 14) {
                fprintf(stderr, "\nerror: device code expired\n");
                oauth2_device_authz_free(&authz);
                oidc_config_free(&oc);
                https_client_destroy(c);
                return __LINE__;
            }
            fprintf(stderr, "\nerror: device poll returned %lu\n", rc);
            oauth2_device_authz_free(&authz);
            oidc_config_free(&oc);
            https_client_destroy(c);
            return __LINE__;

            if (elapsed >= max_wait) {
                fprintf(stderr, "\nerror: timed out waiting for authorization\n");
                oauth2_device_authz_free(&authz);
                oidc_config_free(&oc);
                https_client_destroy(c);
                return __LINE__;
            }
        }
    }

    printf("\n\nGot token!\n");

    /* 5. Save credentials */
    rc = credentials_write(issuer, &tok, client_id);
    if (rc) {
        fprintf(stderr, "error: cannot save credentials (line %lu)\n", rc);
    } else {
        char path[1024];
        credentials_path(path, sizeof(path));
        printf("Saved to %s\n", path);
    }

    oauth2_token_free(&tok);
    oauth2_device_authz_free(&authz);
    oidc_config_free(&oc);
    https_client_destroy(c);
    return rc;
}
