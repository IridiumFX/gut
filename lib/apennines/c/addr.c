#include "apennines/addr.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    static int addr_wsa_ensure_init(void) {
        static int done = 0;
        if (!done) {
            WSADATA wsa;
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
            done = 1;
        }
        return 0;
    }
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

/* Simple decimal parse helper, returns number of chars consumed or 0 on error */
static int parse_decimal(const char *s, unsigned long *out, unsigned long max_val) {
    unsigned long val = 0;
    int len = 0;

    if (!s || !*s) return 0;
    if (*s < '0' || *s > '9') return 0;

    while (s[len] >= '0' && s[len] <= '9') {
        val = val * 10 + (unsigned long)(s[len] - '0');
        if (val > max_val) return 0;
        len++;
    }

    *out = val;
    return len;
}

/* Simple hex parse helper */
static int parse_hex16(const char *s, unsigned long *out) {
    unsigned long val = 0;
    int len = 0;

    while (len < 4) {
        char c = s[len];
        if (c >= '0' && c <= '9') {
            val = val * 16 + (unsigned long)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            val = val * 16 + (unsigned long)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            val = val * 16 + (unsigned long)(c - 'A' + 10);
        } else {
            break;
        }
        len++;
    }

    if (len == 0) return 0;
    *out = val;
    return len;
}

unsigned long addr_ipv4_parse(ipv4_addr *out, const char *str) {
    int i;
    const char *p;

    if (!out) return 1;
    if (!str) return 2;

    p = str;
    for (i = 0; i < 4; i++) {
        unsigned long octet;
        int consumed = parse_decimal(p, &octet, 255);
        if (consumed == 0) return 3;
        out->octets[i] = (u8)octet;
        p += consumed;
        if (i < 3) {
            if (*p != '.') return 3;
            p++;
        }
    }

    if (*p != '\0') return 3;

    return 0;
}

unsigned long addr_ipv4_format(char *out, u64 out_cap, const ipv4_addr *addr) {
    char tmp[16]; /* "255.255.255.255\0" = 16 chars max */
    int pos = 0;
    int i;

    if (!out) return 1;
    if (!addr) return 2;

    for (i = 0; i < 4; i++) {
        u8 val = addr->octets[i];
        if (val >= 100) {
            tmp[pos++] = (char)('0' + val / 100);
            tmp[pos++] = (char)('0' + (val / 10) % 10);
            tmp[pos++] = (char)('0' + val % 10);
        } else if (val >= 10) {
            tmp[pos++] = (char)('0' + val / 10);
            tmp[pos++] = (char)('0' + val % 10);
        } else {
            tmp[pos++] = (char)('0' + val);
        }
        if (i < 3) {
            tmp[pos++] = '.';
        }
    }
    tmp[pos] = '\0';

    if ((u64)(pos + 1) > out_cap) return 3;

    memcpy(out, tmp, (size_t)(pos + 1));
    return 0;
}

unsigned long addr_ipv6_parse(ipv6_addr *out, const char *str) {
    /*
     * Parse standard IPv6 notation with :: compression.
     * Groups are 16-bit hex values separated by ':'.
     * "::" represents one or more groups of zeroes.
     */
    unsigned long groups[8];
    int group_count = 0;
    int double_colon_pos = -1;
    const char *p;
    int i;

    if (!out) return 1;
    if (!str) return 2;

    memset(groups, 0, sizeof(groups));
    p = str;

    /* Handle leading :: */
    if (p[0] == ':' && p[1] == ':') {
        double_colon_pos = 0;
        p += 2;
        if (*p == '\0') {
            /* "::" = all zeros */
            memset(out->octets, 0, 16);
            return 0;
        }
    }

    while (*p != '\0' && group_count < 8) {
        unsigned long val;
        int consumed;

        consumed = parse_hex16(p, &val);
        if (consumed == 0) return 3;

        groups[group_count++] = val;
        p += consumed;

        if (*p == ':') {
            p++;
            if (*p == ':') {
                if (double_colon_pos >= 0) return 3; /* only one :: allowed */
                double_colon_pos = group_count;
                p++;
                if (*p == '\0') break;
            }
        } else if (*p != '\0') {
            return 3;
        }
    }

    if (*p != '\0') return 3;

    /* Expand :: */
    if (double_colon_pos >= 0) {
        int fill = 8 - group_count;
        unsigned long expanded[8];
        int src_idx = 0;

        if (fill < 0) return 3;

        memset(expanded, 0, sizeof(expanded));
        for (i = 0; i < double_colon_pos; i++) {
            expanded[i] = groups[src_idx++];
        }
        for (i = double_colon_pos + fill; i < 8; i++) {
            expanded[i] = groups[src_idx++];
        }
        memcpy(groups, expanded, sizeof(groups));
        group_count = 8;
    }

    if (group_count != 8) return 3;

    /* Write octets */
    for (i = 0; i < 8; i++) {
        out->octets[i * 2]     = (u8)(groups[i] >> 8);
        out->octets[i * 2 + 1] = (u8)(groups[i] & 0xFF);
    }

    return 0;
}

unsigned long addr_ipv6_format(char *out, u64 out_cap, const ipv6_addr *addr) {
    /*
     * Format as full expanded IPv6: "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
     * Max length: 8*4 + 7 + 1 = 40 chars
     */
    static const char hex[] = "0123456789abcdef";
    char tmp[40];
    int pos = 0;
    int i;

    if (!out) return 1;
    if (!addr) return 2;

    for (i = 0; i < 8; i++) {
        u8 hi = addr->octets[i * 2];
        u8 lo = addr->octets[i * 2 + 1];
        tmp[pos++] = hex[hi >> 4];
        tmp[pos++] = hex[hi & 0x0F];
        tmp[pos++] = hex[lo >> 4];
        tmp[pos++] = hex[lo & 0x0F];
        if (i < 7) {
            tmp[pos++] = ':';
        }
    }
    tmp[pos] = '\0';

    if ((u64)(pos + 1) > out_cap) return 3;

    memcpy(out, tmp, (size_t)(pos + 1));
    return 0;
}

unsigned long addr_sockaddr_create(net_sock_addr *out, const char *host, u16 port) {
    unsigned long rc;

    if (!out) return 1;
    if (!host) return 2;

    memset(out, 0, sizeof(net_sock_addr));

    /* Try IPv4 first */
    rc = addr_ipv4_parse(&out->addr.v4, host);
    if (rc == 0) {
        out->family = 4;
        out->port = port;
        return 0;
    }

    /* Try IPv6 */
    rc = addr_ipv6_parse(&out->addr.v6, host);
    if (rc == 0) {
        out->family = 6;
        out->port = port;
        return 0;
    }

    /* Neither parsed successfully */
    return 3;
}
unsigned long addr_resolve(ipv4_addr **out, u64 *out_count, const char *host) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *cur;
    u64 count = 0;
    ipv4_addr *arr = NULL;
    u64 idx = 0;
    int gai_rc;

    if (!out) return 1;
    if (!out_count) return 2;
    if (!host) return 3;

    *out = NULL;
    *out_count = 0;

#ifdef _WIN32
    if (addr_wsa_ensure_init() != 0) return 4;
#endif

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       /* IPv4 only for now */
    hints.ai_socktype = SOCK_STREAM; /* de-duplicate results across socket types */

    gai_rc = getaddrinfo(host, NULL, &hints, &res);
    if (gai_rc != 0 || !res) {
        if (res) freeaddrinfo(res);
        return 4;
    }

    /* First pass: count IPv4 results */
    for (cur = res; cur != NULL; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET && cur->ai_addr != NULL &&
            cur->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
            count++;
        }
    }

    if (count == 0) {
        freeaddrinfo(res);
        return 5;
    }

    arr = (ipv4_addr *)malloc((size_t)count * sizeof(ipv4_addr));
    if (!arr) {
        freeaddrinfo(res);
        return 6;
    }

    /* Second pass: copy 4-byte network-order addresses into ipv4_addr octets */
    for (cur = res; cur != NULL && idx < count; cur = cur->ai_next) {
        if (cur->ai_family == AF_INET && cur->ai_addr != NULL &&
            cur->ai_addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
            struct sockaddr_in *sin = (struct sockaddr_in *)cur->ai_addr;
            /* sin_addr is a 32-bit value in network byte order; octets[0]
             * is the most significant byte, matching ipv4_addr layout. */
            memcpy(arr[idx].octets, &sin->sin_addr, 4);
            idx++;
        }
    }

    freeaddrinfo(res);

    *out = arr;
    *out_count = count;
    return 0;
}
