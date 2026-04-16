#ifndef APENNINES_T2_ADDR_H
#define APENNINES_T2_ADDR_H


#include "apennines/types.h"

typedef struct {
    u8 octets[4];
} ipv4_addr;

typedef struct {
    u8 octets[16];
} ipv6_addr;

typedef struct {
    int family;  /* 4 or 6 */
    union {
        ipv4_addr v4;
        ipv6_addr v6;
    } addr;
    u16 port;
} net_sock_addr;

unsigned long addr_ipv4_parse(ipv4_addr *out, const char *str);
unsigned long addr_ipv4_format(char *out, u64 out_cap, const ipv4_addr *addr);
unsigned long addr_ipv6_parse(ipv6_addr *out, const char *str);
unsigned long addr_ipv6_format(char *out, u64 out_cap, const ipv6_addr *addr);
unsigned long addr_sockaddr_create(net_sock_addr *out, const char *host, u16 port);

/* Resolve hostname to IPv4 addresses via getaddrinfo().
 * On success, *out receives a heap-allocated array of ipv4_addr and *out_count
 * the number of entries; the caller must free(*out).
 * If no A-records are returned, *out is set to NULL and *out_count to 0 (hatch 5).
 * Hatches:
 *   1 = out is NULL
 *   2 = out_count is NULL
 *   3 = host is NULL
 *   4 = getaddrinfo() resolution failed
 *   5 = no IPv4 addresses returned
 *   6 = allocation failed
 */
unsigned long addr_resolve(ipv4_addr **out, u64 *out_count, const char *host);

#endif /* APENNINES_T2_ADDR_H */
