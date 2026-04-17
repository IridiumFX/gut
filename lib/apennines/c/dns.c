#include "apennines/dns.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET dns_sock_t;
    #define DNS_INVALID_SOCKET INVALID_SOCKET
    #define dns_close_socket closesocket

    static int dns_wsa_init(void) {
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
    #include <unistd.h>
    #include <sys/time.h>
    typedef int dns_sock_t;
    #define DNS_INVALID_SOCKET (-1)
    #define dns_close_socket close
#endif

/* ================================================================
 *  Internal helpers
 * ================================================================ */

static u16 read_u16_be(const u8 *p) {
    return (u16)((u16)p[0] << 8 | (u16)p[1]);
}

static u32 read_u32_be(const u8 *p) {
    return (u32)((u32)p[0] << 24 | (u32)p[1] << 16 |
                 (u32)p[2] << 8  | (u32)p[3]);
}

static void write_u16_be(u8 *p, u16 v) {
    p[0] = (u8)(v >> 8);
    p[1] = (u8)(v & 0xFF);
}

/*
 * Encode a domain name into DNS wire format labels.
 * "www.example.com" -> [3]www[7]example[3]com[0]
 * Returns number of bytes written, or 0 on error.
 */
static u64 encode_dns_name(u8 *out, u64 out_cap, const char *name) {
    u64 pos = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        u64 label_len;

        if (!dot) {
            label_len = (u64)strlen(p);
        } else {
            label_len = (u64)(dot - p);
        }

        if (label_len == 0 || label_len > 63) return 0;
        if (pos + 1 + label_len >= out_cap) return 0;

        out[pos++] = (u8)label_len;
        memcpy(out + pos, p, (size_t)label_len);
        pos += label_len;

        if (dot) {
            p = dot + 1;
        } else {
            break;
        }
    }

    if (pos + 1 > out_cap) return 0;
    out[pos++] = 0; /* root label */

    return pos;
}

/*
 * Decode a DNS wire-format name, handling compression pointers (RFC 1035 4.1.4).
 * Returns number of bytes consumed from the current position (not following pointers),
 * or 0 on error.
 */
static u64 decode_dns_name(char *out, u64 out_cap,
                           const u8 *pkt, u64 pkt_len, u64 offset) {
    u64 out_pos = 0;
    u64 cur = offset;
    u64 bytes_consumed = 0;
    int jumped = 0;
    int hops = 0;

    while (cur < pkt_len) {
        u8 len_byte = pkt[cur];

        if (len_byte == 0) {
            /* Root label - end of name */
            if (!jumped) bytes_consumed = cur - offset + 1;
            break;
        }

        if ((len_byte & 0xC0) == 0xC0) {
            /* Compression pointer */
            if (cur + 1 >= pkt_len) return 0;
            if (!jumped) bytes_consumed = cur - offset + 2;
            cur = (u64)((len_byte & 0x3F) << 8 | pkt[cur + 1]);
            jumped = 1;
            hops++;
            if (hops > 128) return 0; /* infinite loop protection */
            continue;
        }

        if ((len_byte & 0xC0) != 0) return 0; /* reserved bits */

        cur++;
        if (cur + len_byte > pkt_len) return 0;

        if (out_pos > 0) {
            if (out_pos + 1 >= out_cap) return 0;
            out[out_pos++] = '.';
        }

        if (out_pos + len_byte >= out_cap) return 0;
        memcpy(out + out_pos, pkt + cur, len_byte);
        out_pos += len_byte;
        cur += len_byte;
    }

    if (out_pos < out_cap) out[out_pos] = '\0';
    else if (out_cap > 0) out[out_cap - 1] = '\0';

    return bytes_consumed;
}

/* ================================================================
 *  dns_response helpers
 * ================================================================ */

static unsigned long response_init(dns_response *resp, u64 cap) {
    resp->records = (dns_record *)calloc((size_t)cap, sizeof(dns_record));
    if (!resp->records) return 1;
    resp->count = 0;
    resp->capacity = cap;
    return 0;
}

static unsigned long response_push(dns_response *resp, const dns_record *rec) {
    if (resp->count >= resp->capacity) {
        u64 new_cap = resp->capacity == 0 ? 4 : resp->capacity * 2;
        dns_record *tmp = (dns_record *)realloc(resp->records,
                                                 (size_t)(new_cap * sizeof(dns_record)));
        if (!tmp) return 1;
        resp->records = tmp;
        resp->capacity = new_cap;
    }
    resp->records[resp->count] = *rec;
    /* Deep copy rdata */
    if (rec->rdata && rec->rdata_len > 0) {
        resp->records[resp->count].rdata = (u8 *)malloc(rec->rdata_len);
        if (!resp->records[resp->count].rdata) return 1;
        memcpy(resp->records[resp->count].rdata, rec->rdata, rec->rdata_len);
    }
    resp->count++;
    return 0;
}

/* ================================================================
 *  dns_query — high-level resolution via getaddrinfo
 * ================================================================ */

unsigned long dns_query(dns_response *out, const char *hostname) {
    struct addrinfo hints, *result, *rp;
    int rc;

    if (!out) return 1;
    if (!hostname) return 2;

#ifdef _WIN32
    if (dns_wsa_init() != 0) return 3;
#endif

    memset(out, 0, sizeof(dns_response));
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(hostname, NULL, &hints, &result);
    if (rc != 0) return 3;

    if (response_init(out, 4) != 0) {
        freeaddrinfo(result);
        return 4;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        dns_record rec;
        memset(&rec, 0, sizeof(rec));

        /* Copy hostname into record name */
        {
            size_t hlen = strlen(hostname);
            if (hlen > DNS_NAME_MAX) hlen = DNS_NAME_MAX;
            memcpy(rec.name, hostname, hlen);
            rec.name[hlen] = '\0';
        }

        rec.rclass = DNS_CLASS_IN;
        rec.ttl = 0; /* unknown from getaddrinfo */

        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)rp->ai_addr;
            rec.type = DNS_TYPE_A;
            rec.rdata_len = 4;
            rec.rdata = (u8 *)malloc(4);
            if (!rec.rdata) {
                dns_response_free(out);
                freeaddrinfo(result);
                return 4;
            }
            memcpy(rec.rdata, &sa->sin_addr, 4);
            if (response_push(out, &rec) != 0) {
                free(rec.rdata);
                dns_response_free(out);
                freeaddrinfo(result);
                return 4;
            }
            /* response_push deep-copies rdata, so free local copy */
            free(rec.rdata);
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)rp->ai_addr;
            rec.type = DNS_TYPE_AAAA;
            rec.rdata_len = 16;
            rec.rdata = (u8 *)malloc(16);
            if (!rec.rdata) {
                dns_response_free(out);
                freeaddrinfo(result);
                return 4;
            }
            memcpy(rec.rdata, &sa6->sin6_addr, 16);
            if (response_push(out, &rec) != 0) {
                free(rec.rdata);
                dns_response_free(out);
                freeaddrinfo(result);
                return 4;
            }
            free(rec.rdata);
        }
    }

    freeaddrinfo(result);
    return 0;
}

/* ================================================================
 *  dns_query_raw — raw UDP query to a DNS server
 * ================================================================ */

unsigned long dns_query_raw(u8 *out_buf, u64 *out_len, u64 out_cap,
                            const u8 *query_buf, u64 query_len,
                            const net_sock_addr *server, u64 timeout_ms) {
    struct sockaddr_in addr4;
    struct sockaddr *sa;
    int sa_len;
    dns_sock_t fd;
    int sent, received;

    if (!out_buf) return 1;
    if (!out_len) return 2;
    if (!query_buf) return 3;
    if (!server) return 4;

    /* Only IPv4 servers supported for now */
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(server->port);
    memcpy(&addr4.sin_addr, server->addr.v4.octets, 4);
    sa = (struct sockaddr *)&addr4;
    sa_len = sizeof(addr4);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == DNS_INVALID_SOCKET) return 5;

    /* Set receive timeout */
    if (timeout_ms > 0) {
#ifdef _WIN32
        DWORD tv = (DWORD)timeout_ms;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = (long)(timeout_ms / 1000);
        tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    sent = sendto(fd, (const char *)query_buf, (int)query_len, 0, sa, sa_len);
    if (sent < 0) {
        dns_close_socket(fd);
        return 6;
    }

    received = recvfrom(fd, (char *)out_buf, (int)out_cap, 0, NULL, NULL);
    dns_close_socket(fd);

    if (received <= 0) return 7;

    *out_len = (u64)received;
    return 0;
}

/* ================================================================
 *  dns_packet_build — construct DNS query wire format (RFC 1035)
 * ================================================================ */

unsigned long dns_packet_build(u8 *out_buf, u64 *out_len, u64 out_cap,
                               const char *hostname, u16 qtype,
                               u16 qclass, u16 txn_id) {
    u64 name_len;
    u64 total;

    if (!out_buf) return 1;
    if (!out_len) return 2;
    if (!hostname) return 3;
    if (strlen(hostname) > DNS_NAME_MAX) return 4;

    /* We need: 12 (header) + encoded_name + 4 (qtype + qclass) */
    /* Encode name into a temp buffer first to know the length */
    {
        u8 name_buf[DNS_NAME_MAX + 2];
        name_len = encode_dns_name(name_buf, sizeof(name_buf), hostname);
        if (name_len == 0) return 4;

        total = 12 + name_len + 4;
        if (total > out_cap) return 5;

        /* DNS header (12 bytes) */
        write_u16_be(out_buf + 0, txn_id);   /* ID */
        write_u16_be(out_buf + 2, 0x0100);   /* Flags: RD=1 (recursion desired) */
        write_u16_be(out_buf + 4, 1);        /* QDCOUNT = 1 */
        write_u16_be(out_buf + 6, 0);        /* ANCOUNT = 0 */
        write_u16_be(out_buf + 8, 0);        /* NSCOUNT = 0 */
        write_u16_be(out_buf + 10, 0);       /* ARCOUNT = 0 */

        /* Question section: name + QTYPE + QCLASS */
        memcpy(out_buf + 12, name_buf, (size_t)name_len);
        write_u16_be(out_buf + 12 + name_len, qtype);
        write_u16_be(out_buf + 12 + name_len + 2, qclass);
    }

    *out_len = total;
    return 0;
}

/* ================================================================
 *  dns_packet_parse — parse DNS response wire format
 * ================================================================ */

unsigned long dns_packet_parse(dns_response *out, const u8 *buf, u64 buf_len) {
    u16 qdcount, ancount, nscount, arcount;
    u64 offset;
    u64 total_rr;
    u64 i;

    if (!out) return 1;
    if (!buf) return 2;
    if (buf_len < 12) return 3;

    memset(out, 0, sizeof(dns_response));

    qdcount = read_u16_be(buf + 4);
    ancount = read_u16_be(buf + 6);
    nscount = read_u16_be(buf + 8);
    arcount = read_u16_be(buf + 10);

    offset = 12;

    /* Skip question section */
    for (i = 0; i < qdcount; i++) {
        char tmp[DNS_NAME_MAX + 1];
        u64 consumed = decode_dns_name(tmp, sizeof(tmp), buf, buf_len, offset);
        if (consumed == 0) return 4;
        offset += consumed;
        if (offset + 4 > buf_len) return 4;
        offset += 4; /* QTYPE + QCLASS */
    }

    /* Parse answer + authority + additional sections */
    total_rr = (u64)ancount + (u64)nscount + (u64)arcount;

    if (total_rr > 0) {
        if (response_init(out, total_rr < 4 ? 4 : total_rr) != 0) return 5;
    }

    for (i = 0; i < total_rr; i++) {
        dns_record rec;
        u64 consumed;
        u16 rdlength;

        memset(&rec, 0, sizeof(rec));

        consumed = decode_dns_name(rec.name, sizeof(rec.name),
                                   buf, buf_len, offset);
        if (consumed == 0) return 4;
        offset += consumed;

        if (offset + 10 > buf_len) return 4;

        rec.type = read_u16_be(buf + offset);
        rec.rclass = read_u16_be(buf + offset + 2);
        rec.ttl = read_u32_be(buf + offset + 4);
        rdlength = read_u16_be(buf + offset + 8);
        offset += 10;

        if (offset + rdlength > buf_len) return 4;

        rec.rdata_len = rdlength;
        if (rdlength > 0) {
            rec.rdata = (u8 *)malloc(rdlength);
            if (!rec.rdata) return 5;
            memcpy(rec.rdata, buf + offset, rdlength);
        }
        offset += rdlength;

        if (response_push(out, &rec) != 0) {
            free(rec.rdata);
            return 5;
        }
        /* response_push deep-copies rdata, free our local copy */
        free(rec.rdata);
    }

    return 0;
}

/* ================================================================
 *  dns_response_free
 * ================================================================ */

unsigned long dns_response_free(dns_response *resp) {
    u64 i;

    if (!resp) return 1;

    if (resp->records) {
        for (i = 0; i < resp->count; i++) {
            free(resp->records[i].rdata);
        }
        free(resp->records);
    }
    resp->records = NULL;
    resp->count = 0;
    resp->capacity = 0;

    return 0;
}

/* ================================================================
 *  DNS cache — linear-probing hash table with TTL expiry
 * ================================================================ */

typedef struct {
    dns_record record;
    u64        expire_sec;   /* monotonic timestamp when entry expires */
    int        occupied;
} dns_cache_entry;

struct dns_cache {
    dns_cache_entry *entries;
    u64              max_entries;
    u64              count;
};

/* FNV-1a hash for cache keys (name + type) */
static u64 cache_hash(const char *name, u16 qtype) {
    u64 h = 14695981039346656037ULL;
    const char *p = name;
    while (*p) {
        h ^= (u64)(u8)*p++;
        h *= 1099511628211ULL;
    }
    h ^= (u64)qtype;
    h *= 1099511628211ULL;
    return h;
}

static int name_type_eq(const dns_cache_entry *e, const char *name, u16 qtype) {
    return e->occupied &&
           e->record.type == qtype &&
           strcmp(e->record.name, name) == 0;
}

unsigned long dns_cache_create(dns_cache **out, u64 max_entries) {
    dns_cache *c;

    if (!out) return 1;
    if (max_entries == 0) max_entries = 64;

    c = (dns_cache *)calloc(1, sizeof(dns_cache));
    if (!c) return 2;

    c->entries = (dns_cache_entry *)calloc((size_t)max_entries,
                                           sizeof(dns_cache_entry));
    if (!c->entries) {
        free(c);
        return 2;
    }
    c->max_entries = max_entries;
    c->count = 0;

    *out = c;
    return 0;
}

unsigned long dns_cache_lookup(dns_record *out, dns_cache *cache,
                               const char *name, u16 qtype) {
    u64 idx, start;

    if (!out) return 1;
    if (!cache) return 2;
    if (!name) return 3;

    start = cache_hash(name, qtype) % cache->max_entries;
    idx = start;

    do {
        dns_cache_entry *e = &cache->entries[idx];

        if (!e->occupied) return 4; /* empty slot = not found */

        if (name_type_eq(e, name, qtype)) {
            /* Copy record to output */
            *out = e->record;
            /* Deep copy rdata */
            if (e->record.rdata && e->record.rdata_len > 0) {
                out->rdata = (u8 *)malloc(e->record.rdata_len);
                if (!out->rdata) return 4;
                memcpy(out->rdata, e->record.rdata, e->record.rdata_len);
            }
            return 0;
        }

        idx = (idx + 1) % cache->max_entries;
    } while (idx != start);

    return 4; /* wrapped all the way around */
}

unsigned long dns_cache_insert(dns_cache *cache, const dns_record *record,
                               u64 now_sec) {
    u64 idx, start;

    if (!cache) return 1;
    if (!record) return 2;

    start = cache_hash(record->name, record->type) % cache->max_entries;
    idx = start;

    /* First pass: look for existing entry or empty slot */
    do {
        dns_cache_entry *e = &cache->entries[idx];

        if (!e->occupied) {
            /* Use this empty slot */
            goto insert_at;
        }

        if (name_type_eq(e, record->name, record->type)) {
            /* Update existing entry — free old rdata */
            free(e->record.rdata);
            e->record.rdata = NULL;
            goto insert_at;
        }

        idx = (idx + 1) % cache->max_entries;
    } while (idx != start);

    /* Table is full — evict the start slot */
    {
        dns_cache_entry *victim = &cache->entries[start];
        free(victim->record.rdata);
        victim->record.rdata = NULL;
        victim->occupied = 0;
        cache->count--;
        idx = start;
    }

insert_at:
    {
        dns_cache_entry *e = &cache->entries[idx];
        if (!e->occupied) cache->count++;

        e->record = *record;
        /* Deep copy name */
        memcpy(e->record.name, record->name, sizeof(e->record.name));
        /* Deep copy rdata */
        if (record->rdata && record->rdata_len > 0) {
            e->record.rdata = (u8 *)malloc(record->rdata_len);
            if (!e->record.rdata) return 3;
            memcpy(e->record.rdata, record->rdata, record->rdata_len);
        } else {
            e->record.rdata = NULL;
            e->record.rdata_len = 0;
        }
        e->expire_sec = now_sec + record->ttl;
        e->occupied = 1;
    }

    return 0;
}

unsigned long dns_cache_evict(u64 *out_evicted, dns_cache *cache, u64 now_sec) {
    u64 evicted = 0;
    u64 i;

    if (!cache) return 1;

    for (i = 0; i < cache->max_entries; i++) {
        dns_cache_entry *e = &cache->entries[i];
        if (e->occupied && now_sec >= e->expire_sec) {
            free(e->record.rdata);
            e->record.rdata = NULL;
            e->occupied = 0;
            cache->count--;
            evicted++;
        }
    }

    if (out_evicted) *out_evicted = evicted;
    return 0;
}

unsigned long dns_cache_destroy(dns_cache *cache) {
    u64 i;

    if (!cache) return 1;

    if (cache->entries) {
        for (i = 0; i < cache->max_entries; i++) {
            if (cache->entries[i].occupied) {
                free(cache->entries[i].record.rdata);
            }
        }
        free(cache->entries);
    }
    free(cache);

    return 0;
}
