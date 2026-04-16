#ifndef APENNINES_T3_DNS_H
#define APENNINES_T3_DNS_H


#include "apennines/types.h"
#include "apennines/addr.h"

/* DNS record type constants (RFC 1035 + RFC 3596) */
#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16

/* DNS class constants */
#define DNS_CLASS_IN    1

/* Maximum DNS name length (RFC 1035 Section 2.3.4) */
#define DNS_NAME_MAX  253
/* Maximum DNS wire packet size for UDP */
#define DNS_PACKET_MAX 512

/* A single DNS resource record */
typedef struct {
    char  name[DNS_NAME_MAX + 1];
    u16   type;
    u16   rclass;
    u32   ttl;
    u8   *rdata;
    u16   rdata_len;
} dns_record;

/* A parsed DNS response: dynamic array of records */
typedef struct {
    dns_record *records;
    u64         count;
    u64         capacity;
} dns_response;

/* Opaque DNS cache */
typedef struct dns_cache dns_cache;

/*
 * dns_query — resolve hostname to addresses (high-level, uses getaddrinfo).
 *   out:      receives a dns_response with A/AAAA records
 *   hostname: null-terminated hostname to resolve
 *
 * Hatches: 1=null out, 2=null hostname, 3=getaddrinfo failed,
 *          4=allocation failed
 */
unsigned long dns_query(dns_response *out,
                                      const char *hostname);

/*
 * dns_query_raw — send raw DNS query over UDP, get raw response.
 *   out_buf:      buffer to receive the raw DNS response
 *   out_len:      receives actual response length in bytes
 *   query_buf:    raw DNS query packet
 *   query_len:    length of query packet
 *   server:       DNS server address (e.g. 8.8.8.8:53)
 *   timeout_ms:   socket receive timeout in milliseconds
 *
 * Hatches: 1=null out_buf, 2=null out_len, 3=null query_buf,
 *          4=null server, 5=socket error, 6=send error,
 *          7=recv error/timeout
 */
unsigned long dns_query_raw(u8 *out_buf,
                                          u64 *out_len,
                                          u64 out_cap,
                                          const u8 *query_buf,
                                          u64 query_len,
                                          const net_sock_addr *server,
                                          u64 timeout_ms);

/*
 * dns_packet_build — build a DNS query packet in wire format (RFC 1035).
 *   out_buf:  buffer to write the packet into
 *   out_len:  receives the number of bytes written
 *   out_cap:  capacity of out_buf
 *   hostname: domain name to query (null-terminated)
 *   qtype:    query type (e.g. DNS_TYPE_A)
 *   qclass:   query class (e.g. DNS_CLASS_IN)
 *   txn_id:   transaction ID for the header
 *
 * Hatches: 1=null out_buf, 2=null out_len, 3=null hostname,
 *          4=hostname too long, 5=buffer too small
 */
unsigned long dns_packet_build(u8 *out_buf,
                                             u64 *out_len,
                                             u64 out_cap,
                                             const char *hostname,
                                             u16 qtype,
                                             u16 qclass,
                                             u16 txn_id);

/*
 * dns_packet_parse — parse a DNS response packet from wire format.
 *   out:     receives parsed dns_response (caller must free with dns_response_free)
 *   buf:     raw DNS packet bytes
 *   buf_len: length of buf in bytes
 *
 * Hatches: 1=null out, 2=null buf, 3=packet too short,
 *          4=malformed packet, 5=allocation failed
 */
unsigned long dns_packet_parse(dns_response *out,
                                             const u8 *buf,
                                             u64 buf_len);

/*
 * dns_response_free — free all memory held by a dns_response.
 *   resp: the response to free (NULL-safe)
 *
 * Hatches: 1=null resp
 */
unsigned long dns_response_free(dns_response *resp);

/*
 * dns_cache_create — create a DNS cache with a given maximum entry count.
 *   out:     receives pointer to the created cache
 *   max_entries: maximum number of cached entries
 *
 * Hatches: 1=null out, 2=allocation failed
 */
unsigned long dns_cache_create(dns_cache **out,
                                             u64 max_entries);

/*
 * dns_cache_lookup — look up a cached DNS record by name and type.
 *   out:    receives the dns_record if found (deep copy; caller frees rdata)
 *   cache:  the cache to search
 *   name:   domain name to look up
 *   qtype:  record type (e.g. DNS_TYPE_A)
 *
 * Hatches: 1=null out, 2=null cache, 3=null name, 4=not found
 */
unsigned long dns_cache_lookup(dns_record *out,
                                             dns_cache *cache,
                                             const char *name,
                                             u16 qtype);

/*
 * dns_cache_insert — insert a DNS record into the cache with its TTL.
 *   cache:     the cache
 *   record:    the record to insert (deep-copied)
 *   now_sec:   current time in seconds (monotonic or real)
 *
 * Hatches: 1=null cache, 2=null record, 3=allocation failed
 */
unsigned long dns_cache_insert(dns_cache *cache,
                                             const dns_record *record,
                                             u64 now_sec);

/*
 * dns_cache_evict — evict all expired entries from the cache.
 *   out_evicted: receives the number of entries evicted (may be NULL)
 *   cache:       the cache
 *   now_sec:     current time in seconds
 *
 * Hatches: 1=null cache
 */
unsigned long dns_cache_evict(u64 *out_evicted,
                                            dns_cache *cache,
                                            u64 now_sec);

/*
 * dns_cache_destroy — free all memory held by a DNS cache.
 *   cache: the cache to destroy
 *
 * Hatches: 1=null cache
 */
unsigned long dns_cache_destroy(dns_cache *cache);

#endif /* APENNINES_T3_DNS_H */
