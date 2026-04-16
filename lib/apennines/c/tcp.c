#include "apennines/tcp.h"
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
typedef int socklen_t;
#define INVALID_SOCK INVALID_SOCKET

static int wsa_ensure_init(void) {
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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#define CLOSE_SOCKET close
#define INVALID_SOCK (-1)
#endif

/* Build a struct sockaddr from a net_sock_addr. Returns sockaddr length or 0 on error. */
static socklen_t build_sockaddr(struct sockaddr_storage *ss, const net_sock_addr *addr) {
    memset(ss, 0, sizeof(*ss));

    if (addr->family == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr->port);
        memcpy(&sin->sin_addr, addr->addr.v4.octets, 4);
        return (socklen_t)sizeof(struct sockaddr_in);
    } else if (addr->family == 6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        memcpy(&sin6->sin6_addr, addr->addr.v6.octets, 16);
        return (socklen_t)sizeof(struct sockaddr_in6);
    }

    return 0;
}

unsigned long tcp_listener_create(tcp_listener *out, const net_sock_addr *addr, int backlog) {
    struct sockaddr_storage ss;
    socklen_t sslen;
    socket_t fd;
    int reuse = 1;
    int af;

    if (!out) return 1;
    if (!addr) return 2;

#ifdef _WIN32
    if (wsa_ensure_init() != 0) return 4;
#endif

    af = (addr->family == 6) ? AF_INET6 : AF_INET;
    sslen = build_sockaddr(&ss, addr);
    if (sslen == 0) return 3;

    fd = socket(af, SOCK_STREAM, 0);
    if (fd == (socket_t)INVALID_SOCK) return 4;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) != 0) {
        CLOSE_SOCKET(fd);
        return 5;
    }

    if (bind(fd, (struct sockaddr *)&ss, sslen) != 0) {
        CLOSE_SOCKET(fd);
        return 6;
    }

    if (listen(fd, backlog) != 0) {
        CLOSE_SOCKET(fd);
        return 7;
    }

    out->fd = fd;
    return 0;
}

unsigned long tcp_listener_accept(tcp_conn *out, tcp_listener *listener) {
    struct sockaddr_storage ss;
    socklen_t sslen;
    socket_t fd;

    if (!out) return 1;
    if (!listener) return 2;

    sslen = (socklen_t)sizeof(ss);
    fd = accept(listener->fd, (struct sockaddr *)&ss, &sslen);
    if (fd == (socket_t)INVALID_SOCK) return 3;

    out->fd = fd;
    return 0;
}

unsigned long tcp_listener_destroy(tcp_listener *listener) {
    if (!listener) return 1;
    if (CLOSE_SOCKET(listener->fd) != 0) return 2;
    listener->fd = (socket_t)INVALID_SOCK;
    return 0;
}

unsigned long tcp_conn_create(tcp_conn *out, const net_sock_addr *addr) {
    struct sockaddr_storage ss;
    socklen_t sslen;
    socket_t fd;
    int af;

    if (!out) return 1;
    if (!addr) return 2;

#ifdef _WIN32
    if (wsa_ensure_init() != 0) return 4;
#endif

    af = (addr->family == 6) ? AF_INET6 : AF_INET;
    sslen = build_sockaddr(&ss, addr);
    if (sslen == 0) return 3;

    fd = socket(af, SOCK_STREAM, 0);
    if (fd == (socket_t)INVALID_SOCK) return 4;

    if (connect(fd, (struct sockaddr *)&ss, sslen) != 0) {
        CLOSE_SOCKET(fd);
        return 5;
    }

    out->fd = fd;
    return 0;
}

unsigned long tcp_conn_read(u64 *bytes_read, tcp_conn *conn, u8 *buf, u64 len) {
#ifdef _WIN32
    int result;
#else
    long result;
#endif

    if (!bytes_read) return 1;
    if (!conn) return 2;
    if (!buf) return 3;

    result = recv(conn->fd, (char *)buf, (int)len, 0);
    if (result < 0) return 4;

    *bytes_read = (u64)result;
    return 0;
}

unsigned long tcp_conn_write(u64 *bytes_written, tcp_conn *conn, const u8 *data, u64 len) {
#ifdef _WIN32
    int result;
#else
    long result;
#endif

    if (!bytes_written) return 1;
    if (!conn) return 2;
    if (!data) return 3;

    result = send(conn->fd, (const char *)data, (int)len, 0);
    if (result < 0) return 4;

    *bytes_written = (u64)result;
    return 0;
}

unsigned long tcp_conn_write_all(u64 *bytes_written, tcp_conn *conn, const u8 *data, u64 len) {
#ifdef _WIN32
    int result;
#else
    long result;
#endif
    u64 total = 0;

    if (!bytes_written) return 1;
    if (!conn) return 2;
    if (!data) return 3;

    while (total < len) {
        result = send(conn->fd, (const char *)(data + total), (int)(len - total), 0);
        if (result < 0) {
            *bytes_written = total;
            return 4;
        }
        if (result == 0) {
            *bytes_written = total;
            return 5;
        }
        total += (u64)result;
    }

    *bytes_written = total;
    return 0;
}

unsigned long tcp_conn_shutdown(tcp_conn *conn, int how) {
    int sys_how;

    if (!conn) return 1;

    switch (how) {
#ifdef _WIN32
    case TCP_SHUTDOWN_READ:  sys_how = SD_RECEIVE; break;
    case TCP_SHUTDOWN_WRITE: sys_how = SD_SEND;    break;
    case TCP_SHUTDOWN_BOTH:  sys_how = SD_BOTH;    break;
#else
    case TCP_SHUTDOWN_READ:  sys_how = SHUT_RD;   break;
    case TCP_SHUTDOWN_WRITE: sys_how = SHUT_WR;   break;
    case TCP_SHUTDOWN_BOTH:  sys_how = SHUT_RDWR; break;
#endif
    default: return 2;
    }

    if (shutdown(conn->fd, sys_how) != 0) return 3;
    return 0;
}

unsigned long tcp_conn_set_nodelay(tcp_conn *conn, int enabled) {
    int flag;

    if (!conn) return 1;

    flag = enabled ? 1 : 0;
    if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&flag, sizeof(flag)) != 0) return 2;
    return 0;
}

unsigned long tcp_conn_set_keepalive(tcp_conn *conn, int enabled) {
    int flag;

    if (!conn) return 1;

    flag = enabled ? 1 : 0;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_KEEPALIVE,
                   (const char *)&flag, sizeof(flag)) != 0) return 2;
    return 0;
}

unsigned long tcp_conn_destroy(tcp_conn *conn) {
    if (!conn) return 1;
    if (CLOSE_SOCKET(conn->fd) != 0) return 2;
    conn->fd = (socket_t)INVALID_SOCK;
    return 0;
}
