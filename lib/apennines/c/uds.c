#include "apennines/uds.h"
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <afunix.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
typedef int socklen_t;

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
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#define CLOSE_SOCKET close
#endif

/* ================================================================
 *  Listener
 * ================================================================ */

unsigned long uds_listener_create(uds_listener *out, const char *path, int backlog) {
    struct sockaddr_un addr;
    uds_fd fd;
    size_t pathlen;

    if (!out)  return 1;
    if (!path) return 2;

    pathlen = strlen(path);
    if (pathlen == 0 || pathlen >= sizeof(addr.sun_path)) return 3;

#ifdef _WIN32
    if (wsa_ensure_init() != 0) return 4;
#endif

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == UDS_INVALID) return 4;

    /* Unlink stale socket file (best-effort, ignore errors). */
#ifdef _WIN32
    DeleteFileA(path);
#else
    unlink(path);
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, pathlen + 1);

    if (bind(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) != 0) {
        CLOSE_SOCKET(fd);
        return 5;
    }

    if (listen(fd, backlog) != 0) {
        CLOSE_SOCKET(fd);
        return 6;
    }

    out->fd = fd;
    memcpy(out->path, path, pathlen + 1);
    return 0;
}

unsigned long uds_listener_accept(uds_conn *out, uds_listener *listener) {
    struct sockaddr_un addr;
    socklen_t addrlen;
    uds_fd fd;

    if (!out)      return 1;
    if (!listener) return 2;

    addrlen = (socklen_t)sizeof(addr);
    fd = accept(listener->fd, (struct sockaddr *)&addr, &addrlen);
    if (fd == UDS_INVALID) return 3;

    out->fd = fd;
    return 0;
}

unsigned long uds_listener_destroy(uds_listener *listener) {
    if (!listener) return 1;

    if (CLOSE_SOCKET(listener->fd) != 0) return 2;
    listener->fd = UDS_INVALID;

    /* Remove the socket file so the path can be reused. */
#ifdef _WIN32
    DeleteFileA(listener->path);
#else
    unlink(listener->path);
#endif

    listener->path[0] = '\0';
    return 0;
}

/* ================================================================
 *  Connection
 * ================================================================ */

unsigned long uds_conn_create(uds_conn *out, const char *path) {
    struct sockaddr_un addr;
    uds_fd fd;
    size_t pathlen;

    if (!out)  return 1;
    if (!path) return 2;

    pathlen = strlen(path);
    if (pathlen == 0 || pathlen >= sizeof(addr.sun_path)) return 3;

#ifdef _WIN32
    if (wsa_ensure_init() != 0) return 4;
#endif

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == UDS_INVALID) return 4;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, pathlen + 1);

    if (connect(fd, (struct sockaddr *)&addr, (socklen_t)sizeof(addr)) != 0) {
        CLOSE_SOCKET(fd);
        return 5;
    }

    out->fd = fd;
    return 0;
}

unsigned long uds_conn_read(u64 *out_read, uds_conn *conn, u8 *buf, u64 len) {
#ifdef _WIN32
    int result;
#else
    long result;
#endif

    if (!out_read) return 1;
    if (!conn)     return 2;
    if (!buf)      return 3;

    result = recv(conn->fd, (char *)buf, (int)len, 0);
    if (result < 0) return 4;

    *out_read = (u64)result;
    return 0;
}

unsigned long uds_conn_write(u64 *out_written, uds_conn *conn, const u8 *data, u64 len) {
#ifdef _WIN32
    int result;
#else
    long result;
#endif

    if (!out_written) return 1;
    if (!conn)        return 2;
    if (!data)        return 3;

    result = send(conn->fd, (const char *)data, (int)len, 0);
    if (result < 0) return 4;

    *out_written = (u64)result;
    return 0;
}

unsigned long uds_conn_write_all(u64 *out_written, uds_conn *conn, const u8 *data, u64 len) {
#ifdef _WIN32
    int result;
#else
    long result;
#endif
    u64 total = 0;

    if (!out_written) return 1;
    if (!conn)        return 2;
    if (!data)        return 3;

    while (total < len) {
        result = send(conn->fd, (const char *)(data + total), (int)(len - total), 0);
        if (result < 0) {
            *out_written = total;
            return 4;
        }
        if (result == 0) {
            *out_written = total;
            return 5;
        }
        total += (u64)result;
    }

    *out_written = total;
    return 0;
}

/* ================================================================
 *  File-descriptor passing (POSIX only)
 * ================================================================ */

#ifndef _WIN32

unsigned long uds_conn_send_fd(uds_conn *conn, int fd) {
    struct msghdr msg;
    struct iovec iov;
    char buf[1] = { 0 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    if (!conn) return 1;

    memset(&msg, 0, sizeof(msg));

    /* Must send at least one byte of real data for sendmsg to work. */
    iov.iov_base = buf;
    iov.iov_len  = 1;
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(conn->fd, &msg, 0) < 0) return 2;

    return 0;
}

unsigned long uds_conn_recv_fd(int *out_fd, uds_conn *conn) {
    struct msghdr msg;
    struct iovec iov;
    char buf[1];
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    long n;

    if (!out_fd) return 1;
    if (!conn)   return 2;

    memset(&msg, 0, sizeof(msg));

    iov.iov_base = buf;
    iov.iov_len  = 1;
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    n = recvmsg(conn->fd, &msg, 0);
    if (n < 0) return 3;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
        return 4;
    }

    memcpy(out_fd, CMSG_DATA(cmsg), sizeof(int));
    return 0;
}

#else /* _WIN32 */

unsigned long uds_conn_send_fd(uds_conn *conn, int fd) {
    (void)fd;
    if (!conn) return 1;
    return 3; /* Not supported on Windows */
}

unsigned long uds_conn_recv_fd(int *out_fd, uds_conn *conn) {
    if (!out_fd) return 1;
    if (!conn)   return 2;
    return 5; /* Not supported on Windows */
}

#endif /* _WIN32 */

unsigned long uds_conn_destroy(uds_conn *conn) {
    if (!conn) return 1;
    if (CLOSE_SOCKET(conn->fd) != 0) return 2;
    conn->fd = UDS_INVALID;
    return 0;
}
