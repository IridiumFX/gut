#ifndef APENNINES_T3_UDS_H
#define APENNINES_T3_UDS_H

#include "apennines/types.h"

/* ================================================================
 *  Unix Domain Sockets — local IPC with fd passing
 *
 *  POSIX: AF_UNIX     Windows: AF_UNIX (Win10 1803+)
 * ================================================================ */

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET uds_fd;
#define UDS_INVALID ((SOCKET)(~0))
#else
typedef int uds_fd;
#define UDS_INVALID (-1)
#endif

typedef struct {
    uds_fd fd;
    char   path[256];
} uds_listener;

typedef struct {
    uds_fd fd;
} uds_conn;

/* ----------------------------------------------------------------
 *  Listener
 * ---------------------------------------------------------------- */

/* uds_listener_create — create, bind, listen on a unix socket path.
 *   out:     receives the listener
 *   path:    socket path (null-terminated, max 255 chars)
 *   backlog: listen backlog
 *
 * Hatches: 1=null out, 2=null path, 3=path too long,
 *          4=socket() failed, 5=bind() failed, 6=listen() failed */
unsigned long uds_listener_create(uds_listener *out,
                                                 const char *path,
                                                 int backlog);

/* uds_listener_accept — accept a connection.
 *   out:      receives the connection
 *   listener: the listening socket
 *
 * Hatches: 1=null out, 2=null listener, 3=accept() failed */
unsigned long uds_listener_accept(uds_conn *out,
                                                 uds_listener *listener);

/* uds_listener_destroy — close the listener and unlink the path.
 *   listener: the listener to destroy
 *
 * Hatches: 1=null listener, 2=close failed */
unsigned long uds_listener_destroy(uds_listener *listener);

/* ----------------------------------------------------------------
 *  Connection
 * ---------------------------------------------------------------- */

/* uds_conn_create — connect to a unix socket path.
 *   out:   receives the connection
 *   path:  socket path
 *
 * Hatches: 1=null out, 2=null path, 3=path too long,
 *          4=socket() failed, 5=connect() failed */
unsigned long uds_conn_create(uds_conn *out, const char *path);

/* uds_conn_read — read up to len bytes.
 *   out_read: receives bytes actually read
 *   conn:     the connection
 *   buf:      output buffer
 *   len:      buffer capacity
 *
 * Hatches: 1=null out_read, 2=null conn, 3=null buf, 4=recv failed */
unsigned long uds_conn_read(u64 *out_read, uds_conn *conn,
                                           u8 *buf, u64 len);

/* uds_conn_write — write up to len bytes.
 *   out_written: receives bytes actually written
 *   conn:        the connection
 *   data:        input data
 *   len:         data length
 *
 * Hatches: 1=null out_written, 2=null conn, 3=null data, 4=send failed */
unsigned long uds_conn_write(u64 *out_written, uds_conn *conn,
                                            const u8 *data, u64 len);

/* uds_conn_write_all — write exactly len bytes (loop).
 *   out_written: receives total bytes written
 *   conn:        the connection
 *   data:        input data
 *   len:         data length
 *
 * Hatches: 1=null out_written, 2=null conn, 3=null data,
 *          4=send failed, 5=peer closed */
unsigned long uds_conn_write_all(u64 *out_written, uds_conn *conn,
                                                const u8 *data, u64 len);

/* uds_conn_send_fd — send a file descriptor over the socket.
 *   conn:   the connection
 *   fd:     file descriptor to send
 *
 * Hatches: 1=null conn, 2=sendmsg failed, 3=not supported (Windows) */
unsigned long uds_conn_send_fd(uds_conn *conn, int fd);

/* uds_conn_recv_fd — receive a file descriptor from the socket.
 *   out_fd:  receives the file descriptor
 *   conn:    the connection
 *
 * Hatches: 1=null out_fd, 2=null conn, 3=recvmsg failed,
 *          4=no fd in message, 5=not supported (Windows) */
unsigned long uds_conn_recv_fd(int *out_fd, uds_conn *conn);

/* uds_conn_destroy — close the connection.
 *   conn:   the connection to close
 *
 * Hatches: 1=null conn, 2=close failed */
unsigned long uds_conn_destroy(uds_conn *conn);

#endif /* APENNINES_T3_UDS_H */
