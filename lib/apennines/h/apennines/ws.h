#ifndef APENNINES_T3_WS_H
#define APENNINES_T3_WS_H

#include "apennines/types.h"

/* ================================================================
 *  WebSocket — RFC 6455 frame encoding, handshake, messaging
 * ================================================================ */

/* Opcodes */
#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT         0x1
#define WS_OPCODE_BINARY       0x2
#define WS_OPCODE_CLOSE        0x8
#define WS_OPCODE_PING         0x9
#define WS_OPCODE_PONG         0xA

typedef struct {
    int   fin;          /* 1 = final fragment */
    u8    opcode;
    u8   *payload;
    u64   payload_len;
    u8    mask_key[4];  /* client→server frames only */
    int   masked;
} ws_frame;

/* ---- Frame operations ---- */

/* ws_frame_encode — encode data into a WebSocket frame.
 *   out:      receives allocated frame bytes (caller frees)
 *   out_len:  receives frame length
 *   opcode:   WS_OPCODE_*
 *   payload:  payload data
 *   len:      payload length
 *   masked:   1=apply masking (client→server), 0=unmasked
 *   mask_key: 4-byte masking key (ignored if masked=0)
 *
 * Hatches: 1=null out, 2=null out_len, 3=alloc failure */
unsigned long ws_frame_encode(u8 **out, u64 *out_len,
                                             u8 opcode,
                                             const u8 *payload, u64 len,
                                             int masked, const u8 mask_key[4]);

/* ws_frame_decode — decode a frame from raw bytes.
 *   out:           receives parsed frame (payload allocated, caller frees)
 *   bytes_consumed: receives number of bytes consumed from input
 *   data:          raw input bytes
 *   data_len:      input length
 *
 * Hatches: 1=null out, 2=null bytes_consumed, 3=null data,
 *          4=incomplete frame (need more data), 5=alloc failure */
unsigned long ws_frame_decode(ws_frame *out, u64 *bytes_consumed,
                                             const u8 *data, u64 data_len);

/* ws_mask — apply/remove XOR masking in-place.
 *   data:     data to mask/unmask
 *   len:      data length
 *   mask_key: 4-byte masking key */
unsigned long ws_mask(u8 *data, u64 len, const u8 mask_key[4]);

/* ws_frame_free — free payload in a decoded frame. */
unsigned long ws_frame_free(ws_frame *f);

/* ---- Handshake ---- */

/* ws_handshake_build_request — build HTTP Upgrade request.
 *   out:      receives allocated request bytes (caller frees)
 *   out_len:  receives request length
 *   host:     server host (null-terminated)
 *   path:     request path (null-terminated)
 *   key:      Sec-WebSocket-Key (16 bytes, base64-encoded internally)
 *
 * Hatches: 1=null out, 2=null out_len, 3=null host,
 *          4=null path, 5=null key, 6=alloc failure */
unsigned long ws_handshake_build_request(u8 **out, u64 *out_len,
                                                        const char *host,
                                                        const char *path,
                                                        const u8 key[16]);

/* ws_handshake_validate_response — validate server's 101 response.
 *   out_valid:     receives 1 if valid, 0 otherwise
 *   response:      raw HTTP response bytes
 *   response_len:  response length
 *   expected_key:  original 16-byte key sent in request
 *
 * Hatches: 1=null out_valid, 2=null response, 3=null expected_key,
 *          4=not a 101 response, 5=missing Sec-WebSocket-Accept,
 *          6=accept value mismatch */
unsigned long ws_handshake_validate_response(int *out_valid,
                                                            const u8 *response,
                                                            u64 response_len,
                                                            const u8 expected_key[16]);

/* ws_handshake_build_response — build server accept response.
 *   out:      receives allocated response bytes (caller frees)
 *   out_len:  receives response length
 *   client_key: Sec-WebSocket-Key from client request (base64-encoded, null-terminated)
 *
 * Hatches: 1=null out, 2=null out_len, 3=null client_key,
 *          4=alloc failure */
unsigned long ws_handshake_build_response(u8 **out, u64 *out_len,
                                                         const char *client_key);

#endif /* APENNINES_T3_WS_H */
unsigned long ws_conn_create_client(void);
unsigned long ws_conn_create_server(void);
unsigned long ws_conn_destroy(void);
unsigned long ws_conn_recv(void);
unsigned long ws_conn_send_binary(void);
unsigned long ws_conn_send_close(void);
unsigned long ws_conn_send_ping(void);
unsigned long ws_conn_send_pong(void);
unsigned long ws_conn_send_text(void);
