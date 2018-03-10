/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * TCP connection handling for remote on-the-wire testing using a real NIC.
 */

#ifndef __WIRE_CONN_H__
#define __WIRE_CONN_H__

#include "types.h"

#include "ip_address.h"
#include "wire_protocol.h"

struct config;

/* Buffer holding input or output data for a TCP socket. */
struct wire_conn_buffer {
	char *buf;	/* malloc-allocated buffer */
	int buf_space;	/* bytes allocated in malloc-allocated "buf" buffer */
	int used;	/* bytes of actual data at the start of "buf" */
};

/* A TCP socket used for client<->server communication for doing
 * remote on-the-wire testing using a real NIC.
 */
struct wire_conn {
	int fd;				/* socket for TCP connection (or -1) */
	struct wire_conn_buffer in;	/* data read in last wire_conn_read() */
};

/* Create a wire_conn. Note that a struct wire_conn shouldn't be
 * stack-allocated and should always use wire_conn_new() and
 * wire_conn_free().
 */
struct wire_conn *wire_conn_new(void);

/* Free a wire_conn. */
void wire_conn_free(struct wire_conn *conn);

/* Blocking connect. */
void wire_conn_connect(struct wire_conn *conn,
		       const struct ip_address *ip, u16 port,
		       enum ip_version_t ip_version);

/* Blocking bind and listen. */
void wire_conn_bind_listen(struct wire_conn *listen_conn, u16 port,
				enum ip_version_t ip_version);

/* Blocking accept. */
void wire_conn_accept(struct wire_conn *listen_conn,
		      struct wire_conn **accepted_conn);

/* Blocking write of a single message. */
int wire_conn_write(struct wire_conn *conn,
		    enum wire_op_t op,
		    const void *buf, int buf_len);

/* Blocking read of a single message. Changes *buf to point to the
 * wire_conn_buffer of this connection, which is guaranteed to be big
 * enough to hold the whole *buf_len bytes returned. The wire_conn
 * owns this memory, not the caller. The returned buffer can be
 * invalidated (freed or re-written) by the next call to
 * wire_conn_read().
 */
int wire_conn_read(struct wire_conn *conn,
		   enum wire_op_t *op,
		   void **buf, int *buf_len);

#endif /* __WIRE_CONN_H__ */
