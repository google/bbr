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

#include "wire_conn.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>

#include "logging.h"
#include "tcp.h"
#include "wrap.h"

/* Cap the max message we're willing to read, so remote side can't OOM us. */
#define MAX_MESSAGE_BYTES (10*1000*1000)

struct wire_conn *wire_conn_new(void)
{
	DEBUGP("wire_conn_new\n");
	struct wire_conn *wire_conn = calloc(1, sizeof(struct wire_conn));
	wire_conn->fd = -1;

	return wire_conn;
}

void wire_conn_free(struct wire_conn *conn)
{
	if (conn->fd != -1)
		close(conn->fd);
	free(conn->in.buf);
	memset(conn, 0, sizeof(*conn));  /* paranoia: catch bugs */
	free(conn);
}

/* Create the TCP socket. */
static void create_tcp_socket(struct wire_conn *conn,
				enum ip_version_t ip_version)
{
	assert(conn->fd == -1);
	conn->fd = wrap_socket(ip_version, SOCK_STREAM);
}

/* Set default TCP socket options for decent performance. */
static void set_default_tcp_options(struct wire_conn *conn)
{
	int val;

	DEBUGP("set_default_tcp_options fd %d\n", conn->fd);

	/* Disable Nagle algorithm so packets go out ASAP regardless of size. */
	val = 1;
	if (setsockopt(conn->fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val)) < 0)
		die_perror("setsockopt TCP_NODELAY");

	/* Set receive buffer to allow high throughput. */
	val = 128*1024;
	if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &val,
		       sizeof(val)) < 0) {
		die_perror("setsockopt SO_RCVBUF");
	}

	/* Set send buffer to allow high throughput and avoid blocking. */
	val = 128*1024;
	if (setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &val,
		       sizeof(val)) < 0) {
		die_perror("setsockopt SO_SNDBUF");
	}
}

void wire_conn_connect(struct wire_conn *conn,
			const struct ip_address *ip,
			u16 port,
			enum ip_version_t ip_version)
{
	DEBUGP("wire_conn_connect\n");
	struct sockaddr_storage sa;
	socklen_t length = 0;

	create_tcp_socket(conn, ip_version);
	set_default_tcp_options(conn);

	/* Do a blocking connect to the server. */
	ip_to_sockaddr(ip, port, (struct sockaddr *)&sa, &length);
	if (connect(conn->fd, (struct sockaddr *)&sa, length) < 0) {
		char ip_string[ADDR_STR_LEN];
		die("error connecting to wire server at %s:%d: %s\n",
		    ip_to_string(ip, ip_string), port, strerror(errno));
	}
}

void wire_conn_bind_listen(struct wire_conn *listen_conn,
				u16 port,
				enum ip_version_t ip_version)
{
	DEBUGP("wire_conn_bind_listen\n");
	int val;

	create_tcp_socket(listen_conn, ip_version);

	val = 1;
	if (setsockopt(listen_conn->fd, SOL_SOCKET, SO_REUSEADDR,
		       &val, sizeof(val)) < 0) {
		die_perror("setsockopt SO_REUSEADDR");
	}

	wrap_bind_listen(listen_conn->fd, ip_version, port);
}

void wire_conn_accept(struct wire_conn *listen_conn,
		      struct wire_conn **accepted_conn)
{
	int fd = -1;

	DEBUGP("wire_conn_accept\n");

	fd = accept(listen_conn->fd, NULL, NULL);
	if (fd < 0)
		die_perror("accept");

	DEBUGP("accepted fd %d\n", fd);

	*accepted_conn = wire_conn_new();
	(*accepted_conn)->fd = fd;

	set_default_tcp_options(*accepted_conn);
}

/* Do blocking writes until all bytes are written.  Given our large
 * socket buffer size and typically small write sizes, in practice all
 * the writes should complete in one call.
 */
static int write_bytes(struct wire_conn *conn,
		       const void *buf, int buf_len)
{
	while (buf_len > 0) {
		int bytes_written = write(conn->fd, buf, buf_len);
		if (bytes_written < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				perror("TCP socket write");
				return STATUS_ERR;
			}
		}
		assert(bytes_written <= buf_len);
		buf_len -= bytes_written;
		buf += bytes_written;
	}
	return STATUS_OK;
}

int wire_conn_write(struct wire_conn *conn,
		    enum wire_op_t op,
		    const void *buf, int buf_len)
{
	DEBUGP("wire_conn_write -> op: %s\n",
	       wire_op_to_string(op));
	struct wire_header header;

	header.length	= htonl(sizeof(header) + buf_len);
	header.op	= htonl(op);

	if (write_bytes(conn, &header, sizeof(header)))
		return STATUS_ERR;

	if (write_bytes(conn, buf, buf_len))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Do blocking reads until we've read the given number of bytes. */
static int read_bytes(struct wire_conn *conn,
		      void *buf, int buf_len)
{
	while (buf_len > 0) {
		int bytes_read = read(conn->fd, buf, buf_len);
		if (bytes_read < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				perror("TCP socket read");
				return STATUS_ERR;
			}
		} else if (bytes_read == 0) {
			fprintf(stderr, "remote side closed connection\n");
			return STATUS_ERR;
		}
		assert(bytes_read <= buf_len);
		buf_len -= bytes_read;
		buf += bytes_read;
	}
	return STATUS_OK;
}

int wire_conn_read(struct wire_conn *conn,
		   enum wire_op_t *op,
		   void **buf, int *buf_len)
{
	DEBUGP("wire_conn_read\n");

	struct wire_header header;

	if (read_bytes(conn, &header, sizeof(header)))
		return STATUS_ERR;

	*op = ntohl(header.op);

	DEBUGP("wire_conn_read -> op: %s\n", wire_op_to_string(*op));

	*buf_len = ntohl(header.length) - sizeof(header);
	if ((*buf_len < 0) || (*buf_len > MAX_MESSAGE_BYTES)) {
		fprintf(stderr, "invalid length %d from remote wire conn\n",
			*buf_len);
		return STATUS_ERR;
	}

	if (conn->in.buf_space < *buf_len) {
		free(conn->in.buf);
		conn->in.buf_space = 2 * *buf_len;
		conn->in.buf = malloc(conn->in.buf_space);
	}

	*buf = conn->in.buf;

	if (read_bytes(conn, *buf, *buf_len))
		return STATUS_ERR;

	return STATUS_OK;
}
