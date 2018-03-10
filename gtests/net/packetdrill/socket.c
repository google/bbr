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
 * Implementation for the socket-related state and logic.
 */

#include "socket.h"

#include <stdlib.h>
#include <string.h>
#include "run.h"

void socket_close(struct state *state, struct fd_state *fd)
{
	struct socket *socket = fd_to_socket(fd);

	if (fd->live_fd >= 0 && !socket->fd.is_closed) {
		assert(fd->script_fd >= 0);
		DEBUGP("closing struct state socket "
		       "live.fd:%d script.fd:%d\n",
		       fd->live_fd, fd->script_fd);
		if (close(fd->live_fd))
			die_perror("close");
	}
	if (socket->protocol == IPPROTO_TCP &&
	    socket->live.local.port != 0 &&
	    socket->live.remote.port != 0 &&
	    !state->config->is_wire_client &&
	    reset_connection(state, socket)) {
		die("error reseting connection\n");
	}

	socket_free(socket);
}

/* Global info about file descriptors that point to sockets. */
struct fd_ops socket_ops = {
	.type = FD_SOCKET,
	.close = socket_close,
};

struct socket *socket_new(struct state *state)
{
	struct socket *socket = calloc(1, sizeof(struct socket));

	socket->fd.ops = &socket_ops;
	socket->ts_val_map = hash_map_new(1);
	state_add_fd(state, to_fd(socket));
	return socket;
}

void socket_free(struct socket *socket)
{
	hash_map_free(socket->ts_val_map);
	memset(socket, 0, sizeof(*socket));  /* paranoia to help catch bugs */
	free(socket);
}
