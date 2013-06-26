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

struct socket *socket_new(struct state *state)
{
	struct socket *socket = calloc(1, sizeof(struct socket));
	socket->ts_val_map = hash_map_new(1);
	socket->next = state->sockets;	/* add socket to the linked list */
	state->sockets = socket;
	return socket;
}

void socket_free(struct socket *socket)
{
	hash_map_free(socket->ts_val_map);
	memset(socket, 0, sizeof(*socket));  /* paranoia to help catch bugs */
	free(socket);
}
