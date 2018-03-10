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
 * Interface for a module to execute a packet event from a test script.
 */

#ifndef __RUN_PACKET_H__
#define __RUN_PACKET_H__

#include "types.h"

#include "script.h"

struct event;
struct packet;
struct socket;
struct state;

/* Internal state for the packet-handling module. */
struct packets {
	int next_ephemeral_port;	/* cached port to use, or -1 */
};

/* Allocate and return internal state for the packets module. */
extern struct packets *packets_new(const struct state *state);

/* Tear down packets module state and free up the resources it has allocated. */
extern void packets_free(struct packets *packets);

/* Execute the packet event. On success, return STATUS_OK; on error
 * return STATUS_ERR and fill in a malloc-allocated error message in
 * *error.
 */
extern int run_packet_event(struct state *state,
			    struct event *event,
			    struct packet *packet,
			    char **error);

/* Inject a TCP RST packet to clear the connection state out of the kernel. */
extern int reset_connection(struct state *state,
			    struct socket *socket);

#endif /* __RUN_PACKET_H__ */
