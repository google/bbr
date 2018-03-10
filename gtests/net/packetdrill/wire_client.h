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
 * Client-side code for remote on-the-wire testing using a real NIC.
 */

#ifndef __WIRE_CLIENT_H__
#define __WIRE_CLIENT_H__

#include "types.h"

#include "ethernet.h"
#include "script.h"
#include "wire_protocol.h"
#include "wire_conn.h"

struct config;
struct state;

/* Internal private state for the wire client. */
struct wire_client {
	struct wire_conn *wire_conn;		/* connection to wire server */

	struct ether_addr client_ether_addr;	/* wire client hardware addr */

	enum event_t last_event_type;	/* type of previous event */
	int num_events;				/* events executed so far */
};

/* Allocate a new wire_client. */
struct wire_client *wire_client_new(void);

/* Initiate remote on-the-wire testing using a real NIC. */
extern int wire_client_init(struct wire_client *wire_client,
			    const struct config *config,
			    const struct script *script);

/* Delete a wire_client and its associated objects. */
extern void wire_client_free(struct wire_client *wire_client);

/* Send a message that the client is starting now. */
extern void wire_client_send_client_starting(struct wire_client *wire_client);

/* Tell the client state machine that the script interpreter has moved
 * on to the next event, and is about to wait for and execute the
 * given event.
 */
extern void wire_client_next_event(struct wire_client *wire_client,
				   struct event *event);

#endif /* __WIRE_CLIENT_H__ */
