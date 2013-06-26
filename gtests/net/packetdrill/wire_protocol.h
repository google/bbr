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
 * Protocol for remote on-the-wire testing using a real NIC.
 */

#ifndef __WIRE_PROTOCOL_H__
#define __WIRE_PROTOCOL_H__

#include "types.h"

/* Types of messages wire_client and wire_server send to each other. */
enum wire_op_t {
	WIRE_INVALID = 0,	/* invalid OP */
	WIRE_COMMAND_LINE_ARGS,	/* "here are my command line arguments" */
	WIRE_SCRIPT_PATH,	/* "here's the path of the script" */
	WIRE_SCRIPT,		/* "here's the script we're going to start" */
	WIRE_HARDWARE_ADDR,	/* "here's my ethernet MAC address" */
	WIRE_SERVER_READY,	/* "server ready to start script execution" */
	WIRE_CLIENT_STARTING,	/* "i'm starting script execution... now!" */
	WIRE_PACKETS_START,	/* "please start handling packet events" */
	WIRE_PACKETS_WARN,	/* "here's a warning about fishy packets" */
	WIRE_PACKETS_DONE,	/* "i'm done handling packet events" */
	WIRE_NUM_OPS,
};

/* Return the human-readable name for a given op (static string). */
extern const char *wire_op_to_string(enum wire_op_t op);

/* Header prefix before all messages in both directions. */
struct wire_header {
	__be32 length;	/* bytes in message (network order), including header */
	__be32 op;	/* enum wire_op_t (network order) */
};

/* A client request for the server to execute some packet events. */
struct wire_packets_start {
	__be32 num_events;	/* total events executed (network order) */
};

/* The server is done executing some packet events. */
struct wire_packets_done {
	__be32 result;		/* STATUS_OK or TCPEST_ERR (network order) */
	__be32 num_events;	/* total events executed (network order) */
	char error_message[0];	/* '\0'-teriminated error message, or empty */
};

#endif /* __WIRE_PROTOCOL_H__ */
