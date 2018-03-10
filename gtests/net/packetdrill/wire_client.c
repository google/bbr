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

#include "wire_client.h"

#include "config.h"
#include "link_layer.h"
#include "script.h"
#include "run.h"

struct wire_client *wire_client_new(void)
{
	return calloc(1, sizeof(struct wire_client));
}

void wire_client_free(struct wire_client *wire_client)
{
	if (wire_client->wire_conn != NULL)
		wire_conn_free(wire_client->wire_conn);

	memset(wire_client, 0, sizeof(*wire_client));  /* help catch bugs */
	free(wire_client);
}

static void wire_client_die(struct wire_client *wire_client,
			    const char *message)
{
	die("error in TCP connection to wire server: %s\n", message);
}

/* Serialize client-side argv into a single string with '\0'
 * characters between args. We do not send the -wire_client argument,
 * since we don't want to give the server an identity crisis.
 */
static void wire_client_serialize_argv(const char **argv, char **args_ptr,
				       int *args_len_ptr)
{
	int i;
	char *args = NULL;
	int args_len = 0;
	char *end = NULL;

	for (i = 0; argv[i]; ++i) {
		if (strstr(argv[i], "-wire_client"))
			continue;
		args_len += strlen(argv[i]) + 1;	/* + 1 for '\0' */
	}

	args = calloc(args_len, 1);
	end = args;

	for (i = 0; argv[i]; ++i) {
		int len = 0;
		if (strstr(argv[i], "-wire_client"))
			continue;
		len = strlen(argv[i]) + 1;	/* + 1 for '\0' */
		memcpy(end, argv[i], len);
		end += len;
	}

	assert(end == args + args_len);

	*args_ptr = args;
	*args_len_ptr = args_len;
}

/* Send a WIRE_COMMAND_LINE_ARGS message with our command line
 * arguments as a single serialized string.
 */
static void wire_client_send_args(struct wire_client *wire_client,
				  const struct config *config)
{
	char *args = NULL;
	int args_len = 0;

	wire_client_serialize_argv(config->argv, &args, &args_len);

	if (wire_conn_write(wire_client->wire_conn,
				    WIRE_COMMAND_LINE_ARGS,
				    args, args_len))
		wire_client_die(wire_client,
				"error sending WIRE_COMMAND_LINE_ARGS");
	free(args);
}

/* Send the path name of the script we're about to run. */
static void wire_client_send_script_path(struct wire_client *wire_client,
					 const struct config *config)
{
	if (wire_conn_write(wire_client->wire_conn,
				    WIRE_SCRIPT_PATH,
				    config->script_path,
				    strlen(config->script_path)))
		wire_client_die(wire_client,
				"error sending WIRE_SCRIPT_PATH");
}

/* Send the ASCII contents of the script we're about to run. */
static void wire_client_send_script(struct wire_client *wire_client,
				    const struct script *script)
{
	if (wire_conn_write(wire_client->wire_conn,
				    WIRE_SCRIPT,
				    script->buffer, script->length))
		wire_client_die(wire_client,
				"error sending WIRE_SCRIPT");
}

/* Send the ethernet address to which the server should send packets. */
static void wire_client_send_hw_address(struct wire_client *wire_client,
					const struct config *config)
{
	if (wire_conn_write(wire_client->wire_conn,
				    WIRE_HARDWARE_ADDR,
				    &wire_client->client_ether_addr,
				    sizeof(wire_client->client_ether_addr)))
		wire_client_die(wire_client,
				"error sending WIRE_HARDWARE_ADDR");
}

/* Receive server's message that the server is ready to execute the script. */
static void wire_client_receive_server_ready(struct wire_client *wire_client)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;

	if (wire_conn_read(wire_client->wire_conn,
				   &op, &buf, &buf_len))
		wire_client_die(wire_client, "error reading WIRE_SERVER_READY");
	if (op != WIRE_SERVER_READY) {
		wire_client_die(wire_client,
				"bad wire server: expected WIRE_SERVER_READY");
	}
	if (buf_len != 0) {
		wire_client_die(wire_client,
				"bad wire server: bad WIRE_SERVER_READY len");
	}
}

/* Tell server that client is starting script execution. */
void wire_client_send_client_starting(struct wire_client *wire_client)
{
	if (wire_conn_write(wire_client->wire_conn,
				    WIRE_CLIENT_STARTING,
				    NULL, 0))
		wire_client_die(wire_client,
				"error sending WIRE_CLIENT_STARTING");
}

/* Send a client request for the server to execute some packet events. */
static void wire_client_send_packets_start(struct wire_client *wire_client)
{
	struct wire_packets_start start;
	start.num_events = htonl(wire_client->num_events);
	if (wire_conn_write(wire_client->wire_conn,
			    WIRE_PACKETS_START,
			    &start, sizeof(start)))
		wire_client_die(wire_client,
				"error sending WIRE_PACKETS_START");
}

/* Receive a message from the server that the server is done executing
 * some packet events. Print any warnings we receive along the way.
 */
static void wire_client_receive_packets_done(struct wire_client *wire_client)
{
	enum wire_op_t op;
	struct wire_packets_done done;
	void *buf = NULL;
	int buf_len = -1;

	DEBUGP("wire_client_receive_packets_done\n");

	while (1) {
		if (wire_conn_read(wire_client->wire_conn,
				   &op, &buf, &buf_len))
			wire_client_die(wire_client, "error reading");
		if (op == WIRE_PACKETS_DONE)
			break;
		else if (op == WIRE_PACKETS_WARN) {
			/* NULL-terminate the warning and print it. */
			char *warning = strndup(buf, buf_len);
			fprintf(stderr, "%s", warning);
			free(warning);
		} else {
			wire_client_die(
				wire_client,
				"bad wire server: expected "
				"WIRE_PACKETS_DONE or WIRE_PACKETS_WARN");
		}
	}

	if (buf_len < sizeof(done) + 1) {
		wire_client_die(wire_client,
				"bad wire server: bad WIRE_PACKETS_DONE len");
	}
	if (((char *)buf)[buf_len - 1] != '\0') {
		wire_client_die(wire_client,
				"bad wire server: missing string terminator");
	}

	memcpy(&done, buf, sizeof(done));

	if (ntohl(done.result) == STATUS_ERR) {
		/* Die with the error message from the server, which
		 * is a C string following the fixed "done" message.
		 */
		die("%s", (char *)(buf + sizeof(done)));
	} else if (ntohl(done.num_events) != wire_client->num_events) {
		char *msg = NULL;
		asprintf(&msg, "bad wire server: bad message count: "
			 "got: %d vs expected: %d",
			 ntohl(done.num_events), wire_client->num_events);
		wire_client_die(wire_client, msg);
	}
}

/* Connect to the wire server, pass it our command line argument
 * options, the script we're going to execute, and our MAC address.
 */
int wire_client_init(struct wire_client *wire_client,
		     const struct config *config,
		     const struct script *script)
{
	DEBUGP("wire_client_init\n");
	assert(config->is_wire_client);

	get_hw_address(config->wire_client_device,
		       &wire_client->client_ether_addr,
		       config->ip_version);

	wire_client->wire_conn = wire_conn_new();
	wire_conn_connect(wire_client->wire_conn,
				  &config->wire_server_ip,
				  config->wire_server_port,
				  config->ip_version);

	wire_client_send_args(wire_client, config);

	wire_client_send_script_path(wire_client, config);

	wire_client_send_script(wire_client, script);

	wire_client_send_hw_address(wire_client, config);

	wire_client_receive_server_ready(wire_client);

	return STATUS_OK;
}


/* Tell the wire client that the interpreter has moved on to the next
 * event.  Inform the wire server if need be. The client informs the
 * server if (a) this event is a packet event and (b) the previous
 * event was not a packet event. In any other cases the server either
 * (i) does not care what time this event is happening at because it's
 * not an on-the-wire event, or (ii) already knows what time to fire
 * this on-the-wire event because the previous event was also an
 * on-the-wire event.
 */
void wire_client_next_event(struct wire_client *wire_client,
			    struct event *event)
{
	/* Tell the server to start executing packet events. */
	if (event && (event->type == PACKET_EVENT) &&
	    (wire_client->last_event_type != PACKET_EVENT)) {
		wire_client_send_packets_start(wire_client);
	}

	/* Get the result from server execution of one or more packet events. */
	if ((!event || (event->type != PACKET_EVENT)) &&
	    (wire_client->last_event_type == PACKET_EVENT)) {
		wire_client_receive_packets_done(wire_client);
	}

	if (event) {
		wire_client->last_event_type = event->type;
		++wire_client->num_events;
	}
}
