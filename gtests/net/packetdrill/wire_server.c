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
 * Server-side code for remote on-the-wire testing using a real NIC.
 */

#include "wire_server.h"

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "link_layer.h"
#include "logging.h"
#include "run.h"
#include "wire_conn.h"
#include "wire_server.h"
#include "wire_server_netdev.h"

/* Internal private state for the wire server to run one script. */
struct wire_server {
	struct wire_conn *wire_conn;		/* connection to wire client */
	u16 port;				/* port we listen on */

	int argc;				/* args in client cmd line */
	char **argv;				/* client command line */

	struct config config;			/* run-time configuration */
	struct script script;			/* raw and parsed script */
	struct state *state;			/* interpreter engine state */

	char *script_path;			/* path of script (on cli!) */
	char *script_buffer;			/* contents of script */

	char *wire_server_device;		/* name of our eth interface */
	struct ether_addr client_ether_addr;	/* wire client hardware addr */
	struct ether_addr server_ether_addr;	/* wire server hardware addr */

	enum event_t last_event_type;	/* type of previous event */
	int num_events;				/* events executed so far */
};

static struct wire_server *wire_server_new(struct wire_conn *accepted_conn,
					   const char *wire_server_device,
					   u16 wire_server_port,
					   enum ip_version_t ip_version)
{
	struct wire_server *wire_server = calloc(1, sizeof(struct wire_server));
	wire_server->wire_conn = accepted_conn;
	wire_server->wire_server_device = strdup(wire_server_device);
	get_hw_address(wire_server_device, &wire_server->server_ether_addr,
			ip_version);
	wire_server->port = wire_server_port;
	return wire_server;
}

static void wire_server_free(struct wire_server *wire_server)
{
	wire_conn_free(wire_server->wire_conn);
	free(wire_server->script_path);
	free(wire_server->script_buffer);
	free(wire_server->wire_server_device);
	memset(wire_server, 0, sizeof(*wire_server));  /* catch bugs */
	free(wire_server);
}

/* Unserialize argv from a single string with '\0' characters between
 * args. Add a --wire_server so that we don't have an identity crisis.
 */
static void wire_server_unserialize_argv(struct wire_server *wire_server,
					 const char *args, int args_len)
{
	int argc, i;
	char **argv = NULL;
	const char *end = NULL;

	argc = 0;
	for (i = 0; i < args_len; ++i) {
		if (args[i] == '\0')
			++argc;
	}
	++argc;		/* for --wire_server argument */
	DEBUGP("argc = %d\n", argc);

	/* We use argc+1 here because, following main() calling
	 * conventions, we make the array element at argv[argc] a NULL
	 * pointer.
	 */
	argv = calloc(argc + 1, sizeof(char *));

	end = args;
	for (i = 0; i < argc; ++i) {
		argv[i] = strdup(end);
		end += strlen(end) + 1;	/* + 1 for '\0' */
	}
	asprintf(&argv[argc-1], "--wire_server");

	for (i = 0; i < argc; ++i)
		DEBUGP("argv[%d] = '%s'\n", i, argv[i]);

	wire_server->argc = argc;
	wire_server->argv = argv;
}

/* Receive a WIRE_COMMAND_LINE_ARGS message */
static int wire_server_receive_args(struct wire_server *wire_server)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;

	if (wire_conn_read(wire_server->wire_conn, &op, &buf, &buf_len))
		return STATUS_ERR;
	if (op != WIRE_COMMAND_LINE_ARGS) {
		fprintf(stderr,
			"bad wire client: expected WIRE_COMMAND_LINE_ARGS\n");
		return STATUS_ERR;
	}

	wire_server_unserialize_argv(wire_server,
				     buf, buf_len);

	return STATUS_OK;
}

/* Receive the path name of the script we're about to run. */
static int wire_server_receive_script_path(struct wire_server *wire_server)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;

	if (wire_conn_read(wire_server->wire_conn, &op, &buf, &buf_len))
		return STATUS_ERR;
	if (op != WIRE_SCRIPT_PATH) {
		fprintf(stderr,
			"bad wire client: expected WIRE_SCRIPT_PATH\n");
		return STATUS_ERR;
	}

	wire_server->script_path = strndup(buf, buf_len);

	return STATUS_OK;
}

/* Receive the script we're about to run. */
static int wire_server_receive_script(struct wire_server *wire_server)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;

	if (wire_conn_read(wire_server->wire_conn, &op, &buf, &buf_len))
		return STATUS_ERR;
	if (op != WIRE_SCRIPT) {
		fprintf(stderr,
			"bad wire client: expected WIRE_SCRIPT\n");
		return STATUS_ERR;
	}

	wire_server->script_buffer = strndup(buf, buf_len);

	return STATUS_OK;
}


/* Receive the ethernet address to which the server should send packets. */
static int wire_server_receive_hw_address(struct wire_server *wire_server)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;

	if (wire_conn_read(wire_server->wire_conn, &op, &buf, &buf_len))
		return STATUS_ERR;
	if (op != WIRE_HARDWARE_ADDR) {
		fprintf(stderr,
			"bad wire client: expected WIRE_HARDWARE_ADDR\n");
		return STATUS_ERR;
	}
	if (buf_len != sizeof(wire_server->client_ether_addr)) {
		fprintf(stderr,
			"bad wire client: bad hw address length\n");
		return STATUS_ERR;
	}

	ether_copy(&wire_server->client_ether_addr, buf);

	return STATUS_OK;
}

/* Send a message to tell the client we're ready to excecute the script. */
static int wire_server_send_server_ready(struct wire_server *wire_server)
{
	if (wire_conn_write(wire_server->wire_conn,
				    WIRE_SERVER_READY,
				    NULL, 0)) {
		fprintf(stderr, "error sending WIRE_SERVER_READY\n");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Wait for the client to say it's starting script execution. */
static int wire_server_receive_client_starting(struct wire_server *wire_server)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;

	if (wire_conn_read(wire_server->wire_conn, &op, &buf, &buf_len))
		return STATUS_ERR;
	if (op != WIRE_CLIENT_STARTING) {
		fprintf(stderr,
			"bad wire client: expected WIRE_CLIENT_STARTING\n");
		return STATUS_ERR;
	}
	if (buf_len != 0) {
		fprintf(stderr,
			"bad wire client: bad WIRE_CLIENT_STARTING length\n");
		return STATUS_ERR;
	}

	return STATUS_OK;
}

/* Wait for the client request for the server to execute some packet events. */
static int wire_server_receive_packets_start(struct wire_server *wire_server)
{
	enum wire_op_t op = WIRE_INVALID;
	void *buf = NULL;
	int buf_len = -1;
	struct wire_packets_start start;

	if (wire_conn_read(wire_server->wire_conn, &op, &buf, &buf_len))
		return STATUS_ERR;
	if (op != WIRE_PACKETS_START) {
		fprintf(stderr,
			"bad wire client: expected WIRE_PACKETS_START\n");
		return STATUS_ERR;
	}
	if (buf_len != sizeof(start)) {
		fprintf(stderr,
			"bad wire client: bad WIRE_PACKETS_START length\n");
		return STATUS_ERR;
	}

	memcpy(&start, buf, sizeof(start));
	if (ntohl(start.num_events) != wire_server->num_events) {
		fprintf(stderr,
			"bad client event count; expected %d but got %d",
			wire_server->num_events, ntohl(start.num_events));
		return STATUS_ERR;
	}

	return STATUS_OK;
}

/* Send back to the client a human-readable warning about a fishy packet. */
static int wire_server_send_packet_warning(struct wire_server *wire_server,
					   const char *warning)
{
	if (wire_conn_write(wire_server->wire_conn, WIRE_PACKETS_WARN,
			    warning, strlen(warning))) {
		fprintf(stderr, "error sending WIRE_PACKETS_WARN\n");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Tell the client that the server is done executing some packet events. */
static int wire_server_send_packets_done(struct wire_server *wire_server,
					 int result,
					 const char *error)
{
	struct wire_packets_done done;
	int error_len = strlen(error) + 1;	/* +1 for '\0' */
	int buf_len = sizeof(done) + error_len;
	char *buf = malloc(buf_len);

	done.result	= htonl(result);
	done.num_events	= htonl(wire_server->num_events);
	memcpy(buf, &done, sizeof(done));
	memcpy(buf + sizeof(done), error, error_len);

	if (wire_conn_write(wire_server->wire_conn,
			    WIRE_PACKETS_DONE,
			    buf, buf_len)) {
		fprintf(stderr, "error sending WIRE_PACKETS_DONE\n");
		return STATUS_ERR;
	}

	return STATUS_OK;
}

/* Coordinate with the wire client. See wire_client_next_event(). */
static int wire_server_next_event(struct wire_server *wire_server,
				  struct event *event)
{
	/* Wait for the client's request to start executing packet events. */
	if (event && (event->type == PACKET_EVENT) &&
	    (wire_server->last_event_type != PACKET_EVENT)) {
		if (wire_server_receive_packets_start(wire_server))
			return STATUS_ERR;
	}

	/* Send the result from server execution of packet events. */
	if ((!event || (event->type != PACKET_EVENT)) &&
	    (wire_server->last_event_type == PACKET_EVENT)) {
		if (wire_server_send_packets_done(wire_server, STATUS_OK, ""))
			return STATUS_ERR;
	}

	if (event) {
		wire_server->last_event_type = event->type;
		++wire_server->num_events;
	}

	return STATUS_OK;
}

/* Run the given packet event; send any error or warning back to the client. */
static int wire_server_run_packet_event(
	struct wire_server *wire_server, struct event *event,
	struct packet *packet, char **error)
{
	int result = STATUS_OK;

	result = run_packet_event(wire_server->state,
					  event, packet, error);
	if (result == STATUS_ERR) {
		/* When we sniff an incorrect packet, don't exit the
		 * process (we're a daemon), just return the error
		 * message via the TCP socket and finish the thread.
		 */
		DEBUGP("wire_server_run_packet_event: error!\n");
		if (wire_server_send_packets_done(wire_server, STATUS_ERR,
						  *error))
			return STATUS_ERR;
	} else if (result == STATUS_WARN) {
		/* A non-fatal problem with the packet. Return the
		 * warning message via the TCP socket and keep going.
		 */
		DEBUGP("wire_server_run_packet_event: warning!\n");
		if (wire_server_send_packet_warning(wire_server, *error))
			return STATUS_ERR;
	}
	return result;
}

/* Execute the server-side duties for remote on-the-wire testing using
 * a real NIC. Basically the server side just needs to send packets
 * over the wire (to the kernel under test) and sniff and verify
 * packets on the wire (from the kernel under test). This is analogous
 * to run_script(), which executes scripts for stand-alone mode,
 * and also executes the client side for remote on-the-wire testing
 * using a real NIC.
 */
static int wire_server_run_script(struct wire_server *wire_server,
				  char **error)
{
	struct state *state = wire_server->state;
	struct event *event = NULL;

	DEBUGP("wire_server_run_script\n");

	state->live_start_time_usecs = now_usecs(state);
	DEBUGP("live_start_time_usecs is %lld\n",
	       state->live_start_time_usecs);

	while (1) {
		if (get_next_event(state, error))
			return STATUS_ERR;
		event = state->event;
		if (event == NULL)
			break;

		if (wire_server_next_event(wire_server, event))
			return STATUS_ERR;

		/* We adjust relative times after getting notification
		 * that previous client-side events have completed.
		 */
		adjust_relative_event_times(state, event);

		switch (event->type) {
		case PACKET_EVENT:
			if (wire_server_run_packet_event(wire_server, event,
							 event->event.packet,
							 error) == STATUS_ERR)
				return STATUS_ERR;
			break;
		case SYSCALL_EVENT:
			DEBUGP("SYSCALL_EVENT happens on client side...\n");
			break;
		case COMMAND_EVENT:
			DEBUGP("COMMAND_EVENT happens on client side...\n");
			break;
		case CODE_EVENT:
			DEBUGP("CODE_EVENT happens on client side...\n");
			break;
		case INVALID_EVENT:
		case NUM_EVENT_TYPES:
			assert(!"bogus type");
			break;
		/* We omit default case so compiler catches missing values. */
		}
	}

	/* Tell the client about any outstanding packet events it requested. */
	wire_server_next_event(wire_server, NULL);

	DEBUGP("wire_server_run_script: done running\n");

	return STATUS_OK;
}

/* Handle a wire connection from a client. */
static void *wire_server_thread(void *arg)
{
	struct wire_server *wire_server = (struct wire_server *)arg;
	struct netdev *netdev = NULL;
	char *error = NULL;

	DEBUGP("wire_server_thread\n");

	set_default_config(&wire_server->config);

	if (wire_server_receive_args(wire_server))
		goto error_done;

	if (wire_server_receive_script_path(wire_server))
		goto error_done;

	if (wire_server_receive_script(wire_server))
		goto error_done;

	if (wire_server_receive_hw_address(wire_server))
		goto error_done;

	if (parse_script_and_set_config(wire_server->argc,
						wire_server->argv,
						&wire_server->config,
						&wire_server->script,
						wire_server->script_path,
						wire_server->script_buffer))
		goto error_done;

	set_scheduling_priority();
	lock_memory();

	netdev =
	  wire_server_netdev_new(&wire_server->config,
				 wire_server->wire_server_device,
				 &wire_server->client_ether_addr,
				 &wire_server->server_ether_addr);

	wire_server->state = state_new(&wire_server->config,
					       &wire_server->script,
					       netdev);

	if (wire_server_send_server_ready(wire_server))
		goto error_done;

	if (wire_server_receive_client_starting(wire_server))
		goto error_done;

	if (wire_server_run_script(wire_server, &error))
		goto error_done;

	DEBUGP("wire_server_thread: finished test successfully\n");

error_done:
	if (error != NULL)
		fprintf(stderr, "%s\n", error);

	if (wire_server->state != NULL)
		state_free(wire_server->state);

	DEBUGP("wire_server_thread: connection is done\n");
	wire_server_free(wire_server);
	return NULL;
}

static void start_wire_server_thread(struct wire_server *wire_server)
{
	DEBUGP("start_wire_server_thread\n");

	pthread_t thread;		/* pthread thread handle */
	if (pthread_create(&thread, NULL, wire_server_thread,
			   wire_server) != 0) {
		die_perror("pthread_create");
	}
}

void run_wire_server(const struct config *config)
{
	struct wire_conn *listen_conn = NULL;

	wire_server_netdev_init(config->wire_server_device);

	listen_conn = wire_conn_new();

	wire_conn_bind_listen(listen_conn, config->wire_server_port,
		config->ip_version);

	while (1) {
		struct wire_conn *accepted_conn = NULL;
		wire_conn_accept(listen_conn, &accepted_conn);

		struct wire_server *wire_server =
			wire_server_new(accepted_conn,
					config->wire_server_device,
					config->wire_server_port,
					config->ip_version);

		start_wire_server_thread(wire_server);
	}
}
