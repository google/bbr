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
 * A module to execute a packet command from a test script.
 */

#include "run_packet.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "checksum.h"
#include "gre.h"
#include "logging.h"
#include "netdev.h"
#include "packet.h"
#include "packet_checksum.h"
#include "packet_to_string.h"
#include "run.h"
#include "script.h"
#include "tcp_options_iterator.h"
#include "tcp_options_to_string.h"
#include "tcp_packet.h"

/* To avoid issues with TIME_WAIT, FIN_WAIT1, and FIN_WAIT2 we use
 * dynamically-chosen, unique 4-tuples for each test. We implement the
 * picking of unique ports by binding a socket to port 0 and seeing
 * what port we are assigned. Note that we keep the socket fd open for
 * the lifetime of our process to ensure that the port is not
 * reused by a later test.
 */
static u16 ephemeral_port(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		die_perror("socket");

	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;		/* let the OS pick the port */
	if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0)
		die_perror("bind");

	memset(&addr, 0, sizeof(addr));
	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0)
		die_perror("getsockname");
	assert(addr.sin_family == AF_INET);

	if (listen(fd, 1) < 0)
		die_perror("listen");

	return ntohs(addr.sin_port);
}

/* Return the next ephemeral port to use. We want quick results for
 * the very common case where there is only one remote port to use
 * over the course of a test. So we avoid paying the overhead of the
 * several system calls in ephemeral_port() right before injecting an
 * incoming SYN by pre-allocating and caching a single port to use
 * before starting each test.
 */
static u16 next_ephemeral_port(struct state *state)
{
	if (state->packets->next_ephemeral_port >= 0) {
		int port = state->packets->next_ephemeral_port;
		assert(port <= 0xffff);
		state->packets->next_ephemeral_port = -1;
		return port;
	} else {
		return ephemeral_port();
	}
}

/* Add a dump of the given packet to the given error message.
 * Frees *error and replaces it with a version that has the original
 * *error followed by the given type and a hex dump of the given
 * packet.
 */
static void add_packet_dump(char **error, const char *type,
			    struct packet *packet, s64 time_usecs,
			    enum dump_format_t format)
{
	if (packet->ip_bytes != 0) {
		char *old_error = *error;
		char *dump = NULL, *dump_error = NULL;

		packet_to_string(packet, format,
				 &dump, &dump_error);
		asprintf(error, "%s\n%s packet: %9.6f %s%s%s",
			 old_error, type, usecs_to_secs(time_usecs), dump,
			 dump_error ? "\n" : "",
			 dump_error ? dump_error : "");

		free(dump);
		free(dump_error);
		free(old_error);
	}
}

/* For verbose runs, print a short packet dump of all live packets. */
static void verbose_packet_dump(struct state *state, const char *type,
				struct packet *live_packet, s64 time_usecs)
{
	if (state->config->verbose) {
		char *dump = NULL, *dump_error = NULL;

		packet_to_string(live_packet, DUMP_SHORT,
				 &dump, &dump_error);

		printf("%s packet: %9.6f %s%s%s\n",
		       type, usecs_to_secs(time_usecs), dump,
		       dump_error ? "\n" : "",
		       dump_error ? dump_error : "");

		free(dump);
		free(dump_error);
	}
}

/* See if the live packet matches the live 4-tuple of the socket under test. */
static struct socket *find_socket_for_live_packet(
	struct state *state, const struct packet *packet,
	enum direction_t *direction)
{
	struct socket *socket = state->socket_under_test;	/* shortcut */
	if (socket == NULL)
		return NULL;

	struct tuple packet_tuple, live_outbound, live_inbound;
	get_packet_tuple(packet, &packet_tuple);

	/* Is packet inbound to the socket under test? */
	socket_get_inbound(&socket->live, &live_inbound);
	if (is_equal_tuple(&packet_tuple, &live_inbound)) {
		*direction = DIRECTION_INBOUND;
		DEBUGP("inbound live packet, socket in state %d\n",
		       socket->state);
		return socket;
	}
	/* Is packet outbound from the socket under test? */
	socket_get_outbound(&socket->live, &live_outbound);
	if (is_equal_tuple(&packet_tuple, &live_outbound)) {
		*direction = DIRECTION_OUTBOUND;
		DEBUGP("outbound live packet, socket in state %d\n",
		       socket->state);
		return socket;
	}
	return NULL;
}

/* See if the socket under test is listening and is willing to receive
 * this incoming SYN packet. If so, create a new child socket, anoint
 * it as the new socket under test, and return a pointer to
 * it. Otherwise, return NULL.
 */
static struct socket *handle_listen_for_script_packet(
	struct state *state, const struct packet *packet,
	enum direction_t direction)
{
	/* Does this packet match this socket? For now we only support
	 * testing one socket at a time, so we merely check whether
	 * the socket is listening. (If we were to support testing
	 * more than one socket at a time then we'd want to check to
	 * see if the address tuples in the packet and socket match.)
	 */
	struct config *config = state->config;
	struct socket *socket = state->socket_under_test;	/* shortcut */

	bool match = (direction == DIRECTION_INBOUND);
	if (!match)
		return NULL;

	if (config->is_wire_server) {
		/* On wire servers we don't see the system calls, so
		 * we won't have any socket_under_test yet.
		 */
		match = (socket == NULL);
	} else {
		/* In local mode we will certainly know about this socket. */
		match = ((socket != NULL) &&
			 (socket->state == SOCKET_PASSIVE_LISTENING));
	}
	if (!match)
		return NULL;

	/* Create a child passive socket for this incoming SYN packet.
	 * Any further packets in the test script will be directed to
	 * this child socket.
	 */
	socket = socket_new(state);
	state->socket_under_test = socket;
	assert(socket->state == SOCKET_INIT);
	socket->state = SOCKET_PASSIVE_PACKET_RECEIVED;
	socket->address_family = packet_address_family(packet);
	socket->protocol = packet_ip_protocol(packet);

	/* Set script info for this socket using script packet. */
	struct tuple tuple;
	get_packet_tuple(packet, &tuple);
	socket->script.remote		= tuple.src;
	socket->script.local		= tuple.dst;
	socket->script.remote_isn	= ntohl(packet->tcp->seq);
	socket->script.fd		= -1;

	/* Set up the live info for this socket based
	 * on the script packet and our overall config.
	 */
	socket->live.remote.ip		= config->live_remote_ip;
	socket->live.remote.port	= htons(next_ephemeral_port(state));
	socket->live.local.ip		= config->live_local_ip;
	socket->live.local.port		= htons(config->live_bind_port);
	socket->live.remote_isn		= ntohl(packet->tcp->seq);
	socket->live.fd			= -1;

	if (DEBUG_LOGGING) {
		char local_string[ADDR_STR_LEN];
		char remote_string[ADDR_STR_LEN];
		DEBUGP("live: local: %s.%d\n",
		       ip_to_string(&socket->live.local.ip, local_string),
		       ntohs(socket->live.local.port));
		DEBUGP("live: remote: %s.%d\n",
		       ip_to_string(&socket->live.remote.ip, remote_string),
		       ntohs(socket->live.remote.port));
		DEBUGP("live: ISN: %u\n", socket->live.remote_isn);
	}

	return socket;
}

/* See if the socket under test is a connecting socket that would emit
 * this outgoing script SYN. If so, return a pointer to the socket;
 * otherwise, return NULL.
 */
static struct socket *handle_connect_for_script_packet(
	struct state *state, const struct packet *packet,
	enum direction_t direction)
{
	/* Does this packet match this socket? For now we only support
	 * testing one socket at a time, so we merely check whether
	 * the socket is connecting. (If we were to support testing
	 * more than one socket at a time then we'd want to check to
	 * see if the address tuples in the packet and socket match.)
	 */
	struct config *config = state->config;
	struct socket *socket = state->socket_under_test;	/* shortcut */

	bool match = ((direction == DIRECTION_OUTBOUND) &&
		      packet->tcp->syn && !packet->tcp->ack);
	if (!match)
		return NULL;

	if (config->is_wire_server) {
		/* On wire servers we don't see the system calls, so
		 * we won't have any socket_under_test yet.
		 */
		match = (socket == NULL);
	} else {
		/* In local mode we will certainly know about this socket. */
		match = ((socket != NULL) &&
			 (socket->state == SOCKET_ACTIVE_CONNECTING));
	}
	if (!match)
		return NULL;

	if (socket == NULL) {
		/* Wire server. Create a socket for this outbound SYN
		 * packet. Any further packets in the test script are
		 * mapped here.
		 */
		socket = socket_new(state);
		state->socket_under_test = socket;
		assert(socket->state == SOCKET_INIT);
		socket->address_family = packet_address_family(packet);
		socket->protocol = packet_ip_protocol(packet);

		socket->script.fd	 = -1;

		socket->live.remote.ip   = config->live_remote_ip;
		socket->live.remote.port = htons(config->live_connect_port);
		socket->live.fd		 = -1;
	}

	/* Fill in the new info about this connection. */
	struct tuple tuple;
	get_packet_tuple(packet, &tuple);
	socket->state			= SOCKET_ACTIVE_SYN_SENT;
	socket->script.remote		= tuple.dst;
	socket->script.local		= tuple.src;
	socket->script.local_isn	= ntohl(packet->tcp->seq);

	return socket;
}

/* Look for a connecting socket that would emit this outgoing live packet. */
static struct socket *find_connect_for_live_packet(
	struct state *state, struct packet *packet,
	enum direction_t *direction)
{
	struct tuple tuple;
	get_packet_tuple(packet, &tuple);

	*direction = DIRECTION_INVALID;
	struct socket *socket = state->socket_under_test;	/* shortcut */
	if (!socket)
		return NULL;

	bool is_udp_match =
		(packet->udp &&
		 (socket->protocol == IPPROTO_UDP) &&
		 (socket->state == SOCKET_ACTIVE_CONNECTING));
	bool is_tcp_match =
		(packet->tcp && packet->tcp->syn && !packet->tcp->ack &&
		 (socket->protocol == IPPROTO_TCP) &&
		 (socket->state == SOCKET_ACTIVE_SYN_SENT));
	if (!is_udp_match && !is_tcp_match)
		return NULL;

	if (!is_equal_ip(&tuple.dst.ip, &socket->live.remote.ip) ||
	    !is_equal_port(tuple.dst.port, socket->live.remote.port))
		return NULL;

	*direction = DIRECTION_OUTBOUND;
	/* Using the details in this outgoing packet, fill in the
	 * new details we've learned about this actively initiated
	 * connection (for which we've seen a connect() call).
	 */
	socket->live.local.ip	= tuple.src.ip;
	socket->live.local.port	= tuple.src.port;

	if (packet->tcp)
		socket->live.local_isn	= ntohl(packet->tcp->seq);

	return socket;
}

/* Convert outbound TCP timestamp value from scripted value to live value. */
static int get_outbound_ts_val_mapping(
	struct socket *socket, u32 script_timestamp, u32 *live_timestamp)
{
	DEBUGP("get_outbound_ts_val_mapping\n");
	DEBUGP("ts_val_mapping %u -> ?\n", ntohl(script_timestamp));
	if (hash_map_get(socket->ts_val_map,
				 script_timestamp, live_timestamp))
		return STATUS_OK;
	return STATUS_ERR;
}

/* Store script->live mapping for outbound TCP timestamp value. */
static void set_outbound_ts_val_mapping(
	struct socket *socket, u32 script_timestamp, u32 live_timestamp)
{
	DEBUGP("set_outbound_ts_val_mapping\n");
	DEBUGP("ts_val_mapping %u -> %u\n",
	       ntohl(script_timestamp), ntohl(live_timestamp));
	hash_map_set(socket->ts_val_map,
			     script_timestamp, live_timestamp);
}

/* A helper to find the TCP timestamp option in a packet. Parse the
 * TCP options and fill in packet->tcp_ts_val with the location of the
 * TCP timestamp value field (or NULL if there isn't one), and
 * likewise fill in packet->tcp_ts_ecr with the location of the TCP
 * timestamp echo reply field (or NULL if there isn't one). Returns
 * STATUS_OK on success; on failure returns STATUS_ERR and sets
 * error message.
 */
static int find_tcp_timestamp(struct packet *packet, char **error)
{
	struct tcp_options_iterator iter;
	struct tcp_option *option = NULL;

	packet->tcp_ts_val = NULL;
	packet->tcp_ts_ecr = NULL;
	for (option = tcp_options_begin(packet, &iter); option != NULL;
	     option = tcp_options_next(&iter, error))
		if (option->kind == TCPOPT_TIMESTAMP) {
			packet->tcp_ts_val = &(option->data.time_stamp.val);
			packet->tcp_ts_ecr = &(option->data.time_stamp.ecr);
		}
	return *error ? STATUS_ERR : STATUS_OK;
}

/* A helper to help translate SACK sequence numbers between live and
 * script space. Specifically, it offsets SACK block sequence numbers
 * by the given 'ack_offset'. Returns STATUS_OK on success; on
 * failure returns STATUS_ERR and sets error message.
 */
static int offset_sack_blocks(struct packet *packet,
			      u32 ack_offset, char **error)
{
	struct tcp_options_iterator iter;
	struct tcp_option *option = NULL;
	for (option = tcp_options_begin(packet, &iter); option != NULL;
	     option = tcp_options_next(&iter, error)) {
		if (option->kind == TCPOPT_SACK) {
			int num_blocks = 0;
			if (num_sack_blocks(option->length,
						    &num_blocks, error))
				return STATUS_ERR;
			int i = 0;
			for (i = 0; i < num_blocks; ++i) {
				u32 val;
				val = ntohl(option->data.sack.block[i].left);
				val += ack_offset;
				option->data.sack.block[i].left = htonl(val);
				val = ntohl(option->data.sack.block[i].right);
				val += ack_offset;
				option->data.sack.block[i].right = htonl(val);
			}
		}
	}
	return *error ? STATUS_ERR : STATUS_OK;
}


/* Rewrite the TCP sequence number echoed by the ICMP packet.
 * The Linux TCP layer ignores ICMP messages with bogus sequence numbers.
 */
static int map_inbound_icmp_tcp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	u32 *seq = packet_echoed_tcp_seq(live_packet);
	bool is_syn = false;
	u32 seq_offset = local_seq_script_to_live_offset(socket, is_syn);
	*seq = htonl(ntohl(*seq) + seq_offset);
	return STATUS_OK;
}

/* UDP headers echoed by ICMP messages need no special rewriting. */
static int map_inbound_icmp_udp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	return STATUS_OK;
}

static int map_inbound_icmp_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	if (packet_echoed_ip_protocol(live_packet) == IPPROTO_TCP)
		return map_inbound_icmp_tcp_packet(socket, live_packet, error);
	else if (packet_echoed_ip_protocol(live_packet) == IPPROTO_UDP)
		return map_inbound_icmp_udp_packet(socket, live_packet, error);
	else
		assert(!"unsupported layer 4 protocol echoed in ICMP packet");
	return STATUS_ERR;
}

/* Rewrite the IP and TCP, UDP, or ICMP fields in 'live_packet', mapping
 * inbound packet values (address 4-tuple and sequence numbers in seq,
 * ACK, SACK blocks) from script values to live values, so that we can
 * inject this packet into the kernel and have the kernel accept it
 * for the given socket and process it. Returns STATUS_OK on success;
 * on failure returns STATUS_ERR and sets error message.
 */
static int map_inbound_packet(
	struct socket *socket, struct packet *live_packet, char **error)
{
	DEBUGP("map_inbound_packet\n");

	/* Remap packet to live values. */
	struct tuple live_inbound;
	socket_get_inbound(&socket->live, &live_inbound);
	set_packet_tuple(live_packet, &live_inbound);

	if ((live_packet->icmpv4 != NULL) || (live_packet->icmpv6 != NULL))
		return map_inbound_icmp_packet(socket, live_packet, error);

	/* If no TCP headers to rewrite, then we're done. */
	if (live_packet->tcp == NULL)
		return STATUS_OK;

	/* Remap the sequence number from script sequence number to live. */
	const bool is_syn = live_packet->tcp->syn;
	const u32 seq_offset = remote_seq_script_to_live_offset(socket, is_syn);
	live_packet->tcp->seq =
	    htonl(ntohl(live_packet->tcp->seq) + seq_offset);

	/* Remap the ACK and SACKs from script sequence number to live. */
	const u32 ack_offset = local_seq_script_to_live_offset(socket, is_syn);
	if (live_packet->tcp->ack)
		live_packet->tcp->ack_seq =
			htonl(ntohl(live_packet->tcp->ack_seq) + ack_offset);
	if (offset_sack_blocks(live_packet, ack_offset, error))
		return STATUS_ERR;

	/* Find the timestamp echo reply is, so we can remap that below. */
	if (find_tcp_timestamp(live_packet, error))
		return STATUS_ERR;

	/* Remap TCP timestamp echo reply from script value to a live
	 * value. We say "a" rather than "the" live value because
	 * there could be multiple live values corresponding to the
	 * same script value if a live test replay flips to a new
	 * jiffie in a spot where the script did not.
	 */
	if (live_packet->tcp->ack && (live_packet->tcp_ts_ecr != NULL)) {
		u32 live_ts_ecr = 0;

		if (get_outbound_ts_val_mapping(socket,
						packet_tcp_ts_ecr(live_packet),
						&live_ts_ecr)) {
			asprintf(error,
				 "unable to find mapping for timestamp ecr %u",
				 packet_tcp_ts_ecr(live_packet));
			return STATUS_ERR;
		}
		packet_set_tcp_ts_ecr(live_packet, live_ts_ecr);
	}

	return STATUS_OK;
}

/* Transforms values in the 'actual_packet' by mapping outbound packet
 * values in the sniffed 'live_packet' (address 4-tuple, sequence
 * number in seq, timestamp value) from live values to script values
 * in the space of 'script_packet'. This will allow us to compare a
 * packet sent by the kernel to the packet expected by the script.
 */
static int map_outbound_live_packet(
	struct socket *socket,
	struct packet *live_packet,
	struct packet *actual_packet,
	struct packet *script_packet,
	char **error)
{
	DEBUGP("map_outbound_live_packet\n");

	struct tuple live_packet_tuple, live_outbound, script_outbound;

	/* Verify packet addresses are outbound and live for this socket. */
	get_packet_tuple(live_packet, &live_packet_tuple);
	socket_get_outbound(&socket->live, &live_outbound);
	assert(is_equal_tuple(&live_packet_tuple, &live_outbound));

	/* Rewrite 4-tuple to be outbound script values. */
	socket_get_outbound(&socket->script, &script_outbound);
	set_packet_tuple(actual_packet, &script_outbound);

	/* If no TCP headers to rewrite, then we're done. */
	if (live_packet->tcp == NULL)
		return STATUS_OK;

	/* Rewrite TCP sequence number from live to script space. */
	const bool is_syn = live_packet->tcp->syn;
	const u32 seq_offset = local_seq_live_to_script_offset(socket, is_syn);
	actual_packet->tcp->seq =
	    htonl(ntohl(live_packet->tcp->seq) + seq_offset);

	/* Rewrite ACKs and SACKs from live to script space. */
	const u32 ack_offset = remote_seq_live_to_script_offset(socket, is_syn);
	if (actual_packet->tcp->ack)
		actual_packet->tcp->ack_seq =
		    htonl(ntohl(live_packet->tcp->ack_seq) + ack_offset);
	if (offset_sack_blocks(actual_packet, ack_offset, error))
		return STATUS_ERR;

	/* Extract location of script and actual TCP timestamp values. */
	if (find_tcp_timestamp(script_packet, error))
		return STATUS_ERR;
	if (find_tcp_timestamp(actual_packet, error))
		return STATUS_ERR;
	if ((script_packet->tcp_ts_val != NULL) &&
	    (actual_packet->tcp_ts_val != NULL)) {
		u32 script_ts_val = packet_tcp_ts_val(script_packet);
		u32 actual_ts_val = packet_tcp_ts_val(actual_packet);

		/* Remember script->actual TS val mapping for later. */
		set_outbound_ts_val_mapping(socket,
					    script_ts_val,
					    actual_ts_val);

		/* Find baseline for socket's live->script TS val mapping. */
		if (!socket->found_first_tcp_ts) {
			socket->found_first_tcp_ts = true;
			socket->first_script_ts_val = script_ts_val;
			socket->first_actual_ts_val = actual_ts_val;
		}

		/* Rewrite TCP timestamp value to script space, so we
		 * can compare the script and actual outbound TCP
		 * timestamp val.
		 */
		packet_set_tcp_ts_val(actual_packet,
				      socket->first_script_ts_val +
				      (actual_ts_val -
				       socket->first_actual_ts_val));
	}

	return STATUS_OK;
}

/* Verify IP and TCP checksums on an outbound live packet. */
static int verify_outbound_live_checksums(struct packet *live_packet,
					  char **error)
{
	/* Verify IP header checksum. */
	if ((live_packet->ipv4 != NULL) &&
	    ipv4_checksum(live_packet->ipv4,
			  ipv4_header_len(live_packet->ipv4))) {
		asprintf(error, "bad outbound IP checksum");
		return STATUS_ERR;
	}

	/* TODO(ncardwell): Verify TCP and UDP checksum. This is a little
	 * subtle, due to TCP checksum offloading.
	 */

	return STATUS_OK;
}

/* Check whether the given field of a packet matches the expected
 * value, and emit a human-readable error message if not.
 */
static int check_field(
	const char *name,	/* human-readable name of the header field */
	u32 expected,		/* value script hopes to see */
	u32 actual,		/* actual value seen during test */
	char **error)		/* human-readable error string on failure */
{
	if (actual != expected) {
		asprintf(error, "live packet field %s: "
			 "expected: %u (0x%x) vs actual: %u (0x%x)",
			 name, expected, expected, actual, actual);
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Verify that the actual ECN bits are as the script expected. */
static int verify_outbound_live_ecn(enum ip_ecn_t ecn,
				    u8 actual_ecn_bits,
				    u8 script_ecn_bits,
				    char **error)
{
	if (ecn == ECN_NOCHECK)
		return STATUS_OK;

	if (ecn == ECN_ECT01) {
		if ((actual_ecn_bits != IP_ECN_ECT0) &&
		    (actual_ecn_bits != IP_ECN_ECT1)) {
			asprintf(error, "live packet field ip_ecn: "
				 "expected: 0x1 or 0x2 vs actual: 0x%x",
				 actual_ecn_bits);
			return STATUS_ERR;
		}
	} else if (check_field("ip_ecn",
			       script_ecn_bits,
			       actual_ecn_bits, error)) {
		return STATUS_ERR;
	}

	return STATUS_OK;
}

/* How many bytes should we tack onto the script packet to account for
 * the actual TCP options we did see?
 */
static int tcp_options_allowance(const struct packet *actual_packet,
				 const struct packet *script_packet)
{
	if (script_packet->flags & FLAG_OPTIONS_NOCHECK)
		return packet_tcp_options_len(actual_packet);
	else
		return 0;
}

/* Verify that required actual IPv4 header fields are as the script expected. */
static int verify_ipv4(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct ipv4 *actual_ipv4 = actual_packet->headers[layer].h.ipv4;
	const struct ipv4 *script_ipv4 = script_packet->headers[layer].h.ipv4;

	if (check_field("ipv4_version",
			script_ipv4->version,
			actual_ipv4->version, error) ||
	    check_field("ipv4_protocol",
			script_ipv4->protocol,
			actual_ipv4->protocol, error) ||
	    check_field("ipv4_header_length",
			script_ipv4->ihl,
			actual_ipv4->ihl, error) ||
	    check_field("ipv4_total_length",
			(ntohs(script_ipv4->tot_len) +
			 tcp_options_allowance(actual_packet,
					       script_packet)),
			ntohs(actual_ipv4->tot_len), error))
		return STATUS_ERR;

	if (verify_outbound_live_ecn(script_packet->ecn,
				     ipv4_ecn_bits(actual_ipv4),
				     ipv4_ecn_bits(script_ipv4),
				     error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Verify that required actual IPv6 header fields are as the script expected. */
static int verify_ipv6(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct ipv6 *actual_ipv6 = actual_packet->headers[layer].h.ipv6;
	const struct ipv6 *script_ipv6 = script_packet->headers[layer].h.ipv6;

	if (check_field("ipv6_version",
			script_ipv6->version,
			actual_ipv6->version, error) ||
	    check_field("ipv6_payload_len",
			(ntohs(script_ipv6->payload_len) +
			 tcp_options_allowance(actual_packet,
					       script_packet)),
			ntohs(actual_ipv6->payload_len), error) ||
	    check_field("ipv6_next_header",
			script_ipv6->next_header,
			actual_ipv6->next_header, error))
		return STATUS_ERR;

	if (verify_outbound_live_ecn(script_packet->ecn,
				     ipv6_ecn_bits(actual_ipv6),
				     ipv6_ecn_bits(script_ipv6),
				     error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Verify that required actual TCP header fields are as the script expected. */
static int verify_tcp(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct tcp *actual_tcp = actual_packet->headers[layer].h.tcp;
	const struct tcp *script_tcp = script_packet->headers[layer].h.tcp;

	if (check_field("tcp_data_offset",
			(script_tcp->doff +
			 tcp_options_allowance(actual_packet,
					       script_packet)/sizeof(u32)),
			actual_tcp->doff, error) ||
	    check_field("tcp_fin",
			script_tcp->fin,
			actual_tcp->fin, error) ||
	    check_field("tcp_syn",
			script_tcp->syn,
			actual_tcp->syn, error) ||
	    check_field("tcp_rst",
			script_tcp->rst,
			actual_tcp->rst, error) ||
	    check_field("tcp_psh",
			script_tcp->psh,
			actual_tcp->psh, error) ||
	    check_field("tcp_ack",
			script_tcp->ack,
			actual_tcp->ack, error) ||
	    check_field("tcp_urg",
			script_tcp->urg,
			actual_tcp->urg, error) ||
	    check_field("tcp_ece",
			script_tcp->ece,
			actual_tcp->ece, error) ||
	    check_field("tcp_cwr",
			script_tcp->cwr,
			actual_tcp->cwr, error) ||
	    check_field("tcp_reserved_bits",
			script_tcp->res1,
			actual_tcp->res1, error) ||
	    check_field("tcp_seq",
			ntohl(script_tcp->seq),
			ntohl(actual_tcp->seq), error) ||
	    check_field("tcp_ack_seq",
			ntohl(script_tcp->ack_seq),
			ntohl(actual_tcp->ack_seq), error) ||
	    (script_packet->flags & FLAG_WIN_NOCHECK ? STATUS_OK :
		check_field("tcp_window",
			    ntohs(script_tcp->window),
			    ntohs(actual_tcp->window), error))  ||
	    check_field("tcp_urg_ptr",
			ntohs(script_tcp->urg_ptr),
			ntohs(actual_tcp->urg_ptr), error))
		return STATUS_ERR;

	return STATUS_OK;
}

/* Verify that required actual UDP header fields are as the script expected. */
static int verify_udp(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct udp *actual_udp = actual_packet->headers[layer].h.udp;
	const struct udp *script_udp = script_packet->headers[layer].h.udp;

	if (check_field("udp_len",
			script_udp->len,
			actual_udp->len, error))
		return STATUS_ERR;
	return STATUS_OK;
}

/* Verify that required actual GRE header fields are as the script expected. */
static int verify_gre(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct gre *actual_gre = actual_packet->headers[layer].h.gre;
	const struct gre *script_gre = script_packet->headers[layer].h.gre;

	/* TODO(ncardwell) check all fields of GRE header */
	if (check_field("gre_len",
			gre_len(script_gre),
			gre_len(actual_gre), error))
		return STATUS_ERR;
	return STATUS_OK;
}

/* Verify that required actual MPLS header fields are as the script expected. */
static int verify_mpls(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	const struct header *actual_header = &actual_packet->headers[layer];
	const struct header *script_header = &script_packet->headers[layer];
	const struct mpls *actual_mpls = actual_packet->headers[layer].h.mpls;
	const struct mpls *script_mpls = script_packet->headers[layer].h.mpls;
	int num_entries = script_header->header_bytes / sizeof(struct mpls);
	int i = 0;

	if (script_header->header_bytes != actual_header->header_bytes) {
		asprintf(error, "mismatch in MPLS label stack depth");
		return STATUS_ERR;
	}

	for (i = 0; i < num_entries; ++i) {
		const struct mpls *actual_entry = actual_mpls + i;
		const struct mpls *script_entry = script_mpls + i;
		if (memcmp(actual_entry, script_entry, sizeof(*script_entry))) {
			asprintf(error, "mismatch in MPLS label %d", i);
			return STATUS_ERR;
		}
	}

	return STATUS_OK;
}

typedef int (*verifier_func)(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error);

/* Verify that required actual header fields are as the script expected. */
static int verify_header(
	const struct packet *actual_packet,
	const struct packet *script_packet,
	int layer, char **error)
{
	verifier_func verifiers[HEADER_NUM_TYPES] = {
		[HEADER_IPV4]	= verify_ipv4,
		[HEADER_IPV6]	= verify_ipv6,
		[HEADER_GRE]	= verify_gre,
		[HEADER_MPLS]	= verify_mpls,
		[HEADER_TCP]	= verify_tcp,
		[HEADER_UDP]	= verify_udp,
	};
	verifier_func verifier = NULL;
	const struct header *actual_header = &actual_packet->headers[layer];
	const struct header *script_header = &script_packet->headers[layer];
	enum header_t type = script_header->type;

	if (script_header->type != actual_header->type) {
		asprintf(error, "live packet header layer %d: "
			 "expected: %s header vs actual: %s header",
			 layer,
			 header_type_info(script_header->type)->name,
			 header_type_info(actual_header->type)->name);
		return STATUS_ERR;
	}

	assert(type > HEADER_NONE);
	assert(type < HEADER_NUM_TYPES);
	verifier = verifiers[type];
	assert(verifier != NULL);
	return verifier(actual_packet, script_packet, layer, error);
}

/* Verify that required actual header fields are as the script expected. */
static int verify_outbound_live_headers(
	const struct packet *actual_packet,
	const struct packet *script_packet, char **error)
{
	const int actual_headers = packet_header_count(actual_packet);
	const int script_headers = packet_header_count(script_packet);
	int i;

	assert((actual_packet->ipv4 != NULL) || (actual_packet->ipv6 != NULL));
	assert((actual_packet->tcp != NULL) || (actual_packet->udp != NULL));

	if (actual_headers != script_headers) {
		asprintf(error, "live packet header layers: "
			 "expected: %d headers vs actual: %d headers",
			 script_headers, actual_headers);
		return STATUS_ERR;
	}

	/* Compare actual vs script headers, layer by layer. */
	for (i = 0; i < ARRAY_SIZE(script_packet->headers); ++i) {
		if (script_packet->headers[i].type == HEADER_NONE)
			break;

		if (verify_header(actual_packet, script_packet, i, error))
			return STATUS_ERR;
	}

	return STATUS_OK;
}

/* Return true iff the TCP options for the packets are bytewise identical. */
static bool same_tcp_options(struct packet *packet_a,
			     struct packet *packet_b)
{
	return ((packet_tcp_options_len(packet_a) ==
		 packet_tcp_options_len(packet_b)) &&
		(memcmp(packet_tcp_options(packet_a),
			packet_tcp_options(packet_b),
			packet_tcp_options_len(packet_a)) == 0));
}

/* Verify that the TCP option values matched expected values. */
static int verify_outbound_live_tcp_options(
	struct config *config,
	struct packet *actual_packet,
	struct packet *script_packet, char **error)
{
	/* See if we should validate TCP options at all. */
	if (script_packet->flags & FLAG_OPTIONS_NOCHECK)
		return STATUS_OK;

	/* Simplest case: see if full options are bytewise identical. */
	if (same_tcp_options(actual_packet, script_packet))
		return STATUS_OK;

	/* Otherwise, see if we just have a slight difference in TS val. */
	if (script_packet->tcp_ts_val != NULL &&
	    actual_packet->tcp_ts_val != NULL) {
		u32 script_ts_val = packet_tcp_ts_val(script_packet);
		u32 actual_ts_val = packet_tcp_ts_val(actual_packet);

		/* See if the deviation from the script TS val is
		 * within our configured tolerance.
		 */
		if (config->tcp_ts_tick_usecs &&
		    ((abs((s32)(actual_ts_val - script_ts_val)) *
		      config->tcp_ts_tick_usecs) >
		     config->tolerance_usecs)) {
			asprintf(error, "bad outbound TCP timestamp value");
			return STATUS_ERR;
		}

		/* Now see if the rest of the TCP options outside the
		 * TS val match: temporarily re-write the actual TS
		 * val to the script TS val and then see if the full
		 * options are now bytewise identical.
		 */
		packet_set_tcp_ts_val(actual_packet, script_ts_val);
		bool is_same = same_tcp_options(actual_packet, script_packet);
		packet_set_tcp_ts_val(actual_packet, actual_ts_val);
		if (is_same)
			return STATUS_OK;
	}

	asprintf(error, "bad outbound TCP options");
	return STATUS_ERR;	/* The TCP options did not match */
}


/* Verify TCP/UDP payload matches expected value. */
static int verify_outbound_live_payload(
	struct packet *actual_packet,
	struct packet *script_packet, char **error)
{
	/* Diff the TCP/UDP data payloads. We've already implicitly
	 * checked their length by checking the IP and TCP/UDP headers.
	 */
	assert(packet_payload_len(actual_packet) ==
	       packet_payload_len(script_packet));
	if (memcmp(packet_payload(script_packet),
		   packet_payload(actual_packet),
		   packet_payload_len(script_packet)) != 0) {
		asprintf(error, "incorrect outbound data payload");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Verify that the outbound packet correctly matches the expected
 * outbound packet from the script.
 * Return STATUS_OK upon success.  If non_fatal_packet is unset in the
 * config, return STATUS_ERR upon all failures.  With non_fatal_packet,
 * return STATUS_WARN upon non-fatal failures.
 */
static int verify_outbound_live_packet(
	struct state *state, struct socket *socket,
	struct packet *script_packet, struct packet *live_packet,
	char **error)
{
	DEBUGP("verify_outbound_live_packet\n");

	int result = STATUS_ERR;	/* return value */
	bool non_fatal = false;		/* ok to continue on error? */
	enum event_time_t time_type = state->event->time_type;
	s64 script_usecs = state->event->time_usecs;
	s64 script_usecs_end = state->event->time_usecs_end;

	/* The "actual" packet will be the live packet with values
	 * mapped into script space.
	 */
	struct packet *actual_packet = packet_copy(live_packet);
	s64 actual_usecs = live_time_to_script_time_usecs(
		state, live_packet->time_usecs);

	/* Before mapping, see if the live outgoing checksums are correct. */
	if (verify_outbound_live_checksums(live_packet, error))
		goto out;

	/* Map live packet values into script space for easy comparison. */
	if (map_outbound_live_packet(
		    socket, live_packet, actual_packet, script_packet, error))
		goto out;

	/* Verify actual IP, TCP/UDP header values matched expected ones. */
	if (verify_outbound_live_headers(actual_packet, script_packet, error)) {
		non_fatal = true;
		goto out;
	}

	if (script_packet->tcp) {
		/* Verify TCP options matched expected values. */
		if (verify_outbound_live_tcp_options(
			    state->config, actual_packet, script_packet,
			    error)) {
			non_fatal = true;
			goto out;
		}
	}

	/* Verify TCP/UDP payload matches expected value. */
	if (verify_outbound_live_payload(actual_packet, script_packet, error)) {
		non_fatal = true;
		goto out;
	}

	/* Verify that kernel sent packet at the time the script expected. */
	DEBUGP("packet time_usecs: %lld\n", live_packet->time_usecs);
	if (verify_time(state, time_type, script_usecs,
				script_usecs_end, live_packet->time_usecs,
				"outbound packet", error)) {
		non_fatal = true;
		goto out;
	}

	result = STATUS_OK;

out:
	add_packet_dump(error, "script", script_packet, script_usecs,
			DUMP_SHORT);
	if (actual_packet != NULL) {
		add_packet_dump(error, "actual", actual_packet, actual_usecs,
				DUMP_SHORT);
		packet_free(actual_packet);
	}
	if (result == STATUS_ERR &&
	    non_fatal &&
	    state->config->non_fatal_packet) {
		result = STATUS_WARN;
	}
	return result;
}

/* Sniff the next outbound live packet and return it. */
static int sniff_outbound_live_packet(
	struct state *state, struct socket *expected_socket,
	struct packet **packet, char **error)
{
	DEBUGP("sniff_outbound_live_packet\n");
	struct socket *socket = NULL;
	enum direction_t direction = DIRECTION_INVALID;
	assert(*packet == NULL);
	while (1) {
		if (netdev_receive(state->netdev, packet, error))
			return STATUS_ERR;
		/* See if the packet matches an existing, known socket. */
		socket = find_socket_for_live_packet(state, *packet,
						     &direction);
		if ((socket != NULL) && (direction == DIRECTION_OUTBOUND))
			break;
		/* See if the packet matches a recent connect() call. */
		socket = find_connect_for_live_packet(state, *packet,
						      &direction);
		if ((socket != NULL) && (direction == DIRECTION_OUTBOUND))
			break;
		packet_free(*packet);
		*packet = NULL;
	}

	assert(*packet != NULL);
	assert(socket != NULL);
	assert(direction == DIRECTION_OUTBOUND);

	if (socket != expected_socket) {
		asprintf(error, "packet is not for expected socket");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

/* Return true iff the given packet could be sent/received by the socket. */
static bool is_script_packet_match_for_socket(
	struct state *state, struct packet *packet, struct socket *socket)
{
	const bool is_packet_icmp = (packet->icmpv4 || packet->icmpv6);

	if (socket->protocol == IPPROTO_TCP)
		return packet->tcp || is_packet_icmp;
	else if (socket->protocol == IPPROTO_UDP)
		return packet->udp || is_packet_icmp;
	else
		assert(!"unsupported layer 4 protocol in socket");
	return false;
}

/* Find or create a socket object matching the given packet. */
static int find_or_create_socket_for_script_packet(
	struct state *state, struct packet *packet,
	enum direction_t direction, struct socket **socket,
	char **error)
{
	*socket = NULL;

	DEBUGP("find_or_create_socket_for_script_packet\n");

	if (packet->tcp != NULL) {
		/* Is this an inbound packet matching a listening
		 * socket? If so, this call will create a new child
		 * socket object.
		 */
		*socket = handle_listen_for_script_packet(state,
							  packet, direction);
		if (*socket != NULL)
			return STATUS_OK;

		/* Is this an outbound packet matching a connecting socket? */
		*socket = handle_connect_for_script_packet(state,
							   packet, direction);
		if (*socket != NULL)
			return STATUS_OK;
	}
	/* See if there is an existing connection to handle this packet. */
	if (state->socket_under_test != NULL &&
	    is_script_packet_match_for_socket(state, packet,
					      state->socket_under_test)) {
		*socket = state->socket_under_test;
		return STATUS_OK;
	}

	asprintf(error, "no matching socket for script packet");
	return STATUS_ERR;
}

/* Perform the action implied by an outbound packet in a script
 * Return STATUS_OK upon success.  Without --use_expect, return STATUS_ERR
 * upon all failures.  With --use_expect, return STATUS_WARN upon non-fatal
 * failures.
 */
static int do_outbound_script_packet(
	struct state *state, struct packet *packet,
	struct socket *socket,	char **error)
{
	DEBUGP("do_outbound_script_packet\n");
	int result = STATUS_ERR;		/* return value */
	struct packet *live_packet = NULL;

	if ((packet->icmpv4 != NULL) || (packet->icmpv6 != NULL)) {
		asprintf(error, "outbound ICMP packets are not supported");
		goto out;
	}

	if ((socket->state == SOCKET_PASSIVE_PACKET_RECEIVED) &&
	    packet->tcp && packet->tcp->syn && packet->tcp->ack) {
		/* Script says we should see an outbound server SYNACK. */
		socket->script.local_isn = ntohl(packet->tcp->seq);
		DEBUGP("SYNACK script.local_isn: %u\n",
		       socket->script.local_isn);
	}

	/* Sniff outbound live packet and verify it's for the right socket. */
	if (sniff_outbound_live_packet(state, socket, &live_packet, error))
		goto out;

	if ((socket->state == SOCKET_PASSIVE_PACKET_RECEIVED) &&
	    packet->tcp && packet->tcp->syn && packet->tcp->ack) {
		socket->state = SOCKET_PASSIVE_SYNACK_SENT;
		socket->live.local_isn = ntohl(live_packet->tcp->seq);
		DEBUGP("SYNACK live.local_isn: %u\n",
		       socket->live.local_isn);
	}

	verbose_packet_dump(state, "outbound sniffed", live_packet,
			    live_time_to_script_time_usecs(
				    state, live_packet->time_usecs));

	/* Save the TCP header so we can reset the connection at the end. */
	if (live_packet->tcp)
		socket->last_outbound_tcp_header = *(live_packet->tcp);

	/* Verify the bits the kernel sent were what the script expected. */
	result = verify_outbound_live_packet(
			state, socket, packet, live_packet, error);

out:
	if (live_packet != NULL)
		packet_free(live_packet);
	return result;
}

/* Checksum the packet and inject it into the kernel under test. */
static int send_live_ip_packet(struct netdev *netdev,
			       struct packet *packet)
{
	assert(packet->ip_bytes > 0);
	/* We do IPv4 and IPv6 */
	assert(packet->ipv4 || packet->ipv6);
	/* We only do TCP, UDP, and ICMP */
	assert(packet->tcp || packet->udp || packet->icmpv4 || packet->icmpv6);

	/* Fill in layer 3 and layer 4 checksums */
	checksum_packet(packet);

	return netdev_send(netdev, packet);
}

/* Perform the action implied by an inbound packet in a script */
static int do_inbound_script_packet(
	struct state *state, struct packet *packet,
	struct socket *socket,	char **error)
{
	DEBUGP("do_inbound_script_packet\n");
	int result = STATUS_ERR;	/* return value */

	if ((socket->state == SOCKET_PASSIVE_SYNACK_SENT) &&
	    packet->tcp && packet->tcp->ack) {
		/* Received the ACK that completes the 3-way handshake. */
		socket->state = SOCKET_PASSIVE_SYNACK_ACKED;
	} else if ((socket->state == SOCKET_ACTIVE_SYN_SENT) &&
		   packet->tcp && packet->tcp->syn && packet->tcp->ack) {
		/* Received the server's SYNACK, which ACKs our SYN. */
		socket->state = SOCKET_ACTIVE_SYN_ACKED;
		socket->script.remote_isn	= ntohl(packet->tcp->seq);
		socket->live.remote_isn		= ntohl(packet->tcp->seq);
	}

	/* Start with a bit-for-bit copy of the packet from the script. */
	struct packet *live_packet = packet_copy(packet);
	/* Map packet fields from script values to live values. */
	if (map_inbound_packet(socket, live_packet, error))
		goto out;

	verbose_packet_dump(state, "inbound injected", live_packet,
			    live_time_to_script_time_usecs(
				    state, now_usecs()));

	if (live_packet->tcp) {
		/* Save the TCP header so we can reset the connection later. */
		socket->last_injected_tcp_header = *(live_packet->tcp);
		socket->last_injected_tcp_payload_len =
			packet_payload_len(live_packet);
	}

	/* Inject live packet into kernel. */
	result = send_live_ip_packet(state->netdev, live_packet);

out:
	packet_free(live_packet);
	return result;
}

int run_packet_event(
	struct state *state, struct event *event, struct packet *packet,
	char **error)
{
	DEBUGP("%d: packet\n", event->line_number);

	char *err = NULL;
	struct socket *socket = NULL;
	int result = STATUS_ERR;

	enum direction_t direction = packet_direction(packet);
	assert(direction != DIRECTION_INVALID);

	if (find_or_create_socket_for_script_packet(
		    state, packet, direction, &socket, &err))
		goto out;

	assert(socket != NULL);

	if (direction == DIRECTION_OUTBOUND) {
		/* We don't wait for outbound event packets because we
		 * want to start sniffing ASAP in order to see if
		 * packets go out earlier than the script specifies.
		 */
		result = do_outbound_script_packet(state, packet, socket, &err);
		if (result == STATUS_WARN)
			goto out;
		else if (result == STATUS_ERR)
			goto out;
	} else if (direction == DIRECTION_INBOUND) {
		wait_for_event(state);
		if (do_inbound_script_packet(state, packet, socket, &err))
			goto out;
	} else {
		assert(!"bad direction");  /* internal bug */
	}

	return STATUS_OK;	 /* everything went fine */

out:
	/* Format a more complete error message and return that. */
	asprintf(error, "%s:%d: %s handling packet: %s\n",
		 state->config->script_path, event->line_number,
		 result == STATUS_ERR ? "error" : "warning", err);
	free(err);
	return result;
}

/* Inject a TCP RST packet to clear the connection state out of the
 * kernel, so the connection does not continue to retransmit packets
 * that may be sniffed during later test executions and cause false
 * negatives.
 */
int reset_connection(struct state *state, struct socket *socket)
{
	char *error = NULL;
	u32 seq = 0, ack_seq = 0;
	u16 window = 0;
	struct packet *packet = NULL;
	struct tuple live_inbound;
	int result = 0;

	/* Pick TCP header fields to be something the kernel will accept. */
	if (socket->last_injected_tcp_header.ack) {
		/* If we've already injected something, then use a sequence
		 * number right after the last one we injected, and ACK
		 * the last thing we ACKed, and offer the same receive
		 * window we last offered.
		 */
		seq	= (ntohl(socket->last_injected_tcp_header.seq) +
			   (socket->last_injected_tcp_header.syn ? 1 : 0) +
			   (socket->last_injected_tcp_header.fin ? 1 : 0) +
			   socket->last_injected_tcp_payload_len);
		ack_seq	= ntohl(socket->last_injected_tcp_header.ack_seq);
		window	= ntohs(socket->last_injected_tcp_header.window);
	} else if (socket->last_outbound_tcp_header.ack) {
		/* If the kernel ACKed something, then just make sure
		 * we use the sequence number it ACKed, which will be
		 * something it expects.
		 */
		seq = ntohl(socket->last_outbound_tcp_header.ack_seq);
		ack_seq = ntohl(socket->last_outbound_tcp_header.seq);
	} else {
		/* If the kernel didn't ACK anything, then it probably
		 * sent only an initial SYN. So we get to send any
		 * sequence number we want, but should send an ACK
		 * suggesting we've seen the kernel's SYN.
		 */
		seq = 0;
		ack_seq = ntohl(socket->last_outbound_tcp_header.seq) + 1;
	}

	packet = new_tcp_packet(socket->address_family,
				DIRECTION_INBOUND, ECN_NONE,
				"R.", seq, 0, ack_seq, window, NULL, &error);
	if (packet == NULL)
		die("%s", error);

	/* Rewrite addresses and port to match inbound live traffic. */
	socket_get_inbound(&socket->live, &live_inbound);
	set_packet_tuple(packet, &live_inbound);

	/* Inject live packet into kernel. */
	result = send_live_ip_packet(state->netdev, packet);

	packet_free(packet);

	return result;
}

struct packets *packets_new(void)
{
	struct packets *packets = calloc(1, sizeof(struct packets));

	packets->next_ephemeral_port = ephemeral_port();  /* cache a port */

	return packets;
}

void packets_free(struct packets *packets)
{
	memset(packets, 0, sizeof(*packets));  /* to help catch bugs */
	free(packets);
}
