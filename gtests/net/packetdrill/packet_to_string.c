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
 * Implementation for generating human-readable representations of IP
 * packets.
 */

#include "packet_to_string.h"

#include <stdlib.h>
#include "socket.h"
#include "tcp_options_to_string.h"

static void endpoints_to_string(FILE *s, const struct packet *packet)
{
	char src_string[ADDR_STR_LEN];
	char dst_string[ADDR_STR_LEN];
	struct tuple tuple;

	get_packet_tuple(packet, &tuple);

	fprintf(s, "%s:%u > %s:%u",
		ip_to_string(&tuple.src.ip, src_string), ntohs(tuple.src.port),
		ip_to_string(&tuple.dst.ip, dst_string), ntohs(tuple.dst.port));
}

static void packet_buffer_to_string(FILE *s, struct packet *packet)
{
	char *hex = NULL;
	hex_dump(packet->buffer, packet->ip_bytes, &hex);
	fputc('\n', s);
	fprintf(s, "%s", hex);
	free(hex);
}

/* Print a string representation of the TCP packet:
 *  direction opt_ip_info flags seq ack window tcp_options
 */
static int tcp_packet_to_string(FILE *s, struct packet *packet,
				enum dump_format_t format, char **error)
{
	int result = STATUS_OK;       /* return value */

	if ((format == DUMP_FULL) || (format == DUMP_VERBOSE)) {
		endpoints_to_string(s, packet);
		fputc(' ', s);
	}


	/* We print flags in the same order as tcpdump 4.1.1. */
	if (packet->tcp->fin)
		fputc('F', s);
	if (packet->tcp->syn)
		fputc('S', s);
	if (packet->tcp->rst)
		fputc('R', s);
	if (packet->tcp->psh)
		fputc('P', s);
	if (packet->tcp->ack)
		fputc('.', s);
	if (packet->tcp->urg)
		fputc('U', s);
	if (packet->tcp->ece)
		fputc('E', s);   /* ECN *E*cho sent (ECN) */
	if (packet->tcp->cwr)
		fputc('W', s);   /* Congestion *W*indow reduced (ECN) */

	fprintf(s, " %u:%u(%u) ",
		ntohl(packet->tcp->seq),
		ntohl(packet->tcp->seq) + packet_payload_len(packet),
		packet_payload_len(packet));

	if (packet->tcp->ack)
		fprintf(s, "ack %u ", ntohl(packet->tcp->ack_seq));

	if (!(packet->flags & FLAG_WIN_NOCHECK))
		fprintf(s, "win %u ", ntohs(packet->tcp->window));

	if (packet_tcp_options_len(packet) > 0) {
		char *tcp_options = NULL;
		if (tcp_options_to_string(packet, &tcp_options, error))
			result = STATUS_ERR;
		else
			fprintf(s, "<%s>", tcp_options);
	}

	if (format == DUMP_VERBOSE)
		packet_buffer_to_string(s, packet);

	return result;
}

static int udp_packet_to_string(FILE *s, struct packet *packet,
				enum dump_format_t format, char **error)
{
	int result = STATUS_OK;       /* return value */

	if ((format == DUMP_FULL) || (format == DUMP_VERBOSE)) {
		endpoints_to_string(s, packet);
		fputc(' ', s);
	}

	fprintf(s, "udp (%u)", packet_payload_len(packet));

	if (format == DUMP_VERBOSE)
		packet_buffer_to_string(s, packet);

	return result;
}

static int icmpv4_packet_to_string(FILE *s, struct packet *packet,
				   enum dump_format_t format, char **error)
{
	fprintf(s, "icmpv4");
	/* TODO(ncardwell): print type, code; use tables from icmp_packet.c */
	return STATUS_OK;
}

static int icmpv6_packet_to_string(FILE *s, struct packet *packet,
				   enum dump_format_t format, char **error)
{
	fprintf(s, "icmpv6");
	/* TODO(ncardwell): print type, code; use tables from icmp_packet.c */
	return STATUS_OK;
}

int packet_to_string(struct packet *packet,
		     enum dump_format_t format,
		     char **ascii_string, char **error)
{
	assert(packet != NULL);
	int result = STATUS_ERR;       /* return value */
	size_t size = 0;
	FILE *s = open_memstream(ascii_string, &size);  /* output string */

	if ((packet->ipv4 == NULL) && (packet->ipv6 == NULL)) {
		fprintf(s, "[NO IP HEADER]");
	} else {
		if (packet->tcp != NULL) {
			if (tcp_packet_to_string(s, packet, format, error))
				goto out;
		} else if (packet->udp != NULL) {
			if (udp_packet_to_string(s, packet, format, error))
				goto out;
		} else if (packet->icmpv4 != NULL) {
			if (icmpv4_packet_to_string(s, packet, format, error))
				goto out;
		} else if (packet->icmpv6 != NULL) {
			if (icmpv6_packet_to_string(s, packet, format, error))
				goto out;
		} else {
			fprintf(s, "[NO TCP OR ICMP HEADER]");
		}
	}

	result = STATUS_OK;

out:
	fclose(s);
	return result;
}
