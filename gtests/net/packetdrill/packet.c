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
 * Implementation for a representation of TCP/IP packets.
 * Packets are represented in their wire format.
 */

#include "packet.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct packet *packet_new(u32 buffer_bytes)
{
	struct packet *packet = calloc(1, sizeof(struct packet));
	packet->buffer = malloc(buffer_bytes);
	packet->buffer_bytes = buffer_bytes;
	return packet;
}

void packet_free(struct packet *packet)
{
	free(packet->buffer);
	memset(packet, 0, sizeof(*packet));  /* paranoia to help catch bugs */
	free(packet);
}

struct packet *packet_copy(struct packet *old_packet)
{
	int offset;

	/* Allocate a new packet and copy link layer header and IP datagram. */
	const u32 bytes_used = packet_end(old_packet) - old_packet->buffer;
	struct packet *packet = packet_new(bytes_used);
	memcpy(packet->buffer, old_packet->buffer, bytes_used);

	packet->ip_bytes = old_packet->ip_bytes;

	/* Set up layer 3 header pointer. */
	if (old_packet->ipv4 != NULL) {
		offset = (u8 *) old_packet->ipv4 - old_packet->buffer;
		packet->ipv4 = (struct ipv4 *) (packet->buffer + offset);
	} else if (old_packet->ipv6 != NULL) {
		offset = (u8 *) old_packet->ipv6 - old_packet->buffer;
		packet->ipv6 = (struct ipv6 *) (packet->buffer + offset);
	}

	/* Set up layer 4 header pointer. */
	if (old_packet->tcp != NULL) {
		offset = (u8 *)old_packet->tcp - old_packet->buffer;
		packet->tcp = (struct tcp *)(packet->buffer + offset);
	} else if (old_packet->udp != NULL) {
		offset = (u8 *)old_packet->udp - old_packet->buffer;
		packet->udp = (struct udp *)(packet->buffer + offset);
	} else if (old_packet->icmpv4 != NULL) {
		offset = (u8 *)old_packet->icmpv4 - old_packet->buffer;
		packet->icmpv4 = (struct icmpv4 *)(packet->buffer + offset);
	} else if (old_packet->icmpv6 != NULL) {
		offset = (u8 *)old_packet->icmpv6 - old_packet->buffer;
		packet->icmpv6 = (struct icmpv6 *)(packet->buffer + offset);
	}

	return packet;
}
