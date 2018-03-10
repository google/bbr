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
 * Interface for module for formatting UDP packets.
 */

#ifndef __UDP_PACKET_H__
#define __UDP_PACKET_H__

#include "types.h"

#include "packet.h"

/* Create and initialize a new struct packet containing a UDP segment.
 * The 'flags' are a tcpdump-style sequence of UDP header flags.
 * On success, returns a newly-allocated packet. On failure, returns NULL
 * and fills in *error with an error message.
 */
extern struct packet *new_udp_packet(int address_family,
				     enum direction_t direction,
				     struct ip_info ip_info,
				     u16 udp_payload_bytes,
				     u16 src_port,
				     u16 dst_port,
				     char **error);
#endif /* __UDP_PACKET_H__ */
