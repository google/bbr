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
 * Interface for module for formatting ICMP packets.
 */

#ifndef __ICMP_PACKET_H__
#define __ICMP_PACKET_H__

#include "types.h"

#include "packet.h"

/* Create and initialize a new struct packet containing an ICMP
 * packet. The 'type_string' identifies the ICMP type. The
 * 'code_string' identifies the ICMP code (and NULL means no code was
 * provided, in which case we assume a default code of 0).
 * The 'protocol' is either IPPROTO_UDP or IPPROTO_TCP.
 * The 'tcp_start_sequence' and 'payload_bytes' describe the TCP or UDP
 * packet echoed inside the ICMP message. The 'mtu' specifies the MTU
 * advertised in "packet is too big" ICMP message, or -1 for no
 * MTU. On success, returns a newly-allocated packet. On failure,
 * returns NULL and fills in *error with an error message.
 */
extern struct packet *new_icmp_packet(int address_family,
				      enum direction_t direction,
				      const char *type_string,
				      const char *code_string,
				      int protocol,
				      u32 tcp_start_sequence,
				      u32 payload_bytes,
				      struct ip_info ip_info,
				      s64 mtu,
				      s64 echo_id,
				      char **error);

#endif /* __ICMP_PACKET_H__ */
