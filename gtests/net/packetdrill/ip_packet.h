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
 * Interface for module for formatting IP packets.
 */

#ifndef __IP_PACKET_H__
#define __IP_PACKET_H__

#include "types.h"

#include "packet.h"

/* Populate header fields in the IP header at the given address. */
extern void set_ip_header(void *ip_header,
			  int address_family,
			  u16 ip_bytes,
			  enum direction_t direction,
			  enum ip_ecn_t ecn, u8 protocol);

/* Set the packet's IP header pointer and then populate the IP header fields. */
extern void set_packet_ip_header(struct packet *packet,
				 int address_family,
				 u16 ip_bytes,
				 enum direction_t direction,
				 enum ip_ecn_t ecn, u8 protocol);

#endif /* __IP_PACKET_H__ */
