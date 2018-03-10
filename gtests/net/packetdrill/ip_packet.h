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
			  u8 tos, u32 flowlabel,
			  u8 ttl, u8 protocol);

/* Set the packet's IP header pointer and then populate the IP header fields. */
extern void set_packet_ip_header(struct packet *packet,
				 int address_family,
				 u16 ip_bytes,
				 u8 tos, u32 flowlabel,
				 u8 ttl, u8 protocol);

/* Append an IPv4 header to the end of the given packet and fill in
 * src/dst.  On success, return STATUS_OK; on error return STATUS_ERR
 * and fill in a malloc-allocated error message in *error.
 */
extern int ipv4_header_append(struct packet *packet,
			      const char *ip_src,
			      const char *ip_dst,
			      const u8 tos,
			      const u8 ttl,
			      char **error);

/* Append an IPv6 header to the end of the given packet and fill in
 * src/dst.  On success, return STATUS_OK; on error return STATUS_ERR
 * and fill in a malloc-allocated error message in *error.
 */
extern int ipv6_header_append(struct packet *packet,
			      const char *ip_src,
			      const char *ip_dst,
			      const u8 tos,
			      const u8 hop_limit,
			      char **error);

/* Finalize the IPv4 header by filling in all necessary fields that
 * were not filled in at parse time.
 */
extern int ipv4_header_finish(struct packet *packet,
			      struct header *header, struct header *next_inner);

/* Finalize the IPv6 header by filling in all necessary fields that
 * were not filled in at parse time.
 */
extern int ipv6_header_finish(struct packet *packet,
			      struct header *header, struct header *next_inner);

#endif /* __IP_PACKET_H__ */
