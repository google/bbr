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
 * Interface and type declarations for packetdrill's representation of
 * packet headers. We support multi-layer encapsulation. In order to
 * make it easier to iterate through all the headers in a packet, we
 * keep separate, explicit metadata about the types and locations of
 * headers in a packet.
 */

#ifndef __HEADER_H__
#define __HEADER_H__

#include "types.h"

#include <sys/time.h>
#include "assert.h"
#include "gre.h"
#include "icmp.h"
#include "icmpv6.h"
#include "ip.h"
#include "ipv6.h"
#include "mpls.h"
#include "tcp.h"
#include "udp.h"

struct packet;

/* The type of a header in a packet. */
enum header_t {
	HEADER_NONE,
	HEADER_IPV4,
	HEADER_IPV6,
	HEADER_GRE,
	HEADER_MPLS,
	HEADER_TCP,
	HEADER_UDP,
	HEADER_ICMPV4,
	HEADER_ICMPV6,
	HEADER_NUM_TYPES
};

/* Metadata about a header in a packet. We support multi-layer encapsulation. */
struct header {
	enum header_t type;	/* type of this header */
	u32 header_bytes;	/* length of this header */
	u32 total_bytes;	/* length of header plus data inside */
	union {
		u8 *ptr;		/* a pointer to the header bits */
		struct ipv4 *ipv4;
		struct ipv6 *ipv6;
		struct gre *gre;
		struct mpls *mpls;
		struct tcp *tcp;
		struct udp *udp;
		struct icmpv4 *icmpv4;
		struct icmpv6 *icmpv6;
	} h;
};

/* Info for a particular type of header. */
struct header_type_info {
	const char* name;	/* human-readable protocol name */
	u8 ip_proto;		/* IP protocol code */
	u16 eth_proto;		/* Ethernet protocol code */

	/* Call this to finalize the header once we know what's inside... */
	int (*finish)(struct packet *packet,
		      struct header *header, struct header *next_inner);
};

/* Return the info for the given type of header. */
extern struct header_type_info *header_type_info(enum header_t header_type);

#endif /* __HEADER_H__ */
