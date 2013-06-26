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
 * Implementation for module for formatting IPv4 and IPv6 packets.
 */

#include "ip_packet.h"

#include "ip.h"
#include "ipv6.h"

/* Return the ECN header bits for the given ECN treatment. */
static u8 ip_ecn_bits(enum ip_ecn_t ecn)
{
	if (ecn == ECN_ECT0)
		return IP_ECN_ECT0;
	else if (ecn == ECN_ECT1)
		return IP_ECN_ECT1;
	else if (ecn == ECN_CE)
		return IP_ECN_CE;
	else
		return 0;
}

/* Fill in IPv4 header fields. */
static void set_ipv4_header(struct ipv4 *ipv4,
			    u16 ip_bytes,
			    enum direction_t direction,
			    enum ip_ecn_t ecn, u8 protocol)
{
	ipv4->version = 4;
	ipv4->ihl = sizeof(struct ipv4) / sizeof(u32);
	ipv4->tos = ip_ecn_bits(ecn);

	ipv4->tot_len = htons(ip_bytes);
	ipv4->id = 0;
	ipv4->frag_off = 0;
	ipv4->ttl = 255;
	ipv4->protocol = protocol;
	ipv4->check = 0;

	ipv4->src_ip = in4addr_any;
	ipv4->dst_ip = in4addr_any;
}

/* Fill in IPv6 header fields. */
static void set_ipv6_header(struct ipv6 *ipv6,
			    u16 ip_bytes,
			    enum direction_t direction,
			    enum ip_ecn_t ecn, u8 protocol)
{
	ipv6->version = 6;
	ipv6->traffic_class_hi = 0;
	ipv6->traffic_class_lo = ip_ecn_bits(ecn);
	ipv6->flow_label_hi = 0;
	ipv6->flow_label_lo = 0;

	assert(ip_bytes >= sizeof(*ipv6));
	ipv6->payload_len = htons(ip_bytes - sizeof(*ipv6));
	ipv6->next_header = protocol;
	ipv6->hop_limit = 255;

	ipv6->src_ip = in6addr_any;
	ipv6->dst_ip = in6addr_any;
}

void set_ip_header(void *ip_header,
		   int address_family,
		   u16 ip_bytes,
		   enum direction_t direction,
		   enum ip_ecn_t ecn, u8 protocol)
{
	if (address_family == AF_INET)
		set_ipv4_header(ip_header, ip_bytes, direction, ecn, protocol);
	else if (address_family == AF_INET6)
		set_ipv6_header(ip_header, ip_bytes, direction, ecn, protocol);
	else
		assert(!"bad ip_version in config");
}

void set_packet_ip_header(struct packet *packet,
			  int address_family,
			  u16 ip_bytes,
			  enum direction_t direction,
			  enum ip_ecn_t ecn, u8 protocol)
{
	if (address_family == AF_INET) {
		struct ipv4 *ipv4 = (struct ipv4 *) packet->buffer;
		packet->ipv4 = ipv4;
		assert(packet->ipv6 == NULL);
		set_ipv4_header(ipv4, ip_bytes, direction, ecn, protocol);
	} else if (address_family == AF_INET6) {
		struct ipv6 *ipv6 = (struct ipv6 *) packet->buffer;
		packet->ipv6 = ipv6;
		assert(packet->ipv4 == NULL);
		set_ipv6_header(ipv6, ip_bytes, direction, ecn, protocol);
	} else {
		assert(!"bad ip_version in config");
	}
}
