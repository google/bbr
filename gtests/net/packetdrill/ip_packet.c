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

#include "checksum.h"
#include "ip.h"
#include "ipv6.h"

/* Fill in IPv4 header fields. */
static void set_ipv4_header(struct ipv4 *ipv4,
			    u16 ip_bytes, u8 tos,
			    u8 ttl, u8 protocol)
{
	ipv4->version = 4;
	ipv4->ihl = sizeof(struct ipv4) / sizeof(u32);
	ipv4->tos = tos;

	ipv4->tot_len = htons(ip_bytes);
	ipv4->id = 0;
	ipv4->frag_off = 0;
	if (ttl)
		ipv4->ttl = ttl;
	else
		ipv4->ttl = TTL_CHECK_NONE;
	ipv4->protocol = protocol;
	ipv4->check = 0;

	ipv4->src_ip = in4addr_any;
	ipv4->dst_ip = in4addr_any;
}

/* Fill in IPv6 header fields. */
static void set_ipv6_header(struct ipv6 *ipv6,
			    u16 ip_bytes,
			    u8 tos, u32 flow_label,
			    u8 hop_limit, u8 protocol)
{
	ipv6->version = 6;
	ipv6->traffic_class_hi = tos >> 4;
	ipv6->traffic_class_lo = tos & 0x0f;
	ipv6->flow_label_hi = (flow_label >> 16) & 0xf;
	ipv6->flow_label_lo = htons(flow_label & 0xffff);

	assert(ip_bytes >= sizeof(*ipv6));
	ipv6->payload_len = htons(ip_bytes - sizeof(*ipv6));
	ipv6->next_header = protocol;
	if (hop_limit)
		ipv6->hop_limit = hop_limit;
	else
		ipv6->hop_limit = TTL_CHECK_NONE;

	ipv6->src_ip = in6addr_any;
	ipv6->dst_ip = in6addr_any;
}

void set_ip_header(void *ip_header,
		   int address_family,
		   u16 ip_bytes,
		   u8 tos, u32 flowlabel,
		   u8 ttl, u8 protocol)
{
	if (address_family == AF_INET)
		set_ipv4_header(ip_header, ip_bytes, tos, ttl, protocol);
	else if (address_family == AF_INET6)
		set_ipv6_header(ip_header, ip_bytes, tos, flowlabel,
				ttl, protocol);
	else
		assert(!"bad ip_version in config");
}

void set_packet_ip_header(struct packet *packet,
			  int address_family,
			  u16 ip_bytes,
			  u8 tos, u32 flowlabel,
			  u8 ttl, u8 protocol)
{
	struct header *ip_header = NULL;

	if (address_family == AF_INET) {
		struct ipv4 *ipv4 = (struct ipv4 *) packet->buffer;
		packet->ipv4 = ipv4;
		assert(packet->ipv6 == NULL);
		ip_header = packet_append_header(packet, HEADER_IPV4,
						 sizeof(*ipv4));
		ip_header->total_bytes = ip_bytes;
		set_ipv4_header(ipv4, ip_bytes, tos, ttl, protocol);
	} else if (address_family == AF_INET6) {
		struct ipv6 *ipv6 = (struct ipv6 *) packet->buffer;
		packet->ipv6 = ipv6;
		assert(packet->ipv4 == NULL);
		ip_header = packet_append_header(packet, HEADER_IPV6,
						 sizeof(*ipv6));
		ip_header->total_bytes = ip_bytes;
		set_ipv6_header(ipv6, ip_bytes, tos, flowlabel, ttl, protocol);
	} else {
		assert(!"bad ip_version in config");
	}
}

int ipv4_header_append(struct packet *packet,
		       const char *ip_src,
		       const char *ip_dst,
		       const u8 tos,
		       const u8 ttl,
		       char **error)
{
	struct header *header = NULL;
	const int ipv4_bytes = sizeof(struct ipv4);
	struct ipv4 *ipv4 = NULL;

	header = packet_append_header(packet, HEADER_IPV4, ipv4_bytes);
	if (header == NULL) {
		asprintf(error, "too many headers");
		return STATUS_ERR;
	}

	ipv4 = header->h.ipv4;
	set_ip_header(ipv4, AF_INET, 0, tos, 0, ttl, 0);

	if (inet_pton(AF_INET, ip_src, &ipv4->src_ip) != 1) {
		asprintf(error, "bad IPv4 src address: '%s'\n", ip_src);
		return STATUS_ERR;
	}

	if (inet_pton(AF_INET, ip_dst, &ipv4->dst_ip) != 1) {
		asprintf(error, "bad IPv4 dst address: '%s'\n", ip_dst);
		return STATUS_ERR;
	}

	return STATUS_OK;
}

int ipv6_header_append(struct packet *packet,
		       const char *ip_src,
		       const char *ip_dst,
		       const u8 tos,
		       const u8 hop_limit,
		       char **error)
{
	struct header *header = NULL;
	const int ipv6_bytes = sizeof(struct ipv6);
	struct ipv6 *ipv6 = NULL;

	header = packet_append_header(packet, HEADER_IPV6, ipv6_bytes);
	if (header == NULL) {
		asprintf(error, "too many headers");
		return STATUS_ERR;
	}

	ipv6 = header->h.ipv6;
	set_ip_header(ipv6, AF_INET6, sizeof(struct ipv6), tos, 0, hop_limit, 0);

	if (inet_pton(AF_INET6, ip_src, &ipv6->src_ip) != 1) {
		asprintf(error, "bad IPv6 src address: '%s'\n", ip_src);
		return STATUS_ERR;
	}

	if (inet_pton(AF_INET6, ip_dst, &ipv6->dst_ip) != 1) {
		asprintf(error, "bad IPv6 dst address: '%s'\n", ip_dst);
		return STATUS_ERR;
	}

	return STATUS_OK;
}

int ipv4_header_finish(struct packet *packet,
		       struct header *header, struct header *next_inner)
{
	struct ipv4 *ipv4 = header->h.ipv4;
	int ip_bytes = sizeof(struct ipv4) + next_inner->total_bytes;

	ipv4->tot_len = htons(ip_bytes);
	ipv4->protocol = header_type_info(next_inner->type)->ip_proto;

	/* Fill in IPv4 header checksum. */
	ipv4->check = 0;
	ipv4->check = ipv4_checksum(ipv4, ipv4->ihl * sizeof(u32));

	header->total_bytes = ip_bytes;

	return STATUS_OK;
}

int ipv6_header_finish(struct packet *packet,
		       struct header *header, struct header *next_inner)
{
	struct ipv6 *ipv6 = header->h.ipv6;
	int ip_bytes = sizeof(struct ipv6) + next_inner->total_bytes;

	assert(next_inner->total_bytes <= 0xffff);
	ipv6->payload_len = htons(next_inner->total_bytes);
	ipv6->next_header = header_type_info(next_inner->type)->ip_proto;

	/* IPv6 has no header checksum. */

	header->total_bytes = ip_bytes;

	return STATUS_OK;
}
