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
 * Implementation for a module to parse TCP/IP packets.
 */

#include "packet_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "assert.h"
#include "checksum.h"
#include "ethernet.h"
#include "gre.h"
#include "ip.h"
#include "ip_address.h"
#include "logging.h"
#include "packet.h"
#include "tcp.h"

static int parse_ipv4(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error);
static int parse_ipv6(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error);
static int parse_mpls(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error);
static int parse_layer3_packet_by_proto(struct packet *packet,
					u16 proto, u8 *header_start,
					u8 *packet_end, char **error);
static int parse_layer4(struct packet *packet, u8 *header_start,
			int layer4_protocol, int layer4_bytes,
			u8 *packet_end, char **error);

static int parse_layer2_packet(struct packet *packet,
			       u8 *header_start, u8 *packet_end,
			       char **error)
{
	u8 *p = header_start;
	struct ether_header *ether = NULL;

	/* Find Ethernet header */
	if (p + sizeof(*ether) > packet_end) {
		asprintf(error, "Ethernet header overflows packet");
		goto error_out;
	}
	ether = (struct ether_header *)p;
	p += sizeof(*ether);
	packet->l2_header_bytes = sizeof(*ether);

	return parse_layer3_packet_by_proto(packet, ntohs(ether->ether_type),
					    p, packet_end, error);

error_out:
	return PACKET_BAD;
}

static int parse_layer3_packet_by_proto(struct packet *packet,
					u16 proto, u8 *header_start,
					u8 *packet_end, char **error)
{
	u8 *p = header_start;

	if (proto == ETHERTYPE_IP) {
		struct ipv4 *ip = NULL;

		/* Examine IPv4 header. */
		if (p + sizeof(struct ipv4) > packet_end) {
			asprintf(error, "IPv4 header overflows packet");
			goto error_out;
		}

		/* Look at the IP version number, which is in the first 4 bits
		 * of both IPv4 and IPv6 packets.
		 */
		ip = (struct ipv4 *)p;
		if (ip->version == 4) {
			return parse_ipv4(packet, p, packet_end, error);
		} else {
			asprintf(error, "Bad IP version (%d) for ETHERTYPE_IP", ip->version);
			goto error_out;
		}
	} else if (proto == ETHERTYPE_IPV6) {
		struct ipv6 *ip = NULL;

		/* Examine IPv6 header. */
		if (p + sizeof(struct ipv6) > packet_end) {
			asprintf(error, "IPv6 header overflows packet");
			goto error_out;
		}

		/* Look at the IP version number, which is in the first 4 bits
		 * of both IPv4 and IPv6 packets.
		 */
		ip = (struct ipv6 *)p;
		if (ip->version == 6) {
			return parse_ipv6(packet, p, packet_end, error);
		} else {
			asprintf(error, "Bad IP version for ETHERTYPE_IPV6");
			goto error_out;
		}
	} else if ((proto == ETHERTYPE_MPLS_UC) ||
		   (proto == ETHERTYPE_MPLS_MC)) {
		return parse_mpls(packet, p, packet_end, error);
	} else {
		return PACKET_UNKNOWN_L4;
	}

error_out:
	return PACKET_BAD;
}

static int parse_layer3_packet(struct packet *packet,
			       u8 *header_start, u8 *packet_end,
			       char **error)
{
	u8 *p = header_start;
	/* Note that packet_end points to the byte beyond the end of packet. */
	struct ipv4 *ip = NULL;

	/* Examine IPv4/IPv6 header. */
	if (p + sizeof(struct ipv4) > packet_end) {
		asprintf(error, "IP header overflows packet");
		return PACKET_BAD;
	}

	/* Look at the IP version number, which is in the first 4 bits
	 * of both IPv4 and IPv6 packets.
	 */
	ip = (struct ipv4 *) (p);
	if (ip->version == 4)
		return parse_ipv4(packet, p, packet_end, error);
	else if (ip->version == 6)
		return parse_ipv6(packet, p, packet_end, error);

	asprintf(error, "Unsupported IP version");
	return PACKET_BAD;
}

int parse_packet(struct packet *packet, int in_bytes,
			 enum packet_layer_t layer, char **error)
{
	assert(in_bytes <= packet->buffer_bytes);
	char *message = NULL;		/* human-readable error summary */
	char *hex = NULL;		/* hex dump of bad packet */
	enum packet_parse_result_t result = PACKET_BAD;
	u8 *header_start = packet->buffer;
	/* packet_end points to the byte beyond the end of packet. */
	u8 *packet_end = packet->buffer + in_bytes;

	if (layer == PACKET_LAYER_2_ETHERNET)
		result = parse_layer2_packet(packet, header_start, packet_end,
					     error);
	else if (layer == PACKET_LAYER_3_IP)
		result = parse_layer3_packet(packet, header_start, packet_end,
					     error);
	else
		assert(!"bad layer");

	if (result != PACKET_BAD)
		return result;

	/* Error. Add a packet hex dump to the error string we're returning. */
	hex_dump(packet->buffer, in_bytes, &hex);
	message = *error;
	asprintf(error, "%s: packet of %d bytes:\n%s", message, in_bytes, hex);
	free(message);
	free(hex);

	return PACKET_BAD;
}

/* Parse the IPv4 header and the TCP header inside. Return a
 * packet_parse_result_t.
 * Note that packet_end points to the byte beyond the end of packet.
 */
static int parse_ipv4(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error)
{
	struct header *ip_header = NULL;
	u8 *p = header_start;
	const bool is_outer = (packet->ip_bytes == 0);
	enum packet_parse_result_t result = PACKET_BAD;
	struct ipv4 *ipv4 = (struct ipv4 *) (p);

	const int ip_header_bytes = ipv4_header_len(ipv4);
	assert(ip_header_bytes >= 0);
	if (ip_header_bytes < sizeof(*ipv4)) {
		asprintf(error, "IP header too short");
		goto error_out;
	}
	if (p + ip_header_bytes > packet_end) {
		asprintf(error, "Full IP header overflows packet");
		goto error_out;
	}
	const int ip_total_bytes = ntohs(ipv4->tot_len);

	if (p + ip_total_bytes > packet_end) {
		asprintf(error, "IP payload overflows packet");
		goto error_out;
	}
	if (ip_header_bytes > ip_total_bytes) {
		asprintf(error, "IP header bigger than datagram");
		goto error_out;
	}
	if (ntohs(ipv4->frag_off) & IP_MF) {	/* more fragments? */
		asprintf(error, "More fragments remaining");
		goto error_out;
	}
	if (ntohs(ipv4->frag_off) & IP_OFFMASK) {  /* fragment offset */
		asprintf(error, "Non-zero fragment offset");
		goto error_out;
	}
	const u16 checksum = ipv4_checksum(ipv4, ip_header_bytes);
	if (checksum != 0) {
		asprintf(error, "Bad IP checksum");
		goto error_out;
	}

	ip_header = packet_append_header(packet, HEADER_IPV4, ip_header_bytes);
	if (ip_header == NULL) {
		asprintf(error, "Too many nested headers at IPv4 header");
		goto error_out;
	}
	ip_header->total_bytes = ip_total_bytes;

	/* Move on to the header inside. */
	p += ip_header_bytes;
	assert(p <= packet_end);

	if (DEBUG_LOGGING) {
		char src_string[ADDR_STR_LEN];
		char dst_string[ADDR_STR_LEN];
		struct ip_address src_ip, dst_ip;
		ip_from_ipv4(&ipv4->src_ip, &src_ip);
		ip_from_ipv4(&ipv4->dst_ip, &dst_ip);
		DEBUGP("src IP: %s\n", ip_to_string(&src_ip, src_string));
		DEBUGP("dst IP: %s\n", ip_to_string(&dst_ip, dst_string));
	}

	/* Examine the L4 header. */
	const int layer4_bytes = ip_total_bytes - ip_header_bytes;
	const int layer4_protocol = ipv4->protocol;
	result = parse_layer4(packet, p, layer4_protocol, layer4_bytes,
			      packet_end, error);

	/* If this is the innermost L3 header then this is the primary. */
	if (!packet->ipv4 && !packet->ipv6)
		packet->ipv4 = ipv4;
	/* If this is the outermost IP header then this is the packet length. */
	if (is_outer)
		packet->ip_bytes = ip_total_bytes;

	return result;

error_out:
	return PACKET_BAD;
}

/* Parse the IPv6 header and the TCP header inside. We do not
 * currently support parsing IPv6 extension headers or any layer 4
 * protocol other than TCP. Return a packet_parse_result_t.
 * Note that packet_end points to the byte beyond the end of packet.
 */
static int parse_ipv6(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error)
{
	struct header *ip_header = NULL;
	u8 *p = header_start;
	const bool is_outer = (packet->ip_bytes == 0);
	struct ipv6 *ipv6 = (struct ipv6 *) (p);
	enum packet_parse_result_t result = PACKET_BAD;

	/* Check that header fits in sniffed packet. */
	const int ip_header_bytes = sizeof(*ipv6);
	if (p + ip_header_bytes > packet_end) {
		asprintf(error, "IPv6 header overflows packet");
		goto error_out;
	}

	/* Check that payload fits in sniffed packet. */
	const int ip_total_bytes = (ip_header_bytes +
				    ntohs(ipv6->payload_len));

	if (p + ip_total_bytes > packet_end) {
		asprintf(error, "IPv6 payload overflows packet");
		goto error_out;
	}
	assert(ip_header_bytes <= ip_total_bytes);

	ip_header = packet_append_header(packet, HEADER_IPV6, ip_header_bytes);
	if (ip_header == NULL) {
		asprintf(error, "Too many nested headers at IPv6 header");
		goto error_out;
	}
	ip_header->total_bytes = ip_total_bytes;

	/* Move on to the header inside. */
	p += ip_header_bytes;
	assert(p <= packet_end);

	if (DEBUG_LOGGING) {
		char src_string[ADDR_STR_LEN];
		char dst_string[ADDR_STR_LEN];
		struct ip_address src_ip, dst_ip;
		ip_from_ipv6(&ipv6->src_ip, &src_ip);
		ip_from_ipv6(&ipv6->dst_ip, &dst_ip);
		DEBUGP("src IP: %s\n", ip_to_string(&src_ip, src_string));
		DEBUGP("dst IP: %s\n", ip_to_string(&dst_ip, dst_string));
	}

	/* Examine the L4 header. */
	const int layer4_bytes = ip_total_bytes - ip_header_bytes;
	const int layer4_protocol = ipv6->next_header;
	result = parse_layer4(packet, p, layer4_protocol, layer4_bytes,
			      packet_end, error);

	/* If this is the innermost L3 header then this is the primary. */
	if (!packet->ipv4 && !packet->ipv6)
		packet->ipv6 = ipv6;
	/* If this is the outermost IP header then this is the packet length. */
	if (is_outer)
		packet->ip_bytes = ip_total_bytes;

	return result;

error_out:
	return PACKET_BAD;
}

/* Parse the TCP header. Return a packet_parse_result_t. */
static int parse_tcp(struct packet *packet, u8 *layer4_start, int layer4_bytes,
		     u8 *packet_end, char **error)
{
	struct header *tcp_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct tcp)) {
		asprintf(error, "Truncated TCP header");
		goto error_out;
	}
	packet->tcp = (struct tcp *) p;
	const int tcp_header_len = packet_tcp_header_len(packet);
	if (tcp_header_len < sizeof(struct tcp)) {
		asprintf(error, "TCP data offset too small");
		goto error_out;
	}
	if (tcp_header_len > layer4_bytes) {
		asprintf(error, "TCP data offset too big");
		goto error_out;
	}

	tcp_header = packet_append_header(packet, HEADER_TCP, tcp_header_len);
	if (tcp_header == NULL) {
		asprintf(error, "Too many nested headers at TCP header");
		goto error_out;
	}
	tcp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("TCP src port: %d\n", ntohs(packet->tcp->src_port));
	DEBUGP("TCP dst port: %d\n", ntohs(packet->tcp->dst_port));
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the UDP header. Return a packet_parse_result_t. */
static int parse_udp(struct packet *packet, u8 *layer4_start, int layer4_bytes,
		     u8 *packet_end, char **error)
{
	struct header *udp_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct udp)) {
		asprintf(error, "Truncated UDP header");
		goto error_out;
	}
	packet->udp = (struct udp *) p;
	const int udp_len = ntohs(packet->udp->len);
	const int udp_header_len = sizeof(struct udp);
	if (udp_len < udp_header_len) {
		asprintf(error, "UDP datagram length too small for UDP header");
		goto error_out;
	}
	if (udp_len < layer4_bytes) {
		asprintf(error, "UDP datagram length too small");
		goto error_out;
	}
	if (udp_len > layer4_bytes) {
		asprintf(error, "UDP datagram length too big");
		goto error_out;
	}

	udp_header = packet_append_header(packet, HEADER_UDP, udp_header_len);
	if (udp_header == NULL) {
		asprintf(error, "Too many nested headers at UDP header");
		goto error_out;
	}
	udp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("UDP src port: %d\n", ntohs(packet->udp->src_port));
	DEBUGP("UDP dst port: %d\n", ntohs(packet->udp->dst_port));
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the ICMP header. Return a packet_parse_result_t. */
static int parse_icmpv4(struct packet *packet, u8 *layer4_start, int layer4_bytes,
			u8 *packet_end, char **error)
{
	struct header *icmp_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	const int icmpv4_len = sizeof(struct icmpv4);
	if (layer4_bytes < icmpv4_len) {
		asprintf(error, "Truncated ICMPv4 header");
		goto error_out;
	}
	packet->icmpv4 = (struct icmpv4 *) p;
	icmp_header = packet_append_header(packet, HEADER_ICMPV4, icmpv4_len);

	if (icmp_header == NULL) {
		asprintf(error, "Too many nested headers at ICMP header");
		goto error_out;
	}
	icmp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("ICMPv4 type: %d\n", packet->icmpv4->type);
	DEBUGP("ICMPv4 code: %d\n", packet->icmpv4->code);
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

static int parse_icmpv6(struct packet *packet, u8 *layer4_start, int layer4_bytes,
			u8 *packet_end, char **error)
{
	struct header *icmp_header = NULL;
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	const int icmpv6_len = sizeof(struct icmpv6);
	if (layer4_bytes < icmpv6_len) {
		asprintf(error, "Truncated ICMPv6 header");
		goto error_out;
	}
	packet->icmpv6 = (struct icmpv6 *) p;
	icmp_header = packet_append_header(packet, HEADER_ICMPV6, icmpv6_len);

	if (icmp_header == NULL) {
		asprintf(error, "Too many nested headers at ICMP header");
		goto error_out;
	}
	icmp_header->total_bytes = layer4_bytes;

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("ICMPv6 type: %d\n", packet->icmpv6->type);
	DEBUGP("ICMPv6 code: %d\n", packet->icmpv6->code);
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

/* Parse the GRE header. Return a packet_parse_result_t. */
static int parse_gre(struct packet *packet, u8 *layer4_start, int layer4_bytes,
		     u8 *packet_end, char **error)
{
	struct header *gre_header = NULL;
	u8 *p = layer4_start;
	struct gre *gre = (struct gre *) p;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < GRE_MINLEN) {
		asprintf(error, "Truncated GRE header");
		goto error_out;
	}
	if (gre->version != 0) {
		asprintf(error, "GRE header has unsupported version number");
		goto error_out;
	}
	if (gre->has_routing) {
		asprintf(error, "GRE header has unsupported routing info");
		goto error_out;
	}
	const int gre_header_len = gre_len(gre);
	if (gre_header_len < GRE_MINLEN) {
		asprintf(error, "GRE header length too small for GRE header");
		goto error_out;
	}
	if (gre_header_len > layer4_bytes) {
		asprintf(error, "GRE header length too big");
		goto error_out;
	}

	assert(p + layer4_bytes <= packet_end);

	DEBUGP("GRE header len: %d\n", gre_header_len);

	gre_header = packet_append_header(packet, HEADER_GRE, gre_header_len);
	if (gre_header == NULL) {
		asprintf(error, "Too many nested headers at GRE header");
		goto error_out;
	}
	gre_header->total_bytes = layer4_bytes;

	p += gre_header_len;
	assert(p <= packet_end);
	return parse_layer3_packet_by_proto(packet, ntohs(gre->proto),
					    p, packet_end, error);

error_out:
	return PACKET_BAD;
}

int parse_mpls(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error)
{
	struct header *mpls_header = NULL;
	u8 *p = header_start;
	int mpls_header_bytes = 0;
	int mpls_total_bytes = packet_end - p;
	bool is_stack_bottom = false;

	do {
		struct mpls *mpls_entry = (struct mpls *)(p);

		if (p + sizeof(struct mpls) > packet_end) {
			asprintf(error, "MPLS stack entry overflows packet");
			goto error_out;
		}

		is_stack_bottom = mpls_entry_stack(mpls_entry);

		p += sizeof(struct mpls);
		mpls_header_bytes += sizeof(struct mpls);
	} while (!is_stack_bottom && p < packet_end);

	assert(mpls_header_bytes <= mpls_total_bytes);

	mpls_header = packet_append_header(packet, HEADER_MPLS,
					   mpls_header_bytes);
	if (mpls_header == NULL) {
		asprintf(error, "Too many nested headers at MPLS header");
		goto error_out;
	}
	mpls_header->total_bytes = mpls_total_bytes;

	/* Move on to the header inside the MPLS label stack. */
	assert(p <= packet_end);
	return parse_layer3_packet(packet, p, packet_end, error);

error_out:
	return PACKET_BAD;
}

static int parse_layer4(struct packet *packet, u8 *layer4_start,
			int layer4_protocol, int layer4_bytes,
			u8 *packet_end, char **error)
{
	if (layer4_protocol == IPPROTO_TCP) {
		return parse_tcp(packet, layer4_start, layer4_bytes, packet_end,
				 error);
	} else if (layer4_protocol == IPPROTO_UDP) {
		return parse_udp(packet, layer4_start, layer4_bytes, packet_end,
				 error);
	} else if (layer4_protocol == IPPROTO_ICMP) {
		return parse_icmpv4(packet, layer4_start, layer4_bytes, packet_end,
				    error);
	} else if (layer4_protocol == IPPROTO_ICMPV6) {
		return parse_icmpv6(packet, layer4_start, layer4_bytes, packet_end,
				    error);
	} else if (layer4_protocol == IPPROTO_GRE) {
		return parse_gre(packet, layer4_start, layer4_bytes, packet_end,
				 error);
	} else if (layer4_protocol == IPPROTO_IPIP) {
		return parse_ipv4(packet, layer4_start, packet_end, error);
	} else if (layer4_protocol == IPPROTO_IPV6) {
		return parse_ipv6(packet, layer4_start, packet_end, error);
	}
	return PACKET_UNKNOWN_L4;
}
