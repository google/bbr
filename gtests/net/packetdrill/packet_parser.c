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
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "checksum.h"
#include "ethernet.h"
#include "ip.h"
#include "ip_address.h"
#include "logging.h"
#include "packet.h"
#include "tcp.h"

static int parse_ipv4(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error);
static int parse_ipv6(struct packet *packet, u8 *header_start, u8 *packet_end,
		      char **error);
static int parse_layer4(struct packet *packet, u8 *header_start,
			int layer4_protocol, int layer4_bytes,
			u8 *packet_end, char **error);

static int parse_layer2_packet(struct packet *packet, int in_bytes,
				       char **error)
{
	u8 *p = packet->buffer;
	/* Note that packet_end points to the byte beyond the end of packet. */
	u8 *packet_end = packet->buffer + in_bytes;
	struct ether_header *ether = NULL;

	/* Find Ethernet header */
	if (p + sizeof(*ether) > packet_end) {
		asprintf(error, "Ethernet header overflows packet");
		goto error_out;
	}
	ether = (struct ether_header *)p;
	p += sizeof(*ether);

	if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
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
			asprintf(error, "Bad IP version for ETHERTYPE_IP");
			goto error_out;
		}
	} else if (ntohs(ether->ether_type) == ETHERTYPE_IPV6) {
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
	} else {
		return PACKET_UNKNOWN_L4;
	}

error_out:
	return PACKET_BAD;
}

static int parse_layer3_packet(struct packet *packet, int in_bytes,
				       char **error)
{
	u8 *p = packet->buffer;
	/* Note that packet_end points to the byte beyond the end of packet. */
	u8 *packet_end = packet->buffer + in_bytes;
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
	enum packet_parse_result_t result;

	if (layer == PACKET_LAYER_2_ETHERNET)
		result = parse_layer2_packet(packet, in_bytes, error);
	else if (layer == PACKET_LAYER_3_IP)
		result = parse_layer3_packet(packet, in_bytes, error);
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
	u8 *p = header_start;

	packet->ipv4 = (struct ipv4 *) (p);

	const int ip_header_bytes = packet_ip_header_len(packet);
	assert(ip_header_bytes >= 0);
	if (ip_header_bytes < sizeof(*packet->ipv4)) {
		asprintf(error, "IP header too short");
		goto error_out;
	}
	if (p + ip_header_bytes > packet_end) {
		asprintf(error, "Full IP header overflows packet");
		goto error_out;
	}
	const int ip_total_bytes = ntohs(packet->ipv4->tot_len);
	packet->ip_bytes = ip_total_bytes;
	if (p + ip_total_bytes > packet_end) {
		asprintf(error, "IP payload overflows packet");
		goto error_out;
	}
	if (ip_header_bytes > ip_total_bytes) {
		asprintf(error, "IP header bigger than datagram");
		goto error_out;
	}
	if (ntohs(packet->ipv4->frag_off) & IP_MF) {	/* more fragments? */
		asprintf(error, "More fragments remaining");
		goto error_out;
	}
	if (ntohs(packet->ipv4->frag_off) & IP_OFFMASK) {  /* fragment offset */
		asprintf(error, "Non-zero fragment offset");
		goto error_out;
	}
	const u16 checksum = ipv4_checksum(packet->ipv4, ip_header_bytes);
	if (checksum != 0) {
		asprintf(error, "Bad IP checksum");
		goto error_out;
	}

	/* Move on to the header inside. */
	p += ip_header_bytes;
	assert(p <= packet_end);

	if (DEBUG_LOGGING) {
		char src_string[ADDR_STR_LEN];
		char dst_string[ADDR_STR_LEN];
		struct ip_address src_ip, dst_ip;
		ip_from_ipv4(&packet->ipv4->src_ip, &src_ip);
		ip_from_ipv4(&packet->ipv4->dst_ip, &dst_ip);
		DEBUGP("src IP: %s\n", ip_to_string(&src_ip, src_string));
		DEBUGP("dst IP: %s\n", ip_to_string(&dst_ip, dst_string));
	}

	/* Examine the L4 header. */
	const int layer4_bytes = ip_total_bytes - ip_header_bytes;
	const int layer4_protocol = packet->ipv4->protocol;
	return parse_layer4(packet, p, layer4_protocol, layer4_bytes,
			    packet_end, error);

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
	u8 *p = header_start;

	packet->ipv6 = (struct ipv6 *) (p);

	/* Check that header fits in sniffed packet. */
	const int ip_header_bytes = packet_ip_header_len(packet);
	assert(ip_header_bytes >= 0);
	assert(ip_header_bytes == sizeof(*packet->ipv6));
	if (p + ip_header_bytes > packet_end) {
		asprintf(error, "IPv6 header overflows packet");
		goto error_out;
	}

	/* Check that payload fits in sniffed packet. */
	const int ip_total_bytes = (ip_header_bytes +
				    ntohs(packet->ipv6->payload_len));
	packet->ip_bytes = ip_total_bytes;
	if (p + ip_total_bytes > packet_end) {
		asprintf(error, "IPv6 payload overflows packet");
		goto error_out;
	}
	assert(ip_header_bytes <= ip_total_bytes);

	/* Move on to the header inside. */
	p += ip_header_bytes;
	assert(p <= packet_end);

	if (DEBUG_LOGGING) {
		char src_string[ADDR_STR_LEN];
		char dst_string[ADDR_STR_LEN];
		struct ip_address src_ip, dst_ip;
		ip_from_ipv6(&packet->ipv6->src_ip, &src_ip);
		ip_from_ipv6(&packet->ipv6->dst_ip, &dst_ip);
		DEBUGP("src IP: %s\n", ip_to_string(&src_ip, src_string));
		DEBUGP("dst IP: %s\n", ip_to_string(&dst_ip, dst_string));
	}

	/* Examine the L4 header. */
	const int layer4_bytes = ip_total_bytes - ip_header_bytes;
	const int layer4_protocol = packet->ipv6->next_header;
	return parse_layer4(packet, p, layer4_protocol, layer4_bytes,
			    packet_end, error);

error_out:
	return PACKET_BAD;
}

/* Parse the TCP header. Return a packet_parse_result_t. */
static int parse_tcp(struct packet *packet, u8 *layer4_start, int layer4_bytes,
		     u8 *packet_end, char **error)
{
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
	u8 *p = layer4_start;

	assert(layer4_bytes >= 0);
	if (layer4_bytes < sizeof(struct udp)) {
		asprintf(error, "Truncated UDP header");
		goto error_out;
	}
	packet->udp = (struct udp *) p;
	const int udp_len = ntohs(packet->udp->len);
	if (udp_len < sizeof(struct udp)) {
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

	p += layer4_bytes;
	assert(p <= packet_end);

	DEBUGP("UDP src port: %d\n", ntohs(packet->udp->src_port));
	DEBUGP("UDP dst port: %d\n", ntohs(packet->udp->dst_port));
	return PACKET_OK;

error_out:
	return PACKET_BAD;
}

static int parse_layer4(struct packet *packet, u8 *layer4_start,
			int layer4_protocol, int layer4_bytes,
			u8 *packet_end, char **error)
{
	if (layer4_protocol == IPPROTO_TCP)
		return parse_tcp(packet, layer4_start, layer4_bytes, packet_end,
				 error);
	else if (layer4_protocol == IPPROTO_UDP)
		return parse_udp(packet, layer4_start, layer4_bytes, packet_end,
				 error);
	return PACKET_UNKNOWN_L4;
}
