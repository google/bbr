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
 * Test for parsing IP packets.
 */

#include "assert.h"
#include "packet_parser.h"

#include <stdlib.h>
#include <string.h>

static void test_parse_tcp_ipv4_packet(void)
{
	/* A TCP/IPv4 packet. */
	u8 data[] = {
		/* 192.0.2.1:53055 > 192.168.0.1:8080
		 * . 1:1(0) ack 2202903899 win 257
		 * <sack 2202905347:2202906795,TS val 300 ecr 1623332896>
		 */
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0x39, 0x11, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0xcf, 0x3f, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x83, 0x4d, 0xa5, 0x5b,
		0xa0, 0x10, 0x01, 0x01, 0xdb, 0x2d, 0x00, 0x00,
		0x05, 0x0a, 0x83, 0x4d, 0xab, 0x03, 0x83, 0x4d,
		0xb0, 0xab, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x2c,
		0x60, 0xc2, 0x18, 0x20
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	struct ipv4 *expected_ipv4 = (struct ipv4 *)(packet->buffer);
	struct tcp *expected_tcp = (struct tcp *)(expected_ipv4 + 1);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== expected_ipv4);
	assert(packet->ipv6		== NULL);
	assert(packet->tcp		== expected_tcp);
	assert(packet->udp		== NULL);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

static void test_parse_tcp_ipv6_packet(void)
{
	/* A TCP/IPv6 packet. */
	u8 data[] = {
		/* 2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080
		 * S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>
		 */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0xff,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xfd, 0x3d, 0xfa, 0x7b, 0xd1, 0x7d, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xd3, 0xe2, 0x1f, 0x90, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x80, 0x18,
		0x06, 0x60, 0x00, 0x00, 0x02, 0x04, 0x03, 0xe8,
		0x04, 0x02, 0x01, 0x01, 0x01, 0x03, 0x03, 0x07,
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	struct ipv6 *expected_ipv6 = (struct ipv6 *)(packet->buffer);
	struct tcp *expected_tcp = (struct tcp *)(expected_ipv6 + 1);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== NULL);
	assert(packet->ipv6		== expected_ipv6);
	assert(packet->tcp		== expected_tcp);
	assert(packet->udp		== NULL);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

static void test_parse_udp_ipv4_packet(void)
{
	/* A UDP/IPv4 packet. */
	u8 data[] = {
		/* 192.0.2.1.8080 > 192.168.0.1.57845: UDP, length 4 */
		0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x11, 0x39, 0x22, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0x1f, 0x90, 0xe1, 0xf5,
		0x00, 0x0c, 0x7b, 0xa5, 0x00, 0x00, 0x00, 0x00,
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	struct ipv4 *expected_ipv4 = (struct ipv4 *)(packet->buffer);
	struct udp *expected_udp = (struct udp *)(expected_ipv4 + 1);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== expected_ipv4);
	assert(packet->ipv6		== NULL);
	assert(packet->tcp		== NULL);
	assert(packet->udp		== expected_udp);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}


static void test_parse_udp_ipv6_packet(void)
{
	/* A UDP/IPv6 packet. */
	u8 data[] = {
		/* 2001:db8::1.8080 > fd3d:fa7b:d17d::1.51557: UDP, length 4 */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0xff,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xfd, 0x3d, 0xfa, 0x7b, 0xd1, 0x7d, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x1f, 0x90, 0xc9, 0x65, 0x00, 0x0c, 0x1f, 0xee,
		0x00, 0x00, 0x00, 0x00,
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	struct ipv6 *expected_ipv6 = (struct ipv6 *)(packet->buffer);
	struct udp *expected_udp = (struct udp *)(expected_ipv6 + 1);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== NULL);
	assert(packet->ipv6		== expected_ipv6);
	assert(packet->tcp		== NULL);
	assert(packet->udp		== expected_udp);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

static void test_parse_ipv4_gre_ipv4_tcp_packet(void)
{
	u8 *p = NULL;
	int i = 0;

	/* An IPv4/GRE/IPv4/TCP packet. */
	u8 data[] = {
		/* IP 2.2.2.2 > 1.1.1.1: GREv0, length 48:
		   IP 192.0.2.1.47078 > 192.168.0.1.8080:
		   . 2:6(4) ack 1 win 123 */
		0x45, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x2f, 0xb5, 0x85, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0x39, 0x21, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0xb7, 0xe6, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
		0x50, 0x10, 0x00, 0x7b, 0x55, 0x31, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	p = packet->buffer;
	i = 0;			/* outer most layer, 0 */

	assert(packet->headers[i].type	== HEADER_IPV4);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == sizeof(struct ipv4));
	p += packet->headers[i].header_bytes;
	i++;

	assert(packet->headers[i].type	== HEADER_GRE);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == GRE_MINLEN);
	p += packet->headers[i].header_bytes;
	i++;

	struct ipv4 *expected_inner_ipv4 = (struct ipv4 *)p;
	assert(packet->headers[i].type	== HEADER_IPV4);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == sizeof(struct ipv4));
	p += packet->headers[i].header_bytes;
	i++;

	struct tcp *expected_tcp = (struct tcp *)p;
	assert(packet->headers[i].type	== HEADER_TCP);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == sizeof(struct tcp));
	p += packet->headers[i].header_bytes;
	i++;

	assert(packet->headers[i].type	== HEADER_NONE);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== expected_inner_ipv4);
	assert(packet->ipv6		== NULL);
	assert(packet->tcp		== expected_tcp);
	assert(packet->udp		== NULL);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

static void test_parse_ipv4_gre_mpls_ipv4_tcp_packet(void)
{
	u8 *p = NULL;
	int i = 0;

	/* An IPv4/GRE/MPLS/IPv4/TCP packet. */
	u8 data[] = {
		/* ipv4 192.168.0.1 > 192.0.2.2: gre:
		   mpls
		   (label 0, tc 0, ttl 0)
		   (label 1048575, tc 7, [S], ttl 255):
		   192.168.0.1:8080 > 192.0.2.1:56268
		   F. 2072102268:2072102268(0) ack 1 win 453
		   <nop,nop,TS val 117573699 ecr 5>
		*/

		/* IPv4: */
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x2f, 0xb7, 0xcf, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0x00, 0x02, 0x02,
		/* GRE: */
		0x00, 0x00, 0x88, 0x47,
		/* MPLS: */
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
		/* IPv4, TCP: */
		0x45, 0x00, 0x00, 0x34, 0x86, 0x99, 0x40, 0x00,
		0x40, 0x06, 0x31, 0x80, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0x00, 0x02, 0x01, 0x1f, 0x90, 0xdb, 0xcc,
		0x7b, 0x81, 0xc5, 0x7c, 0x00, 0x00, 0x00, 0x01,
		0x80, 0x11, 0x01, 0xc5, 0xa6, 0xa6, 0x00, 0x00,
		0x01, 0x01, 0x08, 0x0a, 0x07, 0x02, 0x08, 0x43,
		0x00, 0x00, 0x00, 0x05
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	p = packet->buffer;
	i = 0;			/* outer most layer, 0 */

	assert(packet->headers[i].type	== HEADER_IPV4);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == sizeof(struct ipv4));
	p += packet->headers[i].header_bytes;
	i++;

	assert(packet->headers[i].type	== HEADER_GRE);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == GRE_MINLEN);
	p += packet->headers[i].header_bytes;
	i++;

	assert(packet->headers[i].type	== HEADER_MPLS);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == 2*sizeof(struct mpls));
	p += packet->headers[i].header_bytes;
	i++;

	struct ipv4 *expected_inner_ipv4 = (struct ipv4 *)p;
	assert(packet->headers[i].type	== HEADER_IPV4);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes == sizeof(struct ipv4));
	p += packet->headers[i].header_bytes;
	i++;

	struct tcp *expected_tcp = (struct tcp *)p;
	assert(packet->headers[i].type	== HEADER_TCP);
	assert(packet->headers[i].h.ptr	== p);
	assert(packet->headers[i].header_bytes ==
	       sizeof(struct tcp) + TCPOLEN_TIMESTAMP + 2);  /* 2 for 2 NOPs */
	p += packet->headers[i].header_bytes;
	i++;

	assert(packet->headers[i].type	== HEADER_NONE);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== expected_inner_ipv4);
	assert(packet->ipv6		== NULL);
	assert(packet->tcp		== expected_tcp);
	assert(packet->udp		== NULL);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

static void test_parse_icmpv4_packet(void)
{
	/* An ICMPv4 packet. */
	u8 data[] = {
		/* 192.168.1.101:0 > 192.168.1.103:0
		 * icmpv4 echo request, id 10960, seq 1, length 8
		 */
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0xb6, 0xc4, 0xc0, 0xa8, 0x01, 0x65,
		0xc0, 0xa8, 0x01, 0x67, 0x08, 0x00, 0xcd, 0x2e,
		0x2a, 0xd0, 0x00, 0x01,
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	struct ipv4 *expected_ipv4 = (struct ipv4 *)(packet->buffer);
	struct icmpv4 *expected_icmpv4 = (struct icmpv4 *)(expected_ipv4 + 1);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== expected_ipv4);
	assert(packet->ipv6		== NULL);
	assert(packet->tcp		== NULL);
	assert(packet->udp		== NULL);
	assert(packet->icmpv4		== expected_icmpv4);
	assert(packet->icmpv6		== NULL);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

static void test_parse_icmpv6_packet(void)
{
	/* An ICMPv6 packet. */
	u8 data[] = {
		/* IP6 fd6b:6bbb:34a1::2 > fd6b:6bbb:34a1::1: ICMP6,
		 *  echo request, seq 1, length 64
		 */
		/* IPv6: */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x40, 0x3a, 0x40,
		0xfd, 0x6b, 0x6b, 0xbb, 0x34, 0xa1, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0xfd, 0x6b, 0x6b, 0xbb, 0x34, 0xa1, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		/* ICMPv6: Echo Request */
		0x80, 0x00, 0xb7, 0x44, 0x74, 0x7f, 0x00, 0x01,
		0x08, 0xb7, 0xc9, 0x52, 0x4d, 0x1f, 0x0e, 0x00,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	};

	struct packet *packet = packet_new(sizeof(data));

	/* Populate and parse a packet */
	memcpy(packet->buffer, data, sizeof(data));
	char *error = NULL;
	enum packet_parse_result_t result =
		parse_packet(packet, sizeof(data), PACKET_LAYER_3_IP,
				     &error);
	assert(result == PACKET_OK);
	assert(error == NULL);

	struct ipv6 *expected_ipv6 = (struct ipv6 *)(packet->buffer);
	struct icmpv6 *expected_icmpv6 = (struct icmpv6 *)(expected_ipv6 + 1);

	assert(packet->ip_bytes		== sizeof(data));
	assert(packet->ipv4		== NULL);
	assert(packet->ipv6		== expected_ipv6);
	assert(packet->tcp		== NULL);
	assert(packet->udp		== NULL);
	assert(packet->icmpv4		== NULL);
	assert(packet->icmpv6		== expected_icmpv6);

	assert(packet->time_usecs	== 0);
	assert(packet->flags		== 0);

	packet_free(packet);
}

int main(void)
{
	test_parse_tcp_ipv4_packet();
	test_parse_tcp_ipv6_packet();
	test_parse_udp_ipv4_packet();
	test_parse_udp_ipv6_packet();
	test_parse_ipv4_gre_ipv4_tcp_packet();
	test_parse_ipv4_gre_mpls_ipv4_tcp_packet();
	test_parse_icmpv4_packet();
	test_parse_icmpv6_packet();

	return 0;
}
