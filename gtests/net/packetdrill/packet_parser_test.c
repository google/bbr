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

#include "packet_parser.h"

#include <assert.h>
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
	assert(packet->ecn		== 0);

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
	assert(packet->ecn		== 0);

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
	assert(packet->ecn		== 0);

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
	assert(packet->ecn		== 0);

	packet_free(packet);
}

int main(void)
{
	test_parse_tcp_ipv4_packet();
	test_parse_tcp_ipv6_packet();
	test_parse_udp_ipv4_packet();
	test_parse_udp_ipv6_packet();
	return 0;
}
