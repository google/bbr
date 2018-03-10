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
 * Test for generating human-readable representations of IP packets.
 */

#include "packet_to_string.h"

#include <stdlib.h>
#include <string.h>
#include "assert.h"
#include "packet_parser.h"

static void test_tcp_ipv4_packet_to_string(void)
{
	/* An IPv4/GRE/IPv4/TCP packet. */
	u8 data[] = {
		/* IPv4: */
		0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x2f, 0xb5, 0x75, 0x02, 0x02, 0x02, 0x02,
		0x01, 0x01, 0x01, 0x01,
		/* GRE: */
		0x00, 0x00, 0x08, 0x00,
		/* IPv4, TCP: */
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

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre flags 0x0 proto 0x0800: "
		". 1:1(0) ack 2202903899 win 257 "
		"<sack 2202905347:2202906795,TS val 300 ecr 1623332896>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre flags 0x0 proto 0x0800: "
		"192.0.2.1:53055 > 192.168.0.1:8080 "
		". 1:1(0) ack 2202903899 win 257 "
		"<sack 2202905347:2202906795,TS val 300 ecr 1623332896>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 2.2.2.2 > 1.1.1.1: gre flags 0x0 proto 0x0800: "
		"192.0.2.1:53055 > 192.168.0.1:8080 "
		". 1:1(0) ack 2202903899 win 257 "
		"<sack 2202905347:2202906795,TS val 300 ecr 1623332896>"
		"\n"
		"0x0000: 45 00 00 54 00 00 00 00 ff 2f b5 75 02 02 02 02 " "\n"
		"0x0010: 01 01 01 01 00 00 08 00 45 00 00 3c 00 00 00 00 " "\n"
		"0x0020: ff 06 39 11 c0 00 02 01 c0 a8 00 01 cf 3f 1f 90 " "\n"
		"0x0030: 00 00 00 01 83 4d a5 5b a0 10 01 01 db 2d 00 00 " "\n"
		"0x0040: 05 0a 83 4d ab 03 83 4d b0 ab 08 0a 00 00 01 2c " "\n"
		"0x0050: 60 c2 18 20 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_tcp_ipv6_packet_to_string(void)
{
	/* An IPv6/GRE/TCP/IPv6 packet. */
	u8 data[] = {
		/* IPv6: */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x2f, 0xff,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x22,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
		/* GRE: */
		0x00, 0x00, 0x86, 0xdd,
		/* IPv6, TCP: */
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

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre flags 0x0 proto 0x86dd: "
		"S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre flags 0x0 proto 0x86dd: "
		"2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080 "
		"S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	/* Test a DUMP_VERBOSE dump */
	status = packet_to_string(packet, DUMP_VERBOSE, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv6 2::2222 > 1::1111: gre flags 0x0 proto 0x86dd: "
		"2001:db8::1:54242 > fd3d:fa7b:d17d::1:8080 "
		"S 0:0(0) win 32792 <mss 1000,sackOK,nop,nop,nop,wscale 7>\n"
		"0x0000: 60 00 00 00 00 4c 2f ff 00 02 00 00 00 00 00 00 " "\n"
		"0x0010: 00 00 00 00 00 00 22 22 00 01 00 00 00 00 00 00 " "\n"
		"0x0020: 00 00 00 00 00 00 11 11 00 00 86 dd 60 00 00 00 " "\n"
		"0x0030: 00 20 06 ff 20 01 0d b8 00 00 00 00 00 00 00 00 " "\n"
		"0x0040: 00 00 00 01 fd 3d fa 7b d1 7d 00 00 00 00 00 00 " "\n"
		"0x0050: 00 00 00 01 d3 e2 1f 90 00 00 00 00 00 00 00 00 " "\n"
		"0x0060: 80 02 80 18 06 60 00 00 02 04 03 e8 04 02 01 01 " "\n"
		"0x0070: 01 03 03 07 " "\n";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

static void test_gre_mpls_tcp_ipv4_packet_to_string(void)
{
	/* An IPv4/GRE/MPLS/IPv4/TCP packet. */
	u8 data[] = {
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

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_FULL dump */
	status = packet_to_string(packet, DUMP_FULL, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"ipv4 192.168.0.1 > 192.0.2.2: gre flags 0x0 proto 0x8847: "
		"mpls (label 0, tc 0, ttl 0) "
		"(label 1048575, tc 7, [S], ttl 255): "
		"192.168.0.1:8080 > 192.0.2.1:56268 "
		"F. 2072102268:2072102268(0) ack 1 win 453 "
		"<nop,nop,TS val 117573699 ecr 5>";
	assert(strcmp(dump, expected) == 0);
	free(dump);
}

static void test_tcp_md5_option_to_string(void)
{
	/* An IPv4/TCP packet. */
	u8 data[] = {
		/* IPv4, TCP: */
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0x89, 0x56, 0xc0, 0x00, 0x02, 0x01,
		0xc0, 0xa8, 0xaf, 0xbb, 0x8a, 0x6f, 0x1f, 0x90,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0xa0, 0x02, 0x01, 0x00, 0x36, 0x14, 0x00, 0x00,
		0x13, 0x12, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x01, 0x01
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

	int status = 0;
	char *dump = NULL, *expected = NULL;

	/* Test a DUMP_SHORT dump */
	status = packet_to_string(packet, DUMP_SHORT, &dump, &error);
	assert(status == STATUS_OK);
	assert(error == NULL);
	printf("dump = '%s'\n", dump);
	expected =
		"S 1:1(0) win 256 "
		"<md5 000102030405060708090a0b0c0d0e0f,nop,nop>";
	assert(strcmp(dump, expected) == 0);
	free(dump);

	packet_free(packet);
}

int main(void)
{
	test_tcp_ipv4_packet_to_string();
	test_tcp_ipv6_packet_to_string();
	test_gre_mpls_tcp_ipv4_packet_to_string();
	test_tcp_md5_option_to_string();
	return 0;
}
