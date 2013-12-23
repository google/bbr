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
 * Unit test for checksum.c.
 */

#include "checksum.h"

#include <arpa/inet.h>
#include <assert.h>
#include "ip.h"
#include "ipv6.h"
#include "sctp.h"
#include "tcp.h"

static void test_tcp_udp_v4_checksum(void)
{
	u8 data[] = {
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0xf9, 0x10, 0x01, 0x01, 0x01, 0x01,
		0xc0, 0xa8, 0x00, 0x01, 0x04, 0xd2, 0xeb, 0x35,
		0x00, 0x00, 0x00, 0x00, 0xc6, 0xf0, 0x56, 0x00,
		0xa0, 0x12, 0x16, 0xa0, 0x54, 0x12, 0x00, 0x00,
		0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
		0x00, 0x00, 0x02, 0xbc, 0x00, 0x06, 0x0a, 0xd8,
		0x01, 0x03, 0x03, 0x07,
	};

	struct in_addr src_ip, dst_ip;
	struct tcp *tcp = (struct tcp *) (data + sizeof(struct ipv4));
	int len = sizeof(data) - sizeof(struct ipv4);
	u16 checksum = 0;

	assert(inet_pton(AF_INET, "1.1.1.1", &src_ip) == 1);
	assert(inet_pton(AF_INET, "192.168.0.1", &dst_ip) == 1);

	checksum =
	    ntohs(tcp_udp_v4_checksum(src_ip, dst_ip, IPPROTO_TCP, tcp, len));
	assert(checksum == 0);

	tcp->check = 0;
	checksum =
	    ntohs(tcp_udp_v4_checksum(src_ip, dst_ip, IPPROTO_TCP, tcp, len));
	assert(checksum == 0x5412);
}

static void test_tcp_udp_v6_checksum(void)
{
	u8 data[] = {
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

	struct ipv6 *ipv6 = (struct ipv6 *) (data);
	struct tcp *tcp = (struct tcp *) (data + sizeof(struct ipv6));
	int len = sizeof(data) - sizeof(struct ipv6);
	u16 checksum = 0;

	checksum =
	    ntohs(tcp_udp_v6_checksum(&ipv6->src_ip,
				      &ipv6->dst_ip,
				      IPPROTO_TCP, tcp, len));
	assert(checksum == 0);

	tcp->check = 0;
	checksum =
	    ntohs(tcp_udp_v6_checksum(&ipv6->src_ip,
				      &ipv6->dst_ip,
				      IPPROTO_TCP, tcp, len));
	assert(checksum == 0x0660);
}

static void test_ipv4_checksum(void)
{
	u8 data[] = {
		0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x06, 0xf9, 0x10, 0x01, 0x01, 0x01, 0x01,
		0xc0, 0xa8, 0x00, 0x01,
	};
	struct ipv4 *ip = (struct ipv4 *) data;
	u16 checksum = 0;

	checksum = ntohs(ipv4_checksum(data, sizeof(data)));
	assert(checksum == 0);

	ip->check = 0;
	checksum = ntohs(ipv4_checksum(data, sizeof(data)));
	assert(checksum == 0xf910);
}

static void test_sctp_crc32c(void)
{
	u8 data[] = {
		0x07, 0xd0, 0xd6, 0x61, 0x11, 0x0c, 0xc5, 0x6c,
		0xda, 0xd7, 0x37, 0x74, 0x06, 0x00, 0x00, 0x0f,
		0x00, 0x0c, 0x00, 0x0b, 0x47, 0x6f, 0x6f, 0x64,
		0x62, 0x79, 0x65, 0x00,
	};
	struct sctp_common_header *sctp_common_header;
	u32 crc32c;

	sctp_common_header = (struct sctp_common_header *)data;
	sctp_common_header->crc32c = 0;
	crc32c = ntohl(sctp_crc32c(data, sizeof(data)));
	assert(crc32c == 0xdad73774);
}

int main(void)
{
	test_tcp_udp_v4_checksum();
	test_tcp_udp_v6_checksum();
	test_ipv4_checksum();
	test_sctp_crc32c();
	return 0;
}
