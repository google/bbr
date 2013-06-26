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
 * Helpers to calculate IP, TCP, and UDP checksums.
 */

#include "checksum.h"

#include <assert.h>

/* Add bytes in buffer to a running checksum. Returns the new
 * intermediate checksum. Use ip_checksum_fold() to convert the
 * intermediate checksum to final form.
 */
static u64 ip_checksum_partial(const void *p, size_t len, u64 sum)
{
	/* Main loop: 32 bits at a time.
	 * We take advantage of intel's ability to do unaligned memory
	 * accesses with minimal additional cost. Other architectures
	 * probably want to be more careful here.
	 */
	const u32 *p32 = (const u32 *)(p);
	for (; len >= sizeof(*p32); len -= sizeof(*p32))
		sum += *p32++;

	/* Handle un-32bit-aligned trailing bytes */
	const u16 *p16 = (const u16 *)(p32);
	if (len >= 2) {
		sum += *p16++;
		len -= sizeof(*p16);
	}
	if (len > 0) {
		const u8 *p8 = (const u8 *)(p16);
		sum += ntohs(*p8 << 8);	/* RFC says pad last byte */
	}

	return sum;
}

static __be16 ip_checksum_fold(u64 sum)
{
	while (sum & ~0xffffffffULL)
		sum = (sum >> 32) + (sum & 0xffffffffULL);
	while (sum & 0xffff0000ULL)
		sum = (sum >> 16) + (sum & 0xffffULL);

	return ~sum;
}

static u64 tcp_udp_v4_header_checksum_partial(
	struct in_addr src_ip, struct in_addr dst_ip, u8 protocol, u16 len)
{
	/* The IPv4 pseudo-header is defined in RFC 793, Section 3.1. */
	struct ipv4_pseudo_header_t {
		/* We use a union here to avoid aliasing issues with gcc -O2 */
		union {
			struct header {
				struct in_addr src_ip;
				struct in_addr dst_ip;
				__u8 mbz;
				__u8 protocol;
				__be16 length;
			} __packed fields;
			u32 words[3];
		};
	};
	struct ipv4_pseudo_header_t pseudo_header;
	assert(sizeof(pseudo_header) == 12);

	/* Fill in the pseudo-header. */
	pseudo_header.fields.src_ip = src_ip;
	pseudo_header.fields.dst_ip = dst_ip;
	pseudo_header.fields.mbz = 0;
	pseudo_header.fields.protocol = protocol;
	pseudo_header.fields.length = htons(len);
	return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}

__be16 tcp_udp_v4_checksum(struct in_addr src_ip, struct in_addr dst_ip,
			   u8 protocol, const void *payload, u16 len)
{
	u64 sum = tcp_udp_v4_header_checksum_partial(
		src_ip, dst_ip, protocol, len);
	sum = ip_checksum_partial(payload, len, sum);
	return ip_checksum_fold(sum);
}

/* Calculates and returns IPv4 header checksum. */
__be16 ipv4_checksum(void *ip_header, size_t ip_header_bytes)
{
	return ip_checksum_fold(
		ip_checksum_partial(ip_header, ip_header_bytes, 0));
}

static u64 tcp_udp_v6_header_checksum_partial(
	const struct in6_addr *src_ip,
	const struct in6_addr *dst_ip,
	u8 protocol, u32 len)
{
	/* The IPv6 pseudo-header is defined in RFC 2460, Section 8.1. */
	struct ipv6_pseudo_header_t {
		/* We use a union here to avoid aliasing issues with gcc -O2 */
		union {
			struct header {
				struct in6_addr src_ip;
				struct in6_addr dst_ip;
				__be32 length;
				__u8 mbz[3];
				__u8 next_header;
			} __packed fields;
			u32 words[10];
		};
	};
	struct ipv6_pseudo_header_t pseudo_header;
	assert(sizeof(pseudo_header) == 40);

	/* Fill in the pseudo-header. */
	pseudo_header.fields.src_ip = *src_ip;
	pseudo_header.fields.dst_ip = *dst_ip;
	pseudo_header.fields.length = htonl(len);
	memset(pseudo_header.fields.mbz, 0, sizeof(pseudo_header.fields.mbz));
	pseudo_header.fields.next_header = protocol;
	return ip_checksum_partial(&pseudo_header, sizeof(pseudo_header), 0);
}

__be16 tcp_udp_v6_checksum(const struct in6_addr *src_ip,
			   const struct in6_addr *dst_ip,
			   u8 protocol, const void *payload, u32 len)
{
	u64 sum = tcp_udp_v6_header_checksum_partial(
		src_ip, dst_ip, protocol, len);
	sum = ip_checksum_partial(payload, len, sum);
	return ip_checksum_fold(sum);
}
