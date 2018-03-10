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
 * Our own IPv4 header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __IP_HEADERS_H__
#define __IP_HEADERS_H__

#include "types.h"

struct ipv4 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	__u8	ihl:4,
		version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	__u8	version:4,
		ihl:4;
#else
# error "Please fix endianness defines"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	struct in_addr	src_ip;
	struct in_addr	dst_ip;
};

/* ----------------------- IP socket option values -------------------- */

/* Oddly enough, Linux distributions are typically missing even some
 * of the older and more common IP socket options, such as IP_MTU.
 */
#ifdef linux
#define IP_TOS		1
#define IP_TTL		2
#define IP_HDRINCL	3
#define IP_OPTIONS	4
#define IP_ROUTER_ALERT	5
#define IP_RECVOPTS	6
#define IP_RETOPTS	7
#define IP_PKTINFO	8
#define IP_PKTOPTIONS	9
#define IP_MTU_DISCOVER	10
#define IP_RECVERR	11
#define IP_RECVTTL	12
#define IP_RECVTOS	13
#define IP_MTU		14
#define IP_FREEBIND	15
#define IP_IPSEC_POLICY	16
#define IP_XFRM_POLICY	17
#define IP_PASSSEC	18
#define IP_TRANSPARENT	19
#endif  /* linux */

/* ECN: RFC 3168: http://tools.ietf.org/html/rfc3168 */
#define IP_ECN_MASK 3
#define IP_ECN_NONE 0
#define IP_ECN_ECT1 1
#define IP_ECN_ECT0 2
#define IP_ECN_CE   3

static inline u8 ipv4_tos_byte(const struct ipv4 *ipv4)
{
	return ipv4->tos;
}

static inline u8 ipv4_ttl_byte(const struct ipv4 *ipv4)
{
	return ipv4->ttl;
}

static inline int ipv4_header_len(const struct ipv4 *ipv4)
{
	return ipv4->ihl * sizeof(u32);
}

/* IP fragmentation bit flags */
#define IP_RF		0x8000	/* reserved fragment flag */
#define IP_DF		0x4000	/* don't fragment flag */
#define IP_MF		0x2000	/* more fragments flag */
#define IP_OFFMASK	0x1FFF	/* mask for fragmenting bits */

#endif /* __IP_HEADERS_H__ */
