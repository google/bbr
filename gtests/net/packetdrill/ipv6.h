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
 * Our own IPv6 header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __IPV6_HEADERS_H__
#define __IPV6_HEADERS_H__

#include "types.h"

#include <netinet/in.h>

struct ipv6 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	__u8			traffic_class_hi:4,
				version:4;
	__u8			flow_label_hi:4,
				traffic_class_lo:4;
	__u16			flow_label_lo;
#elif __BYTE_ORDER == __BIG_ENDIAN
	__u8			version:4,
				traffic_class_hi:4;
	__u8			traffic_class_lo:4,
				flow_label_hi:4;
	__u16			flow_label_lo;
#else
# error "Please fix endianness defines"
#endif

	__be16			payload_len;
	__u8			next_header;
	__u8			hop_limit;

	struct	in6_addr	src_ip;
	struct	in6_addr	dst_ip;
};

#ifdef linux
#define IPV6_HOPLIMIT   52
#define IPV6_TCLASS	67
#endif  /* linux */

static inline u8 ipv6_tos_byte(const struct ipv6 *ipv6)
{
	return (ipv6->traffic_class_hi << 4) | ipv6->traffic_class_lo;
}

static inline u32 ipv6_flow_label(const struct ipv6 *ipv6)
{
	return (ntohs(ipv6->flow_label_lo)) | (ipv6->flow_label_hi << 16);
}

static inline u8 ipv6_hoplimit_byte(const struct ipv6 *ipv6)
{
	return ipv6->hop_limit;
}

/* The following struct declaration is needed for the IPv6 ioctls
 * SIOCSIFADDR and SIOCDIFADDR that add and delete IPv6 addresses from
 * a network interface. We have to declare our own version here
 * because this struct is only available in /usr/include/linux/ipv6.h,
 * but that .h file has kernel IPv6 declarations that conflict with
 * standard user-space IPv6 declarations.
 */
struct in6_ifreq {
	struct in6_addr	ifr6_addr;
	__u32		ifr6_prefixlen;
	int		ifr6_ifindex;
};

#endif /* __IPV6_HEADERS_H__ */
