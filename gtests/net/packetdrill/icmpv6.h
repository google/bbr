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
 * Our own ICMPv6 header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __ICMPV6_HEADERS_H__
#define __ICMPV6_HEADERS_H__

#include "types.h"

/* ICMPv6 hader. See RFC 4443. */
struct icmpv6 {
	__u8		type;
	__u8		code;
	__sum16		checksum;
	union {
		struct {
			__be32	unused;
		} unreachable;
		struct {
			__be32	mtu;
		} packet_too_big;
		struct {
			__be32	unused;
		} time_exceeded;
		struct {
			__be32	pointer;
		} parameter_problem;
		struct icmpv6_echo {
			__be16	identifier;
			__be16	sequence;
		} u_echo;
	} message;
};

/* Supported ICMPv6 types */
#define ICMPV6_DEST_UNREACH		1
#define ICMPV6_PKT_TOOBIG		2
#define ICMPV6_TIME_EXCEED		3
#define ICMPV6_PARAMPROB		4
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129

/* Codes for ICMPV6 Destination Unreachable */
#define ICMPV6_NOROUTE			0
#define ICMPV6_ADM_PROHIBITED		1
#define ICMPV6_NOT_NEIGHBOUR		2
#define ICMPV6_ADDR_UNREACH		3
#define ICMPV6_PORT_UNREACH		4

/* Codes for ICMPV6 Time Exceeded */
#define ICMPV6_EXC_HOPLIMIT		0
#define ICMPV6_EXC_FRAGTIME		1

/* Codes for ICMPV6 Parameter Problem */
#define ICMPV6_HDR_FIELD		0
#define ICMPV6_UNK_NEXTHDR		1
#define ICMPV6_UNK_OPTION		2

#endif /* __ICMPV6_HEADERS_H__ */
