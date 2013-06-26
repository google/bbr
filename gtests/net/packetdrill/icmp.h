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
 * Our own ICMPv4 header declarations, so we have something that's
 * portable and somewhat more readable than a typical system header
 * file.
 */

#ifndef __ICMP_HEADERS_H__
#define __ICMP_HEADERS_H__

#include "types.h"

/* Most ICMPv6 message types include a copy of the outbound IP header
 * and the first few bytes inside, to allow the receiver to demux by
 * TCP/UDP port. The following constant specifies the number of bytes
 * of TCP header that we will echo. We echo 8 bytes because that
 * is the minimum number of bytes that the Linux TCP stack needs to
 * read the source and destination TCP port and TCP sequence number,
 * which it needs to properly demux an incoming ICMP packet to a
 * specific TCP connection.
 */
#define ICMP_ECHO_BYTES  8

struct icmpv4 {
	__u8		type;
	__u8		code;
	__sum16		checksum;
	union {
		struct {
			__be16	id;
			__be16	sequence;
		} echo;
		__be32	gateway;
		struct {
			__be16	unused;
			__be16	mtu;
		} frag;				/* PMTU discovery, RFC 1191 */
	} message;
};

/* Our own ICMP definitions, since the names vary between platforms. */

/* ICMPv4 types */
#define ICMP_ECHOREPLY          0
#define ICMP_DEST_UNREACH       3
#define ICMP_SOURCE_QUENCH      4
#define ICMP_REDIRECT           5
#define ICMP_ECHO               8
#define ICMP_TIME_EXCEEDED      11
#define ICMP_PARAMETERPROB      12
#define ICMP_TIMESTAMP          13
#define ICMP_TIMESTAMPREPLY     14
#define ICMP_INFO_REQUEST       15
#define ICMP_INFO_REPLY         16
#define ICMP_ADDRESS            17
#define ICMP_ADDRESSREPLY       18
#define NR_ICMP_TYPES           18

/* Codes for ICMP_DEST_UNREACH */
#define ICMP_NET_UNREACH        0
#define ICMP_HOST_UNREACH       1
#define ICMP_PROT_UNREACH       2
#define ICMP_PORT_UNREACH       3
#define ICMP_FRAG_NEEDED        4
#define ICMP_SR_FAILED          5
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13
#define ICMP_PREC_VIOLATION     14
#define ICMP_PREC_CUTOFF        15
#define NR_ICMP_UNREACH         15

#endif /* __ICMP_HEADERS_H__ */
