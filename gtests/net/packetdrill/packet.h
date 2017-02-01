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
 * Interface and type declarations for a representation of TCP/IP packets.
 * Packets are represented in their wire format.
 */

#ifndef __PACKET_H__
#define __PACKET_H__

#include "types.h"

#include <assert.h>
#include <sys/time.h>
#include "gre.h"
#include "header.h"
#include "icmp.h"
#include "icmpv6.h"
#include "ip.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "unaligned.h"

/* The data offset field is 4 bits, and specifies the length of the TCP header,
 * including options, in 32-bit words.
 */
#define MAX_TCP_HEADER_BYTES (15*4)

#define MAX_TCP_DATAGRAM_BYTES (64*1024)	/* for sanity-checking */
#define MAX_UDP_DATAGRAM_BYTES (64*1024)	/* for sanity-checking */

/* We allow reading pretty big packets, since some interface MTUs can
 * be pretty big (the Linux loopback MTU, for example, is typically
 * around 16KB).
 */
static const int PACKET_READ_BYTES = 64 * 1024;

/* Maximum number of headers. */
#define PACKET_MAX_HEADERS	6

/* Maximum number of bytes of headers. */
#define PACKET_MAX_HEADER_BYTES	256

/* TCP/UDP/IPv4 packet, including IPv4 header, TCP/UDP header, and data. There
 * may also be a link layer header between the 'buffer' and 'ip'
 * pointers, but we typically ignore that. The 'buffer_bytes' field
 * gives the total space in the buffer, which may be bigger than the
 * actual amount occupied by the packet data.
 */
struct packet {
	u8 *buffer;		/* data buffer: full contents of packet */
	u32 buffer_bytes;	/* bytes of space in data buffer */
	u32 l2_header_bytes;	/* bytes in outer hardware/layer-2 header */
	u32 ip_bytes;		/* bytes in outermost IP hdrs/payload */
	enum direction_t direction;	/* direction packet is traveling */

	/* Metadata about all the headers in the packet, including all
	 * layers of encapsulation, from outer to inner, starting from
	 * the outermost IP header at headers[0].
	 */
	struct header headers[PACKET_MAX_HEADERS];

	/* The following pointers point into the 'buffer' area. Each
	 * pointer may be NULL if there is no header of that type
	 * present in the packet. In each case these are pointers to
	 * the innermost header of that kind, since that is where most
	 * of the interesting TCP/UDP/IP action is.
	 */

	/* Layer 3 */
	struct ipv4 *ipv4;	/* start of IPv4 header, if present */
	struct ipv6 *ipv6;	/* start of IPv6 header, if present */

	/* Layer 4 */
	struct tcp *tcp;	/* start of TCP header, if present */
	struct udp *udp;	/* start of UDP header, if present */
	struct icmpv4 *icmpv4;	/* start of ICMPv4 header, if present */
	struct icmpv6 *icmpv6;	/* start of ICMPv6 header, if present */

	s64 time_usecs;		/* wall time of receive/send if non-zero */

	u32 flags;		/* various meta-flags */
#define FLAG_WIN_NOCHECK	0x1  /* don't check TCP receive window */
#define FLAG_OPTIONS_NOCHECK	0x2  /* don't check TCP options */

	enum ip_ecn_t ecn;	/* IPv4/IPv6 ECN treatment for packet */

	__be32 *tcp_ts_val;	/* location of TCP timestamp val, or NULL */
	__be32 *tcp_ts_ecr;	/* location of TCP timestamp ecr, or NULL */
	int	mss;
};

/* Allocate and initialize a packet. */
extern struct packet *packet_new(u32 buffer_length);

/* Free all the memory used by the packet. */
extern void packet_free(struct packet *packet);

/* Create a packet that is a copy of the contents of the given packet. */
extern struct packet *packet_copy(struct packet *old_packet);

/* Return the number of headers in the given packet. */
extern int packet_header_count(const struct packet *packet);

/* Return the inner-most header in the given packet. */
static inline struct header *packet_inner_header(struct packet *packet)
{
	int num_headers = packet_header_count(packet);

	assert(num_headers > 0);
	return &packet->headers[num_headers - 1];
}

/* Attempt to append a new header to the given packet. Return a
 * pointer to the new header metadata, or NULL if we can't add the
 * header.
 */
extern struct header *packet_append_header(struct packet *packet,
					   enum header_t header_type,
					   int header_bytes);

/* Return a newly-allocated packet that is a copy of the given inner packet
 * but with the given outer packet prepended.
 */
extern struct packet *packet_encapsulate(struct packet *outer,
					 struct packet *inner);

/* Encapsulate a packet and free the original outer and inner packets. */
static inline struct packet *packet_encapsulate_and_free(struct packet *outer,
							 struct packet *inner)
{
	struct packet *packet = packet_encapsulate(outer, inner);
	packet_free(outer);
	packet_free(inner);
	return packet;
}

/* Return the direction in which the given packet is traveling. */
static inline enum direction_t packet_direction(const struct packet *packet)
{
	return packet->direction;
}

/* Convenience accessors for peeking around in the packet... */

/* Return the address family corresponding to the packet protocol. */
static inline int packet_address_family(const struct packet *packet)
{
	if (packet->ipv4 != NULL)
		return AF_INET;
	if (packet->ipv6 != NULL)
		return AF_INET6;
	return AF_UNSPEC;
}

/* Return a pointer to the first byte of the outermost IP header. */
static inline u8 *packet_start(struct packet *packet)
{
	u8 *start = packet->headers[0].h.ptr;
	assert(start != NULL);
	return start;
}

/* Return a pointer to the first byte of the innermost IP header. */
static inline u8 *ip_start(struct packet *packet)
{
	if (packet->ipv4 != NULL)
		return (u8 *)packet->ipv4;
	if (packet->ipv6 != NULL)
		return (u8 *)packet->ipv6;
	assert(!"bad address family");
	return 0;
}


/* Return the length in bytes of the IP header for packets of the
 * given address family, assuming no IP options.
 */
static inline int ip_header_min_len(int address_family)
{
	if (address_family == AF_INET)
		return sizeof(struct ipv4);
	else if (address_family == AF_INET6)
		return sizeof(struct ipv6);
	else
		assert(!"bad ip_version in config");
}

/* Return the layer4 protocol of the packet. */
static inline int packet_ip_protocol(const struct packet *packet)
{
	if (packet->ipv4 != NULL)
		return packet->ipv4->protocol;
	if (packet->ipv6 != NULL)
		return packet->ipv6->next_header;
	assert(!"no valid IP header");
	return 0;
}

/* Return the length of an optionless TCP or UDP header. */
static inline int layer4_header_len(int protocol)
{
	if (protocol == IPPROTO_TCP)
		return sizeof(struct tcp);
	if (protocol == IPPROTO_UDP)
		return sizeof(struct udp);
	assert(!"bad protocol");
	return 0;
}

/* Return the length of the TCP header, including options. */
static inline int packet_tcp_header_len(const struct packet *packet)
{
	assert(packet->tcp);
	return packet->tcp->doff * sizeof(u32);
}

/* Return the length of the UDP header. */
static inline int packet_udp_header_len(const struct packet *packet)
{
	assert(packet->udp);
	return sizeof(struct udp);
}

/* Return the length of the TCP options. */
static inline int packet_tcp_options_len(const struct packet *packet)
{
	assert(packet->tcp);
	return packet_tcp_header_len(packet) - sizeof(*(packet->tcp));
}

/* Return a pointer to the TCP options. */
static inline u8 *packet_tcp_options(struct packet *packet)
{
	assert(packet->tcp);
	return (u8 *) (packet->tcp + 1);
}

static inline u32 packet_tcp_ts_val(const struct packet *packet)
{
	return get_unaligned_be32(packet->tcp_ts_val);
}

static inline u32 packet_tcp_ts_ecr(const struct packet *packet)
{
	return get_unaligned_be32(packet->tcp_ts_ecr);
}

static inline void packet_set_tcp_ts_val(struct packet *packet, u32 ts_val)
{
	put_unaligned_be32(ts_val, packet->tcp_ts_val);
}

static inline void packet_set_tcp_ts_ecr(struct packet *packet, u32 ts_ecr)
{
	put_unaligned_be32(ts_ecr, packet->tcp_ts_ecr);
}

/* Return a pointer to the TCP/UDP data payload. */
static inline u8 *packet_payload(struct packet *packet)
{
	if (packet->tcp)
		return ((u8 *) packet->tcp) + packet_tcp_header_len(packet);
	if (packet->udp)
		return ((u8 *) packet->udp) + packet_udp_header_len(packet);
	assert(!"no valid payload; not TCP or UDP!?");
	return NULL;
}

/* Return a pointer to the byte beyond the end of the packet. */
static inline u8 *packet_end(struct packet *packet)
{
	return packet_start(packet) + packet->ip_bytes;
}

/* Return the length of the TCP/UDP payload. */
static inline int packet_payload_len(struct packet *packet)
{
	return packet_end(packet) - packet_payload(packet);
}

/* Return the location of the IP header echoed by an ICMP message. */
static inline u8 *packet_echoed_ip_header(struct packet *packet)
{
	if (packet->icmpv4 != NULL)
		return (u8 *)(packet->icmpv4 + 1);
	if (packet->icmpv6 != NULL)
		return (u8 *)(packet->icmpv6 + 1);
	assert(!"no valid icmp header");
	return NULL;
}

/* Return the location of the IPv4 header echoed by an ICMP message, or NULL. */
static inline struct ipv4 *packet_echoed_ipv4_header(struct packet *packet)
{
	return (struct ipv4 *)((packet->icmpv4 != NULL) ?
			       (packet->icmpv4 + 1) : NULL);
}

/* Return the location of the IPv6 header echoed by an ICMP message, or NULL. */
static inline struct ipv6 *packet_echoed_ipv6_header(struct packet *packet)
{
	return (struct ipv6 *)((packet->icmpv6 != NULL) ?
			       (packet->icmpv6 + 1) : NULL);
}

/* Return the length in bytes of the IP header echoed by an ICMP message.
 * For now we do not generate any IP options for echoed IP headers.
 */
static inline int packet_echoed_ip_header_len(struct packet *packet)
{
	if (packet->icmpv4 != NULL)
		return sizeof(struct ipv4);
	if (packet->icmpv6 != NULL)
		return sizeof(struct ipv6);
	assert(!"no valid icmp header");
	return 0;
}

/* Return the layer4 protocol of the packet echoed inside an ICMP packet. */
static inline int packet_echoed_ip_protocol(struct packet *packet)
{
	if (packet->icmpv4 != NULL)
		return packet_echoed_ipv4_header(packet)->protocol;
	if (packet->icmpv6 != NULL)
		return packet_echoed_ipv6_header(packet)->next_header;
	assert(!"no valid icmp header");
	return 0;
}

/* Return the location of the TCP or UDP header echoed by an ICMP message. */
static inline u8 *packet_echoed_layer4_header(struct packet *packet)
{
	u8 *echoed_ip = packet_echoed_ip_header(packet);
	int ip_header_len = packet_echoed_ip_header_len(packet);
	return echoed_ip + ip_header_len;
}

/* Return the location of the TCP header echoed by an ICMP message. */
static inline struct tcp *packet_echoed_tcp_header(struct packet *packet)
{
	if (packet_echoed_ip_protocol(packet) == IPPROTO_TCP)
		return (struct tcp *)(packet_echoed_layer4_header(packet));
	return NULL;
}

/* Return the location of the UDP header echoed by an ICMP message. */
static inline struct udp *packet_echoed_udp_header(struct packet *packet)
{
	if (packet_echoed_ip_protocol(packet) == IPPROTO_UDP)
		return (struct udp *)(packet_echoed_layer4_header(packet));
	return NULL;
}

/* Return the location of the TCP sequence number echoed by an ICMP message. */
static inline u32 *packet_echoed_tcp_seq(struct packet *packet)
{
	struct tcp *echoed_tcp = packet_echoed_tcp_header(packet);
	assert(echoed_tcp);
	u32 *seq = &(echoed_tcp->seq);
	/* Check that the seq field is actually in the space we
	 * reserved for the echoed prefix of the TCP header.
	 */
	assert((char *) (seq + 1) <= (char *) echoed_tcp + ICMP_ECHO_BYTES);
	return seq;
}

#endif /* __PACKET_H__ */
