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
 * Interface for tracking sockets in the kernel under test.
 */

#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "types.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include "config.h"
#include "fd_state.h"
#include "hash_map.h"
#include "logging.h"
#include "packet.h"

/* All possible states for a socket we're tracking. */
enum socket_state_t {
	SOCKET_INIT,			/* uninitialized */
	SOCKET_NEW,			/* after socket() call */
	SOCKET_PASSIVE_LISTENING,	/* after listen() call */
	SOCKET_PASSIVE_PACKET_RECEIVED,	/* after receiving first packet */
	SOCKET_PASSIVE_SYNACK_SENT,	/* after sending SYNACK */
	SOCKET_PASSIVE_SYNACK_ACKED,	/* after server's SYN is ACKed */
	SOCKET_ACTIVE_CONNECTING,	/* after connect() call */
	SOCKET_ACTIVE_SYN_SENT,		/* after sending client's SYN */
	SOCKET_ACTIVE_SYN_ACKED,	/* after client's SYN is ACKed */
};

/* A TCP/UDP/IP address for an endpoint. */
struct endpoint {
	struct ip_address ip;		/* IP address */
	__be16 port;			/* TCP/UDP port (network order) */
};

/* The 4-tuple for a TCP/UDP/IP packet. */
struct tuple {
	struct endpoint src;
	struct endpoint dst;
};

/* The scripted or live aspects of socket state */
struct socket_state {
	struct endpoint local;		/* local endpoint address */
	u32 local_isn;			/* initial TCP sequence (host order) */
	struct endpoint remote;		/* remote endpoint address */
	u32 remote_isn;			/* initial TCP sequence (host order) */
};

/* Flowlabel mapping between script and live */
struct flowlabel_map {
	u32 flowlabel_script;
	u32 flowlabel_live;
};

/* The runtime state for a socket */
struct socket {
	/* NOTE: struct fd_state must be first field in all fd flavors. */
	struct fd_state fd;		/* info about fd for this socket */

	enum socket_state_t state;	/* current state of socket */
	int address_family;		/* AF_INET or AF_INET6 */
	int type;			/* e.g. SOCK_STREAM, SOCK_DGRAM */
	int protocol;			/* IPPROTO_UDP or IPPROTO_TCP */

	/* The "canned" info from the test script */
	struct socket_state script;

	/* The "live" info at runtime while executing the test */
	struct socket_state live;

	/* We look at outgoing TCP timestamp values and learn the
	 * mapping between script values and live values. We store
	 * this mapping in a hash map mapping outgoing TCP timestamp
	 * values from scripted value to live value. Then we use this
	 * to map incoming TCP timestamp echo replies from their
	 * script value to their live value.
	 */
	struct hash_map *ts_val_map;

	/* Baseline to map TCP timestamp val from live to script space. */
	bool found_first_tcp_ts;
	u32 first_script_ts_val;
	u32 first_actual_ts_val;
	u32 first_script_ts_ecr;
	u32 first_actual_ts_ecr;

	/* We remember the last inbound/outbound TCP header so we can send a
	 * RST packet that the kernel will accept for this socket, in
	 * order to induce the kernel to free the socket.
	 */
	struct tcp last_outbound_tcp_header;
	struct tcp last_injected_tcp_header;
	u32 last_injected_tcp_payload_len;

	/* flowlabel mapping */
	struct flowlabel_map flowlabel_map;
};

/* Convert to socket pointer if the fd is a socket, otherwise return NULL. */
static inline struct socket *fd_to_socket(struct fd_state *fd)
{
	if (fd && fd->ops->type == FD_SOCKET)
		return (struct socket *)fd;
	else
		return NULL;
}

struct state;

/* Allocate and return a new socket object. */
extern struct socket *socket_new(struct state *state);

/* Deallocate a socket. */
extern void socket_free(struct socket *socket);

/* Get the tuple we expect to see in outbound packets from this socket. */
static inline void socket_get_outbound(
	const struct socket_state *socket_state, struct tuple *tuple)
{
	memset(tuple, 0, sizeof(*tuple));
	tuple->src = socket_state->local;
	tuple->dst = socket_state->remote;
}

/* Get the tuple we expect to see in inbound packets from this socket. */
static inline void socket_get_inbound(
	const struct socket_state *socket_state, struct tuple *tuple)
{
	memset(tuple, 0, sizeof(*tuple));
	tuple->src = socket_state->remote;
	tuple->dst = socket_state->local;
}

/* Return true iff the two tuples are equal. */
static inline bool is_equal_tuple(const struct tuple *a,
				  const struct tuple *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/* Fill in the *dst_tuple with the tuple for packet flow in the
 * direction opposite that of *src_tuple
 */
static inline void reverse_tuple(const struct tuple *src_tuple,
				 struct tuple *dst_tuple)
{
	dst_tuple->src.ip	= src_tuple->dst.ip;
	dst_tuple->dst.ip	= src_tuple->src.ip;
	dst_tuple->src.port	= src_tuple->dst.port;
	dst_tuple->dst.port	= src_tuple->src.port;
}

/* Get the tuple for a packet. */
static inline void get_packet_tuple(const struct packet *packet,
				    struct tuple *tuple)
{
	memset(tuple, 0, sizeof(*tuple));
	if (packet->ipv4 != NULL) {
		ip_from_ipv4(&packet->ipv4->src_ip, &tuple->src.ip);
		ip_from_ipv4(&packet->ipv4->dst_ip, &tuple->dst.ip);
	} else if (packet->ipv6 != NULL) {
		ip_from_ipv6(&packet->ipv6->src_ip, &tuple->src.ip);
		ip_from_ipv6(&packet->ipv6->dst_ip, &tuple->dst.ip);
	} else {
		assert(!"bad IP version in packet");
	}
	if (packet->tcp != NULL) {
		tuple->src.port	= packet->tcp->src_port;
		tuple->dst.port	= packet->tcp->dst_port;
	} else if (packet->udp != NULL) {
		tuple->src.port	= packet->udp->src_port;
		tuple->dst.port	= packet->udp->dst_port;
	}
}

/* Set the tuple inside some TCP/IPv4 or TCP/IPv6 headers. */
static inline void set_headers_tuple(struct ipv4 *ipv4,
				     struct ipv6 *ipv6,
				     struct tcp *tcp,
				     struct udp *udp,
				     const struct tuple *tuple)
{
	if (ipv4 != NULL) {
		ip_to_ipv4(&tuple->src.ip, &ipv4->src_ip);
		ip_to_ipv4(&tuple->dst.ip, &ipv4->dst_ip);
	} else if (ipv6 != NULL) {
		ip_to_ipv6(&tuple->src.ip, &ipv6->src_ip);
		ip_to_ipv6(&tuple->dst.ip, &ipv6->dst_ip);
	} else {
		assert(!"bad IP version in packet");
	}
	if (tcp != NULL) {
		tcp->src_port = tuple->src.port;
		tcp->dst_port = tuple->dst.port;
	} else if (udp != NULL) {
		udp->src_port = tuple->src.port;
		udp->dst_port = tuple->dst.port;
	}
}

/* Set the tuple for a packet header echoed inside an ICMPv4/ICMPv6 message. */
static inline void set_icmp_echoed_tuple(struct packet *packet,
					 const struct tuple *tuple)
{
	/* All currently supported ICMP message types include a copy
	 * of the outbound IP header and the first few bytes inside,
	 * which so far always means the first ICMP_ECHO_BYTES of
	 * TCP header.
	 */
	DEBUGP("set_icmp_echoed_tuple");

	/* Flip the direction of the tuple, since the ICMP message is
	 * flowing in the direction opposite that of the echoed TCP/IP
	 * packet, and then fill in the fields of the echoed packet.
	 */
	struct tuple echoed_tuple;
	reverse_tuple(tuple, &echoed_tuple);
	set_headers_tuple(packet_echoed_ipv4_header(packet),
			  packet_echoed_ipv6_header(packet),
			  packet_echoed_tcp_header(packet),
			  packet_echoed_udp_header(packet),
			  &echoed_tuple);
}

/* Set the tuple for a packet. */
static inline void set_packet_tuple(struct packet *packet,
				    const struct tuple *tuple)
{
	set_headers_tuple(packet->ipv4, packet->ipv6, packet->tcp, packet->udp,
			  tuple);
	if ((packet->icmpv4 != NULL) || (packet->icmpv6 != NULL))
		set_icmp_echoed_tuple(packet, tuple);
}


/* Helpers for translating between script and live sequence numbers.
 *
 * We try to interpret sequence numbers in scripts in
 * a manner that is similar to tcpdump output: sequence numbers and
 * ACK numbers in all packets with the SYN flag set are absolute, and
 * for other packets the sequence numbers and ACK numbers are relative
 * to the first SYN.
 *
 * Using this approach has several advantages:
 *
 * o tcpdump output may be more easily converted into packetdrill scripts.
 *
 * o we follow the principle of least surprise: it's basically what
 *   tcpdump does, so users should be more used to that and thus it
 *   should lead to fewer bugs and it should requires less
 *   documentation.
 *
 * o it gives convenience and expressiveness in allowing arbitrary
 *   ISNs without requiring a command line argument, so tests can be
 *   more self-contained..
 *
 * The code below for remote and local cases are different because the
 * packetdrill tool gets to pick the live ISN for remote packets but the
 * local kernel under test always gets to pick its live ISN.
 */

static inline u32 remote_seq_script_to_live_offset(struct socket *socket,
						   bool is_syn)
{
	return is_syn ? 0 : socket->live.remote_isn;
}

static inline u32 remote_seq_live_to_script_offset(struct socket *socket,
						   bool is_syn)
{
	return -remote_seq_script_to_live_offset(socket, is_syn);
}

static inline u32 local_seq_script_to_live_offset(struct socket *socket,
						  bool is_syn)
{
	return is_syn ?
		(socket->live.local_isn - socket->script.local_isn) :
		socket->live.local_isn;
}

static inline u32 local_seq_live_to_script_offset(struct socket *socket,
						  bool is_syn)
{
	return -local_seq_script_to_live_offset(socket, is_syn);
}

#endif /* __SOCKET_H__ */
