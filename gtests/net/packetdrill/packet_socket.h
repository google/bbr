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
 * Platform-independent API to read and write raw packets.
 *
 * We allocate and configure things much like tcpdump. We do this so
 * we can get timestamps on the outbound packets the kernel sends, to
 * verify the correct timing (tun devices do not take timestamps).
 */

#ifndef __PACKET_SOCKET_H__
#define __PACKET_SOCKET_H__

#include "types.h"

#include "ethernet.h"
#include "ip_address.h"
#include "packet.h"

struct packet_socket;

/* Allocate and initialize a packet socket. */
extern struct packet_socket *packet_socket_new(const char *device_name);

/* Free all the memory used by the packet socket. */
extern void packet_socket_free(struct packet_socket *packet_socket);

/* Add a filter so we only sniff packets we want. */
extern void packet_socket_set_filter(
	struct packet_socket *psock,
	const struct ether_addr *client_ether_addr,
	const struct ip_address *client_live_ip);

/* Send the given packet using writev. Return STATUS_OK on success,
 * or STATUS_ERR if writev returns an error.
 */
extern int packet_socket_writev(struct packet_socket *psock,
				const struct iovec *iov, int iovcnt);

/* Do a blocking sniff of the next packet going over the given device
 * in the given direction, fill in the given packet with the sniffed
 * packet info, and return the number of bytes in the packet in
 * *in_bytes. If we successfully read a matching packet, return
 * STATUS_OK; else return STATUS_ERR (in which case the caller can
 * retry).
 */
extern int packet_socket_receive(struct packet_socket *psock,
				 enum direction_t direction,
				 struct packet *packet, int *in_bytes);

#endif /* __PACKET_SOCKET_H__ */
