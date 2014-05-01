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
 * Interface for a "virtual network device" module to inject packets
 * into the kernel and sniff packets leaving the kernel.
 */

#ifndef __PACKET_NETDEV_H__
#define __PACKET_NETDEV_H__

#include "types.h"

#include "config.h"
#include "packet.h"
#include "packet_parser.h"
#include "packet_socket.h"

struct netdev_ops;

/* A C-style poor-man's "pure virtual" netdev. */
struct netdev {
	struct netdev_ops *ops;	/* C-style vtable pointer */
};

struct netdev_ops {
	/* Tear down a netdev and free up the resources it has allocated. */
	void (*free)(struct netdev *netdev);

	/* Inject a raw TCP/IP packet into the kernel. */
	int (*send)(struct netdev *netdev,
		    struct packet *packet);

	/* Sniff the next TCP/IP packet leaving the kernel and return a
	 * pointer to the newly-allocated packet. Caller must free the packet
	 * with packet_free().
	 */
	int (*receive)(struct netdev *netdev,
		       struct packet **packet, char **error);
};


/* Tear down a netdev and free up the resources it has allocated. */
static inline void netdev_free(struct netdev *netdev)
{
	netdev->ops->free(netdev);
}

/* Inject a raw TCP/IP packet into the kernel. */
static inline int netdev_send(struct netdev *netdev,
			      struct packet *packet)
{
	return netdev->ops->send(netdev, packet);
}

/* Sniff the next TCP/IP packet leaving the kernel and return a
 * pointer to the newly-allocated packet. Caller must free the packet
 * with packet_free().
 */
static inline int netdev_receive(struct netdev *netdev,
				 struct packet **packet,
				 char **error)
{
	return netdev->ops->receive(netdev, packet, error);
}


/* Keep sniffing packets leaving the kernel until we see one we know
 * about and can parse. Return a pointer to the newly-allocated
 * packet. Caller must free the packet with packet_free().
 */
extern int netdev_receive_loop(struct packet_socket *psock,
			       enum packet_layer_t layer,
			       enum direction_t direction,
			       struct packet **packet,
			       int *num_packets,
			       char **error);

/* Allocate and return a new netdev for purely local tests. */
extern struct netdev *local_netdev_new(struct config *config);

#endif /* __PACKET_NETDEV_H__ */
