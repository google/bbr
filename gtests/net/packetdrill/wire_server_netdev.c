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
 * Server-side network device code for remote on-the-wire testing
 * using a real NIC.
 */

#include "wire_server_netdev.h"

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "logging.h"
#include "net_utils.h"
#include "packet.h"
#include "packet_socket.h"
#include "packet_parser.h"

struct wire_server_netdev {
	struct netdev netdev;		/* "inherit" from netdev */

	char *name;			/* copy of the interface name (owned) */
	struct config *config;		/* this test's config (not owned) */

	struct ether_addr client_ether_addr;
	struct ether_addr server_ether_addr;

	struct packet_socket *psock;	/* for sniffing packets (owned) */
};

struct netdev_ops wire_server_netdev_ops;

/* "Downcast" an abstract netdev to our flavor. */
static inline struct wire_server_netdev *to_server_netdev(
	struct netdev *netdev)
{
	return (struct wire_server_netdev *)netdev;
}

void wire_server_netdev_init(const char *netdev_name)
{
#ifdef linux
	char *command = NULL;

	/* If Large Receive Offload (LRO) or Generic Receive Offload
	 * (GRO) is enabled, then disable them both, so that we are
	 * sniffing packets as seen on the wire, not packets
	 * aggregated by LRO or GRO.
	 *
	 * TOOD(ncardwell): if netdev_name is not a bonding interface,
	 * then we should just disable LRO/GRO on that interface; if
	 * netdev_name is a bonding interface then we should
	 * programmatically figure out all the physical interfaces for
	 * the given netdev_name, instead of using this overly broad
	 * approach.
	 */
	asprintf(&command,
		 "(ethtool --offload eth0 lro off gro off; "
		 " ethtool --offload eth1 lro off gro off; "
		 " ethtool --offload eth2 lro off gro off) "
		 " > /dev/null 2>&1");
	/* For now, intentionally ignoring errors rather than figuring
	 * out how many Ethernet interfaces there are. TODO: clean up.
	 */
	system(command);
	free(command);

	/* Block outgoing IPv6 "destination unreachable" messages, to
	 * block the "destination unreachable, unreachable route"
	 * messages we would otherwise send the kernel under test.
	 * That would cause the kernel under test to delete the TCP
	 * socket under test and send a RST.
	 */
	asprintf(&command,
		 "ip6tables -F OUTPUT; "
		 "ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 1 -j DROP");
	/* For now, intentionally ignoring. TODO: clean up. */
	system(command);
	free(command);
#endif
}

struct netdev *wire_server_netdev_new(
	struct config *config,
	const char *wire_server_device,
	const struct ether_addr *client_ether_addr,
	const struct ether_addr *server_ether_addr)
{
	DEBUGP("wire_server_netdev_new\n");

	struct wire_server_netdev *netdev =
		calloc(1, sizeof(struct wire_server_netdev));

	netdev->netdev.ops = &wire_server_netdev_ops;
	netdev->name = strdup(wire_server_device);
	netdev->config = config;
	ether_copy(&netdev->client_ether_addr, client_ether_addr);
	ether_copy(&netdev->server_ether_addr, server_ether_addr);

	/* Add the gateway IP to our NIC, so it answers ARP or
	 * neighbor discovery requests, so we can receive packets from
	 * the client. TODO(ncardwell): support multiple concurrent
	 * tests, by perhaps ref-counting the gateway IPs we need to
	 * be using. TODO(ncardwell): make sure we don't delete our
	 * primary host IP (the one matching our hostname).
	 */
	net_setup_dev_address(netdev->name,
			      &config->live_gateway_ip,
			      config->live_prefix_len);

	netdev->psock = packet_socket_new(netdev->name);

	/* Make sure we only see packets from the machine under test. */
	packet_socket_set_filter(netdev->psock,
				 client_ether_addr,
				 &config->live_local_ip);  /* client IP */

	return (struct netdev *)netdev;
}

static void wire_server_netdev_free(struct netdev *a_netdev)
{
	struct wire_server_netdev *netdev = to_server_netdev(a_netdev);

	DEBUGP("wire_server_netdev_free\n");

	net_del_dev_address(netdev->name,
			    &netdev->config->live_gateway_ip,
			    netdev->config->live_prefix_len);

	free(netdev->name);
	if (netdev->psock)
		packet_socket_free(netdev->psock);

	memset(netdev, 0, sizeof(*netdev));  /* paranoia */
	free(netdev);
}

static int wire_server_netdev_send(struct netdev *a_netdev,
				   struct packet *packet)
{
	struct wire_server_netdev *netdev = to_server_netdev(a_netdev);
	struct ether_header ether;
	struct iovec ether_frame[2];
	int address_family = packet_address_family(packet);
	int result = STATUS_ERR;

	DEBUGP("wire_server_netdev_send\n");

	/* Prepend an ethernet header. */
	ether_copy(ether.ether_dhost, &netdev->client_ether_addr);
	ether_copy(ether.ether_shost, &netdev->server_ether_addr);
	ether.ether_type = htons(ether_type_for_family(address_family));
	ether_frame[0].iov_base	= &ether;
	ether_frame[0].iov_len	= sizeof(ether);

	/* Then after that we have the IP datagram. */
	ether_frame[1].iov_base	= packet_start(packet);
	ether_frame[1].iov_len	= packet->ip_bytes;

	result = packet_socket_writev(netdev->psock,
				      ether_frame, ARRAY_SIZE(ether_frame));

	return result;
}

static int wire_server_netdev_receive(struct netdev *a_netdev,
				      struct packet **packet, char **error)
{
	struct wire_server_netdev *netdev = to_server_netdev(a_netdev);
	int num_packets = 0;

	DEBUGP("wire_server_netdev_receive\n");

	return netdev_receive_loop(netdev->psock, PACKET_LAYER_2_ETHERNET,
				   DIRECTION_INBOUND, packet, &num_packets,
				   error);
}

struct netdev_ops wire_server_netdev_ops = {
	.free = wire_server_netdev_free,
	.send = wire_server_netdev_send,
	.receive = wire_server_netdev_receive,
};
