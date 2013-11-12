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
 * Client-side network device code for remote on-the-wire testing
 * using a real NIC.
 */

#include "wire_client_netdev.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"
#include "net_utils.h"

struct wire_client_netdev {
	struct netdev netdev;		/* "inherit" from netdev */

	char *name;		/* malloc-allocated copy of interface name */
};

struct netdev_ops wire_client_netdev_ops;

/* "Downcast" an abstract netdev to our flavor. */
static inline struct wire_client_netdev *to_client_netdev(
	struct netdev *netdev)
{
	return (struct wire_client_netdev *)netdev;
}

/* Check that the remote IP is actually remote. It must be to ensure
 * that test packets will pass through our device.
 */
static void check_remote_address(struct config *config,
				 struct wire_client_netdev *netdev)
{
	if (is_ip_local(&config->live_remote_ip)) {
		die("error: live_remote_ip %s is not remote\n",
		    config->live_remote_ip_string);
	}
}


/* Route traffic destined for our remote IP through this device */
static void route_traffic_to_wire_server(struct config *config,
					 struct wire_client_netdev *netdev)
{
	char *route_command = NULL;
#ifdef linux
	asprintf(&route_command,
		 "ip %s route del %s > /dev/null 2>&1 ; "
		 "ip %s route add %s dev %s via %s > /dev/null 2>&1",
		 (config->wire_protocol == AF_INET6) ? "-6" : "",
		 config->live_remote_prefix_string,
		 (config->wire_protocol == AF_INET6) ? "-6" : "",
		 config->live_remote_prefix_string,
		 netdev->name,
		 config->live_gateway_ip_string);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	if (config->wire_protocol == AF_INET) {
		asprintf(&route_command,
			 "route delete %s > /dev/null 2>&1 ; "
			 "route add %s %s > /dev/null 2>&1",
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else if (config->wire_protocol == AF_INET6) {
		asprintf(&route_command,
			 "route delete -inet6 %s > /dev/null 2>&1 ; "
			 "route add -inet6 %s %s > /dev/null 2>&1",
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else {
		assert(!"bad wire protocol");
	}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

	/* We intentionally ignore failures and output to stderr,
	 * since they can happen if there is no previously existing
	 * route.
	 */
	system(route_command);

	free(route_command);
}

struct netdev *wire_client_netdev_new(struct config *config)
{
	DEBUGP("wire_client_netdev_new\n");

	struct wire_client_netdev *netdev =
		calloc(1, sizeof(struct wire_client_netdev));

	netdev->netdev.ops = &wire_client_netdev_ops;

	netdev->name = strdup(config->wire_client_device);

	check_remote_address(config, netdev);

	/* Add the client live local IP to our NIC, so we can send/receive */
	net_setup_dev_address(netdev->name,
			      &config->live_local_ip,
			      config->live_prefix_len);

	route_traffic_to_wire_server(config, netdev);

	return (struct netdev *)netdev;
}

static void wire_client_netdev_free(struct netdev *a_netdev)
{
	DEBUGP("wire_client_netdev_free\n");

	struct wire_client_netdev *netdev = to_client_netdev(a_netdev);

	free(netdev->name);

	memset(netdev, 0, sizeof(*netdev));  /* paranoia */
	free(netdev);
}

static int wire_client_netdev_send(struct netdev *a_netdev,
				   struct packet *packet)
{
	DEBUGP("wire_client_netdev_send\n");
	assert(!"wire clients should not be sending packets themselves!");
	/* The server side should be sending the packets... */

	return STATUS_ERR;
}

static int wire_client_netdev_receive(struct netdev *a_netdev,
				      struct packet **packet, char **error)
{
	DEBUGP("wire_client_netdev_receive\n");
	assert(!"wire clients should not be receiving packets themselves!");
	/* The server side should be receiving and checking the packets... */

	return STATUS_ERR;
}

struct netdev_ops wire_client_netdev_ops = {
	.free = wire_client_netdev_free,
	.send = wire_client_netdev_send,
	.receive = wire_client_netdev_receive,
};
