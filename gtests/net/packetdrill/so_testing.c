/*
 * Copyright 2015 Google Inc.
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
 * Author: xiaoj@google.com (Xiao Jia)
 *
 * Testing against a shared object (*.so) file.
 */

#include "so_testing.h"

#include <dlfcn.h>

#include "logging.h"
#include "netdev.h"
#include "packetdrill.h"
#include "run.h"

struct so_netdev {
	struct netdev netdev;		/* "inherit" from netdev */
	struct packetdrill_interface *ifc;	/* to be filled in later */
};

/* "Downcast" an abstract netdev to our flavor. */
static inline struct so_netdev *to_so_netdev(struct netdev *netdev)
{
	return (struct so_netdev *)netdev;
}

static void so_netdev_free(struct netdev *a_netdev)
{
	struct so_netdev *netdev = to_so_netdev(a_netdev);

	memset(netdev, 0, sizeof(*netdev));  /* paranoia */
	free(netdev);
}

static int so_netdev_send(struct netdev *a_netdev, struct packet *packet)
{
	struct so_netdev *netdev = to_so_netdev(a_netdev);

	assert(packet->ip_bytes > 0);
	/* We do IPv4 and IPv6 */
	assert(packet->ipv4 || packet->ipv6);
	/* We only do TCP and ICMP */
	assert(packet->tcp || packet->udp || packet->icmpv4 || packet->icmpv6);

	return netdev->ifc->netdev_send(netdev->ifc->userdata,
					packet_start(packet),
					packet->ip_bytes);
}

static int so_netdev_receive(struct netdev *a_netdev, struct packet **packet,
			     char **error)
{
	struct so_netdev *netdev = to_so_netdev(a_netdev);
	enum packet_parse_result_t result;
	enum packet_layer_t layer = PACKET_LAYER_3_IP;
	size_t in_bytes;

	assert(*packet == NULL);	/* should be no packet yet */

	for (;;) {
		*packet = packet_new(PACKET_READ_BYTES);
		in_bytes = (*packet)->buffer_bytes;

		/* Sniff the next outbound packet from the stack under test. */
		if (netdev->ifc->netdev_receive(netdev->ifc->userdata,
						(*packet)->buffer, &in_bytes,
						&((*packet)->time_usecs)))
			goto next;

		result = parse_packet(*packet, in_bytes, layer, error);

		if (result == PACKET_OK)
			return STATUS_OK;

		if (result == PACKET_BAD)
			return STATUS_ERR;

		DEBUGP("parse_result:%d; error parsing packet: %s\n",
		       result, *error);
next:
		packet_free(*packet);
		*packet = NULL;
	}

	assert(!"should not be reached");
	return STATUS_ERR;	/* not reached */
}

static struct netdev_ops so_netdev_ops = {
	.free = so_netdev_free,
	.send = so_netdev_send,
	.receive = so_netdev_receive,
};

struct netdev *so_netdev_new(struct config *config)
{
	struct so_netdev *netdev = calloc(1, sizeof(struct so_netdev));

	netdev->netdev.ops = &so_netdev_ops;
	return (struct netdev *)netdev;
}

struct so_instance *so_instance_new(void)
{
	return calloc(1, sizeof(struct so_instance));
}

int so_instance_init(struct so_instance *instance,
		     const struct config *config,
		     const struct script *script,
		     const struct state *state)
{
	packetdrill_interface_init_t init;
	char *error;

	instance->handle = dlopen(config->so_filename,
				  RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE |
				  RTLD_DEEPBIND);
	if (!instance->handle)
		die("%s\n", dlerror());
	dlerror();  /* clear any existing error */

	init = dlsym(instance->handle, "packetdrill_interface_init");
	error = dlerror();
	if (error)
		die("%s\n", error);

	init(config->so_flags, &instance->ifc);
	to_so_netdev(state->netdev)->ifc = &instance->ifc;
	return STATUS_OK;
}

void so_instance_free(struct so_instance *instance)
{
	if (!instance)
		return;

	instance->ifc.free(instance->ifc.userdata);

	if (instance->handle)
		dlclose(instance->handle);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}
