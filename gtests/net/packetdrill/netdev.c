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
 * Implementation for a "virtual network device" module to
 * inject packets into the kernel and read packets leaving the kernel.
 */

#include "netdev.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/if_tun.h>
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#include "ip.h"
#include "ipv6.h"
#include "logging.h"
#include "net_utils.h"
#include "packet.h"
#include "packet_parser.h"
#include "packet_socket.h"
#include "tcp.h"
#include "tun.h"

/* Internal private state for the netdev for purely local tests. */
struct local_netdev {
	struct netdev netdev;		/* "inherit" from netdev */

	char *name;		/* malloc-ed copy of interface name (owned) */
	int tun_fd;		/* tun for sending/receiving packets */
	int ipv4_control_fd;	/* fd for IPv4 configuration of tun interface */
	int ipv6_control_fd;	/* fd for IPv6 configuration of tun interface */
	int index;		/* interface index from if_nametoindex */
	struct packet_socket *psock;	/* for sniffing packets (owned) */
};

struct netdev_ops local_netdev_ops;

/* "Downcast" an abstract netdev to our local flavor. */
static inline struct local_netdev *to_local_netdev(struct netdev *netdev)
{
	return (struct local_netdev *)netdev;
}

/* Clean up any old tun device state that might be lying around from
 * previous tests. NetBSD the kernel does not automatically tear down
 * unreferenced tun devices and routes referencing those routes.
 */
static void cleanup_old_device(struct config *config,
				struct local_netdev *netdev)
{
#if defined(__NetBSD__)
	char *cleanup_command = NULL;
	int result;

	asprintf(&cleanup_command,
		 "/sbin/ifconfig %s down delete > /dev/null 2>&1",
		 TUN_DEV);
	DEBUGP("running: '%s'\n", cleanup_command);
	result = system(cleanup_command);
	DEBUGP("result: %d\n", result);
	free(cleanup_command);
#endif  /* defined(__NetBSD__) */
}

/* Check that the remote IP is actually remote. It must be to ensure
 * that test packets will pass into our tun device.
 */
static void check_remote_address(struct config *config,
				 struct local_netdev *netdev)
{
	if (is_ip_local(&config->live_remote_ip)) {
		die("error: live_remote_ip %s is not remote\n",
		    config->live_remote_ip_string);
	}
}

/* Create a tun device for the lifetime of this test. */
static void create_device(struct config *config, struct local_netdev *netdev)
{
	/* Open the tun device, which "clones" it for our purposes. */
	int tun_fd = open(TUN_PATH, O_RDWR);
	if (tun_fd < 0)
		die_perror("open tun device");

	netdev->tun_fd = tun_fd;

#ifdef linux
	/* Create the device. Since we do not specify a device name, the
	 * kernel will try to allocate the "next" device of the specified
	 * type. This device will disappear when we are done.
	 */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
	int status = ioctl(netdev->tun_fd, TUNSETIFF, (void *)&ifr);
	if (status < 0)
		die_perror("TUNSETIFF");

	netdev->name = strdup(ifr.ifr_name);
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	const int mode = IFF_BROADCAST | IFF_MULTICAST;
	if (ioctl(netdev->tun_fd, TUNSIFMODE, &mode, sizeof(mode)) < 0)
		die_perror("TUNSIFMODE");

	netdev->name = strdup(TUN_DEV);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#if defined(__FreeBSD__) ||  defined(__NetBSD__)
	/* On FreeBSD and NetBSD we need to explicitly ask to be able
	 * to prepend the address family when injecting tun packets.
	 * OpenBSD presumes we are doing this, even without the ioctl.
	 */
	const int header = 1;
	if (ioctl(netdev->tun_fd, TUNSIFHEAD, &header, sizeof(header)) < 0)
		die_perror("TUNSIFHEAD");
#endif /* defined(__FreeBSD__) ||  defined(__NetBSD__) */

	DEBUGP("tun name: '%s'\n", netdev->name);

	netdev->index = if_nametoindex(netdev->name);
	if (netdev->index == 0)
		die_perror("if_nametoindex");

	DEBUGP("tun index: '%d'\n", netdev->index);

	if (config->speed != TUN_DRIVER_SPEED_CUR) {
		char *command;
		asprintf(&command, "ethtool -s %s speed %u autoneg off",
			 netdev->name, config->speed);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);

		/* Need to bring interface down and up so the interface speed
		 * will be copied to the link_speed field. This field is
		 * used by TCP's cwnd bound. */
		asprintf(&command, "ifconfig %s down; sleep 1; ifconfig %s up; "
			      "sleep 1", netdev->name, netdev->name);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}

	if (config->mtu != TUN_DRIVER_DEFAULT_MTU) {
		char *command;
		asprintf(&command, "ifconfig %s mtu %d",
			 netdev->name, config->mtu);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}

	/* Open a socket we can use to configure the tun interface.
	 * We only open up an AF_INET6 socket on-demand as needed,
	 * so that we can run IPv4 tests on a machine without IPv6.
	 */
	netdev->ipv4_control_fd = -1;
	netdev->ipv6_control_fd = -1;
	netdev->ipv4_control_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (netdev->ipv4_control_fd < 0)
		die_perror("opening AF_INET, SOCK_DGRAM, IPPROTO_IP socket");
}

/* Set the offload flags to be like a typical ethernet device */
static void set_device_offload_flags(struct local_netdev *netdev)
{
#ifdef linux
	const u32 offload =
	    TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN | TUN_F_UFO;
	if (ioctl(netdev->tun_fd, TUNSETOFFLOAD, offload) != 0)
		die_perror("TUNSETOFFLOAD");
#endif
}

/* Bring up the device */
static void bring_up_device(struct local_netdev *netdev)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, netdev->name, IFNAMSIZ);
	if (ioctl(netdev->ipv4_control_fd, SIOCGIFFLAGS, &ifr) < 0)
		die_perror("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(netdev->ipv4_control_fd, SIOCSIFFLAGS, &ifr) < 0)
		die_perror("SIOCSIFFLAGS");
}

/* Route traffic destined for our remote IP through this device */
static void route_traffic_to_device(struct config *config,
				    struct local_netdev *netdev)
{
	char *route_command = NULL;
#ifdef linux
	asprintf(&route_command,
		 "ip route del %s > /dev/null 2>&1 ; "
		 "ip route add %s dev %s via %s > /dev/null 2>&1",
		 config->live_remote_prefix_string,
		 config->live_remote_prefix_string,
		 netdev->name,
		 config->live_gateway_ip_string);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	if (config->wire_protocol == AF_INET) {
		asprintf(&route_command,
			 "route delete %s > /dev/null 2>&1 ; "
			 "route add %s %s > /dev/null",
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else if (config->wire_protocol == AF_INET6) {
		asprintf(&route_command,
			 "route delete -inet6 %s > /dev/null 2>&1 ; "
#if defined(__FreeBSD__)
			 "route add -inet6 %s -interface tun0 %s > /dev/null",
#elif defined(__OpenBSD__) || defined(__NetBSD__)
			 "route add -inet6 %s %s > /dev/null",
#endif
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else {
		assert(!"bad wire protocol");
	}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */
	int result = system(route_command);
	if ((result == -1) || (WEXITSTATUS(result) != 0)) {
		die("error executing route command '%s'\n",
		    route_command);
	}
	free(route_command);
}

struct netdev *local_netdev_new(struct config *config)
{
	struct local_netdev *netdev = calloc(1, sizeof(struct local_netdev));

	netdev->netdev.ops = &local_netdev_ops;

	cleanup_old_device(config, netdev);

	check_remote_address(config, netdev);
	create_device(config, netdev);
	set_device_offload_flags(netdev);
	bring_up_device(netdev);

	net_setup_dev_address(netdev->name,
			      &config->live_local_ip,
			      config->live_prefix_len);

	route_traffic_to_device(config, netdev);
	netdev->psock = packet_socket_new(netdev->name);

	return (struct netdev *)netdev;
}

static void local_netdev_free(struct netdev *a_netdev)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);

	if (netdev->psock)
		packet_socket_free(netdev->psock);
	if (netdev->tun_fd >= 0)
		close(netdev->tun_fd);
	if (netdev->ipv4_control_fd >= 0)
		close(netdev->ipv4_control_fd);
	if (netdev->ipv6_control_fd >= 0)
		close(netdev->ipv6_control_fd);
	if (netdev->name != NULL)
		free(netdev->name);
	memset(netdev, 0, sizeof(*netdev));  /* paranoia to help catch bugs */
	free(netdev);
}

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
/* According to `man 4 tun` on OpenBSD: "Each packet read or written
 * is prefixed with a tunnel header consisting of a 4-byte network
 * byte order integer containing the address family in the case of
 * layer 3 tunneling." Similarly, on FreeBSD and NetBSD one must use
 * ioctl(TUNSIFHEAD) and prepend an address family, in order to be
 * able to send IPv6 packets (otherwise FreeBSD and NetBSD assume the
 * packets are IPv4).
 */
static void bsd_tun_write(struct local_netdev *netdev,
			  struct packet *packet)
{
	int address_family = htonl(packet_address_family(packet));
	struct iovec vector[2] = {
		{ &address_family, sizeof(address_family) },
		{ packet_start(packet), packet->ip_bytes }
	};

	if (writev(netdev->tun_fd, vector, ARRAY_SIZE(vector)) < 0)
		die_perror("BSD tun write()");
}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#ifdef linux
#include <linux/virtio_net.h>

static void linux_tun_write(struct local_netdev *netdev,
			    struct packet *packet)
{
	struct virtio_net_hdr gso = { 0 };
	struct iovec vector[2] = {
		{ &gso, sizeof(gso) },
		{ packet_start(packet), packet->ip_bytes }
	};

	if (packet->tcp && packet->mss) {
		if (packet->ipv4)
			gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		else
			gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		gso.gso_size = packet->mss;
	}
	if (writev(netdev->tun_fd, vector, ARRAY_SIZE(vector)) < 0)
		die_perror("Linux tun write()");
}
#endif  /* linux */

static int local_netdev_send(struct netdev *a_netdev,
			     struct packet *packet)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);

	assert(packet->ip_bytes > 0);
	/* We do IPv4 and IPv6 */
	assert(packet->ipv4 || packet->ipv6);
	/* We only do TCP and ICMP */
	assert(packet->tcp || packet->udp || packet->icmpv4 || packet->icmpv6);

	DEBUGP("local_netdev_send\n");

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	bsd_tun_write(netdev, packet);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#ifdef linux
	linux_tun_write(netdev, packet);
#endif  /* linux */

	return STATUS_OK;
}

/* Read the given number of packets out of the tun device. We read
 * these packets so that the kernel can exercise its normal code paths
 * for packet transmit completion, since this code path may feed back
 * to TCP behavior; e.g., see the Linux patch "tcp: avoid retransmits
 * of TCP packets hanging in host queues".  We don't need to actually
 * need the packet contents, but on Linux we need to read at least 1
 * byte of packet data to consume the packet.
 * After we added IFF_VNET_HDR attribute to the linux tun device,
 * we expect to receive a virtio_net_hdr at the beginning.
 */
static void local_netdev_read_queue(struct local_netdev *netdev,
				    int num_packets)
{
#ifdef linux
	char buf[sizeof(struct virtio_net_hdr) + 1];
#else
	char buf[1];
#endif
	int i = 0, in_bytes = 0;

	for (i = 0; i < num_packets; ++i) {
		in_bytes = read(netdev->tun_fd, buf, sizeof(buf));
		assert(in_bytes <= (int)sizeof(buf));

		if (in_bytes < 0) {
			if (errno == EINTR)
				continue;
			else
				die_perror("tun read()");
		}
       }
}

static int local_netdev_receive(struct netdev *a_netdev,
				struct packet **packet, char **error)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);
	int status = STATUS_ERR;
	int num_packets = 0;

	DEBUGP("local_netdev_receive\n");

	status = netdev_receive_loop(netdev->psock, PACKET_LAYER_3_IP,
				     DIRECTION_OUTBOUND, packet, &num_packets,
				     error);
	local_netdev_read_queue(netdev, num_packets);
	return status;
}

int netdev_receive_loop(struct packet_socket *psock,
			enum packet_layer_t layer,
			enum direction_t direction,
			struct packet **packet,
			int *num_packets,
			char **error)
{
	assert(*packet == NULL);	/* should be no packet yet */

	*num_packets = 0;
	while (1) {
		int in_bytes = 0;
		enum packet_parse_result_t result;

		*packet = packet_new(PACKET_READ_BYTES);

		/* Sniff the next outbound packet from the kernel under test. */
		if (packet_socket_receive(psock, direction, *packet, &in_bytes))
			continue;

		++*num_packets;
		result = parse_packet(*packet, in_bytes, layer, error);

		if (result == PACKET_OK)
			return STATUS_OK;

		packet_free(*packet);
		*packet = NULL;

		if (result == PACKET_BAD)
			return STATUS_ERR;

		DEBUGP("parse_result:%d; error parsing packet: %s\n",
		       result, *error);
	}

	assert(!"should not be reached");
	return STATUS_ERR;	/* not reached */
}

struct netdev_ops local_netdev_ops = {
	.free = local_netdev_free,
	.send = local_netdev_send,
	.receive = local_netdev_receive,
};
