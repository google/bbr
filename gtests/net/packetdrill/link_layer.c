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
 * Link-layer utilities.
 */

#include "link_layer.h"

#include <stdlib.h>
#include <unistd.h>

#include "logging.h"

#ifdef linux

#include <net/if.h>
#include <sys/ioctl.h>

#include "wrap.h"

void get_hw_address(const char *name, struct ether_addr *hw_address,
			enum ip_version_t ip_version)
{
	u8 *m = NULL;
	struct ifreq ifr;
	int fd;

	DEBUGP("get_hw_address for device %s\n", name);

	fd = wrap_socket(ip_version, SOCK_DGRAM);

	/* Discover the index of the interface. */
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		die_perror("ioctl SIOCGIFINDEX");

	/* Get hardware address for the interface. */
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0)
		die_perror("ioctl SIOCGIFHWADDR");

	m = (u8 *)&ifr.ifr_addr.sa_data;
	DEBUGP("%s HWaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       name, m[0], m[1], m[2], m[3], m[4], m[5]);
	memcpy(hw_address, m, sizeof(*hw_address));

	if (close(fd))
		die_perror("close");
}

#else

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/if_types.h>
#include <net/if_dl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

void get_hw_address(const char *name, struct ether_addr *hw_address)
{
	struct ifaddrs *ifaddrs_list, *ifaddr;

	DEBUGP("get_hw_address for device %s\n", name);

	if (getifaddrs(&ifaddrs_list) < 0)
		die_perror("getifaddrs");

	for (ifaddr = ifaddrs_list; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
		if (strcmp(name, ifaddr->ifa_name) == 0 &&
		    ifaddr->ifa_addr->sa_family == AF_LINK) {
			struct sockaddr_dl *sdl;
			sdl = (struct sockaddr_dl *)ifaddr->ifa_addr;
			if (sdl->sdl_type == IFT_ETHER) {
				memcpy(hw_address, LLADDR(sdl),
				       sizeof(*hw_address));
				freeifaddrs(ifaddrs_list);
				return;
			}
		}
	}

	die("unable to find hw address for %s\n", name);
}

#endif
