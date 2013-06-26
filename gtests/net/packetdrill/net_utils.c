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
 * Implementation for various network utilities.
 */

#include "net_utils.h"

#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>

#include "logging.h"

static void verbose_system(const char *command)
{
	int result;

	DEBUGP("running: '%s'\n", command);
	result = system(command);
	DEBUGP("result: %d\n", result);
	if (result != 0)
		DEBUGP("error executing command '%s'\n", command);
}

/* Configure a local IPv4 address and netmask for the device */
static void net_add_ipv4_address(const char *dev_name,
				 const struct ip_address *ip,
				 int prefix_len)
{
	char *command = NULL;
	char ip_string[ADDR_STR_LEN];

	ip_to_string(ip, ip_string);

#ifdef linux
	asprintf(&command, "ip addr add %s/%d dev %s > /dev/null 2>&1",
		 ip_string, prefix_len, dev_name);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	asprintf(&command, "/sbin/ifconfig %s %s/%d alias",
		 dev_name, ip_string, prefix_len);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

	verbose_system(command);
	free(command);
}

/* Configure a local IPv6 address and prefix length for the device */
static void net_add_ipv6_address(const char *dev_name,
				 const struct ip_address *ip,
				 int prefix_len)
{
	char *command = NULL;
	char ip_string[ADDR_STR_LEN];

	ip_to_string(ip, ip_string);

#ifdef linux

	asprintf(&command, "ip addr add %s/%d dev %s > /dev/null 2>&1",
		 ip_string, prefix_len, dev_name);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)

	asprintf(&command, "/sbin/ifconfig %s inet6 %s/%d",
		 dev_name, ip_string, prefix_len);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

	verbose_system(command);
	free(command);

	/* Wait for IPv6 duplicate address detection to converge,
	 * so that this address no longer shows as "tentative".
	 * e.g. "ip addr show" shows:
	 * inet6 fd3d:fa7b:d17d::36/48 scope global tentative
	 */
#ifdef linux
	if (!strstr(dev_name, "tun"))
		sleep(2);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	sleep(3);
#endif
}

void net_add_dev_address(const char *dev_name,
			 const struct ip_address *ip,
			 int prefix_len)
{
	switch (ip->address_family) {
	case AF_INET:
		net_add_ipv4_address(dev_name, ip, prefix_len);
		break;
	case AF_INET6:
		net_add_ipv6_address(dev_name, ip, prefix_len);
		break;
	default:
		assert(!"bad family");
		break;
	}
}

void net_del_dev_address(const char *dev_name,
			 const struct ip_address *ip,
			 int prefix_len)
{
	char *command = NULL;
	char ip_string[ADDR_STR_LEN];

	ip_to_string(ip, ip_string);

#ifdef linux
	asprintf(&command, "ip addr del %s/%d dev %s > /dev/null 2>&1",
		 ip_string, prefix_len, dev_name);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	asprintf(&command, "/sbin/ifconfig %s %s %s/%d -alias",
		 dev_name,
		 ip->address_family ==  AF_INET6 ? "inet6" : "",
		 ip_string, prefix_len);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

	verbose_system(command);
	free(command);
}

/* In general we want to avoid configuring a new IP address on an
 * interface, because we do not want to pay the latency penaly
 * (e.g. it takes about one second for IPv6 duplicate address
 * detection). So if we find the IP configured the correct local
 * network device, then we're done, and we short-circuit and return
 * immediately. Otherwise remove the address from the current device
 * and add it on the newly-requested device.
 */
void net_setup_dev_address(const char *dev_name,
			   const struct ip_address *ip,
			   int prefix_len)
{
	char cur_dev_name[IFNAMSIZ];

	bool found = get_ip_device(ip, cur_dev_name);

	DEBUGP("net_setup_dev_address: found: %d\n", found);

	if (found && strcmp(cur_dev_name, dev_name) == 0) {
		DEBUGP("net_setup_dev_address: found on correct device\n");
		return;
	}

	if (found)
		net_del_dev_address(cur_dev_name, ip, prefix_len);
	net_add_dev_address(dev_name, ip, prefix_len);
}
