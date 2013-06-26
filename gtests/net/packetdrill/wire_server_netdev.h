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

#ifndef __WIRE_SERVER_NETDEV_H__
#define __WIRE_SERVER_NETDEV_H__

#include "types.h"

#include "config.h"
#include "ethernet.h"
#include "netdev.h"

struct wire_server_netdev;

/* Do any one-time start-up initialization a wire server netdev needs. */
extern void wire_server_netdev_init(const char *netdev_name);

/* Allocate and return a new wire server netdev. */
extern struct netdev *wire_server_netdev_new(
	struct config *config,
	const char *wire_server_device,
	const struct ether_addr *client_ether_addr,
	const struct ether_addr *server_ether_addr);

#endif /* __WIRE_SERVER_NETDEV_H__ */
