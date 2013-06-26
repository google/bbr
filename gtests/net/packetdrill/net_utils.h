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
 * Interface for various network utilities related to configuring IP
 * addresses for network devices.
 */

#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__

#include "types.h"

#include "ip_address.h"

/* Add the given IP address, with the given subnet/prefix length,
 * to the given device.
 */
extern void net_add_dev_address(const char *dev_name,
				const struct ip_address *ip,
				int prefix_len);

/* Delete the given IP address, with the given subnet/prefix length,
 * from the given device.
 */
extern void net_del_dev_address(const char *dev_name,
				const struct ip_address *ip,
				int prefix_len);

/* See if the given IP address, with the given subnet/prefix length,
 * is already on the given device. If so, return without doing
 * anything.  If not, delete it from any device it's currently on, and
 * add it to the given network device.
 */
extern void net_setup_dev_address(const char *dev_name,
				  const struct ip_address *ip,
				  int prefix_len);

#endif /* __NET_UTILS_H__ */
