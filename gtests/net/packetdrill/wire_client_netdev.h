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

#ifndef __WIRE_CLIENT_NETDEV_H__
#define __WIRE_CLIENT_NETDEV_H__

#include "types.h"

#include "config.h"
#include "netdev.h"

/* Allocate and return a new wire client netdev. */
extern struct netdev *wire_client_netdev_new(struct config *config);

#endif /* __WIRE_CLIENT_NETDEV_H__ */
