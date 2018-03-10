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

#ifndef __LINK_LAYER_H__
#define __LINK_LAYER_H__

#include "types.h"

#include "ethernet.h"

struct config;

/* Get the link layer address for the device with the given name, or die. */
void get_hw_address(const char *name, struct ether_addr *hw_address,
			enum ip_version_t ip_version);

#endif /* __LINK_LAYER_H__ */
