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

#ifndef __SO_TESTING_H__
#define __SO_TESTING_H__

#include "packetdrill.h"

struct config;
struct netdev;
struct script;
struct state;

struct so_instance {
	struct packetdrill_interface ifc;
	void *handle;
};

/* Allocate and return a new netdev for SO testing. */
struct netdev *so_netdev_new(struct config *config);

/* Allocate a new so_instance. */
struct so_instance *so_instance_new(void);

/* Load the shared object and setup callback functions. */
int so_instance_init(struct so_instance *instance,
		     const struct config *config,
		     const struct script *script,
		     const struct state *state);

/* Delete a so_instance and its associated objects. */
void so_instance_free(struct so_instance *instance);

#endif /* __SO_TESTING_H__ */
