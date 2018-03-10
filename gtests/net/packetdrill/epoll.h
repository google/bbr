/*
 * Copyright 2017 Google Inc.
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
 * Author: weiwan@google.com (Wei Wang)
 *
 * Interface for tracking epolls in the kernel under test.
 */

#ifndef __EPOLL_HDR_H__
#define __EPOLL_HDR_H__

#include "types.h"

#include "fd_state.h"

/* Type specification for epoll_event->data */
enum epoll_data_type_t {
	EPOLL_DATA_PTR = 1,
	EPOLL_DATA_FD,
	EPOLL_DATA_U32,
	EPOLL_DATA_U64,
};

/* The runtime state for epoll */
struct epoll {
	/* NOTE: struct fd_state must be first field in all fd flavors. */
	struct fd_state fd;		/* info about fd for this epoll event */
};

/* Convert to epoll pointer if the fd has type FD_EPOLL,
 * otherwise return NULL.
 */
static inline struct epoll *fd_to_epoll(struct fd_state *fd)
{
	if (fd && fd->ops->type == FD_EPOLL)
		return (struct epoll *)fd;
	else
		return NULL;
}

struct state;

/* Allocate and return a new epoll object. */
extern struct epoll *epoll_new(struct state *state);

#endif /* __EPOLL_HDR_H__ */
