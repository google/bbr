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
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Interface for tracking file descriptors in the kernel under test.
 */

#ifndef __FD_STATE_H__
#define __FD_STATE_H__

#include "types.h"

/* The types of file descriptor objects packetdrill can test. */
enum fd_type_t {
	FD_SOCKET = 1,
	FD_FILE,
	FD_PIPE,
	FD_EPOLL,
};

struct state;
struct fd_state;

/* Global info about a particular kind of file descriptor. */
struct fd_ops {
	enum fd_type_t type;	/* type of this file descriptor */

	/* Handler for closing fd. */
	void (*close)(struct state *state, struct fd_state *fd);
};

/* State for a file descriptor during script execution. */
struct fd_state {
	struct fd_ops *ops;	/* info/ops for this type of fd */
	int script_fd;		/* file descriptor in the script source */
	int live_fd;		/* file descriptor in packetdrill runtime */
	bool is_closed;		/* has app called close(2) ? */
	struct fd_state *next;	/* next fd in linked list */
};

/* To cast any type of fd to the base classs. */
static inline struct fd_state *to_fd(void *fd)
{
	return (struct fd_state *)fd;
}

#endif /* __FD_STATE_H__ */
